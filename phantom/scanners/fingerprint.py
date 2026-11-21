from __future__ import annotations

import re
from phantom.core.models import StackFingerprint, Finding, FindingCategory, Severity
from phantom.scanners.base import BaseScanner

SERVER_SIGS: dict[str, str] = {
    "nginx": "Nginx",
    "apache": "Apache",
    "litespeed": "LiteSpeed",
    "microsoft-iis": "IIS",
    "cloudflare": "Cloudflare",
    "openresty": "OpenResty",
    "gunicorn": "Gunicorn",
    "uvicorn": "Uvicorn",
    "caddy": "Caddy",
    "envoy": "Envoy",
    "traefik": "Traefik",
}

WAF_SIGS: dict[str, list[str]] = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid"],
    "AWS WAF": ["x-amzn-requestid", "x-amz-apigw-id"],
    "Akamai": ["x-akamai-transformed", "akamai-grn"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "Imperva": ["x-iinfo", "x-cdn"],
    "F5 BIG-IP": ["x-wa-info", "bigipserver"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Barracuda": ["barra_counter_session"],
}

CDN_SIGS: dict[str, list[str]] = {
    "Cloudflare": ["cf-ray"],
    "Fastly": ["x-served-by", "x-cache", "fastly"],
    "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop"],
    "Akamai": ["x-akamai-transformed"],
    "Vercel": ["x-vercel-id"],
    "Netlify": ["x-nf-request-id"],
}

PROXY_SIGS: dict[str, list[str]] = {
    "Nginx": ["x-nginx-proxy"],
    "Varnish": ["x-varnish", "via"],
    "HAProxy": ["x-haproxy-server-state"],
    "Envoy": ["x-envoy-upstream-service-time"],
    "Traefik": ["x-traefik-"],
}

FRAMEWORK_SIGS: dict[str, list[str]] = {
    "Express": ["x-powered-by: express"],
    "Django": ["csrftoken", "x-frame-options: deny"],
    "Rails": ["x-request-id", "x-runtime"],
    "Laravel": ["laravel_session"],
    "ASP.NET": ["x-aspnet-version", "x-powered-by: asp.net"],
    "Spring": ["x-application-context"],
    "Flask": ["werkzeug"],
    "Next.js": ["x-nextjs-", "x-powered-by: next.js"],
    "PHP": ["x-powered-by: php"],
}

INTERESTING_HEADERS = [
    "x-debug", "x-debug-token", "x-request-id", "x-trace-id",
    "x-powered-by", "x-aspnet-version", "x-runtime",
    "server-timing", "x-backend-server", "x-upstream",
    "x-forwarded-host", "x-original-url", "x-rewrite-url",
]


class FingerprintScanner(BaseScanner):
    name = "fingerprint"
    description = "Fingerprint the technology stack and enumerate parsing layers"

    async def run(self) -> list[Finding]:
        fp = StackFingerprint()

        baseline = await self.http.get(self.target)
        if baseline.error:
            return self.findings

        fp.headers = baseline.headers
        self._detect_server(fp, baseline.headers)
        self._detect_waf(fp, baseline.headers)
        self._detect_cdn(fp, baseline.headers)
        self._detect_proxy(fp, baseline.headers)
        self._detect_framework(fp, baseline.headers, baseline.body)
        self._detect_language(fp, baseline.headers)
        self._find_interesting_headers(fp, baseline.headers)

        error_resp = await self.http.get(
            self.target.rstrip("/") + "/PhAnToM_404_pRoBe_" + "x" * 40,
        )
        if not error_resp.error:
            self._analyze_error_page(fp, error_resp)

        options_resp = await self.http.options(self.target)
        if not options_resp.error and "allow" in options_resp.headers:
            fp.technologies.append(f"Allowed methods: {options_resp.headers['allow']}")

        self.fingerprint = fp

        if fp.layer_count >= 3:
            self.add(Finding(
                title="Multi-layer parsing stack detected",
                category=FindingCategory.INFO_DISCLOSURE,
                severity=Severity.INFO,
                description=(
                    f"Detected {fp.layer_count} distinct parsing layers. "
                    "More layers increase the probability of parser differentials."
                ),
                evidence="\n".join(f"  {k}: {v}" for k, v in fp.summary_lines()),
            ))

        verbose_headers = [
            h for h in ["x-powered-by", "server", "x-aspnet-version", "x-runtime"]
            if h in baseline.headers
        ]
        if verbose_headers:
            self.add(Finding(
                title="Verbose technology disclosure via headers",
                category=FindingCategory.INFO_DISCLOSURE,
                severity=Severity.LOW,
                description="The server exposes technology details in response headers.",
                evidence="\n".join(f"  {h}: {baseline.headers[h]}" for h in verbose_headers),
                remediation="Remove or obfuscate version-disclosing headers.",
                chainable=True,
                chain_tags=["info_leak", "version_disclosure"],
            ))

        return self.findings

    def _detect_server(self, fp: StackFingerprint, headers: dict[str, str]) -> None:
        server = headers.get("server", "").lower()
        for sig, name in SERVER_SIGS.items():
            if sig in server:
                fp.web_server = name
                version_match = re.search(r"[\d]+\.[\d]+\.?[\d]*", headers.get("server", ""))
                if version_match:
                    fp.web_server_version = version_match.group()
                break

    def _detect_waf(self, fp: StackFingerprint, headers: dict[str, str]) -> None:
        lower_headers = {k.lower(): v for k, v in headers.items()}
        for waf_name, signatures in WAF_SIGS.items():
            for sig in signatures:
                if sig.lower() in lower_headers:
                    fp.waf = waf_name
                    return

    def _detect_cdn(self, fp: StackFingerprint, headers: dict[str, str]) -> None:
        lower_headers = {k.lower() for k in headers}
        for cdn_name, signatures in CDN_SIGS.items():
            for sig in signatures:
                if sig.lower() in lower_headers:
                    fp.cdn = cdn_name
                    return

    def _detect_proxy(self, fp: StackFingerprint, headers: dict[str, str]) -> None:
        lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
        all_text = " ".join(f"{k} {v}" for k, v in lower_headers.items())
        for proxy_name, signatures in PROXY_SIGS.items():
            for sig in signatures:
                if sig.lower() in all_text:
                    fp.reverse_proxy = proxy_name
                    return
        via = lower_headers.get("via", "")
        if via:
            fp.reverse_proxy = f"Proxy (via: {headers.get('via', via)})"

    def _detect_framework(
        self, fp: StackFingerprint, headers: dict[str, str], body: str
    ) -> None:
        lower_text = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        for fw_name, signatures in FRAMEWORK_SIGS.items():
            for sig in signatures:
                if sig.lower() in lower_text:
                    fp.framework = fw_name
                    return

        if "csrfmiddlewaretoken" in body:
            fp.framework = "Django"
        elif "laravel_session" in lower_text:
            fp.framework = "Laravel"
        elif "__viewstate" in body.lower():
            fp.framework = "ASP.NET WebForms"

    def _detect_language(self, fp: StackFingerprint, headers: dict[str, str]) -> None:
        powered = headers.get("x-powered-by", "").lower()
        if "php" in powered:
            fp.language = "PHP"
        elif "asp.net" in powered:
            fp.language = "C# / ASP.NET"
        elif fp.framework:
            lang_map = {
                "Django": "Python", "Flask": "Python",
                "Rails": "Ruby", "Express": "JavaScript/Node.js",
                "Next.js": "JavaScript/Node.js", "Spring": "Java",
                "Laravel": "PHP", "Gunicorn": "Python",
            }
            fp.language = lang_map.get(fp.framework)

    def _find_interesting_headers(self, fp: StackFingerprint, headers: dict[str, str]) -> None:
        lower_map = {k.lower(): k for k in headers}
        for ih in INTERESTING_HEADERS:
            if ih in lower_map:
                fp.interesting_headers.append(f"{lower_map[ih]}: {headers[lower_map[ih]]}")

    def _analyze_error_page(self, fp: StackFingerprint, resp) -> None:
        body_lower = resp.body.lower()
        if "nginx" in body_lower and not fp.web_server:
            fp.web_server = "Nginx"
        elif "apache" in body_lower and not fp.web_server:
            fp.web_server = "Apache"
        elif "iis" in body_lower and not fp.web_server:
            fp.web_server = "IIS"

        if "stack trace" in body_lower or "traceback" in body_lower:
            self.add(Finding(
                title="Detailed error page exposes internals",
                category=FindingCategory.INFO_DISCLOSURE,
                severity=Severity.MEDIUM,
                description="The server returns detailed error information including stack traces.",
                evidence=resp.body[:500],
                remediation="Disable detailed error pages in production.",
                chainable=True,
                chain_tags=["info_leak", "debug_info"],
            ))
