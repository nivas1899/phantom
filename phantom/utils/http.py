from __future__ import annotations

import asyncio
import ssl
import socket
from typing import Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx


@dataclass
class RawResponse:
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0
    error: Optional[str] = None
    raw: str = ""


class PhantomHTTP:
    """Async HTTP client with raw-socket fallback for smuggling tests."""

    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        proxy: Optional[str] = None,
        custom_headers: Optional[dict[str, str]] = None,
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.custom_headers = custom_headers or {}
        self._request_count = 0
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                verify=self.verify_ssl,
                follow_redirects=False,
                proxy=self.proxy,
                headers=self.custom_headers,
                http2=True,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    @property
    def request_count(self) -> int:
        return self._request_count

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict[str, str]] = None,
        body: Optional[str] = None,
        follow_redirects: bool = False,
    ) -> RawResponse:
        client = await self._get_client()
        self._request_count += 1
        try:
            resp = await client.request(
                method,
                url,
                headers=headers,
                content=body.encode() if body else None,
                follow_redirects=follow_redirects,
            )
            return RawResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:4096],
                elapsed_ms=resp.elapsed.total_seconds() * 1000,
                raw=f"HTTP/{resp.http_version} {resp.status_code}\n"
                + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
            )
        except Exception as e:
            return RawResponse(error=str(e))

    async def get(self, url: str, **kwargs) -> RawResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> RawResponse:
        return await self.request("POST", url, **kwargs)

    async def options(self, url: str, **kwargs) -> RawResponse:
        return await self.request("OPTIONS", url, **kwargs)

    async def raw_request(
        self,
        host: str,
        port: int,
        raw_data: bytes,
        use_tls: bool = False,
        timeout: float = 5.0,
    ) -> RawResponse:
        """Send a raw TCP request — used for HTTP smuggling probes."""
        self._request_count += 1
        try:
            reader: Optional[asyncio.StreamReader] = None
            writer: Optional[asyncio.StreamWriter] = None

            if use_tls:
                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx),
                    timeout=timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout,
                )

            writer.write(raw_data)
            await writer.drain()

            data = b""
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                    if not chunk:
                        break
                    data += chunk
            except asyncio.TimeoutError:
                pass

            writer.close()

            text = data.decode("utf-8", errors="replace")
            status = 0
            headers: dict[str, str] = {}
            body = text

            if text.startswith("HTTP/"):
                parts = text.split("\r\n\r\n", 1)
                header_block = parts[0]
                body = parts[1] if len(parts) > 1 else ""
                first_line = header_block.split("\r\n")[0]
                try:
                    status = int(first_line.split(" ", 2)[1])
                except (IndexError, ValueError):
                    pass
                for line in header_block.split("\r\n")[1:]:
                    if ": " in line:
                        k, v = line.split(": ", 1)
                        headers[k.lower()] = v

            return RawResponse(
                status_code=status,
                headers=headers,
                body=body[:4096],
                raw=text[:4096],
            )

        except Exception as e:
            return RawResponse(error=str(e))

    async def smuggle_probe(
        self,
        target_url: str,
        technique: str,
        payload: bytes,
    ) -> RawResponse:
        """Convenience wrapper for smuggling probes."""
        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"
        return await self.raw_request(host, port, payload, use_tls=use_tls)


def parse_target(target: str) -> tuple[str, str, int, bool]:
    """Return (url, host, port, tls) from a target string."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    parsed = urlparse(target)
    host = parsed.hostname or ""
    tls = parsed.scheme == "https"
    port = parsed.port or (443 if tls else 80)
    url = f"{parsed.scheme}://{host}:{port}{parsed.path or '/'}"
    return url, host, port, tls
