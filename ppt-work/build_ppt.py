"""
Build PHANTOM internship PPT from Gokulraj's template.
- Slides 1-5: change name/reg only
- Slides 6+: replace with PHANTOM content using same layout
"""
import copy
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
from lxml import etree
import re

SRC = "/home/nivx/Downloads/Internship_Review_PPT_Gokulraj(1).pptx"
OUT = "/home/nivx/intern/phantom/ppt-work/Internship_Review_PPT_Nivas.pptx"

prs = Presentation(SRC)

# ── HELPER: replace text in all runs of all paragraphs of a shape ──
def replace_in_shape(shape, old, new):
    if not shape.has_text_frame:
        return
    for para in shape.text_frame.paragraphs:
        for run in para.runs:
            if old in run.text:
                run.text = run.text.replace(old, new)

# ── HELPER: set paragraph text preserving first run formatting ──
def set_para_text(para, text, bold=None, size=None, color=None):
    if para.runs:
        run = para.runs[0]
        run.text = text
        # remove extra runs
        for r in para.runs[1:]:
            r.text = ""
        if bold is not None:
            run.font.bold = bold
        if size is not None:
            run.font.size = size
        if color is not None:
            run.font.color.rgb = color
    else:
        run = para.add_run()
        run.text = text
        if bold is not None:
            run.font.bold = bold
        if size is not None:
            run.font.size = size
        if color is not None:
            run.font.color.rgb = color

# ── HELPER: clear all paragraphs from a text frame ──
def clear_text_frame(tf):
    for i in range(len(tf.paragraphs) - 1, 0, -1):
        p = tf.paragraphs[i]._p
        p.getparent().remove(p)
    if tf.paragraphs:
        for run in tf.paragraphs[0].runs:
            run.text = ""

# ── HELPER: add a bullet paragraph copying style from a reference paragraph ──
def add_bullet_para(tf, text, ref_para=None, bold_prefix=None):
    """Add a paragraph with bullet. If bold_prefix, make that part bold."""
    p = etree.SubElement(tf._txBody, '{http://schemas.openxmlformats.org/drawingml/2006/main}p')

    # Copy paragraph properties from reference if available
    if ref_para is not None:
        ref_pPr = ref_para._p.find('{http://schemas.openxmlformats.org/drawingml/2006/main}pPr')
        if ref_pPr is not None:
            new_pPr = copy.deepcopy(ref_pPr)
            p.insert(0, new_pPr)

    from pptx.oxml.ns import qn

    if bold_prefix and text.startswith(bold_prefix):
        # Bold run
        r1 = etree.SubElement(p, qn('a:r'))
        rPr1 = etree.SubElement(r1, qn('a:rPr'), attrib={'lang': 'en-US', 'b': '1', 'dirty': '0'})
        if ref_para and ref_para.runs:
            ref_rPr = ref_para.runs[0]._r.find(qn('a:rPr'))
            if ref_rPr is not None:
                sz = ref_rPr.get('sz')
                if sz:
                    rPr1.set('sz', sz)
                for child in ref_rPr:
                    if child.tag != qn('a:hlinkClick'):
                        rPr1.append(copy.deepcopy(child))
        t1 = etree.SubElement(r1, qn('a:t'))
        t1.text = bold_prefix

        # Normal run for the rest
        rest = text[len(bold_prefix):]
        if rest:
            r2 = etree.SubElement(p, qn('a:r'))
            rPr2 = etree.SubElement(r2, qn('a:rPr'), attrib={'lang': 'en-US', 'dirty': '0'})
            if ref_para and ref_para.runs:
                ref_rPr = ref_para.runs[0]._r.find(qn('a:rPr'))
                if ref_rPr is not None:
                    sz = ref_rPr.get('sz')
                    if sz:
                        rPr2.set('sz', sz)
                    for child in ref_rPr:
                        if child.tag != qn('a:hlinkClick'):
                            rPr2.append(copy.deepcopy(child))
            t2 = etree.SubElement(r2, qn('a:t'))
            t2.text = rest
    else:
        r = etree.SubElement(p, qn('a:r'))
        rPr = etree.SubElement(r, qn('a:rPr'), attrib={'lang': 'en-US', 'dirty': '0'})
        if ref_para and ref_para.runs:
            ref_rPr = ref_para.runs[0]._r.find(qn('a:rPr'))
            if ref_rPr is not None:
                sz = ref_rPr.get('sz')
                if sz:
                    rPr.set('sz', sz)
                for child in ref_rPr:
                    if child.tag != qn('a:hlinkClick'):
                        rPr.append(copy.deepcopy(child))
        t = etree.SubElement(r, qn('a:t'))
        t.text = text


def set_content_bullets(slide, bullets, title_text=None, bold_prefixes=None):
    """Set title and bullet content on a standard Title+Content slide."""
    for shape in slide.shapes:
        if shape.has_text_frame:
            if shape.name.startswith("Title"):
                if title_text:
                    set_para_text(shape.text_frame.paragraphs[0], title_text)
            elif "Content" in shape.name:
                tf = shape.text_frame
                # Save reference to first paragraph for style
                ref_para = tf.paragraphs[0] if tf.paragraphs else None
                # Clear existing content
                clear_text_frame(tf)
                # Set first paragraph
                if bullets:
                    if bold_prefixes and len(bold_prefixes) > 0:
                        bp = bold_prefixes[0] if bold_prefixes[0] else None
                        if bp and bullets[0].startswith(bp):
                            # need bold prefix in first para too
                            first_p = tf.paragraphs[0]
                            # Clear runs
                            for run in first_p.runs:
                                run.text = ""
                            from pptx.oxml.ns import qn
                            # Remove existing runs
                            for r in first_p._p.findall(qn('a:r')):
                                first_p._p.remove(r)
                            # Add bold run
                            r1 = etree.SubElement(first_p._p, qn('a:r'))
                            rPr1 = etree.SubElement(r1, qn('a:rPr'), attrib={'lang': 'en-US', 'b': '1', 'dirty': '0'})
                            if ref_para and ref_para.runs:
                                ref_rPr = ref_para.runs[0]._r.find(qn('a:rPr'))
                                if ref_rPr is not None:
                                    sz = ref_rPr.get('sz')
                                    if sz: rPr1.set('sz', sz)
                                    for child in ref_rPr:
                                        if child.tag != qn('a:hlinkClick'):
                                            rPr1.append(copy.deepcopy(child))
                            t1 = etree.SubElement(r1, qn('a:t'))
                            t1.text = bp
                            rest = bullets[0][len(bp):]
                            if rest:
                                r2 = etree.SubElement(first_p._p, qn('a:r'))
                                rPr2 = etree.SubElement(r2, qn('a:rPr'), attrib={'lang': 'en-US', 'dirty': '0'})
                                if ref_para and ref_para.runs:
                                    ref_rPr = ref_para.runs[0]._r.find(qn('a:rPr'))
                                    if ref_rPr is not None:
                                        sz = ref_rPr.get('sz')
                                        if sz: rPr2.set('sz', sz)
                                        for child in ref_rPr:
                                            if child.tag != qn('a:hlinkClick'):
                                                rPr2.append(copy.deepcopy(child))
                                t2 = etree.SubElement(r2, qn('a:t'))
                                t2.text = rest
                        else:
                            set_para_text(tf.paragraphs[0], bullets[0])
                    else:
                        set_para_text(tf.paragraphs[0], bullets[0])

                    for i, bullet in enumerate(bullets[1:], 1):
                        bp = None
                        if bold_prefixes and i < len(bold_prefixes):
                            bp = bold_prefixes[i]
                        add_bullet_para(tf, bullet, ref_para, bold_prefix=bp)


# ═══════════════════════════════════════════════════════
# SLIDES 1-5: Replace name and reg number
# ═══════════════════════════════════════════════════════
slides = list(prs.slides)

# Slide 1 — title slide with name
for shape in slides[0].shapes:
    replace_in_shape(shape, "GOKULRAJ S,", "NIVAS B,")
    replace_in_shape(shape, "GOKULRAJ S", "NIVAS B")
    replace_in_shape(shape, "73152426018,", "73152426037,")
    replace_in_shape(shape, "73152426018", "73152426037")

# Slides 2-5 — no name/reg changes needed in content, but check
for si in range(1, 5):
    for shape in slides[si].shapes:
        replace_in_shape(shape, "GOKULRAJ", "NIVAS")
        replace_in_shape(shape, "Gokulraj", "Nivas")
        replace_in_shape(shape, "73152426018", "73152426037")

# ═══════════════════════════════════════════════════════
# SLIDES 6-12: Replace with PHANTOM content
# ═══════════════════════════════════════════════════════

# --- Slide 6: Project Overview ---
set_content_bullets(slides[5],
    title_text="Project Overview",
    bullets=[
        "PHANTOM: Protocol Hallucination & Anomaly Network Testing Oracle Machine",
        "An inter-layer semantic gap exploitation framework that discovers vulnerabilities in the gaps between protocol parsing layers — where the proxy sees one thing and the backend sees another.",
        "",
        "Objective",
        "Fingerprint the full technology stack (CDN, WAF, Web Server, Framework, Language).",
        "Detect parser differentials between protocol layers using encoding, path and method probes.",
        "Identify HTTP request smuggling vulnerabilities (CL.TE, TE.CL, TE.TE, CL.0).",
        "Discover cache poisoning, method confusion and header injection flaws.",
        "Automatically chain low-severity findings into high-impact exploit paths.",
        "Generate real-time dashboards and exportable HTML/JSON reports.",
    ],
    bold_prefixes=[
        "PHANTOM: Protocol Hallucination & Anomaly Network Testing Oracle Machine",
        None, None,
        "Objective",
        None, None, None, None, None, None,
    ]
)

# --- Slide 7: Basic Workflow ---
# Remove the old workflow diagram from the content placeholder
for shape in list(slides[6].shapes):
    if "Content" in shape.name:
        sp = shape._element
        sp.getparent().remove(sp)

for shape in slides[6].shapes:
    if shape.has_text_frame:
        if shape.name.startswith("Title"):
            set_para_text(shape.text_frame.paragraphs[0], "Basic Workflow")
        elif shape.name.startswith("TextBox"):
            # Move textbox up to fill the space where the diagram was
            shape.top = Emu(1752600)
            shape.height = Emu(4800000)
            tf = shape.text_frame
            ref_para = tf.paragraphs[0] if tf.paragraphs else None
            clear_text_frame(tf)
            steps = [
                "Target Input — Enter a URL and select scan modules (Fingerprint, Differential, Smuggling, Confusion, Header).",
                "Stack Fingerprinting — Detect CDN, WAF, web server, framework and language from response headers.",
                "Parser Differential Probing — Send encoding, path and method variants to find layer disagreements.",
                "HTTP Smuggling Detection — Test CL.TE, TE.CL, TE.TE and CL.0 desync patterns via raw sockets.",
                "Confusion Attack Testing — Probe cache poisoning, verb tampering and host header manipulation.",
                "Header Injection Scanning — Test CRLF injection, header reflection and CORS misconfigurations.",
                "Chain Synthesis — Combine findings into multi-step exploit chains using 15 attack chain recipes.",
            ]
            set_para_text(tf.paragraphs[0], steps[0])
            for s in steps[1:]:
                add_bullet_para(tf, s, ref_para)

# --- Slide 8: Implementation (Architecture) ---
# Remove pictures, use content area
for shape in list(slides[7].shapes):
    if shape.shape_type == 13:  # PICTURE
        sp = shape._element
        sp.getparent().remove(sp)

for shape in slides[7].shapes:
    if shape.has_text_frame:
        if shape.name.startswith("Title"):
            set_para_text(shape.text_frame.paragraphs[0], "Implementation")
        elif "Content" in shape.name:
            tf = shape.text_frame
            ref_para = tf.paragraphs[0] if tf.paragraphs else None
            clear_text_frame(tf)
            # Expand content area
            shape.left = Emu(457200)
            shape.top = Emu(1752600)
            shape.width = Emu(8229600)
            shape.height = Emu(4495800)
            items = [
                "Scanner Architecture — Five modular scanners (Fingerprint, Differential, Smuggling, Confusion, Header) orchestrated by the scan engine.",
                "Async HTTP Client — Built on httpx with raw TCP socket support for smuggling probes that require malformed HTTP.",
                "Parser Differential Engine — Eight probe categories (encoding variants, path confusion, method override, HPP, host manipulation, content-type) testing layer disagreements.",
                "Chain Synthesis Engine — 15 rule-based recipes that combine findings by chain tags into multi-step exploit paths with severity escalation.",
                "Web Dashboard — FastAPI backend with real-time polling, live scan progress, animated SVG visualisations and severity-filtered findings.",
                "Report Generation — JSON and styled HTML exports with full finding details, differential evidence and chain visualisations.",
            ]
            set_para_text(tf.paragraphs[0], items[0])
            for item in items[1:]:
                add_bullet_para(tf, item, ref_para)
        elif shape.name.startswith("TextBox"):
            sp = shape._element
            sp.getparent().remove(sp)

# --- Slide 9: Implementation contd (Technologies) ---
# Remove pictures
for shape in list(slides[8].shapes):
    if shape.shape_type == 13:  # PICTURE
        sp = shape._element
        sp.getparent().remove(sp)

set_content_bullets(slides[8],
    title_text="Implementation",
    bullets=[
        "Technologies and Tools Used",
        "Python 3.12 — Core language for all scanners, async HTTP client and web server.",
        "FastAPI + Uvicorn — Async web framework for the real-time scanning dashboard API.",
        "httpx + h2 — Async HTTP/1.1 and HTTP/2 client with connection pooling.",
        "Raw TCP Sockets — Custom socket client for crafting malformed HTTP smuggling probes.",
        "Rich — Terminal UI with progress bars, tables and styled output for CLI mode.",
        "Click — CLI framework with commands: scan, demo, modules, info, web.",
        "Docker — Containerised deployment with Dockerfile and docker-compose.yml.",
        "HTML/CSS/JavaScript — Single-page dashboard with SVG animations, Lucide icons and real-time polling.",
    ],
    bold_prefixes=[
        "Technologies and Tools Used",
        "Python 3.12", "FastAPI + Uvicorn", "httpx + h2", "Raw TCP Sockets",
        "Rich", "Click", "Docker", "HTML/CSS/JavaScript",
    ]
)

# --- Slide 10: Results and Outcomes ---
set_content_bullets(slides[9],
    title_text="Results and Outcomes",
    bullets=[
        "Scanned bugbop.com (Rails/Ruby behind Cloudflare) in 20 seconds with 115 non-destructive requests.",
        "Detected 29 findings — 16 HIGH, 10 MEDIUM, 2 LOW, 1 INFO — across all five scan modules.",
        "Identified 7 attack chains including 2 CRITICAL chains (WAF Bypass → Backend Exploitation, Request Smuggling → Cache Poisoning).",
        "Fingerprinted a 4-layer parsing stack (Cloudflare CDN → Cloudflare WAF → Cloudflare Server → Rails) with \"Very High\" differential risk.",
        "Discovered parser differentials where Cloudflare and Rails disagree on URL encoding, path normalisation, HTTP method and Transfer-Encoding headers.",
        "Demonstrated Unicode normalisation bypasses (fullwidth, Turkish-i, superscript) that bypass WAF ACL rules.",
        "Built a production-ready web dashboard with real-time scan progress, animated visualisations and exportable HTML/JSON reports.",
    ]
)

# --- Slide 11: Challenges, Solutions and Key Learnings ---
set_content_bullets(slides[10],
    title_text="Challenges, Solutions and Key Learnings",
    bullets=[
        "Smuggling probes need malformed HTTP that standard libraries reject — built a custom raw TCP socket client for byte-level CL.TE/TE.TE requests.",
        "CDN, WAF and backend parse the same request differently — designed a differential engine that compares responses across encoding, path and method variants systematically.",
        "Individual low-severity findings have limited impact — implemented a chain synthesis engine with 15 recipes that combines findings into high-impact exploit chains.",
        "Real-time dashboard must update during scans without blocking — used FastAPI background tasks with async polling and progressive result streaming.",
        "Key Learning: Protocol-layer security gaps are widespread. The innovation is testing between layers, not individual endpoints.",
    ],
    bold_prefixes=[None, None, None, None, "Key Learning:"]
)

# --- Slide 12: Thank You ---
# Already has the right layout, just keep it
for shape in slides[11].shapes:
    replace_in_shape(shape, "GOKULRAJ", "NIVAS")
    replace_in_shape(shape, "Gokulraj", "Nivas")

# ═══════════════════════════════════════════════════════
# SAVE
# ═══════════════════════════════════════════════════════
prs.save(OUT)
print(f"Saved to {OUT}")
