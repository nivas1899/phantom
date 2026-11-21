const pptxgen = require("pptxgenjs");

const pres = new pptxgen();
pres.layout = "LAYOUT_16x9";
pres.author = "Nivas B";
pres.subject = "Internship Presentation";
pres.title = "PHANTOM - Internship Review";

// ── THEME ──
const THEME = {
  name: "PHANTOM White",
  headFontFace: "Calibri",
  bodyFontFace: "Calibri",
  colors: {
    dk1: "1A1A2E", lt1: "FFFFFF", dk2: "2D2D44", lt2: "F5F5FA",
    accent1: "9333FF", accent2: "22D3EE", accent3: "FF334F",
    accent4: "20D88A", accent5: "FFA126", accent6: "398BFF",
    hlink: "9333FF", folHlink: "6B21A8"
  }
};
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };

// ── COLORS ──
const C = {
  title: "1A1A2E",
  body: "333344",
  muted: "666680",
  accent: "9333FF",
  white: "FFFFFF",
  bg: "FFFFFF",
  lightBg: "F7F5FF",
  cardBg: "F5F5FA",
  crit: "FF334F",
  high: "FF334F",
  med: "FFA126",
  low: "20D88A",
  info: "398BFF",
  cyan: "22D3EE",
  purple: "9333FF",
  darkPurple: "6B21A8",
};

// ── HELPERS ──
function addTopBar(slide) {
  slide.addShape(pres.ShapeType.rect, {
    x: 0, y: 0, w: "100%", h: 0.06,
    fill: { color: C.accent },
  });
}

function addFooter(slide, num) {
  slide.addText("PHANTOM — Inter-Layer Semantic Gap Exploitation Framework", {
    x: 0.5, y: 6.85, w: 7, h: 0.3,
    fontSize: 8, color: C.muted, fontFace: "Calibri",
    isTextBox: true, margin: 0,
  });
  slide.addText(String(num), {
    x: 9, y: 6.85, w: 0.8, h: 0.3,
    fontSize: 8, color: C.muted, fontFace: "Calibri",
    align: "right", isTextBox: true, margin: 0,
  });
}

function bulletSlide(slide, title, items, slideNum) {
  addTopBar(slide);
  slide.addText(title, {
    x: 0.6, y: 0.35, w: 8.8, h: 0.6,
    fontSize: 28, fontFace: "Calibri", bold: true,
    color: C.title, isTextBox: true, margin: 0,
  });
  slide.addShape(pres.ShapeType.rect, {
    x: 0.6, y: 1.0, w: 1.2, h: 0.04,
    fill: { color: C.accent },
  });
  const textItems = items.map((item, i) => {
    if (typeof item === "string") {
      return { text: item, options: { fontSize: 14, color: C.body, bullet: true, breakLine: i < items.length - 1, paraSpaceAfter: 6 } };
    }
    return { text: item.text, options: { ...item.options, breakLine: i < items.length - 1 } };
  });
  slide.addText(textItems, {
    x: 0.6, y: 1.3, w: 8.8, h: 5.2,
    fontFace: "Calibri", valign: "top",
    isTextBox: true, margin: [0, 0, 0, 10],
  });
  addFooter(slide, slideNum);
}

// ════════════════════════════════════════════
// SLIDE 1: Title Slide
// ════════════════════════════════════════════
let slide = pres.addSlide();
slide.addShape(pres.ShapeType.rect, {
  x: 0, y: 0, w: "100%", h: "100%",
  fill: { color: C.bg },
});
addTopBar(slide);
// College name
slide.addText("K.S.R. COLLEGE OF ENGINEERING", {
  x: 0.5, y: 0.4, w: 9, h: 0.5,
  fontSize: 22, fontFace: "Calibri", bold: true,
  color: C.title, align: "center", isTextBox: true, margin: 0,
});
// Subject info
slide.addText([
  { text: "24CBP51", options: { fontSize: 14, bold: true, color: C.title } },
  { text: "\nINTERNSHIP PRESENTATION", options: { fontSize: 16, bold: true, color: C.accent, breakLine: true } },
  { text: "\nV SEMESTER", options: { fontSize: 12, color: C.muted, breakLine: true } },
], {
  x: 0.5, y: 1.2, w: 9, h: 1.2,
  fontFace: "Calibri", align: "center",
  isTextBox: true, margin: 0,
});
// Presented by
slide.addText("Presented by,", {
  x: 0.5, y: 2.8, w: 9, h: 0.35,
  fontSize: 12, color: C.accent, fontFace: "Calibri",
  align: "center", isTextBox: true, margin: 0,
});
// Name card
slide.addShape(pres.ShapeType.roundedRectangle, {
  x: 2.8, y: 3.4, w: 4.4, h: 2.2,
  fill: { color: C.lightBg },
  rectRadius: 0.15,
  shadow: { type: "outer", blur: 10, offset: 3, angle: 135, color: "000000", opacity: 0.08 },
});
slide.addText([
  { text: "NIVAS B", options: { fontSize: 24, bold: true, color: C.title } },
  { text: "\n73152426037", options: { fontSize: 14, color: C.accent, breakLine: true } },
  { text: "\nIII Year / V Sem", options: { fontSize: 12, color: C.muted, breakLine: true } },
  { text: "\nDepartment of Computer Science and Engineering", options: { fontSize: 11, color: C.body, breakLine: true } },
  { text: "\n(CYBER SECURITY)", options: { fontSize: 11, bold: true, color: C.accent, breakLine: true } },
], {
  x: 2.9, y: 3.5, w: 4.2, h: 2.0,
  fontFace: "Calibri", align: "center", valign: "middle",
  isTextBox: true, margin: 0,
});
addFooter(slide, 1);

// ════════════════════════════════════════════
// SLIDE 2: Presentation Overview
// ════════════════════════════════════════════
slide = pres.addSlide();
addTopBar(slide);
slide.addText("Presentation Overview", {
  x: 0.6, y: 0.35, w: 8.8, h: 0.6,
  fontSize: 28, fontFace: "Calibri", bold: true,
  color: C.title, isTextBox: true, margin: 0,
});
slide.addShape(pres.ShapeType.rect, {
  x: 0.6, y: 1.0, w: 1.2, h: 0.04,
  fill: { color: C.accent },
});
const overviewData = [
  ["NAME OF THE COMPANY", "Pargavan Cyber Solutions"],
  ["LOCATION", "Near Income Tax Office, Gandhi Rd, Salem, Tamil Nadu"],
  ["FROM", "23.06.2026"],
  ["TO", "10.07.2026"],
  ["NO. OF DAYS", "15"],
  ["DOMAIN", "CYBER SECURITY"],
];
const tableRows = overviewData.map(([k, v]) => [
  { text: k, options: { fontSize: 13, bold: true, color: C.title, fontFace: "Calibri" } },
  { text: v, options: { fontSize: 13, color: C.body, fontFace: "Calibri" } },
]);
slide.addTable(tableRows, {
  x: 0.8, y: 1.4, w: 8.4,
  colW: [3.2, 5.2],
  border: { type: "solid", pt: 0.5, color: "E0E0E8" },
  rowH: 0.55,
  fill: { color: C.bg },
  altFill: { color: C.lightBg },
  margin: [8, 12, 8, 12],
});
addFooter(slide, 2);

// ════════════════════════════════════════════
// SLIDE 3: Company Profile
// ════════════════════════════════════════════
slide = pres.addSlide();
addTopBar(slide);
slide.addText("Company Profile", {
  x: 0.6, y: 0.35, w: 8.8, h: 0.6,
  fontSize: 28, fontFace: "Calibri", bold: true,
  color: C.title, isTextBox: true, margin: 0,
});
slide.addShape(pres.ShapeType.rect, {
  x: 0.6, y: 1.0, w: 1.2, h: 0.04,
  fill: { color: C.accent },
});
const profileData = [
  ["Company Name", "Pargavan Cyber Solutions"],
  ["Headquarters", "Salem, Tamil Nadu, India (Gandhi Road, near Income Tax Office)"],
  ["Core Business", "Cybersecurity consulting, managed IT infrastructure solutions, application development support, and technical training"],
  ["Organisation Structure", "Cyber Security Services, IT Solutions, Application Development Support, and Pargavan Academy (Technical Training & Internships)"],
  ["Technologies Used", "Microsoft, AWS, Google Cloud, Cisco, Fortinet, Linux and Windows Server Administration, Network Infrastructure, and Enterprise Security"],
];
const profileRows = profileData.map(([k, v]) => [
  { text: k, options: { fontSize: 12, bold: true, color: C.title, fontFace: "Calibri", valign: "top" } },
  { text: v, options: { fontSize: 12, color: C.body, fontFace: "Calibri", valign: "top" } },
]);
slide.addTable(profileRows, {
  x: 0.6, y: 1.3, w: 8.8,
  colW: [2.5, 6.3],
  border: { type: "solid", pt: 0.5, color: "E0E0E8" },
  fill: { color: C.bg },
  altFill: { color: C.lightBg },
  margin: [6, 10, 6, 10],
  autoPage: false,
});
addFooter(slide, 3);

// ════════════════════════════════════════════
// SLIDE 4: Internship Objectives and Scope
// ════════════════════════════════════════════
slide = pres.addSlide();
bulletSlide(slide, "Internship Objectives and Scope", [
  "Gained foundational knowledge of cybersecurity principles including the CIA Triad, types of security testing and penetration testing basics.",
  "Studied computer networking fundamentals including IP addressing, subnetting, static routing, DHCP, LAN and VLAN configurations.",
  "Explored industry-standard security tools such as Nmap, Nessus and Burp Suite for vulnerability identification and assessment.",
  "Performed hands-on practical exercises for network scanning and vulnerability assessment using authorised lab environments.",
], 4);

// ════════════════════════════════════════════
// SLIDE 5: Tasks Performed
// ════════════════════════════════════════════
slide = pres.addSlide();
bulletSlide(slide, "Tasks Performed", [
  "Studied cybersecurity fundamentals — CIA Triad, black box, white box and gray box testing, and penetration testing basics.",
  "Configured network topologies using Cisco Packet Tracer — IP addressing, subnetting, static routing, DHCP, LAN and VLAN.",
  "Used Nmap for network discovery and port scanning on authorised targets.",
  "Used Nessus for automated vulnerability scanning, report analysis and CVE-based identification.",
  "Explored Burp Suite and its role in web application security testing.",
], 5);

// ════════════════════════════════════════════
// SLIDE 6: Project Overview
// ════════════════════════════════════════════
slide = pres.addSlide();
addTopBar(slide);
slide.addText("Project Overview", {
  x: 0.6, y: 0.35, w: 8.8, h: 0.6,
  fontSize: 28, fontFace: "Calibri", bold: true,
  color: C.title, isTextBox: true, margin: 0,
});
slide.addShape(pres.ShapeType.rect, {
  x: 0.6, y: 1.0, w: 1.2, h: 0.04,
  fill: { color: C.accent },
});
// Project name card
slide.addShape(pres.ShapeType.roundedRectangle, {
  x: 0.6, y: 1.25, w: 8.8, h: 1.1,
  fill: { color: C.lightBg },
  rectRadius: 0.1,
});
slide.addText([
  { text: "PHANTOM", options: { fontSize: 20, bold: true, color: C.accent } },
  { text: "  Protocol Hallucination & Anomaly Network Testing Oracle Machine", options: { fontSize: 13, color: C.title } },
  { text: "\nAn inter-layer semantic gap exploitation framework that discovers vulnerabilities in the gaps between protocol parsing layers — where the proxy sees one thing and the backend sees another.", options: { fontSize: 12, color: C.muted, breakLine: true } },
], {
  x: 0.8, y: 1.3, w: 8.4, h: 1.0,
  fontFace: "Calibri", valign: "middle",
  isTextBox: true, margin: 0,
});
// Objectives
slide.addText("Objectives", {
  x: 0.6, y: 2.6, w: 3, h: 0.35,
  fontSize: 16, fontFace: "Calibri", bold: true,
  color: C.title, isTextBox: true, margin: 0,
});
const objectives = [
  "Fingerprint the full technology stack (CDN, WAF, Web Server, Framework, Language).",
  "Detect parser differentials between protocol layers using encoding, path and method probes.",
  "Identify HTTP request smuggling vulnerabilities (CL.TE, TE.CL, TE.TE, CL.0).",
  "Discover cache poisoning, method confusion and header injection flaws.",
  "Automatically chain low-severity findings into high-impact exploit paths.",
  "Generate real-time dashboards and exportable HTML/JSON reports.",
];
slide.addText(objectives.map((t, i) => ({
  text: t, options: { fontSize: 13, color: C.body, bullet: true, breakLine: i < objectives.length - 1, paraSpaceAfter: 4 }
})), {
  x: 0.6, y: 3.0, w: 8.8, h: 3.5,
  fontFace: "Calibri", valign: "top",
  isTextBox: true, margin: [0, 0, 0, 10],
});
addFooter(slide, 6);

// ════════════════════════════════════════════
// SLIDE 7: Basic Workflow
// ════════════════════════════════════════════
slide = pres.addSlide();
addTopBar(slide);
slide.addText("Basic Workflow", {
  x: 0.6, y: 0.35, w: 8.8, h: 0.6,
  fontSize: 28, fontFace: "Calibri", bold: true,
  color: C.title, isTextBox: true, margin: 0,
});
slide.addShape(pres.ShapeType.rect, {
  x: 0.6, y: 1.0, w: 1.2, h: 0.04,
  fill: { color: C.accent },
});
const steps = [
  { num: "1", title: "Target Input", desc: "Enter URL, select modules" },
  { num: "2", title: "Fingerprinting", desc: "Detect CDN, WAF, server, framework" },
  { num: "3", title: "Differential Probing", desc: "Encoding, path, method variants" },
  { num: "4", title: "Smuggling Detection", desc: "CL.TE, TE.CL, TE.TE, CL.0" },
  { num: "5", title: "Confusion Testing", desc: "Cache poison, verb tamper, host" },
  { num: "6", title: "Header Injection", desc: "CRLF, reflection, CORS" },
  { num: "7", title: "Chain Synthesis", desc: "15 recipes combine findings" },
];
const cardW = 1.1;
const gap = 0.15;
const startX = 0.5;
steps.forEach((s, i) => {
  const x = startX + i * (cardW + gap);
  // Card background
  slide.addShape(pres.ShapeType.roundedRectangle, {
    x, y: 1.3, w: cardW, h: 2.2,
    fill: { color: C.lightBg },
    rectRadius: 0.08,
    shadow: { type: "outer", blur: 6, offset: 2, angle: 135, color: "000000", opacity: 0.05 },
  });
  // Number circle
  slide.addShape(pres.ShapeType.ellipse, {
    x: x + cardW/2 - 0.2, y: 1.45, w: 0.4, h: 0.4,
    fill: { color: C.accent },
  });
  slide.addText(s.num, {
    x: x + cardW/2 - 0.2, y: 1.45, w: 0.4, h: 0.4,
    fontSize: 14, bold: true, color: C.white,
    align: "center", valign: "middle", fontFace: "Calibri",
    isTextBox: true, margin: 0,
  });
  // Title
  slide.addText(s.title, {
    x: x + 0.05, y: 2.0, w: cardW - 0.1, h: 0.5,
    fontSize: 10, bold: true, color: C.title,
    align: "center", valign: "top", fontFace: "Calibri",
    isTextBox: true, margin: 0,
  });
  // Description
  slide.addText(s.desc, {
    x: x + 0.05, y: 2.5, w: cardW - 0.1, h: 0.8,
    fontSize: 9, color: C.muted,
    align: "center", valign: "top", fontFace: "Calibri",
    isTextBox: true, margin: 0,
  });
  // Arrow between cards
  if (i < steps.length - 1) {
    slide.addText("→", {
      x: x + cardW, y: 2.1, w: gap, h: 0.3,
      fontSize: 14, color: C.accent, align: "center",
      fontFace: "Calibri", isTextBox: true, margin: 0,
    });
  }
});
// Description below
const workflowDesc = [
  { text: "Target Input", options: { bold: true, fontSize: 12, color: C.accent } },
  { text: " → Enter a URL and select scan modules. ", options: { fontSize: 12, color: C.body } },
  { text: "Fingerprinting", options: { bold: true, fontSize: 12, color: C.accent } },
  { text: " → Detect stack layers from response headers. ", options: { fontSize: 12, color: C.body } },
  { text: "Differential Probing", options: { bold: true, fontSize: 12, color: C.accent } },
  { text: " → Send encoding, path, method variants to find layer disagreements. ", options: { fontSize: 12, color: C.body } },
  { text: "Chain Synthesis", options: { bold: true, fontSize: 12, color: C.accent } },
  { text: " → Combine findings into multi-step exploit chains using 15 attack recipes.", options: { fontSize: 12, color: C.body } },
];
slide.addText(workflowDesc, {
  x: 0.6, y: 3.8, w: 8.8, h: 2.6,
  fontFace: "Calibri", valign: "top",
  isTextBox: true, margin: 0,
  lineSpacingMultiple: 1.4,
});
addFooter(slide, 7);

// ════════════════════════════════════════════
// SLIDE 8: Implementation — Architecture
// ════════════════════════════════════════════
slide = pres.addSlide();
addTopBar(slide);
slide.addText("Implementation — Architecture", {
  x: 0.6, y: 0.35, w: 8.8, h: 0.6,
  fontSize: 28, fontFace: "Calibri", bold: true,
  color: C.title, isTextBox: true, margin: 0,
});
slide.addShape(pres.ShapeType.rect, {
  x: 0.6, y: 1.0, w: 1.2, h: 0.04,
  fill: { color: C.accent },
});
const archItems = [
  { title: "Scanner Architecture", desc: "Five modular scanners (Fingerprint, Differential, Smuggling, Confusion, Header) orchestrated by the scan engine.", icon: "⚙" },
  { title: "Async HTTP Client", desc: "Built on httpx with raw TCP socket support for smuggling probes that require malformed HTTP.", icon: "⚡" },
  { title: "Differential Engine", desc: "Eight probe categories testing layer disagreements across encoding, path, method, HPP, host and content-type.", icon: "🔍" },
  { title: "Chain Synthesis", desc: "15 rule-based recipes combining findings by chain tags into exploit paths with severity escalation.", icon: "⛓" },
  { title: "Web Dashboard", desc: "FastAPI backend with real-time polling, live progress, animated SVG visualisations and severity filters.", icon: "📊" },
  { title: "Report Generation", desc: "JSON and styled HTML exports with differential evidence, chain visualisations and remediation notes.", icon: "📄" },
];
archItems.forEach((item, i) => {
  const col = i % 2;
  const row = Math.floor(i / 2);
  const x = 0.6 + col * 4.55;
  const y = 1.3 + row * 1.7;
  // Card
  slide.addShape(pres.ShapeType.roundedRectangle, {
    x, y, w: 4.35, h: 1.5,
    fill: { color: C.lightBg },
    rectRadius: 0.08,
  });
  // Title
  slide.addText(item.title, {
    x: x + 0.15, y: y + 0.1, w: 4.0, h: 0.35,
    fontSize: 14, bold: true, color: C.accent,
    fontFace: "Calibri", isTextBox: true, margin: 0,
  });
  // Description
  slide.addText(item.desc, {
    x: x + 0.15, y: y + 0.5, w: 4.0, h: 0.9,
    fontSize: 11, color: C.body,
    fontFace: "Calibri", valign: "top",
    isTextBox: true, margin: 0,
  });
});
addFooter(slide, 8);

// ════════════════════════════════════════════
// SLIDE 9: Implementation — Technologies
// ════════════════════════════════════════════
slide = pres.addSlide();
addTopBar(slide);
slide.addText("Implementation — Technologies", {
  x: 0.6, y: 0.35, w: 8.8, h: 0.6,
  fontSize: 28, fontFace: "Calibri", bold: true,
  color: C.title, isTextBox: true, margin: 0,
});
slide.addShape(pres.ShapeType.rect, {
  x: 0.6, y: 1.0, w: 1.2, h: 0.04,
  fill: { color: C.accent },
});
const techItems = [
  { tech: "Python 3.12", desc: "Core language for all scanners, async HTTP client and web server" },
  { tech: "FastAPI + Uvicorn", desc: "Async web framework for the real-time scanning dashboard API" },
  { tech: "httpx + h2", desc: "Async HTTP/1.1 and HTTP/2 client with connection pooling" },
  { tech: "Raw TCP Sockets", desc: "Custom socket client for crafting malformed HTTP smuggling probes" },
  { tech: "Rich + Click", desc: "Terminal UI with progress bars and CLI commands (scan, demo, web)" },
  { tech: "Docker", desc: "Containerised deployment with Dockerfile and docker-compose.yml" },
  { tech: "HTML/CSS/JS", desc: "Single-page dashboard with SVG animations and real-time polling" },
  { tech: "Lucide Icons", desc: "Icon library for the dashboard navigation and status indicators" },
];
const techRows = techItems.map(t => [
  { text: t.tech, options: { fontSize: 13, bold: true, color: C.accent, fontFace: "Calibri" } },
  { text: t.desc, options: { fontSize: 12, color: C.body, fontFace: "Calibri" } },
]);
slide.addTable(techRows, {
  x: 0.6, y: 1.3, w: 8.8,
  colW: [2.5, 6.3],
  border: { type: "solid", pt: 0.5, color: "E0E0E8" },
  rowH: 0.55,
  fill: { color: C.bg },
  altFill: { color: C.lightBg },
  margin: [6, 12, 6, 12],
});
addFooter(slide, 9);

// ════════════════════════════════════════════
// SLIDE 10: Results and Outcomes
// ════════════════════════════════════════════
slide = pres.addSlide();
addTopBar(slide);
slide.addText("Results and Outcomes", {
  x: 0.6, y: 0.35, w: 8.8, h: 0.6,
  fontSize: 28, fontFace: "Calibri", bold: true,
  color: C.title, isTextBox: true, margin: 0,
});
slide.addShape(pres.ShapeType.rect, {
  x: 0.6, y: 1.0, w: 1.2, h: 0.04,
  fill: { color: C.accent },
});
// Stats row
const stats = [
  { val: "29", label: "Findings", color: C.purple },
  { val: "16", label: "High", color: C.high },
  { val: "10", label: "Medium", color: C.med },
  { val: "7", label: "Chains", color: C.crit },
  { val: "115", label: "Requests", color: C.cyan },
  { val: "20s", label: "Duration", color: C.low },
];
stats.forEach((s, i) => {
  const x = 0.6 + i * 1.55;
  slide.addShape(pres.ShapeType.roundedRectangle, {
    x, y: 1.2, w: 1.4, h: 1.0,
    fill: { color: C.lightBg },
    rectRadius: 0.08,
  });
  slide.addText(s.val, {
    x, y: 1.25, w: 1.4, h: 0.55,
    fontSize: 26, bold: true, color: s.color,
    align: "center", valign: "middle", fontFace: "Calibri",
    isTextBox: true, margin: 0,
  });
  slide.addText(s.label, {
    x, y: 1.8, w: 1.4, h: 0.35,
    fontSize: 10, color: C.muted,
    align: "center", valign: "top", fontFace: "Calibri",
    isTextBox: true, margin: 0,
  });
});
// Target info
slide.addText([
  { text: "Target: ", options: { fontSize: 12, bold: true, color: C.title } },
  { text: "bugbop.com", options: { fontSize: 12, color: C.accent } },
  { text: "  |  ", options: { fontSize: 12, color: C.muted } },
  { text: "Stack: ", options: { fontSize: 12, bold: true, color: C.title } },
  { text: "Cloudflare CDN → Cloudflare WAF → Rails / Ruby", options: { fontSize: 12, color: C.body } },
], {
  x: 0.6, y: 2.4, w: 8.8, h: 0.35,
  fontFace: "Calibri", isTextBox: true, margin: 0,
});
// Findings bullets
const resultItems = [
  "Scanned bugbop.com (Rails/Ruby behind Cloudflare) in 20 seconds with 115 non-destructive requests.",
  "Detected 29 findings — 16 HIGH, 10 MEDIUM, 2 LOW, 1 INFO — across all five scan modules.",
  "Identified 7 attack chains including 2 CRITICAL chains (WAF Bypass → Backend Exploitation, Request Smuggling → Cache Poisoning).",
  "Fingerprinted a 4-layer parsing stack with \"Very High\" differential risk rating.",
  "Discovered parser differentials where Cloudflare and Rails disagree on URL encoding, path normalisation and HTTP methods.",
  "Demonstrated Unicode normalisation bypasses (fullwidth, Turkish-i, superscript) that evade WAF ACL rules.",
  "Built a production-ready web dashboard with real-time scan progress and exportable HTML/JSON reports.",
];
slide.addText(resultItems.map((t, i) => ({
  text: t, options: { fontSize: 12, color: C.body, bullet: true, breakLine: i < resultItems.length - 1, paraSpaceAfter: 4 }
})), {
  x: 0.6, y: 2.9, w: 8.8, h: 3.6,
  fontFace: "Calibri", valign: "top",
  isTextBox: true, margin: [0, 0, 0, 10],
});
addFooter(slide, 10);

// ════════════════════════════════════════════
// SLIDE 11: Challenges, Solutions and Key Learnings
// ════════════════════════════════════════════
slide = pres.addSlide();
addTopBar(slide);
slide.addText("Challenges, Solutions and Key Learnings", {
  x: 0.6, y: 0.35, w: 8.8, h: 0.6,
  fontSize: 26, fontFace: "Calibri", bold: true,
  color: C.title, isTextBox: true, margin: 0,
});
slide.addShape(pres.ShapeType.rect, {
  x: 0.6, y: 1.0, w: 1.2, h: 0.04,
  fill: { color: C.accent },
});
const challenges = [
  { ch: "Standard HTTP libraries reject malformed smuggling probes.", sol: "Built a raw TCP socket client for byte-level CL.TE/TE.TE requests." },
  { ch: "CDN, WAF and backend parse the same request differently.", sol: "Designed a differential engine comparing responses across encoding, path and method variants." },
  { ch: "Low-severity findings have limited individual impact.", sol: "Chain synthesis engine (15 recipes) combines findings into high-impact exploit chains." },
  { ch: "Real-time dashboard must update during active scans without blocking.", sol: "FastAPI background tasks with async polling and progressive result streaming." },
];
challenges.forEach((c, i) => {
  const y = 1.2 + i * 1.2;
  // Challenge
  slide.addText([
    { text: "Challenge: ", options: { bold: true, fontSize: 12, color: C.crit } },
    { text: c.ch, options: { fontSize: 12, color: C.body } },
  ], {
    x: 0.6, y, w: 8.8, h: 0.4,
    fontFace: "Calibri", valign: "top",
    isTextBox: true, margin: 0,
  });
  // Solution
  slide.addText([
    { text: "Solution: ", options: { bold: true, fontSize: 12, color: C.low } },
    { text: c.sol, options: { fontSize: 12, color: C.body } },
  ], {
    x: 0.8, y: y + 0.4, w: 8.6, h: 0.4,
    fontFace: "Calibri", valign: "top",
    isTextBox: true, margin: 0,
  });
});
// Key learning
slide.addShape(pres.ShapeType.roundedRectangle, {
  x: 0.6, y: 6.0, w: 8.8, h: 0.55,
  fill: { color: C.lightBg },
  rectRadius: 0.06,
});
slide.addText([
  { text: "Key Learning: ", options: { bold: true, fontSize: 12, color: C.accent } },
  { text: "Protocol-layer security gaps are widespread — the innovation is testing between layers, not individual endpoints.", options: { fontSize: 12, color: C.title } },
], {
  x: 0.8, y: 6.05, w: 8.4, h: 0.45,
  fontFace: "Calibri", valign: "middle",
  isTextBox: true, margin: 0,
});
addFooter(slide, 11);

// ════════════════════════════════════════════
// SLIDE 12: Thank You
// ════════════════════════════════════════════
slide = pres.addSlide();
addTopBar(slide);
slide.addText("Thank You", {
  x: 0.5, y: 1.5, w: 9, h: 1,
  fontSize: 44, fontFace: "Calibri", bold: true,
  color: C.title, align: "center", isTextBox: true, margin: 0,
});
slide.addShape(pres.ShapeType.rect, {
  x: 4.2, y: 2.7, w: 1.6, h: 0.04,
  fill: { color: C.accent },
});
slide.addText("Q & A", {
  x: 0.5, y: 3.2, w: 9, h: 1.0,
  fontSize: 36, fontFace: "Calibri", bold: true,
  color: C.accent, align: "center", isTextBox: true, margin: 0,
});
slide.addText([
  { text: "NIVAS B", options: { fontSize: 14, bold: true, color: C.title } },
  { text: "  |  73152426037  |  III Year / V Sem  |  CSE (Cyber Security)", options: { fontSize: 12, color: C.muted } },
], {
  x: 0.5, y: 4.8, w: 9, h: 0.4,
  fontFace: "Calibri", align: "center",
  isTextBox: true, margin: 0,
});
addFooter(slide, 12);

// ── SAVE ──
const outPath = "/home/nivx/intern/phantom/ppt-work/Internship_Review_PPT_Nivas_White.pptx";
pres.writeFile({ fileName: outPath }).then(() => {
  console.log("Saved to " + outPath);
  // Apply theme
  const { applyTheme } = require("/home/nivx/.claude/skills/synced/d4a3019c-ab98-4e97-96bc-5161355391a7_3d6dfcc4-2f75-44a5-bf9f-88261f04096a/pptx/scripts/apply_theme.js");
  return applyTheme(outPath, THEME);
}).then(() => {
  console.log("Theme applied successfully");
}).catch(err => {
  console.error("Error:", err);
});
