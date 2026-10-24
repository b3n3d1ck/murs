"""Automatic PDF report generation with ReportLab."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether,
)

from . import __version__
from .findings import Finding, SEVERITY_ORDER, severity_counts, V_CONFIRMED, V_STILL_PRESENT

INK = colors.HexColor("#0b0f0c")
ACCENT = colors.HexColor("#0a7d4f")
MUTE = colors.HexColor("#5b6168")
LINE = colors.HexColor("#c9ced3")
SEV_COLORS = {
    "Critical": colors.HexColor("#b4231d"),
    "High": colors.HexColor("#c2630f"),
    "Medium": colors.HexColor("#b08900"),
    "Low": colors.HexColor("#2f6db0"),
    "Informational": colors.HexColor("#5b6168"),
}


@dataclass
class ReportData:
    project: str
    researcher: str
    target: str
    scope: dict
    findings: list[Finding]
    endpoints: list  # discovery Endpoint list
    technologies: list[str]
    started_at: str
    finished_at: str
    requests_made: int
    methodology: list[str] = field(default_factory=list)
    retest: list = field(default_factory=list)  # RetestEntry list
    upload_attempts: list = field(default_factory=list)  # UploadAttempt list
    notes: list[str] = field(default_factory=list)


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("H1", parent=ss["Heading1"], textColor=INK, fontSize=15,
                          spaceBefore=14, spaceAfter=6))
    ss.add(ParagraphStyle("Body", parent=ss["BodyText"], textColor=INK, fontSize=9.5,
                          leading=13.5, spaceAfter=4))
    ss.add(ParagraphStyle("Small", parent=ss["BodyText"], textColor=MUTE, fontSize=8,
                          leading=10.5))
    ss.add(ParagraphStyle("Cell", parent=ss["BodyText"], textColor=INK, fontSize=8.3,
                          leading=11))
    ss.add(ParagraphStyle("CellHead", parent=ss["BodyText"], textColor=colors.white,
                          fontSize=8.3, leading=11, fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle("CoverTitle", parent=ss["Title"], textColor=INK, fontSize=30,
                          leading=34, alignment=TA_LEFT))
    ss.add(ParagraphStyle("Eyebrow", parent=ss["BodyText"], textColor=ACCENT, fontSize=10,
                          leading=12, fontName="Helvetica-Bold"))
    return ss


def _p(text, style):
    return Paragraph(escape(str(text)).replace("\n", "<br/>"), style)


def _table(rows, col_widths, ss, header=True):
    data = []
    for i, row in enumerate(rows):
        style = ss["CellHead"] if (header and i == 0) else ss["Cell"]
        data.append([_p(c, style) for c in row])
    t = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
    cmds = [
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1),
         [colors.white, colors.HexColor("#f3f5f4")]),
    ]
    if header:
        cmds.append(("BACKGROUND", (0, 0), (-1, 0), INK))
    t.setStyle(TableStyle(cmds))
    return t


class _DocMaker:
    def __init__(self, data: ReportData, path: str):
        self.data = data
        self.path = path
        self.ss = _styles()

    def _header_footer(self, canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.5)
        if doc.page > 1:
            canvas.line(18 * mm, h - 15 * mm, w - 18 * mm, h - 15 * mm)
            canvas.setFont("Helvetica", 7.5)
            canvas.setFillColor(MUTE)
            canvas.drawString(18 * mm, h - 13.5 * mm, "MURS — Matrix Upload Research Suite")
            canvas.drawRightString(w - 18 * mm, h - 13.5 * mm,
                                   escape(self.data.project)[:60])
        canvas.line(18 * mm, 13 * mm, w - 18 * mm, 13 * mm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTE)
        canvas.drawString(18 * mm, 9 * mm,
                          f"Generated {self.data.finished_at} · MURS v{__version__}")
        canvas.drawRightString(w - 18 * mm, 9 * mm, f"Page {doc.page}")
        canvas.drawCentredString(w / 2, 9 * mm, "Authorized research — confidential")
        canvas.restoreState()

    def build(self):
        doc = BaseDocTemplate(
            self.path, pagesize=A4,
            leftMargin=18 * mm, rightMargin=18 * mm,
            topMargin=20 * mm, bottomMargin=16 * mm,
            title=f"MURS report — {self.data.project}",
            author=self.data.researcher, subject="Authorized web upload security assessment",
            creator=f"MURS v{__version__}",
        )
        frame = Frame(doc.leftMargin, doc.bottomMargin,
                      doc.width, doc.height, id="main")
        doc.addPageTemplates([PageTemplate(id="all", frames=[frame],
                                           onPage=self._header_footer)])
        doc.build(self._story())

    # ------------------------------------------------------------- story
    def _story(self):
        ss = self.ss
        s: list = []
        d = self.data
        counts = severity_counts(d.findings)

        # --- cover
        s.append(Spacer(1, 40 * mm))
        s.append(_p("MATRIX UPLOAD RESEARCH SUITE", ss["Eyebrow"]))
        s.append(_p("Web Upload Security Assessment", ss["CoverTitle"]))
        s.append(Spacer(1, 8 * mm))
        s.append(_table([
            ["Project", d.project],
            ["Researcher", d.researcher],
            ["Target", d.target],
            ["Assessment window", f"{d.started_at}  →  {d.finished_at}"],
            ["Findings", str(len(d.findings))],
            ["Requests issued", str(d.requests_made)],
        ], [45 * mm, 120 * mm], ss, header=False))
        s.append(Spacer(1, 10 * mm))
        s.append(_p("This document reports an authorized, passive-by-default upload "
                    "security assessment. External checks used inert, uniquely-marked "
                    "probe files only. Server-side code execution, where reported, was "
                    "proven with an inert echo-marker — never with a functional webshell.",
                    ss["Small"]))
        s.append(PageBreak())

        # 1. Executive summary
        s.append(_p("1. Executive summary", ss["H1"]))
        confirmed = [f for f in d.findings
                     if f.verification_status in (V_CONFIRMED, V_STILL_PRESENT)]
        s.append(_p(
            f"MURS examined {len(d.endpoints)} endpoint(s) on {escape(d.target)} and "
            f"recorded {len(d.findings)} finding(s), of which {len(confirmed)} are "
            f"evidence-confirmed. Severity breakdown: "
            + ", ".join(f"{k} {counts[k]}" for k in SEVERITY_ORDER) + ".",
            ss["Body"]))
        if not d.findings:
            s.append(_p("No findings were produced by the checks that ran.", ss["Body"]))

        # 2. Severity summary
        s.append(_p("2. Severity summary", ss["H1"]))
        s.append(_table(
            [["Severity", "Count"]] + [[k, str(counts[k])] for k in SEVERITY_ORDER],
            [60 * mm, 30 * mm], ss))

        # 3. Scope and limits
        s.append(_p("3. Scope and testing limits", ss["H1"]))
        sc = d.scope
        s.append(_table([
            ["Allowed hosts", ", ".join(sc.get("allowed_hosts", [])) or "—"],
            ["Allowed ports", ", ".join(map(str, sc.get("allowed_ports", []))) or "—"],
            ["Allowed schemes", ", ".join(sc.get("allowed_schemes", [])) or "—"],
            ["Mode", str(sc.get("mode", ""))],
            ["Max requests", str(sc.get("max_requests", ""))],
            ["Crawl depth", str(sc.get("max_depth", ""))],
        ], [45 * mm, 120 * mm], ss, header=False))
        s.append(Spacer(1, 3 * mm))
        for lim in (
            "External probes are inert and uniquely marked; no functional payloads.",
            "Redirects leaving scope are reported, not followed. Private/reserved "
            "addresses are refused (SSRF guard).",
            "Authentication and access control are never bypassed.",
            "A clean result is not a guarantee of security.",
        ):
            s.append(_p("• " + lim, ss["Small"]))

        # 4. Time and methodology
        s.append(_p("4. Time and methodology", ss["H1"]))
        s.append(_p(f"Window: {d.started_at} → {d.finished_at}. "
                    f"Technologies observed: {', '.join(d.technologies) or 'none detected'}.",
                    ss["Body"]))
        for step in (d.methodology or [
            "Normalize the target and validate scope.",
            "Active discovery: crawl, forms, directory wordlist, fingerprinting.",
            "Upload assessment with inert probes; stage-by-stage evidence.",
            "Evidence-bound classification of findings.",
        ]):
            s.append(_p("• " + step, ss["Small"]))

        # 5. Endpoints examined
        s.append(_p("5. Endpoints examined", ss["H1"]))
        if d.endpoints:
            rows = [["URL", "Method", "Status", "Class"]]
            for e in d.endpoints[:80]:
                rows.append([e.url, e.method, str(e.status), e.classification])
            s.append(_table(rows, [95 * mm, 18 * mm, 18 * mm, 34 * mm], ss))
            if len(d.endpoints) > 80:
                s.append(_p(f"(+{len(d.endpoints) - 80} more omitted)", ss["Small"]))
        else:
            s.append(_p("No endpoints were recorded.", ss["Body"]))

        # upload probe outcome matrix (distinguishes the four outcomes)
        if d.upload_attempts:
            s.append(Spacer(1, 3 * mm))
            s.append(_p("Upload probe outcomes", ParagraphStyle(
                "sub", parent=ss["Body"], fontName="Helvetica-Bold", fontSize=10)))
            rows = [["Upload endpoint", "Probe", "Outcome", "Stored URL (verified)",
                     "Execution URL"]]
            for a in d.upload_attempts:
                rows.append([
                    a.endpoint, a.probe_kind, a.outcome_label,
                    # only a marker-verified location is shown as the stored URL
                    a.stored_location or "— (not confirmed)",
                    # only ever shown when execution was actually observed
                    a.execution_url or "— (not confirmed)",
                ])
            s.append(_table(rows, [36 * mm, 22 * mm, 42 * mm, 33 * mm, 32 * mm], ss))
            s.append(_p("URL legend — Upload endpoint: where the probe was POSTed. "
                        "Stored URL: shown only when the unique inert marker was "
                        "actually retrieved there. Execution URL: shown only when the "
                        "evaluated marker was observed. Unverified candidate paths are "
                        "never listed as confirmed results.", ss["Small"]))

        # 6. Verified findings
        s.append(_p("6. Verified findings", ss["H1"]))
        s.append(self._finding_table(confirmed))

        # 7. Potential findings and evidence limitations
        s.append(_p("7. Potential findings and evidence limitations", ss["H1"]))
        potential = [f for f in d.findings if f not in confirmed]
        s.append(self._finding_table(potential))

        # 8. Finding details
        s.append(PageBreak())
        s.append(_p("8. Finding details", ss["H1"]))
        if not d.findings:
            s.append(_p("No findings to detail.", ss["Body"]))
        for f in d.findings:
            s.append(self._finding_block(f))

        # 9. Remediation priority
        s.append(_p("9. Remediation priority", ss["H1"]))
        ordered = sorted(d.findings, key=lambda f: SEVERITY_ORDER.index(f.severity)
                         if f.severity in SEVERITY_ORDER else 9)
        if ordered:
            rows = [["#", "Severity", "Finding", "Recommendation"]]
            for i, f in enumerate(ordered, 1):
                rows.append([str(i), f.severity, f.title, f.recommendation])
            s.append(_table(rows, [10 * mm, 22 * mm, 60 * mm, 73 * mm], ss))
        else:
            s.append(_p("Nothing to prioritise.", ss["Body"]))

        # 10. Retest results
        s.append(_p("10. Retest results", ss["H1"]))
        if d.retest:
            rows = [["ID", "Severity", "Finding", "Result"]]
            for e in d.retest:
                rows.append([e.id, e.severity, e.title, e.result])
            s.append(_table(rows, [26 * mm, 22 * mm, 74 * mm, 43 * mm], ss))
        else:
            s.append(_p("No retest has been run for this assessment yet.", ss["Body"]))

        # 11. Conclusion
        s.append(_p("11. Conclusion", ss["H1"]))
        crit_high = counts["Critical"] + counts["High"]
        s.append(_p(
            (f"{crit_high} high-or-critical issue(s) require prompt attention. "
             if crit_high else "No critical or high findings were confirmed. ")
            + "Re-run MURS after remediation to produce a before/after comparison.",
            ss["Body"]))

        # 12. Technical appendix
        s.append(_p("12. Technical appendix", ss["H1"]))
        s.append(_p("Run notes: " + ("; ".join(d.notes) if d.notes else "none"), ss["Small"]))
        s.append(_p(f"Scope JSON: {escape(str(d.scope))}", ss["Small"]))
        return s

    def _finding_table(self, findings):
        if not findings:
            return _p("None.", self.ss["Body"])
        rows = [["ID", "Severity", "Confidence", "Title", "Status"]]
        for f in findings:
            rows.append([f.id, f.severity, f.confidence, f.title, f.verification_status])
        return _table(rows, [26 * mm, 20 * mm, 22 * mm, 60 * mm, 37 * mm], self.ss)

    def _finding_block(self, f: Finding):
        ss = self.ss
        sev_color = SEV_COLORS.get(f.severity, MUTE)
        head = Table([[
            _p(f"{f.id} — {f.title}", ParagraphStyle("fh", parent=ss["Cell"],
               fontName="Helvetica-Bold", fontSize=9.5, textColor=colors.white)),
            _p(f.severity, ParagraphStyle("fs", parent=ss["Cell"],
               fontName="Helvetica-Bold", fontSize=9, textColor=colors.white,
               alignment=TA_CENTER)),
        ]], colWidths=[135 * mm, 30 * mm])
        head.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), INK),
            ("BACKGROUND", (1, 0), (1, 0), sev_color),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        body = _table([
            ["Category", f.category],
            ["Endpoint", f.endpoint],
            ["Confidence / status", f"{f.confidence} / {f.verification_status}"],
            ["Retest", f.retest_status],
            ["Detection", f.detection_method],
            ["Observed", f.observed_condition],
            ["Impact", f.impact],
            ["Prerequisites", f.prerequisites],
            ["Reproduction (safe)", f.reproduction],
            ["Recommendation", f.recommendation],
            ["Tested at", f.tested_at],
            ["Evidence", ", ".join(f"{k}={v}" for k, v in f.evidence.items()) or "—"],
        ], [36 * mm, 129 * mm], ss, header=False)
        return KeepTogether([Spacer(1, 3 * mm), head, body])


def generate_pdf(data: ReportData, out_dir: str = "reports") -> str:
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe_project = "".join(c if c.isalnum() else "-" for c in data.project)[:40].strip("-")
    name = f"murs-{safe_project or 'report'}-{stamp}.pdf"
    path = str(Path(out_dir) / name)
    _DocMaker(data, path).build()
    return path
