#!/usr/bin/env python3
"""Generate standardized deliverable Markdown and PDF reports for all assignments."""

import os
import re
import subprocess
import sys
from pathlib import Path

import markdown

REPO_ROOT = Path(__file__).resolve().parent.parent
MSEDGE_EXE = Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{title}</title>
  <style>
    @page {{
      size: A4;
      margin: 18mm 16mm 18mm 16mm;
      @bottom-right {{
        content: counter(page);
      }}
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 10pt;
      line-height: 1.5;
      color: #1e293b;
      margin: 0;
      padding: 0;
    }}
    h1 {{
      font-size: 18pt;
      color: #0f172a;
      border-bottom: 2px solid #2563eb;
      padding-bottom: 6px;
      margin-top: 0;
      margin-bottom: 10px;
    }}
    h2 {{
      font-size: 13pt;
      color: #1e40af;
      border-bottom: 1px solid #cbd5e1;
      padding-bottom: 4px;
      margin-top: 20px;
      margin-bottom: 8px;
      page-break-after: avoid;
    }}
    h3 {{
      font-size: 11pt;
      color: #334155;
      margin-top: 14px;
      margin-bottom: 6px;
      page-break-after: avoid;
    }}
    p, ul, ol {{
      margin-top: 0;
      margin-bottom: 8px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 12px 0;
      font-size: 8.5pt;
      page-break-inside: avoid;
    }}
    th, td {{
      border: 1px solid #cbd5e1;
      padding: 6px 8px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      background-color: #f1f5f9;
      font-weight: 600;
      color: #0f172a;
    }}
    tr:nth-child(even) {{
      background-color: #f8fafc;
    }}
    pre, code {{
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      font-size: 8.5pt;
      background-color: #f1f5f9;
      border-radius: 4px;
    }}
    pre {{
      padding: 8px;
      border: 1px solid #e2e8f0;
      overflow-x: auto;
      page-break-inside: avoid;
    }}
    code {{
      padding: 2px 4px;
    }}
    pre code {{
      padding: 0;
      background: none;
    }}
    .diagram-container {{
      text-align: center;
      margin: 14px 0;
      page-break-inside: avoid;
    }}
    .diagram-container svg {{
      max-width: 100%;
      height: auto;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      background: #ffffff;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }}
    hr {{
      border: none;
      border-top: 1px solid #e2e8f0;
      margin: 16px 0;
    }}
    .meta-box {{
      background-color: #f8fafc;
      border-left: 4px solid #2563eb;
      padding: 8px 12px;
      margin-bottom: 14px;
      font-size: 9pt;
    }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""


def compile_md_to_pdf(md_path: Path, pdf_path: Path, title: str) -> None:
    """Compile a Markdown report to HTML and export as PDF via headless Edge."""
    md_content = md_path.read_text(encoding="utf-8")

    # Inline SVG diagrams if present
    def replace_svg(match):
        rel_path = match.group(1)
        svg_file = (md_path.parent / rel_path).resolve()
        if svg_file.exists():
            svg_text = svg_file.read_text(encoding="utf-8")
            svg_text = re.sub(r"<\?xml.*?\?>", "", svg_text).strip()
            return f'<div class="diagram-container">{svg_text}</div>'
        return match.group(0)

    md_content = re.sub(r"!\[.*?\]\((.*?\.svg)\)", replace_svg, md_content)

    html_body = markdown.markdown(
        md_content,
        extensions=["tables", "fenced_code", "toc"],
    )

    full_html = HTML_TEMPLATE.format(title=title, body=html_body)
    html_path = md_path.with_suffix(".html")
    html_path.write_text(full_html, encoding="utf-8")
    print(f"[+] Generated HTML: {html_path.name}")

    if not MSEDGE_EXE.exists():
        print(f"[!] Warning: Edge not found at {MSEDGE_EXE}. Skipping PDF generation.")
        return

    cmd = [
        str(MSEDGE_EXE),
        "--headless",
        "--disable-gpu",
        "--run-all-compositor-stages-before-draw",
        f"--print-to-pdf={pdf_path}",
        f"file:///{html_path.as_posix()}",
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    if pdf_path.exists() and pdf_path.stat().st_size > 0:
        print(f"[+] Generated PDF: {pdf_path.name} ({pdf_path.stat().st_size} bytes)")
    else:
        print(f"[!] Error generating PDF for {md_path.name}")


print("Helper script ready.")
