#!/usr/bin/env python3
"""Convert SentryScan Markdown specifications to standalone HTML and PDF."""

import re
import subprocess
import sys
from pathlib import Path

import markdown

REPO_ROOT = Path(__file__).resolve().parent.parent
MSEDGE_EXE = Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe")


def build_pdf(md_path: Path, output_pdf: Path) -> Path:
    """Render markdown file to HTML and export to PDF via headless browser."""
    if not md_path.exists():
        sys.stderr.write(f"Error: {md_path} not found\n")
        sys.exit(1)

    md_content = md_path.read_text(encoding="utf-8")

    # Inline SVG images if referenced
    def replace_svg(match):
        rel_path = match.group(1)
        svg_file = (md_path.parent / rel_path).resolve()
        if svg_file.exists():
            svg_text = svg_file.read_text(encoding="utf-8")
            # Strip XML declaration if present
            svg_text = re.sub(r"<\?xml.*?\?>", "", svg_text).strip()
            return f'<div class="diagram-container">{svg_text}</div>'
        return match.group(0)

    # Convert ![alt](path.svg)
    md_content = re.sub(r"!\[.*?\]\((.*?\.svg)\)", replace_svg, md_content)

    html_body = markdown.markdown(
        md_content,
        extensions=["tables", "fenced_code", "toc"],
    )

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SentryScan Specification</title>
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
      font-size: 11pt;
      line-height: 1.5;
      color: #1e293b;
      margin: 0;
      padding: 0;
    }}
    h1 {{
      font-size: 20pt;
      color: #0f172a;
      border-bottom: 2px solid #2563eb;
      padding-bottom: 6px;
      margin-top: 0;
      margin-bottom: 12px;
    }}
    h2 {{
      font-size: 14pt;
      color: #1e40af;
      border-bottom: 1px solid #cbd5e1;
      padding-bottom: 4px;
      margin-top: 24px;
      margin-bottom: 10px;
      page-break-after: avoid;
    }}
    h3 {{
      font-size: 12pt;
      color: #334155;
      margin-top: 16px;
      margin-bottom: 8px;
      page-break-after: avoid;
    }}
    p, ul, ol {{
      margin-top: 0;
      margin-bottom: 10px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 14px 0;
      font-size: 9.5pt;
      page-break-inside: avoid;
    }}
    th, td {{
      border: 1px solid #cbd5e1;
      padding: 7px 10px;
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
      font-size: 9pt;
      background-color: #f1f5f9;
      border-radius: 4px;
    }}
    pre {{
      padding: 10px;
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
      margin: 18px 0;
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
      margin: 20px 0;
    }}
  </style>
</head>
<body>
{html_body}
</body>
</html>
"""
    html_file = md_path.with_suffix(".html")
    html_file.write_text(full_html, encoding="utf-8")
    print(f"[+] Rendered HTML: {html_file.name}")

    if not MSEDGE_EXE.exists():
        sys.stderr.write(
            f"Warning: Edge browser not found at {MSEDGE_EXE}. PDF generation skipped.\n"
        )
        return html_file

    print(f"[*] Printing PDF via headless Edge to {output_pdf.name}...")
    cmd = [
        str(MSEDGE_EXE),
        "--headless",
        "--disable-gpu",
        "--run-all-compositor-stages-before-draw",
        f"--print-to-pdf={output_pdf}",
        f"file:///{html_file.as_posix()}",
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    if output_pdf.exists() and output_pdf.stat().st_size > 0:
        print(f"[+] PDF generated successfully: {output_pdf} ({output_pdf.stat().st_size} bytes)")
    else:
        sys.stderr.write("Error: PDF output file was not created or is empty!\n")
        sys.exit(1)

    return output_pdf


if __name__ == "__main__":
    deliverables = REPO_ROOT / "assignments" / "assignment_1_1" / "deliverables"
    spec_md = deliverables / "SentryScan_Design_Specification.md"
    spec_pdf = deliverables / "SentryScan_Design_Specification.pdf"
    build_pdf(spec_md, spec_pdf)
