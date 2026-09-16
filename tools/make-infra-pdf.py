#!/usr/bin/env python3
"""Render the infrastructure Markdown report as a dependency-free A4 PDF."""
from pathlib import Path
import re
import textwrap

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "docs" / "REFERENSI-SERVER-PRODUKSI.md"
OUT = ROOT / "docs" / "REFERENSI-SERVER-PRODUKSI.pdf"

PAGE_W, PAGE_H = 595, 842
LEFT, TOP, BOTTOM = 48, 54, 48


def esc(value):
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def clean(value):
    value = re.sub(r"`([^`]*)`", r"\1", value)
    value = re.sub(r"\*\*([^*]*)\*\*", r"\1", value)
    return value.encode("latin-1", "replace").decode("latin-1")


lines = SRC.read_text(encoding="utf-8").splitlines()
pages, current = [], []
y = PAGE_H - TOP


def new_page():
    global current, y
    if current:
        pages.append(current)
    current = []
    y = PAGE_H - TOP


def put(text, size=9.5, bold=False, indent=0, gap=12):
    global y
    if y - gap < BOTTOM:
        new_page()
    current.append((LEFT + indent, y, size, bold, clean(text)))
    y -= gap


def paragraph(text, width=92, indent=0, prefix=""):
    wrapped = textwrap.wrap(clean(text), width=width, break_long_words=False, break_on_hyphens=False) or [""]
    for idx, row in enumerate(wrapped):
        put((prefix if idx == 0 else " " * len(prefix)) + row, indent=indent)
    global y
    y -= 3


idx = 0
while idx < len(lines):
    raw = lines[idx].rstrip()
    if not raw:
        y -= 5
        idx += 1
        continue
    if raw.startswith("# "):
        put(raw[2:], 19, True, gap=25)
        idx += 1
        continue
    if raw.startswith("## "):
        y -= 5
        put(raw[3:], 13, True, gap=19)
        idx += 1
        continue
    if raw.startswith("| "):
        rows = []
        while idx < len(lines) and lines[idx].startswith("|"):
            cells = [clean(c.strip()) for c in lines[idx].strip().strip("|").split("|")]
            if not all(re.fullmatch(r":?-+:?", c) for c in cells):
                rows.append(cells)
            idx += 1
        for ridx, cells in enumerate(rows):
            joined = " | ".join(cells)
            for part in textwrap.wrap(joined, width=91, break_long_words=False, break_on_hyphens=False):
                put(part, 8.2, ridx == 0, indent=5, gap=10)
            y -= 2
        y -= 4
        continue
    if raw.startswith("- "):
        paragraph(raw[2:], width=86, indent=10, prefix="- ")
        idx += 1
        continue
    if re.match(r"^\d+\. ", raw):
        match = re.match(r"^(\d+\. )(.*)$", raw)
        paragraph(match.group(2), width=86, indent=10, prefix=match.group(1))
        idx += 1
        continue
    if raw.startswith("    "):
        put(raw.strip(), 8.5, False, indent=12, gap=12)
        idx += 1
        continue
    paragraph(raw)
    idx += 1

if current:
    pages.append(current)

objects = [None]


def add(obj):
    objects.append(obj)
    return len(objects) - 1


font_regular = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
font_bold = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
page_ids, content_ids = [], []
for page_no, entries in enumerate(pages, 1):
    cmds = [b"0.13 0.18 0.25 rg"]
    for x, yy, size, bold, value in entries:
        font = "F2" if bold else "F1"
        cmd = f"BT /{font} {size} Tf 1 0 0 1 {x} {yy} Tm ({esc(value)}) Tj ET".encode("latin-1")
        cmds.append(cmd)
    footer = f"PQC PDF Sign - Infrastruktur dan Kapasitas | Halaman {page_no} dari {len(pages)}"
    cmds.append(f"0.35 0.4 0.48 rg BT /F1 7.5 Tf 1 0 0 1 48 26 Tm ({esc(footer)}) Tj ET".encode("latin-1"))
    stream = b"\n".join(cmds)
    content_ids.append(add(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"))
    page_ids.append(add(b""))

pages_id = add(b"")
catalog_id = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode())
for i, page_id in enumerate(page_ids):
    objects[page_id] = (
        f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
        f"/Resources << /Font << /F1 {font_regular} 0 R /F2 {font_bold} 0 R >> >> "
        f"/Contents {content_ids[i]} 0 R >>"
    ).encode()
kids = " ".join(f"{pid} 0 R" for pid in page_ids)
objects[pages_id] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode()

pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
offsets = [0]
for obj_id, obj in enumerate(objects[1:], 1):
    offsets.append(len(pdf))
    pdf.extend(f"{obj_id} 0 obj\n".encode() + obj + b"\nendobj\n")
xref = len(pdf)
pdf.extend(f"xref\n0 {len(objects)}\n".encode())
pdf.extend(b"0000000000 65535 f \n")
for offset in offsets[1:]:
    pdf.extend(f"{offset:010d} 00000 n \n".encode())
pdf.extend(
    f"trailer\n<< /Size {len(objects)} /Root {catalog_id} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
)
OUT.write_bytes(pdf)
print(f"Wrote {OUT} ({len(pages)} pages, {len(pdf)} bytes)")
