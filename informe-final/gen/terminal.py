"""Renderiza sesiones de terminal (comando + salida real) como PNG con Chrome headless."""
import html, json, sys
from pathlib import Path
from playwright.sync_api import sync_playwright

CSS = """body{margin:0;background:#fff}
.win{width:WIDTHpx;border-radius:8px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.25);margin:12px;font-family:'DejaVu Sans Mono',monospace}
.bar{background:#3c3f41;color:#ddd;font:12px 'DejaVu Sans',sans-serif;padding:7px 10px;display:flex;gap:6px;align-items:center}
.d{width:11px;height:11px;border-radius:50%;display:inline-block}
.t{margin-left:10px}
pre{margin:0;background:#1e1f22;color:#d4d4d4;padding:12px 14px;font-size:FONTpx;line-height:1.35;white-space:pre-wrap;word-break:break-all}
.p{color:#6cc644}.c{color:#ffffff;font-weight:bold}.h{color:#e5c07b}.ok{color:#98c379}.bad{color:#e06c75}"""

def color(line):
    e = html.escape(line)
    for w, cls in (("OK", "ok"), ("PASSED", "ok"), ("passed", "ok"), ("REFUSED", "bad"), ("Alert", "bad"), ("fuera de flujo", "bad"), ("SINTÉTICO", "h"), ("BASELINE REAL", "h"), ("LOG REAL", "h"), ("sintetica:", "h")):
        e = e.replace(w, f'<span class="{cls}">{w}</span>')
    return e

def render(spec, out, page):
    parts = []
    for cmd, text in spec["steps"]:
        parts.append(f'<span class="p">{html.escape(spec.get("prompt","$"))}</span> <span class="c">{html.escape(cmd)}</span>')
        parts.extend(color(l) for l in text.rstrip("\n").split("\n"))
    css = CSS.replace("WIDTH", str(spec.get("width", 1100))).replace("FONT", str(spec.get("font", 13)))
    doc = f'<html><head><meta charset="utf-8"><style>{css}</style></head><body><div class="win"><div class="bar"><span class="d" style="background:#ff5f56"></span><span class="d" style="background:#ffbd2e"></span><span class="d" style="background:#27c93f"></span><span class="t">{html.escape(spec["title"])}</span></div><pre>' + "\n".join(parts) + "</pre></div></body></html>"
    page.set_content(doc)
    page.locator(".win").screenshot(path=out)

if __name__ == "__main__":
    specs = json.load(open(sys.argv[1], encoding="utf-8"))
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
        pg = b.new_page(device_scale_factor=2)
        for name, spec in specs.items():
            render(spec, f"{sys.argv[2]}/{name}.png", pg)
            print("ok", name)
        b.close()
