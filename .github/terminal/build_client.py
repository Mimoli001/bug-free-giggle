#!/usr/bin/env python3
"""Inline xterm.js + fit addon + Vazirmatn into client.template.html -> one self-contained HTML file."""
import base64, sys
nm, tpl, out = sys.argv[1:4]            # node_modules dir, template, output
rd  = lambda p: open(f"{nm}/{p}", encoding="utf-8").read()
b64 = lambda p: base64.b64encode(open(f"{nm}/{p}", "rb").read()).decode()
js  = lambda t: t.replace("</script", "<\\/script")
html = open(tpl, encoding="utf-8").read()
for key, val in {
    "/*XTERM_CSS*/":    rd("@xterm/xterm/css/xterm.css"),
    "/*XTERM_JS*/":     js(rd("@xterm/xterm/lib/xterm.js")),
    "/*FIT_JS*/":       js(rd("@xterm/addon-fit/lib/addon-fit.js")),
    "/*FONT_REGULAR*/": b64("vazirmatn/fonts/webfonts/Vazirmatn-Regular.woff2"),
    "/*FONT_BOLD*/":    b64("vazirmatn/fonts/webfonts/Vazirmatn-Bold.woff2"),
}.items():
    html = html.replace(key, val)
open(out, "w", encoding="utf-8").write(html)
print(f"client.html: {len(html)//1024} KB")
