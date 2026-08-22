#!/usr/bin/env python3
"""从 static/icons/*.svg 生成 static/icons.js（Lucide vendored，运行时零网络）。

用法: python3 tools/gen_icons.py
新增图标: 从 https://lucide.dev 下载同名 svg 放入 static/icons/ 后重跑本脚本。
"""
import json
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(BASE, "static", "icons")
OUT = os.path.join(BASE, "static", "icons.js")

def main():
    out = {}
    for f in sorted(os.listdir(SRC)):
        if not f.endswith(".svg"):
            continue
        svg = open(os.path.join(SRC, f), encoding="utf-8").read()
        svg = re.sub(r"<!--.*?-->", "", svg, flags=re.S)      # license 注释
        svg = re.sub(r'\s+class="[^"]*"', "", svg)            # class
        svg = re.sub(r'\s*(?:width|height)="24"', "", svg)    # 固定尺寸
        svg = svg.replace('stroke-width="2"', 'stroke-width="1.75"')
        svg = re.sub(r"\s*\n\s*", " ", svg).strip()           # 压一行，保留单空格
        out[f[:-4]] = svg
        assert svg.startswith("<svg "), f"bad svg start: {f}"
    js = ("/* Lucide 图标库（vendored, lucide-static, ISC）— 运行时零网络。\n"
          "   由 tools/gen_icons.py 生成，勿手改。 */\n"
          "window.LUCIDE = " + json.dumps(out, ensure_ascii=False) + ";\n")
    open(OUT, "w", encoding="utf-8").write(js)
    print("icons.js: %d icons, %d bytes" % (len(out), os.path.getsize(OUT)))

if __name__ == "__main__":
    main()
