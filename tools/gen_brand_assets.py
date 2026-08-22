#!/usr/bin/env python3
"""从品牌 AppIcon 主图生成网页图标与 macOS ICNS。

依赖 Pillow（requirements-dev.txt）和 macOS 自带的 iconutil。
主图必须是带透明通道的正方形 PNG，并自行包含安全留白。
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "static" / "assets" / "console-app-icon.png"
ASSETS = ROOT / "static" / "assets"
ICNS = ROOT / "总控台.app" / "Contents" / "Resources" / "AppIcon.icns"

ICONSET_SIZES = (
    (16, "icon_16x16.png"),
    (32, "icon_16x16@2x.png"),
    (32, "icon_32x32.png"),
    (64, "icon_32x32@2x.png"),
    (128, "icon_128x128.png"),
    (256, "icon_128x128@2x.png"),
    (256, "icon_256x256.png"),
    (512, "icon_256x256@2x.png"),
    (512, "icon_512x512.png"),
    (1024, "icon_512x512@2x.png"),
)


def resized(source: Image.Image, size: int) -> Image.Image:
    return source.resize((size, size), Image.Resampling.LANCZOS)


def main() -> None:
    if not SOURCE.is_file():
        raise SystemExit(f"缺少品牌主图：{SOURCE}")
    source = Image.open(SOURCE).convert("RGBA")
    if source.width != source.height:
        raise SystemExit("品牌主图必须是正方形")

    resized(source, 32).save(ASSETS / "favicon-32.png", optimize=True)
    resized(source, 180).save(ASSETS / "apple-touch-icon.png", optimize=True)
    source.save(
        ASSETS / "favicon.ico",
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48)],
    )

    iconutil = shutil.which("iconutil")
    if not iconutil:
        raise SystemExit("找不到 macOS iconutil，无法生成 AppIcon.icns")
    with tempfile.TemporaryDirectory(prefix="console-brand-") as tmp:
        iconset = Path(tmp) / "AppIcon.iconset"
        iconset.mkdir()
        for size, name in ICONSET_SIZES:
            resized(source, size).save(iconset / name, optimize=True)
        subprocess.run(
            [iconutil, "-c", "icns", str(iconset), "-o", str(ICNS)],
            check=True,
        )

    print(f"已生成 {ASSETS / 'favicon.ico'}")
    print(f"已生成 {ASSETS / 'favicon-32.png'}")
    print(f"已生成 {ASSETS / 'apple-touch-icon.png'}")
    print(f"已生成 {ICNS}")


if __name__ == "__main__":
    main()
