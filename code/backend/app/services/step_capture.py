"""Generación automática de capturas de evidencia por paso (estilo terminal)."""

from __future__ import annotations

import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from app.core.config import SCREENSHOTS_DIR
from app.services.report_content import build_audit_steps, safe_target

WIDTH = 960
PADDING = 24
LINE_HEIGHT = 22
HEADER_H = 56
FONT_PATHS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    "C:/Windows/Fonts/consola.ttf",
]


def _load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in FONT_PATHS:
        if Path(path).is_file():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _wrap_lines(text: str, width: int = 100) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        if not raw.strip():
            lines.append("")
            continue
        lines.extend(textwrap.wrap(raw, width=width) or [""])
    return lines


def render_step_screenshot(
    target: str,
    step_num: int,
    step_key: str,
    title: str,
    body_lines: list[str],
) -> Path:
    folder = SCREENSHOTS_DIR / safe_target(target)
    folder.mkdir(parents=True, exist_ok=True)
    out_path = folder / f"{step_num:02d}_{step_key}.png"

    font = _load_font(16)
    font_sm = _load_font(13)
    font_title = _load_font(20)

    wrapped: list[str] = []
    for line in body_lines:
        wrapped.extend(_wrap_lines(line, width=92))

    content_h = len(wrapped) * LINE_HEIGHT + PADDING * 2
    height = HEADER_H + content_h + PADDING

    img = Image.new("RGB", (WIDTH, max(height, 200)), (12, 12, 12))
    draw = ImageDraw.Draw(img)

    draw.rectangle((0, 0, WIDTH, HEADER_H), fill=(26, 92, 56))
    draw.text((PADDING, 14), f"ReconTool — Paso {step_num}: {title}", fill=(255, 255, 255), font=font_title)
    draw.text((PADDING, HEADER_H - 22), f"Target: {target}", fill=(255, 200, 200), font=font_sm)

    y = HEADER_H + PADDING
    for line in wrapped:
        color = (180, 255, 180) if "HTB{" in line or line.strip().startswith("FLAG") else (220, 220, 220)
        if line.startswith("[") and "]" in line:
            color = (120, 200, 255)
        draw.text((PADDING, y), line, fill=color, font=font)
        y += LINE_HEIGHT

    draw.rectangle((0, 0, WIDTH - 1, height - 1), outline=(60, 60, 60), width=2)
    img.save(out_path, format="PNG")
    return out_path


def capture_all_evidence(scan_data: dict) -> list[str]:
    target = scan_data.get("target", "unknown")
    generated: list[str] = []

    for idx, step in enumerate(build_audit_steps(scan_data), start=1):
        body = [
            f"$ {step.get('tool', 'ReconTool')}",
            "",
            *step.get("findings", "").split("\n"),
        ]
        path = render_step_screenshot(
            target,
            idx,
            step.get("key", f"step{idx}"),
            step.get("title", "Paso"),
            body,
        )
        generated.append(str(path))

    flags = scan_data.get("exploitation", {}).get("flags") or []
    if flags:
        flag_lines = ["$ get flag.txt", ""]
        for f in flags:
            flag_lines.append(f.get("content", ""))
        path = render_step_screenshot(target, 99, "flag", "Flag capturada", flag_lines)
        generated.append(str(path))

    scan_data["evidence_screenshots"] = generated
    return generated
