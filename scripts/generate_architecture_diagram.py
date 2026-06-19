#!/usr/bin/env python3
"""Generate docs/architecture.png — clean engineering diagram for Software Butcher."""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")

from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, PathPatch
from matplotlib.path import Path as MplPath

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "architecture.png"

# Palette — restrained, high contrast
BG = "#0f1419"
LANE = "#151b23"
CARD = "#1c2430"
BORDER = "#3d4f61"
TEXT = "#eef2f6"
SUB = "#8fa3b8"
ACCENT = "#4dabf7"
BRAIN = "#be4bdb"
SHELF = "#40c057"
STATE = "#fab005"
SYNTH = "#ff6b6b"
ARROW = "#5c7080"
HIGHLIGHT = "#364fc7"


def rounded_rect(ax, xy, w, h, fc=CARD, ec=BORDER, lw=1.2, radius=0.012, zorder=2):
    x, y = xy
    patch = FancyBboxPatch(
        (x, y), w, h,
        boxstyle=f"round,pad=0,rounding_size={radius}",
        linewidth=lw, edgecolor=ec, facecolor=fc, zorder=zorder,
    )
    ax.add_patch(patch)
    return patch


def lane_bg(ax, xy, w, h, label, color):
    x, y = xy
    rounded_rect(ax, (x, y), w, h, fc=LANE, ec=BORDER, lw=1.0, radius=0.015, zorder=0)
    ax.text(x + 0.012, y + h - 0.022, label, color=color, fontsize=11, fontweight="bold", va="top", zorder=3)


def card(ax, xy, w, h, title, lines=(), accent=BORDER, title_size=12, line_size=9):
    x, y = xy
    rounded_rect(ax, (x, y), w, h, ec=accent, lw=1.6, zorder=2)
    ax.text(x + w / 2, y + h - 0.028, title, ha="center", va="top", color=TEXT,
            fontsize=title_size, fontweight="bold", zorder=3)
    for i, line in enumerate(lines):
        ax.text(x + w / 2, y + h - 0.065 - i * 0.028, line, ha="center", va="top",
                color=SUB, fontsize=line_size, zorder=3)


def arrow(ax, p0, p1, color=ARROW, lw=1.8, style="-|>", rad=0.0, zorder=1):
    ax.add_patch(FancyArrowPatch(
        p0, p1, arrowstyle=style, mutation_scale=14,
        linewidth=lw, color=color, connectionstyle=f"arc3,rad={rad}",
        shrinkA=6, shrinkB=6, zorder=zorder,
    ))


def elbow(ax, points, color=ARROW, lw=1.8, zorder=1):
    """Draw orthogonal polyline with arrowhead at end."""
    verts = list(points)
    codes = [MplPath.MOVETO] + [MplPath.LINETO] * (len(verts) - 1)
    path = MplPath(verts, codes)
    ax.add_patch(PathPatch(path, facecolor="none", edgecolor=color, lw=lw, zorder=zorder))
    # arrowhead
    x0, y0 = verts[-2]
    x1, y1 = verts[-1]
    arrow(ax, (x0, y0), (x1, y1), color=color, lw=lw, zorder=zorder)


def branch_fork(ax, origin, tips, color=BRAIN, lw=1.4):
    ox, oy = origin
    for tx, ty in tips:
        ax.plot([ox, tx], [oy, ty], color=color, lw=lw, solid_capstyle="round", zorder=2)
        ax.scatter([tx], [ty], s=28, color=color, zorder=3, edgecolors=BG, linewidths=0.8)
    ax.scatter([ox], [oy], s=36, color=color, zorder=3, edgecolors=TEXT, linewidths=1.0)


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(16, 9), facecolor=BG)
    ax.set_facecolor(BG)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # ── Title block ───────────────────────────────────────────────────────
    ax.text(0.05, 0.965, "Software Butcher", color=TEXT, fontsize=26, fontweight="bold", va="top")
    ax.text(0.05, 0.925, "Reasoning harness  ·  not a swarm", color=SUB, fontsize=12, va="top")
    ax.plot([0.05, 0.95], [0.905, 0.905], color=BORDER, lw=1.0)

    # ── Lane backgrounds ──────────────────────────────────────────────────
    lane_bg(ax, (0.04, 0.12), 0.20, 0.76, "INPUT", ACCENT)
    lane_bg(ax, (0.27, 0.12), 0.46, 0.76, "CORE LOOP", BRAIN)
    lane_bg(ax, (0.76, 0.12), 0.20, 0.76, "EXECUTION", SHELF)

    # ── INPUT column ────────────────────────────────────────────────────
    card(ax, (0.055, 0.72), 0.17, 0.13, "Scope", (
        "scope.json",
        "domains · IPs · URLs",
        "max_tool_calls budget",
    ), accent=ACCENT)

    card(ax, (0.055, 0.54), 0.17, 0.13, "Target", (
        "IP · domain · URL",
        "binary · cloud asset",
    ), accent=ACCENT)

    card(ax, (0.055, 0.30), 0.17, 0.17, "Workspace", (
        "finding_state.json",
        "session_state.json",
        "artifacts/",
    ), accent=ACCENT)

    # ── SHELF column ────────────────────────────────────────────────────
    card(ax, (0.775, 0.72), 0.17, 0.15, "HexStrike", (
        "Flask API  :8888",
        "150+ security tools",
        "nmap · nuclei · sqlmap …",
    ), accent=SHELF)

    card(ax, (0.775, 0.52), 0.17, 0.13, "Web / Binary", (
        "Playwright-Curl",
        "Binary triage",
    ), accent=SHELF)

    card(ax, (0.775, 0.32), 0.17, 0.13, "Frameworks", (
        "Caldera · ART",
        "Stratus · BOAZ",
    ), accent=SHELF)

    ax.text(0.86, 0.22, "execute only\nno reasoning", ha="center", color=SUB, fontsize=9, style="italic")

    # ── CORE: central state hub ─────────────────────────────────────────
    sx, sy, sw, sh = 0.40, 0.46, 0.20, 0.18
    rounded_rect(ax, (sx, sy), sw, sh, fc="#252d3a", ec=STATE, lw=2.2, radius=0.014, zorder=2)
    ax.text(sx + sw / 2, sy + sh - 0.03, "Finding State", ha="center", color=STATE,
            fontsize=14, fontweight="bold", zorder=3)
    ax.text(sx + sw / 2, sy + sh / 2 - 0.01, "single source of truth", ha="center", color=TEXT,
            fontsize=10, zorder=3)
    ax.text(sx + sw / 2, sy + sh / 2 - 0.05, "findings  ·  hypothesis queue", ha="center",
            color=SUB, fontsize=9, zorder=3)
    ax.text(sx + sw / 2, sy + 0.025, "auditable · diffable · resumable", ha="center",
            color=SUB, fontsize=8.5, zorder=3)

    # ── CORE: Brain ─────────────────────────────────────────────────────
    card(ax, (0.30, 0.72), 0.18, 0.14, "Brain", (
        "read state → pick tool",
        "interpret output → write findings",
        "generate follow-up hypotheses",
    ), accent=BRAIN, title_size=13)

    card(ax, (0.52, 0.72), 0.18, 0.14, "DeepSeek", (
        "capability selection",
        "hypothesis priority",
        "optional — policy fallback",
    ), accent=HIGHLIGHT, title_size=13)

    # Parallel branch visualization
    ax.text(0.50, 0.665, "parallel branches per step", ha="center", color=SUB, fontsize=9, zorder=3)
    branch_fork(ax, (0.50, 0.62), [(0.36, 0.58), (0.50, 0.57), (0.64, 0.58)], color=BRAIN)
    for i, (bx, _) in enumerate([(0.36, 0), (0.50, 0), (0.64, 0)]):
        ax.text(bx, 0.555, f"B{i+1}", ha="center", color=TEXT, fontsize=8, zorder=3)

    # ── CORE: Synthesis ─────────────────────────────────────────────────
    card(ax, (0.30, 0.16), 0.40, 0.14, "Synthesis", (
        "reads complete finding state  →  connects evidence  →  cited verdict",
        "secure  ·  partially_hardened  ·  compromised",
    ), accent=SYNTH, title_size=13, line_size=9.5)

    # ── Flow arrows ─────────────────────────────────────────────────────
    # Input → Brain
    arrow(ax, (0.225, 0.785), (0.30, 0.785), color=ACCENT)
    arrow(ax, (0.225, 0.605), (0.30, 0.755), color=ACCENT, rad=0.08)
    ax.text(0.255, 0.80, "seed", color=SUB, fontsize=8)

    # Brain ↔ State
    arrow(ax, (0.39, 0.72), (0.44, 0.64), color=BRAIN)
    arrow(ax, (0.56, 0.64), (0.48, 0.72), color=BRAIN)
    ax.text(0.415, 0.695, "read", color=SUB, fontsize=8)
    ax.text(0.535, 0.695, "write", color=SUB, fontsize=8)

    # DeepSeek → Brain
    arrow(ax, (0.52, 0.72), (0.48, 0.72), color=HIGHLIGHT, lw=1.4)

    # Branches → State
    for bx in (0.36, 0.50, 0.64):
        arrow(ax, (bx, 0.575), (bx, 0.55), color=BRAIN, lw=1.2)
        elbow(ax, [(bx, 0.55), (bx, 0.52), (0.50, 0.52), (0.50, 0.46)], color=BRAIN, lw=1.2)

    # State → Shelf (tool request)
    arrow(ax, (0.60, 0.52), (0.775, 0.79), color=SHELF, rad=-0.05)
    ax.text(0.695, 0.68, "tool call", color=SHELF, fontsize=9)

    # Shelf → State (raw output)
    arrow(ax, (0.775, 0.58), (0.60, 0.48), color=SHELF, rad=0.05)
    ax.text(0.695, 0.52, "raw output\n→ findings", color=SHELF, fontsize=8, ha="center")

    # State → Synthesis
    arrow(ax, (0.50, 0.46), (0.50, 0.30), color=SYNTH, lw=2.0)
    ax.text(0.515, 0.38, "full state", color=SUB, fontsize=8)

    # Workspace tie-in
    elbow(ax, [(0.14, 0.38), (0.14, 0.52), (0.40, 0.52), (0.40, 0.46)], color=ACCENT, lw=1.2)

    # ── Footer legend ─────────────────────────────────────────────────────
    legend_y = 0.065
    for i, (label, color) in enumerate([
        ("Brain reasons", BRAIN),
        ("Shelf executes", SHELF),
        ("State persists", STATE),
        ("Synthesis reports", SYNTH),
    ]):
        x = 0.30 + i * 0.17
        ax.add_patch(mpatches.Circle((x, legend_y), 0.006, color=color, zorder=3))
        ax.text(x + 0.015, legend_y, label, color=SUB, fontsize=9, va="center")

    ax.text(0.95, 0.04, "v0.1", color=BORDER, fontsize=8, ha="right")

    fig.savefig(OUT, dpi=220, bbox_inches="tight", facecolor=BG, edgecolor="none", pad_inches=0.35)
    plt.close(fig)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
