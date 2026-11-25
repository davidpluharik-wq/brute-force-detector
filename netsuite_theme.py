"""Shared NetSuite look: navy palette, ttk styling and a header bar with the skull.

Drop this file next to an app and call:

    from netsuite_theme import apply_theme, add_header
    add_header(root, "App Name")   # before you build the body
    ...build your widgets...
    apply_theme(root)              # after, so these ttk styles win

apply_theme restyles ttk widgets and the default colors for tk.Text, so most
widgets pick up the theme without per-widget edits.
"""
import tkinter as tk
from tkinter import ttk
from tkinter import font as tkfont

from skull_art import add_skull

BG_COLOR = "#101722"
PANEL_BG = "#172130"
TEXT_COLOR = "#e4eaf2"
ACCENT = "#83b5f4"
WARN = "#ee9297"
GOOD = "#87c8ab"
MEDIUM = "#dcc18b"
MUTED = "#94a4ba"
BORDER = "#2a3749"
SELECTED_BG = "#253b55"
TEXT_BG = "#111c2a"

UI_FONT = "DejaVu Sans"
MONO_FONT = "DejaVu Sans Mono"


def apply_theme(root):
    """Apply the NetSuite palette and ttk styles to a window. Safe to call once per app."""
    global UI_FONT, MONO_FONT
    families = set(tkfont.families(root))
    UI_FONT = next((f for f in ("Inter", "Segoe UI", "DejaVu Sans") if f in families), "TkDefaultFont")
    MONO_FONT = next((f for f in ("JetBrains Mono", "DejaVu Sans Mono", "Consolas") if f in families), "TkFixedFont")
    for name in ("TkDefaultFont", "TkTextFont"):
        tkfont.nametofont(name).configure(family=UI_FONT, size=10)
    tkfont.nametofont("TkFixedFont").configure(family=MONO_FONT, size=10)

    root.configure(bg=BG_COLOR)
    for option, value in (("background", TEXT_BG), ("foreground", TEXT_COLOR), ("insertBackground", ACCENT),
                          ("selectBackground", SELECTED_BG), ("relief", "flat"), ("borderWidth", 0),
                          ("padX", 10), ("padY", 8), ("font", (MONO_FONT, 10))):
        root.option_add(f"*Text.{option}", value)

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=BG_COLOR, foreground=TEXT_COLOR, font=(UI_FONT, 10), bordercolor=BORDER)
    style.configure("TFrame", background=BG_COLOR)
    style.configure("Card.TFrame", background=PANEL_BG)
    style.configure("TLabel", background=BG_COLOR, foreground=TEXT_COLOR)
    style.configure("Muted.TLabel", foreground=MUTED)
    style.configure("Title.TLabel", font=(UI_FONT, 22, "bold"))
    style.configure("TButton", background=PANEL_BG, foreground=TEXT_COLOR, padding=(12, 8),
                    borderwidth=1, relief="flat")
    style.map("TButton", background=[("active", SELECTED_BG), ("disabled", BG_COLOR)],
              foreground=[("disabled", "#65758b")], bordercolor=[("focus", ACCENT)])
    style.configure("TEntry", fieldbackground=PANEL_BG, foreground=TEXT_COLOR, insertcolor=ACCENT, padding=7)
    style.configure("TCombobox", fieldbackground=PANEL_BG, background=PANEL_BG, foreground=TEXT_COLOR,
                    padding=6, arrowcolor=MUTED)
    style.map("TCombobox", fieldbackground=[("readonly", PANEL_BG)], foreground=[("readonly", TEXT_COLOR)])
    style.configure("TCheckbutton", background=BG_COLOR, foreground=TEXT_COLOR, padding=4)
    style.map("TCheckbutton", background=[("active", BG_COLOR)])
    style.configure("TNotebook", background=BG_COLOR, borderwidth=0)
    style.configure("TNotebook.Tab", padding=(14, 9), background=PANEL_BG)
    style.map("TNotebook.Tab", background=[("selected", SELECTED_BG)], foreground=[("selected", ACCENT)])
    style.configure("Treeview", background=PANEL_BG, fieldbackground=PANEL_BG, foreground=TEXT_COLOR,
                    rowheight=30, borderwidth=0, font=(UI_FONT, 10))
    style.configure("Treeview.Heading", background="#1f2d3f", foreground=MUTED,
                    padding=(10, 10), relief="flat", font=(UI_FONT, 9, "bold"))
    style.map("Treeview", background=[("selected", SELECTED_BG)], foreground=[("selected", TEXT_COLOR)])
    style.configure("TSeparator", background=BORDER)
    style.configure("Vertical.TScrollbar", background=BORDER, troughcolor=BG_COLOR, borderwidth=0, arrowcolor=MUTED)
    style.configure("Horizontal.TScrollbar", background=BORDER, troughcolor=BG_COLOR, borderwidth=0, arrowcolor=MUTED)
    return style


def add_header(root, title):
    """Pack a NetSuite-style header bar (brand badge, title, skull) at the top of the window."""
    header = tk.Frame(root, bg=PANEL_BG, height=96)
    header.pack(fill="x", side="top")
    header.pack_propagate(False)
    add_skull(header, PANEL_BG, side="left", padx=(18, 12), pady=8)  # the skull is the logo
    tk.Label(header, text=title, bg=PANEL_BG, fg=TEXT_COLOR, font=(UI_FONT, 17, "bold")).pack(side="left")
    return header
