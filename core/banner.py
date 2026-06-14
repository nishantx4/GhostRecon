from core.ui import Colors

BANNER = r"""
   _____ _               _   _____
  / ____| |             | | |  __ \
 | |  __| |__   ___  ___| |_| |__) |___  ___ ___  _ __
 | | |_ | '_ \ / _ \/ __| __|  _  // _ \/ __/ _ \| '_ \
 | |__| | | | | (_) \__ \ |_| | \ \  __/ (_| (_) | | | |
  \_____|_| |_|\___/|___/\__|_|  \_\___|\___\___/|_| |_|
"""

SUBTITLE = "  AI Bug Bounty Hunter — v2.0  |  Powered by NVIDIA NIM"
AUTHOR   = "  Made by: Nishant 👻"
TAGLINE  = "  Your personal bug bounty hunting companion"


def print_banner(ui):
    ui.blank()
    for line in BANNER.split('\n'):
        ui.raw(ui.c(Colors.CYAN, line))
    ui.raw(ui.c(Colors.BOLD, ui.c(Colors.TEAL, SUBTITLE)))
    ui.raw(ui.c(Colors.PINK, AUTHOR))
    ui.raw(ui.c(Colors.GRAY, TAGLINE))
    ui.blank()
    ui.raw(ui.c(Colors.GRAY, '  ' + '─' * 68))
    ui.blank()
