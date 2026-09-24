"""
Ghost Ops palette — single source of truth for colors used in Rich markup
inside widget code. Keep these in sync with the $variables at the top of
tui/styles/ghostrecon.tcss (which controls widget/panel chrome).
"""

BG          = "#0a0b0d"
BG_PANEL    = "#101317"
BG_ELEVATED = "#171b20"

BORDER        = "#262b33"
BORDER_STRONG = "#3a4048"

TEXT       = "#c9d1d9"
TEXT_DIM   = "#5b6472"
TEXT_FAINT = "#383e47"

ACCENT     = "#45d1c4"
ACCENT_DIM = "#245853"

OK   = "#4ba876"
CRIT = "#e5484d"
HIGH = "#d97a4d"
MED  = "#c9a227"
LOW  = "#4a90c4"
INFO = "#5b6472"

SEVERITY = {
    "critical": CRIT,
    "high":     HIGH,
    "medium":   MED,
    "low":      LOW,
    "info":     INFO,
}
