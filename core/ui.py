"""
Terminal UI / color output for GhostRecon
"""
import sys
import time
import threading
from datetime import datetime


class Colors:
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    # Foreground
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    ORANGE  = '\033[38;5;208m'
    PINK    = '\033[38;5;205m'
    TEAL    = '\033[38;5;43m'
    PURPLE  = '\033[38;5;135m'
    GRAY    = '\033[38;5;240m'
    # Background
    BG_RED  = '\033[41m'
    BG_DARK = '\033[48;5;235m'


class UI:
    def __init__(self, no_color=False):
        self.no_color = no_color
        self._lock = threading.Lock()
        self._spinner_active = False
        self._spinner_thread = None

    def c(self, color, text):
        if self.no_color:
            return text
        return f"{color}{text}{Colors.RESET}"

    def _ts(self):
        return datetime.now().strftime('%H:%M:%S')

    def _print(self, *args, **kwargs):
        with self._lock:
            print(*args, **kwargs)

    # ── Severity-colored tags ──
    def info(self, msg):
        self._print(f"  {self.c(Colors.CYAN, '[INFO]')} {self.c(Colors.GRAY, self._ts())}  {msg}")

    def ok(self, msg):
        self._print(f"  {self.c(Colors.GREEN, '[ OK ]')} {self.c(Colors.GRAY, self._ts())}  {msg}")

    def warn(self, msg):
        self._print(f"  {self.c(Colors.YELLOW, '[WARN]')} {self.c(Colors.GRAY, self._ts())}  {msg}")

    def error(self, msg):
        self._print(f"  {self.c(Colors.RED, '[ERR!]')} {self.c(Colors.GRAY, self._ts())}  {msg}")

    def ai(self, msg):
        self._print(f"  {self.c(Colors.PURPLE, '[ AI ]')} {self.c(Colors.GRAY, self._ts())}  {msg}")

    def cmd(self, msg):
        self._print(f"  {self.c(Colors.TEAL, '[ $ ]')} {self.c(Colors.DIM, msg)}")

    def find(self, severity, title, url=''):
        sev_colors = {
            'critical': Colors.RED,
            'high':     Colors.ORANGE,
            'medium':   Colors.YELLOW,
            'low':      Colors.CYAN,
            'info':     Colors.BLUE,
        }
        col = sev_colors.get(severity.lower(), Colors.WHITE)
        sev_tag = self.c(col, f'[{severity.upper():^8}]')
        self._print(f"  {self.c(Colors.PINK, '[FIND]')} {self.c(Colors.GRAY, self._ts())}  {sev_tag} {self.c(Colors.WHITE, title)}")
        if url:
            self._print(f"  {' '*7} {' '*10}  {self.c(Colors.DIM, '↳ ' + url)}")

    def section(self, title):
        width = 70
        line = self.c(Colors.TEAL, '─' * width)
        self._print(f"\n{line}")
        self._print(f"  {self.c(Colors.BOLD, self.c(Colors.CYAN, '◉ ' + title.upper()))}")
        self._print(f"{line}")

    def panel(self, title, lines, color=None):
        """Render a boxed panel with a title and a list of content lines."""
        color = color or Colors.TEAL
        width = 68
        top = self.c(color, '╭' + '─' * width + '╮')
        bot = self.c(color, '╰' + '─' * width + '╯')
        self._print(f"\n  {top}")
        title_txt = f" {title} "
        pad = width - len(title_txt)
        self._print(f"  {self.c(color, '│')}{self.c(Colors.BOLD, title_txt)}{' ' * max(0, pad)}{self.c(color, '│')}")
        self._print(f"  {self.c(color, '├' + '─' * width + '┤')}")
        for ln in lines:
            visible = self._strip(ln)
            pad = width - len(visible) - 1
            self._print(f"  {self.c(color, '│')} {ln}{' ' * max(0, pad)}{self.c(color, '│')}")
        self._print(f"  {bot}")

    def badge(self, severity):
        """Return a colored severity badge string."""
        sev_colors = {
            'critical': Colors.BG_RED, 'high': Colors.ORANGE,
            'medium': Colors.YELLOW, 'low': Colors.CYAN, 'info': Colors.BLUE,
        }
        col = sev_colors.get(severity.lower(), Colors.WHITE)
        return self.c(col, f" {severity.upper()} ")

    def sev_bar(self, counts):
        """Render a single-line stacked severity bar from a counts dict."""
        order = [('critical', Colors.RED), ('high', Colors.ORANGE),
                 ('medium', Colors.YELLOW), ('low', Colors.CYAN), ('info', Colors.BLUE)]
        total = sum(counts.get(s, 0) for s, _ in order) or 1
        bar = ''
        for sev, col in order:
            n = counts.get(sev, 0)
            seg = max(0, round(40 * n / total))
            if n and seg == 0:
                seg = 1
            bar += self.c(col, '█' * seg)
        legend = '  '.join(
            f"{self.c(col, '■')} {sev[:4]}:{counts.get(sev, 0)}" for sev, col in order
        )
        self._print(f"  {bar}")
        self._print(f"  {legend}")

    @staticmethod
    def _strip(text):
        import re as _re
        return _re.sub(r'\x1b\[[0-9;]*m', '', text)

    def subsection(self, title):
        self._print(f"\n  {self.c(Colors.CYAN, '┌─')} {self.c(Colors.BOLD, title)}")

    def bullet(self, msg, indent=4):
        self._print(f"{' '*indent}{self.c(Colors.TEAL, '→')} {msg}")

    def blank(self):
        self._print()

    def raw(self, msg, end='\n', flush=False):
        with self._lock:
            print(msg, end=end, flush=flush)

    def input(self, prompt):
        return input(f"  {self.c(Colors.CYAN, '▶')} {prompt}")

    def confirm(self, prompt):
        ans = self.input(f"{prompt} [Y/n]: ").strip().lower()
        return ans in ('', 'y', 'yes')

    # ── Spinner ──
    def start_spinner(self, msg):
        self._spinner_active = True
        self._spinner_msg = msg
        def _spin():
            frames = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
            i = 0
            while self._spinner_active:
                with self._lock:
                    sys.stdout.write(f"\r  {self.c(Colors.CYAN, frames[i % len(frames)])} {self._spinner_msg}   ")
                    sys.stdout.flush()
                i += 1
                time.sleep(0.08)
        self._spinner_thread = threading.Thread(target=_spin, daemon=True)
        self._spinner_thread.start()

    def stop_spinner(self, final_msg=None):
        self._spinner_active = False
        if self._spinner_thread:
            self._spinner_thread.join(timeout=0.5)
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()
        if final_msg:
            self.ok(final_msg)

    # ── Tables ──
    def table(self, headers, rows, col_widths=None):
        if not rows:
            self.info("No data to display.")
            return
        if not col_widths:
            col_widths = [max(len(str(r[i])) for r in [headers] + list(rows)) + 2
                         for i in range(len(headers))]
        sep = '  ' + self.c(Colors.GRAY, '+') + self.c(Colors.GRAY, '+'.join(['─' * w for w in col_widths])) + self.c(Colors.GRAY, '+')
        hdr = '  ' + self.c(Colors.GRAY, '|') + self.c(Colors.GRAY, '|').join(
            self.c(Colors.BOLD, str(h).center(col_widths[i])) for i, h in enumerate(headers)
        ) + self.c(Colors.GRAY, '|')
        self._print(sep)
        self._print(hdr)
        self._print(sep)
        sev_colors = {'CRITICAL': Colors.RED, 'HIGH': Colors.ORANGE,
                      'MEDIUM': Colors.YELLOW, 'LOW': Colors.CYAN, 'INFO': Colors.BLUE}
        for row in rows:
            cells = []
            for i, cell in enumerate(row):
                cell_str = str(cell)
                color = sev_colors.get(cell_str.upper(), Colors.WHITE)
                if headers[i] in ('Severity', 'SEV'):
                    cell_str = self.c(color, cell_str.center(col_widths[i]))
                else:
                    truncated = cell_str[:col_widths[i]-2] if len(cell_str) > col_widths[i]-2 else cell_str
                    cell_str = truncated.ljust(col_widths[i])
                cells.append(cell_str)
            self._print('  ' + self.c(Colors.GRAY, '|') + self.c(Colors.GRAY, '|').join(cells) + self.c(Colors.GRAY, '|'))
        self._print(sep)

    def progress_bar(self, current, total, label='', width=40):
        pct = current / total if total else 0
        filled = int(width * pct)
        bar = self.c(Colors.TEAL, '█' * filled) + self.c(Colors.GRAY, '░' * (width - filled))
        sys.stdout.write(f"\r  [{bar}] {pct*100:.0f}% {label}")
        sys.stdout.flush()
        if current >= total:
            sys.stdout.write('\n')
