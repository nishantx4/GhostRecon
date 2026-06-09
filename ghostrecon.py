#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║          GHOSTRECON — AI Bug Bounty Hunter CLI                ║
║                    Made by: Nishant  👻                       ║
║         AI-Powered Recon, Analysis & Report Engine            ║
╚═══════════════════════════════════════════════════════════════╝

Hey there! Welcome to GhostRecon — a personal project built to make
bug bounty hunting smarter, faster, and a little more fun.

Usage:
  python ghostrecon.py -t example.com [options]
  python ghostrecon.py -t example.com --api-key sk-ant-... --full
  python ghostrecon.py --interactive
"""

import argparse
import sys
import os

# Make sure modules are importable from any CWD
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.banner import print_banner
from core.session import ScanSession
from core.ui import UI

def parse_args():
    parser = argparse.ArgumentParser(
        prog='ghostrecon',
        description='GhostRecon — AI Bug Bounty Hunter by Nishant',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ghostrecon.py -t example.com
  python ghostrecon.py -t example.com --api-key sk-ant-... --full
  python ghostrecon.py -t example.com --modules recon,js,idor,xss
  python ghostrecon.py --interactive
        """
    )
    parser.add_argument('-t', '--target',      help='Target domain (e.g. example.com)')
    parser.add_argument('--api-key',           help='Anthropic Claude API key (enables AI analysis)')
    parser.add_argument('--full',              action='store_true', help='Run all modules')
    parser.add_argument('--modules',           help='Comma-separated modules')
    parser.add_argument('--scope',             help='Scope definition')
    parser.add_argument('--output',            help='Output report file')
    parser.add_argument('--output-dir',        default='./ghostrecon_output', help='Output directory')
    parser.add_argument('--threads',           type=int, default=10, help='Threads')
    parser.add_argument('--timeout',           type=int, default=10, help='Timeout')
    parser.add_argument('--delay',             type=float, default=0.5, help='Delay')
    parser.add_argument('--no-color',          action='store_true', help='Disable color')
    parser.add_argument('--verbose', '-v',     action='store_true', help='Verbose')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive menu mode')
    parser.add_argument('--version',           action='version', version='GhostRecon v2.0 by Nishant')
    return parser.parse_args()


def main():
    args = parse_args()
    ui = UI(no_color=args.no_color)
    print_banner(ui)

    # 1. Logic to determine Target and Modules
    if args.interactive or not args.target:
        from core.interactive import InteractiveMenu
        menu = InteractiveMenu(ui)
        # Capture the data from the menu
        target, modules = menu.run()
    else:
        # Standard CLI mode
        target = args.target
        if args.full:
            modules = ['recon', 'headers', 'js', 'params', 'nuclei', 'xss', 'idor', 'sqli', 'graphql', 'smuggling', 'cors', 'ssrf', 'secrets', 'report']
        elif args.modules:
            modules = [m.strip() for m in args.modules.split(',')]
        else:
            modules = ['recon', 'headers', 'js', 'params', 'nuclei', 'xss', 'idor', 'cors', 'ssrf', 'report']

    # 2. Final Check
    if not target:
        ui.error("No target specified. Exiting.")
        return

    # 3. Create and Run Session
    session = ScanSession(
        target=target,
        api_key=args.api_key,
        modules=modules,
        scope=args.scope,
        output_dir=args.output_dir,
        output_file=args.output,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        verbose=args.verbose,
        ui=ui,
    )

    try:
        session.run()
    except KeyboardInterrupt:
        ui.error("\n\n[!] Scan interrupted by user. Saving partial results...")
        session.save_partial()
        sys.exit(0)

if __name__ == '__main__':
    main()