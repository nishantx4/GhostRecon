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
  python ghostrecon.py --set-api  nvapi-xxxx      (save your NVIDIA key)
  python ghostrecon.py --set-model MODEL          (choose the NIM model)
  python ghostrecon.py --api-test                  (verify the key works)
  python ghostrecon.py --remove-api                (delete saved key)
  python ghostrecon.py --interactive
"""

import argparse
import sys
import os

# Fix Windows terminal encoding so emoji/Unicode don't crash on cp1252
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Make sure modules are importable from any CWD
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.banner import print_banner
from core.session import ScanSession
from core.ui import UI
import core.config as config


def parse_args():
    parser = argparse.ArgumentParser(
        prog='ghostrecon',
        description='GhostRecon — AI Bug Bounty Hunter by Nishant',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
API Key Management:
  python ghostrecon.py --set-api nvapi-xxxx    Save your NVIDIA NIM API key
  python ghostrecon.py --api-test              Test if saved key is working
  python ghostrecon.py --remove-api            Remove the saved key

Scan Examples:
  python ghostrecon.py -t example.com
  python ghostrecon.py -t example.com --full
  python ghostrecon.py -t example.com --modules recon,js,idor,xss
  python ghostrecon.py --interactive

Get a free NVIDIA NIM API key at: https://build.nvidia.com/
        """
    )

    # ── API key management (no target needed) ──
    api_group = parser.add_argument_group('NVIDIA AI Key Management')
    api_group.add_argument('--set-api',    metavar='KEY',
                           help='Save your NVIDIA NIM API key persistently (~/.ghostrecon/config.json)')
    api_group.add_argument('--remove-api', action='store_true',
                           help='Remove the saved NVIDIA API key')
    api_group.add_argument('--api-test',   action='store_true',
                           help='Test whether the saved (or provided) API key is working')
    api_group.add_argument('--set-model',  metavar='MODEL',
                           help='Set the NVIDIA NIM model id (default: meta/llama-3.1-70b-instruct)')
    api_group.add_argument('--show-model', action='store_true',
                           help='Show the currently configured NVIDIA NIM model')

    # ── Scan target ──
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('-t', '--target',      help='Target domain (e.g. example.com)')
    scan_group.add_argument('--api-key',           help='NVIDIA NIM API key for this session only (not saved)')
    scan_group.add_argument('--full',              action='store_true', help='Run all modules')
    scan_group.add_argument('--modules',           help='Comma-separated modules to run')
    scan_group.add_argument('--scope',             help='Scope definition')
    scan_group.add_argument('--output',            help='Output report file')
    scan_group.add_argument('--output-dir',        default='./ghostrecon_output', help='Output directory')
    scan_group.add_argument('--threads',           type=int, default=10, help='Threads (default: 10)')
    scan_group.add_argument('--timeout',           type=int, default=10, help='Request timeout (default: 10s)')
    scan_group.add_argument('--delay',             type=float, default=0.5, help='Delay between requests (default: 0.5s)')
    scan_group.add_argument('--no-color',          action='store_true', help='Disable colored output')
    scan_group.add_argument('--verbose', '-v',     action='store_true', help='Verbose output')
    scan_group.add_argument('--interactive', '-i', action='store_true', help='Interactive menu mode')
    scan_group.add_argument('--version',           action='version', version='GhostRecon v3.0 by Nishant')

    return parser.parse_args()


def handle_api_commands(args, ui) -> bool:
    """
    Handle --set-api, --remove-api, --api-test.
    Returns True if a management command was handled (caller should exit).
    """
    handled = False

    if args.set_api:
        handled = True
        key = args.set_api.strip()
        ui.info("Testing key before saving...")
        from core.ai_engine import AIEngine
        if AIEngine.test_key(key, ui):
            config.set_api_key(key)
            ui.ok(f"✓ API key saved to ~/.ghostrecon/config.json")
            ui.info("AI-assisted hunting is now active on all future scans.")
        else:
            ui.error("Key test failed — key NOT saved. Double-check your NVIDIA NIM key.")
            ui.info("Get a free key at: https://build.nvidia.com/")

    if args.set_model:
        handled = True
        config.set_model(args.set_model.strip())
        ui.ok(f"✓ NVIDIA NIM model set to: {config.get_model()}")

    if args.show_model:
        handled = True
        ui.info(f"Configured NVIDIA NIM model: {config.get_model()}")

    if args.remove_api:
        handled = True
        config.remove_api_key()
        ui.ok("API key removed from ~/.ghostrecon/config.json")

    if args.api_test:
        handled = True
        # Prefer CLI-provided key, fall back to saved one
        key = (args.api_key or "").strip() or config.get_api_key()
        if not key:
            ui.error("No API key found. Run: python ghostrecon.py --set-api nvapi-xxxx")
        else:
            ui.info(f"Testing NVIDIA NIM API key: {key[:12]}...{key[-4:]}")
            from core.ai_engine import AIEngine
            if AIEngine.test_key(key, ui):
                ui.ok("✓ API key is valid and working!")
                ui.info(f"Model: {config.get_model()}  |  Endpoint: https://integrate.api.nvidia.com/v1")
            else:
                ui.error("✗ API key test failed. Check the key and your internet connection.")

    return handled


def main():
    args = parse_args()
    ui   = UI(no_color=args.no_color)
    print_banner(ui)

    # Handle API management commands first (no scan needed)
    if handle_api_commands(args, ui):
        return

    # Resolve API key: CLI flag overrides saved key
    api_key = (args.api_key or "").strip() or config.get_api_key()
    if api_key:
        ui.ok("NVIDIA AI engine active — AI-assisted hunting enabled 🤖")
    else:
        ui.warn("No API key set — running in local-only mode.")
        ui.info("Tip: python ghostrecon.py --set-api nvapi-xxxx  (free at build.nvidia.com)")
    ui.blank()

    # Determine target and modules
    if args.interactive or not args.target:
        from core.interactive import InteractiveMenu
        menu = InteractiveMenu(ui)
        target, modules = menu.run()
    else:
        target = args.target
        if args.full:
            modules = ['recon', 'headers', 'js', 'params', 'nuclei',
                       'xss', 'idor', 'sqli', 'graphql', 'smuggling',
                       'cors', 'ssrf', 'ssti', 'redirect', 'secrets', 'report']
        elif args.modules:
            modules = [m.strip() for m in args.modules.split(',')]
        else:
            modules = ['recon', 'headers', 'js', 'params', 'nuclei',
                       'xss', 'idor', 'cors', 'ssrf', 'redirect', 'report']

    if not target:
        ui.error("No target specified. Exiting.")
        return

    session = ScanSession(
        target=target,
        api_key=api_key,
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