"""SIEM simulator CLI: generate fake logs and/or run detection."""
import argparse
import os

from intel.storage.ioc_store import init_db as init_threat_intel_db

from siemsim.dashboard.cli_dashboard import render
from siemsim.engine import Engine
from siemsim.generators.auth_log import generate_auth_log
from siemsim.generators.firewall_log import generate_firewall_log
from siemsim.parsers.auth_parser import parse_file as parse_auth_file
from siemsim.parsers.firewall_parser import parse_file as parse_firewall_file
from siemsim.rules.repeated_failed_login import RepeatedFailedLoginRule
from siemsim.rules.unknown_ip import UnknownIPRule

DEFAULT_PATHS = {"auth": "logs/auth.log", "firewall": "logs/firewall.log"}

# IPs considered trusted/expected (in a real setup this would come from config).
KNOWN_IPS = {"192.168.1.10", "192.168.1.11", "192.168.1.12", "10.0.0.5"}


def cmd_generate(args):
    out = args.out or DEFAULT_PATHS[args.type]
    if args.type == "auth":
        path = generate_auth_log(num_lines=args.lines, out_path=out, seed=args.seed)
    else:
        path = generate_firewall_log(num_lines=args.lines, out_path=out, seed=args.seed)
    print(f"Generated {args.lines} lines of {args.type} log: {path}")


def cmd_detect(args):
    path = args.file or DEFAULT_PATHS[args.type]

    # Only touch the threat-intel store if the integration is actually
    # configured — otherwise this would silently create an empty data/iocs.db
    # in whatever directory the CLI happens to run from.
    threat_intel_conn = init_threat_intel_db() if os.environ.get("THREAT_INTEL_DB") else None
    try:
        unknown_ip_rule = UnknownIPRule(KNOWN_IPS, threat_intel_conn=threat_intel_conn)
        if args.type == "auth":
            events = parse_auth_file(path)
            rules = [RepeatedFailedLoginRule(), unknown_ip_rule]
        else:
            events = parse_firewall_file(path)
            rules = [unknown_ip_rule]

        alerts = Engine(rules=rules).run(events)
        render(alerts, title=f"{args.type} log — {path}")
    finally:
        if threat_intel_conn is not None:
            threat_intel_conn.close()


def main():
    parser = argparse.ArgumentParser(description="Simple SIEM simulator")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Generate a fake log file")
    gen.add_argument("--type", choices=["auth", "firewall"], default="auth")
    gen.add_argument("--lines", type=int, default=200)
    gen.add_argument("--out", default=None)
    gen.add_argument("--seed", type=int, default=None, help="Fix the random seed for reproducible output")
    gen.set_defaults(func=cmd_generate)

    det = sub.add_parser("detect", help="Scan a log file and produce alerts")
    det.add_argument("--type", choices=["auth", "firewall"], default="auth")
    det.add_argument("--file", default=None)
    det.set_defaults(func=cmd_detect)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
