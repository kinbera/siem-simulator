"""Renders a list of alerts as a summary + detail view in the terminal."""
import sys
from collections import Counter

from siemsim.rules.base import Alert

SEVERITY_ORDER = ("high", "medium", "low")
SEVERITY_COLOR = {
    "high": "\033[91m",    # red
    "medium": "\033[93m",  # yellow
    "low": "\033[94m",     # blue
}
BOLD = "\033[1m"
RESET = "\033[0m"


def _colors_enabled() -> bool:
    return sys.stdout.isatty()


def render(alerts: list[Alert], title: str = "SIEM Simulator") -> None:
    use_color = _colors_enabled()
    bold = BOLD if use_color else ""
    reset = RESET if use_color else ""

    print(f"{bold}== {title} =={reset}")

    if not alerts:
        print("No suspicious activity found.\n")
        return

    by_severity = Counter(alert.severity for alert in alerts)
    by_rule = Counter(alert.rule for alert in alerts)

    print(f"\n{bold}Summary{reset}")
    print(f"  Total alerts: {len(alerts)}")
    for severity in SEVERITY_ORDER:
        if by_severity[severity]:
            color = SEVERITY_COLOR.get(severity, "") if use_color else ""
            print(f"  {color}{severity.upper():<7}{reset} {by_severity[severity]}")

    print(f"\n{bold}By rule{reset}")
    for rule, count in by_rule.most_common():
        print(f"  {rule:<25} {count}")

    print(f"\n{bold}Alerts{reset}")
    for alert in sorted(alerts, key=lambda a: a.event.timestamp):
        color = SEVERITY_COLOR.get(alert.severity, "") if use_color else ""
        ts = alert.event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        print(f"  [{color}{alert.severity.upper():<6}{reset}] {ts}  {alert.rule:<22} {alert.message}")
    print()
