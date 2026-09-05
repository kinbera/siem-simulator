# siemsimulator

A simple SIEM (Security Information and Event Management) simulator. It generates
fake log files, runs a few detection rules over them, and shows the results as
alerts in the terminal.

I built this while working through Security+ and heading toward a SOC analyst
role — wanted to get hands-on with the core log analysis loop (generate → parse
→ apply rules → report) at a small scale, instead of just reading about it.

## What it does

- Generates fake `auth.log` / `firewall.log` files (random, or reproducible with a seed)
- Parses raw log lines into structured events
- Runs a couple of realistic detection rules over them (brute force, unknown IP)
- Shows a summary + detailed alert list in the terminal

## Usage

```bash
# Generate a fake auth.log / firewall.log (default: logs/<type>.log, 200 lines)
python main.py generate --type auth
python main.py generate --type firewall

# Scan the generated log and show alerts
python main.py detect --type auth
python main.py detect --type firewall
```

Use `--seed <number>` for reproducible output — same seed always produces the
same log, which makes it easier to test the rules against a known input.

## Rules

- `repeated_failed_login` (auth) — 5+ failed login attempts from the same IP
  within 2 minutes (possible brute force)
- `unknown_ip` (auth + firewall) — activity from an IP outside the
  known/allowed list, flagged once on first sighting. Severity escalates from
  `medium` to `high` when the IP also matches a known-bad IOC in
  [threat-intel-aggregator](../threat-intel-aggregator)'s local store (see
  Threat intel enrichment below).

I tested the threshold by hand: 4 attempts produce no alert, the 5th triggers
it — so the boundary sits exactly where it should.

## Threat intel enrichment

`unknown_ip` can optionally cross-check flagged IPs against a local IOC
database built by the sibling [threat-intel-aggregator](../threat-intel-aggregator)
project (abuse.ch URLhaus/ThreatFox feeds). This is an editable-install
dependency, not a copy-pasted function — both projects stay independent repos.

Setup (system Python here is externally managed, so a venv is required):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Point `unknown_ip` at the other project's SQLite store via the
`THREAT_INTEL_DB` environment variable:

```bash
export THREAT_INTEL_DB=/absolute/path/to/threat-intel-aggregator/data/iocs.db
python main.py detect --type firewall
```

If `THREAT_INTEL_DB` is unset, or the referenced store hasn't been populated
yet (`python main.py update` was never run in threat-intel-aggregator),
`unknown_ip` still works exactly as before — it just never escalates to
`high`.

## Project structure

- `siemsim/generators/` — fake log generators
- `siemsim/parsers/` — turn raw log lines into structured events
- `siemsim/rules/` — detection rules
- `siemsim/engine.py` — runs events through the rules and produces alerts (source-agnostic)
- `siemsim/dashboard/` — renders alerts as a summary + detail view in the terminal
- `tests/` — run with `python -m unittest discover -s tests`

## Tests

```bash
python -m unittest discover -s tests -v
```

17 tests, covering the parsers, rules (including threat-intel severity
escalation), and dashboard. The threat-intel tests use an in-memory
threat-intel-aggregator store, so `python -m unittest discover -s tests`
works whether or not `THREAT_INTEL_DB` is set.
