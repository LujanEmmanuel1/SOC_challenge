#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
import urllib.error
from pathlib import Path


ESCALATED_SEVERITIES = {"High", "Critical"}


def load_alerts(path: Path) -> list[dict]:
    if not path.exists():
        print(f"[!] No existe: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[!] JSON inválido: {e}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(data, list):
        print(f"[!] Se esperaba lista en {path}", file=sys.stderr)
        sys.exit(1)
    return data


def filter_escalated(alerts: list[dict]) -> list[dict]:
    return [a for a in alerts if a.get("siem_severity") in ESCALATED_SEVERITIES]


def send_webhook(url: str, payload: dict, dry_run: bool = False) -> None:
    body = json.dumps(payload).encode("utf-8")
    if dry_run:
        print(f"[DRY-RUN] POST {url}")
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[+] Webhook OK: HTTP {resp.status}")
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP error: {e.code} {e.reason}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[!] No se pudo conectar a {url}: {e.reason}", file=sys.stderr)
        sys.exit(1)
    except TimeoutError:
        print(f"[!] Timeout al conectar a {url}", file=sys.stderr)
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webhook_notify",
        description="Notifica alertas escaladas por webhook (Acme Fintech).",
    )
    p.add_argument("--alerts", required=True, type=Path, help="JSON de alertas.")
    p.add_argument("--url", required=True, help="Endpoint webhook (HTTP/HTTPS).")
    p.add_argument("--dry-run", action="store_true", help="No envía, solo imprime.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    alerts = load_alerts(args.alerts)
    escalated = filter_escalated(alerts)

    if not escalated:
        print("[i] Sin alertas escaladas para notificar.")
        return 0

    payload = {
        "source": "acme-soc",
        "turn": "2026-08-15T08:00Z",
        "escalated_count": len(escalated),
        "alerts": [
            {
                "alert_id": a.get("alert_id"),
                "rule_name": a.get("rule_name"),
                "severity": a.get("siem_severity"),
                "entity": a.get("entity"),
            }
            for a in escalated
        ],
    }

    print(f"[i] {len(escalated)} alertas escaladas a notificar.")
    send_webhook(args.url, payload, args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())