#!/usr/bin/env python3
"""
soc_helper.py — Búsqueda de IOC y resumen de alertas SOC.
Acme Fintech SOC — Challenge de triage.

Uso:
  python soc_helper.py --alerts alertas_dataset_v2.json --summary
  python soc_helper.py --alerts alertas_dataset_v2.json --ioc 45.146.164.110
  python soc_helper.py --logs logs_soporte/auth_logs.json logs_soporte/edr_events.json logs_soporte/vpc_flow_logs.json --ioc 194.36.191.55

Requiere: Python 3.11+
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Carga de datos con manejo de errores
# ---------------------------------------------------------------------------
def load_json(path: Path) -> Any:
    """Carga un JSON y devuelve su contenido. Sale con error legible si falla."""
    if not path.exists():
        print(f"[!] No existe el archivo: {path}", file=sys.stderr)
        sys.exit(1)
    if not path.is_file():
        print(f"[!] No es un archivo regular: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"[!] JSON inválido en {path}: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"[!] Error leyendo {path}: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Resumen de alertas
# ---------------------------------------------------------------------------
def summarize_alerts(alerts: list[dict]) -> None:
    """Imprime un resumen de severidades, reglas y detalle por alerta."""
    print(f"\n=== RESUMEN DE ALERTAS ({len(alerts)}) ===\n")

    sev = Counter(a.get("siem_severity", "unknown") for a in alerts)
    rules = Counter(a.get("rule_name", "unknown") for a in alerts)

    print("Por severidad:")
    for s, c in sev.most_common():
        print(f"  {s:<12} {c}")

    print("\nPor regla:")
    for r, c in rules.most_common():
        print(f"  {r:<45} {c}")

    print("\nDetalle:")
    for a in alerts:
        entity = a.get("entity", {})
        if isinstance(entity, dict):
            entity_str = ", ".join(f"{k}={v}" for k, v in entity.items())
        else:
            entity_str = str(entity)
        print(
            f"  [{a.get('alert_id', '?')}] "
            f"{a.get('rule_name', '?')} | "
            f"{a.get('siem_severity', '?')} | "
            f"{entity_str}"
        )
    print()


# ---------------------------------------------------------------------------
# Búsqueda de IOC
# ---------------------------------------------------------------------------
def search_ioc_in_data(data: Any, ioc: str, source_name: str, max_hits: int = 20) -> int:
    """Busca un IOC en una estructura JSON (lista de dicts). Devuelve nº de hits."""
    ioc_lower = ioc.lower()
    hits: list[dict] = []

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and ioc_lower in json.dumps(item).lower():
                hits.append(item)

    print(f"\n[{source_name}] {len(hits)} coincidencias para '{ioc}'")

    for h in hits[:max_hits]:
        ts = h.get("timestamp") or h.get("timestamp_first_seen") or "?"
        key = (
            h.get("user")
            or h.get("host")
            or h.get("src_ip")
            or h.get("alert_id")
            or "?"
        )
        evt = h.get("event_type") or h.get("rule_name") or "?"
        print(f"  - {ts} | {key} | {evt}")

    if len(hits) > max_hits:
        print(f"  ... y {len(hits) - max_hits} más (truncado)")
    return len(hits)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="soc_helper",
        description="SOC Helper CLI — búsqueda de IOC y resumen de alertas (Acme Fintech).",
    )
    p.add_argument(
        "--alerts",
        type=Path,
        help="JSON de alertas del SIEM (alertas_dataset_v2.json).",
    )
    p.add_argument(
        "--logs",
        type=Path,
        nargs="+",
        help="Uno o más JSONs de logs crudos (auth, edr, vpc).",
    )
    p.add_argument(
        "--ioc",
        help="IOC a buscar: IP, dominio, hash, usuario, nombre de proceso, etc.",
    )
    p.add_argument(
        "--summary",
        action="store_true",
        help="Imprime un resumen de las alertas (requiere --alerts).",
    )
    p.add_argument(
        "--max-hits",
        type=int,
        default=20,
        help="Máximo de coincidencias a mostrar por fuente (default: 20).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.alerts and not args.logs:
        parser.print_help()
        return 1

    if args.summary and not args.alerts:
        print("[!] --summary requiere --alerts", file=sys.stderr)
        return 1

    if args.summary:
        alerts = load_json(args.alerts)
        if not isinstance(alerts, list):
            print(f"[!] Se esperaba una lista en {args.alerts}", file=sys.stderr)
            return 1
        summarize_alerts(alerts)

    if args.ioc:
        if args.alerts:
            data = load_json(args.alerts)
            search_ioc_in_data(data, args.ioc, args.alerts.name, args.max_hits)
        if args.logs:
            for log_path in args.logs:
                data = load_json(log_path)
                search_ioc_in_data(data, args.ioc, log_path.name, args.max_hits)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())