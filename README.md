# SOC Challenge

Resolución del challenge de Triage, Afinado y Detección de Alertas SOC sobre un entorno GCP simulado.

## Estructura del repo

```
.
├── README.md
├── Challenge-soc.pdf
├── alertas_dataset_v2.json
├── reglas_actuales.md
├── logs_soporte/
│   ├── auth_logs.json
│   ├── edr_events.json
│   └── vpc_flow_logs.json
├── soc_helper.py
├── triage.csv
├── ajustes_reglas.md
├── regla_nueva.md
├── correlacion.md
└── metricas_turno.md
```

## Cómo usar el script de apoyo

Requiere **Python 3.11+**. Sin dependencias externas.

```bash
# Resumen del lote de alertas
python soc_helper.py --alerts alertas_dataset_v2.json --summary

# Buscar un IOC en las alertas
python soc_helper.py --alerts alertas_dataset_v2.json --ioc fmartinez

# Buscar un IOC en todos los logs
python soc_helper.py --logs logs_soporte/auth_logs.json logs_soporte/edr_events.json logs_soporte/vpc_flow_logs.json --ioc 45.146.164.110
```

## Criterios de triage

| Criterio | Valores |
|----------|---------|
| Clasificación | TP / FP / Benigno mal configurado |
| Severidad | Crítica / Alta / Media / Baja / Informativa |
| Acción | Cerrar / Afinar regla / Escalar / Correlacionar |

**Regla de decisión:**
- Actor en inventario + comportamiento esperado → **FP** → afinar regla.
- Actor externo + patrón malicioso → **TP** → escalar.
- Comparte entidad con otra alerta → **correlacionar** antes de decidir.

Detalle por alerta en `triage.csv`.

## Resumen del lote

6 alertas procesadas en 1 h (08:00–09:00 UTC):

- **3 TP escaladas:** SIEM-1001, SIEM-1004, SIEM-1006 (misma intrusión sobre `fmartinez`).
- **3 FP afinadas:** SIEM-1002 (scanner Qualys), SIEM-1003 (VPN multi-PoP), SIEM-1005 (NRPE Nagios).
- **1 pendiente:** validar `45.146.164.110` contra inventario.

## Cadena identificada

Ver `correlacion.md`. Acceso (brute force TOR) → ejecución (macro .docm → PS encoded) → C2 (beaconing) → exfiltración (187 MB). **Escalado a Tier 2 / IR.**

## Reglas afinadas

Ver `ajustes_reglas.md`. Cada exclusión incluye el **trade-off de falso negativo** y su mitigación.

## Regla nueva

Ver `regla_nueva.md`. Detecta la cadena Office → PowerShell encoded → descarga LOLBin en ≤10 min, que hoy ninguna regla cubre.

## Limitaciones

- El inventario de activos no está en el repo; algunas validaciones quedan como "pendientes".
- Los % FP se calculan sobre 1 disparo por regla. En producción se recalculan con más volumen.
- No se incluye whitelist de IPs/dominios de confianza (queda como mejora propuesta).