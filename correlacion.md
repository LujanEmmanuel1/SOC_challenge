# Correlación 

**Referencia:** SIEM-1001, SIEM-1004, SIEM-1006

---

## Cadena identificada

Tres alertas sobre la misma entidad (`fmartinez` / `WKS-FMARTINEZ-01` / `10.20.5.44`) en 2h30m → una sola intrusión:

| Hora | Alerta | Evento |
|------|--------|--------|
| 03:12–03:47 | SIEM-1001 | 12 fallos desde 185.220.101.47 (TOR) + login sin MFA |
| 03:48 | — | Winword abre Factura_0815.docm → PowerShell encoded |
| 04:05 | SIEM-1006 | certutil descarga upd.dat desde 194.36.191.55 |
| 03:50–05:25 | SIEM-1004 | 20 beacons a 45.146.164.110 (C2) |
| 05:36 | — | 187 MB exfiltrados a 45.146.164.110 |

Acceso → ejecución → C2 → exfiltración. No es coincidencia temporal.

---

## Decisión

| Criterio | ¿Se cumple? |
|----------|-------------|
| Misma entidad en ≥2 alertas | ok |
| Ventana continua < 4h | ok (2h30m) |
| Al menos 1 alerta Crítica/Alta | ok |
| Correlación auth + EDR + VPC | ok (3 fuentes) |
| Evidencia de exfiltración | ok (187 MB) |

**5/5 → escala a Tier 2 / IR.**

---

## Acciones

1. Aislar `WKS-FMARTINEZ-01` (EDR isolation).
2. Revocar credenciales de `fmartinez` + invalidar app passwords legacy.
3. Bloquear IPs/dominio: `185.220.101.47`, `194.36.191.55`, `45.146.164.110`, `cdn-edge-sync.net`.
4. Buscar IoCs en el parque (hash de upd.dat, schtasks "OneDriveSyncHelper").
5. Verificar propagación del `.docm` en `\\shared\invoices`.