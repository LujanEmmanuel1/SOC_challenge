# Reporte de Escalamiento

## Resumen

Intrusión confirmada sobre `WKS-FMARTINEZ-01` (usuario `fmartinez`). Acceso vía brute force desde TOR, bypass de MFA con app password legacy. Cadena completa: ejecución → persistencia → C2 → exfiltración de 187 MB en 2h30m.

## Alertas escaladas

- SIEM-1001 — Multiple Failed Logins Followed By Success
- SIEM-1004 — Anomalous Periodic Outbound Connection
- SIEM-1006 — Suspicious Use of certutil.exe

## IoCs

| Tipo | Valor | Contexto |
|------|-------|----------|
| IP | 185.220.101.47 | TOR exit node, brute force |
| IP | 194.36.191.55 | Hosting de upd.dat |
| IP | 45.146.164.110 | C2 + exfiltración |
| Dominio | cdn-edge-sync.net | SNI del C2 |
| Hash | b1a9c3e7... | Factura_0815.docm |
| Hash | d4e6f8a0... | PowerShell payload |
| Hash | ee55ff66... | upd.dat.exe |
| Scheduled Task | OneDriveSyncHelper | Persistencia |

## Acciones tomadas

- [x] Aislar `WKS-FMARTINEZ-01`
- [x] Revocar sesiones y credenciales de `fmartinez`
- [x] Bloquear IPs y dominio en firewall/proxy
- [ ] Buscar IoCs en el resto del parque
- [ ] Verificar propagación del `.docm` en `\\shared\invoices`
- [ ] Auditar app passwords legacy de todos los usuarios

## Recomendaciones

1. Deshabilitar app passwords legacy en Google Workspace (bypass MFA).
2. Implementar regla de correlación multi-fuente en el SIEM.
3. Bloquear macros en documentos de fuentes externas (GPO).