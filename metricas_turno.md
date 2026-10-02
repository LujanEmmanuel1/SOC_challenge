# Métricas del Turno — 2026-08-15

- **Inicio triage:** 08:00 UTC
- **Fin triage:** 09:00 UTC
- **Duración total:** 1 h
- **Alertas procesadas:** 6
- **Escaladas:** 3 (SIEM-1001, SIEM-1004, SIEM-1006)
- **Cerradas:** 0
- **Afinadas:** 3 (SIEM-1002, SIEM-1003, SIEM-1005)
- **Pendientes de validar contra inventario:** 1 (`45.146.164.110`)

---

## % FP por regla

| Regla | Total | FP | % FP |
|-------|-------|----|------|
| Multiple Failed Logins Followed By Success | 1 | 0 | 0% |
| Potential Port Scan Detected | 1 | 1 | 100% |
| Impossible Travel Detected | 1 | 1 | 100% |
| Anomalous Periodic Outbound Connection | 1 | 0 | 0% |
| High Connection Rate From Single Source | 1 | 1 | 100% |
| Suspicious Use of certutil.exe | 1 | 0 | 0% |
| **TOTAL** | **6** | **3** | **50%** |

---

## Observaciones

- 3 de 6 reglas con 100% FP → ruido estructural.
- "High Connection Rate" es la más ruidosa (288 eventos/día solo de NRPE).
- SIEM-1001 y SIEM-1006 son la misma intrusión → el SIEM no correlaciona.