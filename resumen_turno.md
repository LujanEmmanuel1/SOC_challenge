## Estado general

Lote de 6 alertas: 3 escaladas, 3 afinadas. **1 intrusión confirmada en curso.**

## 🔴 Escalado a IR

**SIEM-1001 + SIEM-1004 + SIEM-1006** = cadena única sobre `fmartinez` / `WKS-FMARTINEZ-01`.

- Acceso: fuerza bruta via TOR + bypass MFA.
- Ejecución: macro .docm → PowerShell encoded → certutil.
- C2: beaconing a `45.146.164.110`.
- Exfil: 187 MB.

Host aislado, credenciales revocadas, IPs bloqueadas. Falta verificar propagación del `.docm`.

## 🟡 Afinado de Alertas (tickets abiertos)

- Port Scan: excluir scanner por job activo, no por IP fija.
- Impossible Travel: excluir si hay VPN + MFA + dispositivo valido.
- High Connection Rate: excluir trafico NRPE (Puerto 5666 + paquete ≤64 bytes).

## 🟢 Para el próximo turno

- Confirmar la IP `45.146.164.110` aparece en otros hosts.
- Validar dominio si `cdn-edge-sync.net` es dominio corporativo.
- Auditar app passwords viejas (posible brecha de MFA masivo).
- Correr `soc_helper.py --ioc 45.146.164.110` sobre logs de los últimos 30 días.

## Contexto

El SIEM no correlaciona alertas entre fuentes. SIEM-1001 y SIEM-1006 llegaron como tickets separados. **Recomendación:** implementar regla de correlación por entidad.