# Afinado de Reglas

**Referencia:** `reglas_actuales.md`

Tres reglas afinadas por FP recurrente: SIEM-1002, SIEM-1003, SIEM-1005.

---

## SIEM-1002 — Port Scan

**Problema:** dispara con el scanner Qualys (`10.50.2.15`) porque no distingue origen autorizado.

**Regla actual:**
```
COUNT(DISTINCT dst_host) >= 5 AND COUNT(DISTINCT dst_port) >= 20
en ventana de 10 min
```

**Exclusión propuesta (SQL):**
```sql
-- Lógica de detección intacta, solo se agregan exclusiones
SELECT src_ip,
       COUNT(DISTINCT dst_ip)   AS hosts,
       COUNT(DISTINCT dst_port) AS ports
FROM vpc_flow_logs
WHERE timestamp >= NOW() - INTERVAL '10 minutes'
  AND src_ip NOT IN (
      SELECT ip FROM asset_inventory WHERE role = 'vuln_scanner'
  )
  AND NOT (note ILIKE '%qualys-scan%' OR note ILIKE '%vuln scan%')
GROUP BY src_ip
HAVING COUNT(DISTINCT dst_ip)   >= 5
   AND COUNT(DISTINCT dst_port) >= 20;
```

**Trade-off (falso negativo):** si un atacante compromete el scanner, escanea sin alerta.
**Mitigación:** la exclusión combina IP + nota, no solo IP. Sumar ventana horaria del job.

---

## SIEM-1003 — Impossible Travel

**Problema:** dispara con VPN corporativa multi-PoP (Buenos Aires ↔ Madrid) porque no considera notas de VPN.

**Regla actual:**
```
2 login_success desde geo_country distinto en 60 min
con velocidad > 800 km/h
```

**Exclusión propuesta (SQL):**
```sql
SELECT user, COUNT(DISTINCT geo_country) AS countries
FROM auth_logs
WHERE event_type = 'login_success'
  AND timestamp >= NOW() - INTERVAL '60 minutes'
  AND mfa_used = true
  AND NOT (note ILIKE '%Corporate VPN egress%')
  AND src_ip NOT IN (SELECT ip FROM vpn_egress_ips)
GROUP BY user
HAVING COUNT(DISTINCT geo_country) >= 2
   AND haversine_km(...) / hours_between > 800;
```

**Trade-off:** sesión VPN robada podría saltar entre PoPs sin alerta.
**Mitigación:** exigir mismo `device_id` entre ambos logins. Revisar lista de IPs VPN cada 3 meses.

---

## SIEM-1005 — High Connection Rate

**Problema:** dispara con NRPE de Nagios (`10.50.9.9`, puerto 5666, 48 bytes, cada 5 min) porque cuenta cualquier conexión sin filtrar patrón.

**Regla actual:**
```
COUNT(*) >= 200 en ventana de 24 hs
(sin distinguir puerto ni bytes)
```

**Exclusión propuesta (SQL):**
```sql
SELECT src_ip, COUNT(*) AS conns, SUM(bytes_sent) AS total_bytes
FROM vpc_flow_logs
WHERE timestamp >= NOW() - INTERVAL '24 hours'
  AND NOT (dst_port = 5666 AND bytes_sent <= 64 AND bytes_received <= 64)
  AND NOT (note ILIKE '%nrpe health check%')
GROUP BY src_ip
HAVING COUNT(*) >= 200
   AND SUM(bytes_sent) > 1048576;   -- >1 MB real
```

**Trade-off:** un atacante podría usar el 5666 con payloads grandes.
**Mitigación:** la exclusión exige puerto + bytes chicos + nota. Si falta cualquiera, dispara. Y el `HAVING > 1 MB` filtra exfiltración real.

---

## No afinadas

SIEM-1001, SIEM-1004, SIEM-1006 → TP confirmados.