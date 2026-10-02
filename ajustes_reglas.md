# Afinado de Reglas Ruidosas — Acme Fintech SOC

**Fecha:** 2026-08-15
**Analista:** SOC L1
**Referencia:** `reglas_actuales.md`

Reglas afinadas a partir de las alertas clasificadas como FP o benigno mal configurado:

- SIEM-1002 — Potential Port Scan Detected
- SIEM-1003 — Impossible Travel Detected
- SIEM-1005 — High Connection Rate From Single Source

---

## Regla 1 — Potential Port Scan Detected (SIEM-1002)

### Problema

La regla cuenta conexiones a puertos distintos sin distinguir el origen. El scanner Qualys (`10.50.2.15`) genera exactamente ese patrón cada noche durante la ventana de escaneo programado (`02:00–02:10`), y dispara todos los días.

### Regla actual

```
DISPARA SI:
  COUNT(DISTINCT dst_host) FROM vpc_flow_logs
  WHERE src_ip = X AND timestamp IN ventana_10_min >= 5
  AND COUNT(DISTINCT dst_port) EN LA MISMA VENTANA >= 20
```

### Exclusión propuesta (SQL)

```sql
-- Regla afinada: Port Scan Detected (excluye scanners autorizados)
SELECT src_ip,
       COUNT(DISTINCT dst_ip)   AS hosts,
       COUNT(DISTINCT dst_port) AS ports
FROM vpc_flow_logs
WHERE timestamp >= NOW() - INTERVAL '10 minutes'
  AND src_ip NOT IN (
      SELECT ip FROM asset_inventory WHERE role IN ('vuln_scanner','monitoring')
  )
  AND NOT (note ILIKE '%vuln scan%' OR note ILIKE '%qualys-scan%')
  AND NOT (bytes_received = 0 AND bytes_sent <= 128)  -- probes de scan
GROUP BY src_ip
HAVING COUNT(DISTINCT dst_ip)   >= 5
   AND COUNT(DISTINCT dst_port) >= 20;
```

### Trade-off de falso negativo

Si un atacante compromete `10.50.2.15` (el scanner) y desde ahí hace reconocimiento, la exclusión por `role='vuln_scanner'` lo dejaría pasar sin alerta.

**Mitigación:** la exclusión debe ser por IP ** + ventana horaria del job programado** (ej: `AND NOT (src_ip='10.50.2.15' AND EXTRACT(hour FROM timestamp) BETWEEN 2 AND 3)`), o mejor aún, requerir que el asset del scanner reporte un job activo vía API. Si la excepción queda como "cualquier IP del scanner, siempre", se anula la detección de movimiento lateral desde ese host.

---

## Regla 2 — Impossible Travel Detected (SIEM-1003)

### Problema

La regla compara geolocalización de IPs de salida sin considerar VPN corporativa ni ASN. Los PoPs de Madrid y Buenos Aires son parte de la misma red corporativa, y el usuario viaja entre ellos con MFA activo.

### Regla actual

```
DISPARA SI:
  EXISTEN 2 login_success PARA user = X
  DESDE geo_country DISTINTO EN ventana_60_min
  Y LA DISTANCIA ENTRE AMBAS GEOLOCALIZACIONES IMPLICA
  UNA VELOCIDAD DE DESPLAZAMIENTO FÍSICAMENTE IMPOSIBLE (> 800 km/h)
```

### Exclusión propuesta (pseudo-SQL)

```sql
-- Regla afinada: Impossible Travel (excluye salida VPN corporativo)
SELECT user,
       COUNT(DISTINCT geo_country) AS countries
FROM auth_logs
WHERE event_type = 'login_success'
  AND timestamp >= NOW() - INTERVAL '60 minutes'
  AND mfa_used = true
  AND NOT (note ILIKE '%Corporate VPN salida%')
  AND src_ip NOT IN (SELECT ip FROM vpn_salida_ips)
GROUP BY user
HAVING COUNT(DISTINCT geo_country) >= 2
   AND haversine_km(MIN(lat,lon), MAX(lat,lon)) / hours_between > 800;
```

### Trade-off de falso negativo

Un atacante que robe una sesión VPN corporativa podría moverse entre PoPs sin alerta.

**Mitigación:** exigir que el `user_agent` y el dispositivo (`device_id`/fingerprint) coincidan entre ambos logins, y alertar igual si hay cambio de dispositivo. La exclusión debe limitarse a IPs de salida **conocidas y vigentes** (revisión trimestral), no a cualquier IP que diga "VPN".

---

## Regla 3 — High Connection Rate From Single Source (SIEM-1005)

### Problema

La regla cuenta cualquier conexión sin distinguir puerto, bytes ni nota. Los NRPE health checks (puerto 5666, 48 bytes) disparan todo el día desde `10.50.9.9` (Nagios).

### Regla actual

```
DISPARA SI:
  COUNT(*) FROM vpc_flow_logs
  WHERE src_ip = X AND timestamp IN ventana_24_hs >= 200
  (sin distinguir puerto ni patrón de bytes)
```

### Exclusión propuesta (SQL)

```sql
-- Regla afinada: High Connection Rate (excluye monitoreo conocido)
SELECT src_ip,
       COUNT(*)        AS conns,
       SUM(bytes_sent) AS total_bytes
FROM vpc_flow_logs
WHERE timestamp >= NOW() - INTERVAL '24 hours'
  AND NOT (dst_port = 5666 AND bytes_sent <= 64 AND bytes_received <= 64)  -- NRPE
  AND NOT (note ILIKE '%nrpe health check%')
  AND dst_ip NOT LIKE '10.50.%'  -- subnet de monitoreo
GROUP BY src_ip
HAVING COUNT(*) >= 200
   AND SUM(bytes_sent) > 1048576;  -- >1 MB real, no probes
```

### Trade-off de falso negativo

Un atacante podría usar el puerto 5666 con payloads grandes para exfiltrar.

**Mitigación:** la exclusión combina **puerto + tamaño de bytes + nota**, así que un uso anómalo de 5666 (bytes grandes) sí dispararía. Si la excepción se dejara solo por puerto, se perdería visibilidad sobre abuso de NRPE.

---

## Reglas NO afinadas (TP confirmados)

| Regla | Alert ID | Motivo |
|-------|----------|--------|
| Multiple Failed Logins Followed By Success | SIEM-1001 | TP confirmado, no se toca |
| Anomalous Periodic Outbound Connection | SIEM-1004 | TP confirmado (C2 beaconing), no se toca |
| Suspicious Use of certutil.exe | SIEM-1006 | TP confirmado, no se toca |