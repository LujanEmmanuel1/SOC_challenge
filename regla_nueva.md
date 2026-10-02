# Regla Nueva — Cadena Office → PowerShell → Descarga

**Referencia:** `logs_soporte/edr_events.json`, `reglas_actuales.md`

---

## Patrón no detectado

El SIEM solo detecta el certutil al final. Las macros y el PowerShell pasan bajo el radar, regalándole 17 minutos al atacante.

```
03:48:05 | winword.exe (Factura_0815.docm)
03:48:22 | powershell.exe -nop -w hidden -enc    [NO DETECTADO]
03:49:10 | schtasks (Persistencia)               [NO DETECTADO]
04:05:18 | certutil -urlcache descarga upd.dat   [ÚNICA ALERTA]
04:05:42 | upd.dat.exe -silent
```

---

## Regla propuesta (SQL)

```sql
-- Office -> PowerShell encoded -> descarga LOLBin en <=10 min
-- MITRE: T1566.001, T1059.001, T1105

WITH office AS (
  SELECT host, user, timestamp AS t0
  FROM edr_events
  WHERE process_name IN ('winword.exe','excel.exe','powerpnt.exe')
    AND event_type = 'process_create'
),
ps AS (
  SELECT e.host, e.user, e.timestamp AS t1, e.command_line AS ps_cmd
  FROM edr_events e
  JOIN office o ON e.host = o.host
   AND e.parent_process IN ('winword.exe','excel.exe','powerpnt.exe')
   AND e.timestamp BETWEEN o.t0 AND o.t0 + INTERVAL '2 minutes'
  WHERE e.process_name = 'powershell.exe'
    AND e.command_line ILIKE '%-enc%'
    AND (e.command_line ILIKE '%-nop%' OR e.command_line ILIKE '%-w hidden%')
),
dl AS (
  SELECT e.host, e.user, e.timestamp AS t2, e.command_line AS dl_cmd
  FROM edr_events e
  JOIN ps p ON e.host = p.host AND e.user = p.user
   AND e.timestamp BETWEEN p.t1 AND p.t1 + INTERVAL '10 minutes'
  WHERE e.process_name IN ('certutil.exe','bitsadmin.exe','curl.exe')
    AND (e.command_line ILIKE '%http%' OR e.command_line ILIKE '%urlcache%')
)
SELECT DISTINCT d.host, d.user, p.ps_cmd, d.dl_cmd
FROM dl d JOIN ps p ON d.host = p.host AND d.user = p.user;
```

---

## Umbral

La cadena completa es tan rara que no genera ruido.

• Office → PS: 2 min (la macro arranca al toque).
• PS → Descarga: 10 min (margen por si el payload duerme).
• Filtro estricto: Exige `-enc` + `-nop` o `-w hidden` (evasión pura).

---

## ¿Por qué no dispara con actividad legítima?

• Ningún usuario abre un documento común que ejecute un PS oculto y codificado.
• Ningún admin corre certutil teniendo a Word (winword.exe) como proceso padre.
• Los scripts de backup usan sus propios procesos (ej. 7z.exe), no Office.

## Trade-off

Si aflojamos el `-enc`, te tapan las macros legales de TI. Si subís a 30 min, la alerta llega tarde. 10 minutos es el punto justo.

## MITRE ATT&CK

| Técnica | Descripción |
|---------|-------------|
| T1566.001 | Phishing: adjunto .docm |
| T1059.001 | PowerShell |
| T1053.005 | Scheduled Task (persistencia) |
| T1105 | Ingress Tool Transfer (certutil) |
| T1560.001 | Archive Collected Data (7z) |