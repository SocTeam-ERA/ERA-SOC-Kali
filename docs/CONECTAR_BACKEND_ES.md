# Conectar Kali con el backend — el forwarder de alertas

Ya quedó listo en `scripts/soc_core.py`. Cuando los devs te den el endpoint y el token, **solo pones dos variables de entorno** y todas las alertas (de nmap, zmap, los detectores, todo) se envían solas al backend, que las muestra en el dashboard.

Mientras no configures nada, todo sigue igual que hoy (escribe el archivo local). El forwarder se **prende solo** cuando defines `SOC_INGEST_URL`.

---

## 1. Qué pedirle a Sixto y Tomás
- **La URL del endpoint de ingesta** (ej.: `https://soc.era.ca/api/ingest/alerts`).
- **El token** de ingesta.
- Confirmar que aceptan el **JSON del alerta tal cual** (el esquema de `soc_core.py`: `id, timestamp, type, severity, title, source_ip, hostname, user, description, detector, details, status`). Si esperan otro formato o encabezado, se ajusta en un solo lugar.

## 2. Activarlo (en el Kali)
```bash
export SOC_INGEST_URL="https://soc.era.ca/api/ingest/alerts"
export SOC_INGEST_TOKEN="el-token-que-te-dieron"
```
Opcionales:
```bash
export SOC_INGEST_VERIFY_TLS=0     # solo si usan CA interna / cert self-signed
export SOC_INGEST_AUTH_HEADER="Authorization"   # por si piden otro header
export SOC_INGEST_AUTH_PREFIX="Bearer "         # o "" si el token va sin prefijo
```

## 3. Probar la conexión (antes de nada)
```bash
cd /opt/sentinel-soc/scripts
python3 soc_core.py --status        # ¿está ENABLED? ¿token set?
python3 soc_core.py --test-ingest   # manda UNA alerta de prueba al backend
```
Si ves `[OK] ... HTTP 2xx` y la alerta aparece en el dashboard, **Kali ↔ backend funciona**. 🎉

## 4. Dejarlo permanente (24/7)
Para que las variables estén siempre, ponlas en el servicio systemd o en el entorno del sistema. Ejemplo en un servicio:
```ini
[Service]
Environment=SOC_INGEST_URL=https://soc.era.ca/api/ingest/alerts
Environment=SOC_INGEST_TOKEN=el-token
ExecStart=/usr/bin/python3 login_monitor.py --auth-log /var/log/auth.log --follow
```
O global, en `/etc/environment` (una línea por variable).

## 5. Si el backend se cae, no se pierde nada
Si un POST falla, la alerta se guarda en `data/ingest_outbox.jsonl`. Para reintentarlas cuando el backend vuelva:
```bash
python3 soc_core.py --replay
```
Deja esto en cron cada pocos minutos para que se auto-repare solo:
```
*/5 * * * * cd /opt/sentinel-soc/scripts && /usr/bin/python3 soc_core.py --replay >/dev/null 2>&1
```

---

**Resumen:** el envío al backend ya está programado y probado (con reintentos y outbox). Tú solo defines `SOC_INGEST_URL` y `SOC_INGEST_TOKEN` cuando los devs te los den, corres `--test-ingest`, y listo — Kali empieza a alimentar el dashboard en vivo.
