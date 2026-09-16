# Changelog — Sentinel // SOC · 2026-09-15
### Handoff para Sixto y Tomás (backend/frontend)

Hola Sixto y Tomás 👋 — lo más importante de este changelog cierra algo que ya estaba en su propio roadmap: **los botones de Acknowledge/Resolve del panel de detalle del dashboard ya tienen un backend real donde persistir.** El changelog del 27 de agosto marcaba exactamente este pendiente ("Acknowledge/Resolve del panel de detalle son visuales; el próximo poll los vuelve al estado del archivo. Cuando metan backend/DB, ahí se persiste — está en el roadmap"). Ese backend ya existe.

Todo lo de abajo se construyó y se probó hoy, solo del lado del Kali (no se tocó nada del servidor Ubuntu/Dokploy). Todo es aditivo: ningún campo existente se quitó ni se renombró, así que si no cambian nada de su lado, todo sigue funcionando exactamente igual que antes.

---

## Resumen de archivos

### 🆕 Nuevos
| Archivo | Qué es |
|---------|--------|
| `scripts/archive_alerts.py` | Job mensual de retención — mueve alertas de más de 180 días de `alerts.jsonl` a archivos mensuales comprimidos. No afecta el API ni el dashboard. |
| `scripts/soc_doctor.py` | Chequeo de salud del pipeline a demanda (permisos, candados de scan huérfanos, servicios, timers, disco, último scan). No es relevante para frontend, solo FYI. |
| `scripts/weekly_digest.py` | Resumen semanal en texto de hallazgos nuevos / vulnerabilidades resueltas / hosts con más hallazgos. Escribe a `data/digests/`, no es relevante para frontend, solo FYI. |

### ✏️ Modificados
| Archivo | Cambio |
|---------|--------|
| `scripts/soc_core.py` | Se agregó `set_alert_status()` y `group_by_host()`. Las alertas ahora pueden traer `status` (`open`/`acknowledged`/`resolved`), `status_updated`, `status_note` — antes `status` ya existía en el esquema pero nada lo cambiaba del default `"open"`. |
| `scripts/soc_api.py` | **Nuevo endpoint de escritura** `POST /api/alerts/<id>/status`. **Nuevo endpoint de lectura** `GET /api/hosts`. `GET /api/alerts` ahora acepta filtro `?status=`. Detalle abajo. |
| `kali/nmap_to_alerts.py` | Los hallazgos de vulnerabilidades (TLS débil, ftp-anon, CVEs, etc.) ahora se deduplican igual que ya pasaba con los puertos abiertos — un hallazgo que sigue sin arreglarse ya no se re-alerta en cada ciclo de scan (~4h). Las alertas que jalen ahora van a traer mucho menos ruido de duplicados exactos. |
| `kali/arp_to_alerts.py` | Las alertas de "dispositivo nuevo" para una MAC de WiFi aleatoria (locally-administered) ahora llegan en severidad `normal` en vez de `medium`/`critical`, con una nota en el título/descripción explicando que muy probablemente es un celular reconectándose con una MAC privada nueva, no un dispositivo físico nuevo. Campo nuevo en el detalle: `locally_administered` (bool). |

**Sin cambios que rompan nada** del esquema de alertas que ya usan: todo lo de arriba es un campo opcional nuevo o un endpoint nuevo, nada existente se renombró ni se quitó.

---

## Cambio 1 — El triage de estado de alertas ya es real (`scripts/soc_core.py`, `scripts/soc_api.py`)

**Antes:** hacer clic en Acknowledge/Resolve en el dashboard solo cambiaba el DOM; el siguiente poll (cada 5s) lo regresaba al estado del archivo, porque no había dónde persistirlo.

**Ahora:** `POST /api/alerts/<id>/status` en el mismo API de Sentinel SOC que ya usan (mismo host/puerto/token que usan para `/api/alerts`) persiste el cambio.

```
POST /api/alerts/<id>/status
Authorization: Bearer <token>
Content-Type: application/json

{"status": "acknowledged", "note": "texto libre opcional", "actor": "opcional, ej. un username"}
```

- `status` debe ser uno de `open`, `acknowledged`, `resolved` — cualquier otra cosa regresa `400`.
- Un `<id>` que no existe regresa `404`.
- Token faltante o inválido regresa `401`, igual que en cualquier otro endpoint.
- Si funciona, regresa el registro completo de la alerta ya actualizado (`200`), ahora incluyendo `status`, `status_updated` (timestamp ISO), y `status_note` si se mandó uno.

**Un detalle de integración que sí importa:** el feed en vivo (`alerts.json`) es una ventana móvil de las 500 alertas más recientes. Si alguien le da clic a Acknowledge/Resolve en una alerta que ya salió de esa ventana, esto regresa `404` — su registro original sigue existiendo para siempre en `alerts.jsonl`, solo que ya no forma parte de la vista "actual" mutable que maneja este endpoint. En la práctica esto solo importa para alertas bien viejas que sigan visibles en un feed scrolleado muy hacia atrás.

Cada cambio de status también se registra (quién/cuándo/de qué a qué) en `data/alert_status_log.jsonl` para auditoría — todavía no expuesto vía el API, con gusto le agrego un `GET` si les sirve de su lado.

`GET /api/alerts` también acepta ahora `?status=open` (o `acknowledged`/`resolved`) por si quieren filtrar del lado del servidor en vez de en el cliente.

---

## Cambio 2 — Agrupación por host (`GET /api/hosts`)

Endpoint nuevo, misma autenticación que todo lo demás. Recibe los mismos filtros que `/api/alerts` (`severity`, `type`, `detector`, `status`, `since`) y regresa un objeto resumen por cada `source_ip` en vez de una fila por hallazgo — útil si en algún momento quieren una vista "peores hosts primero" además de (o en vez de) el feed plano:

```json
{
  "count": 161,
  "hosts": [
    {
      "source_ip": "192.168.7.212",
      "hostname": null,
      "counts": {"critical": 9, "medium": 10, "normal": 10},
      "status_counts": {"open": 29, "acknowledged": 0, "resolved": 0},
      "total": 29,
      "last_seen": "2026-09-15T19:20:43+00:00",
      "alert_ids": ["...", "..."]
    }
  ]
}
```

Ordenado de peor a mejor (más críticos primero, luego más medios, luego mayor total). Totalmente opcional de conectar — la vista plana de `/api/alerts` sigue igual que siempre.

---

## Prueba rápida

```bash
# desde el Kali, o desde cualquier lado con acceso de red a él:
curl -H "Authorization: Bearer $SOC_API_TOKEN" http://10.69.0.40:8080/api/hosts | python3 -m json.tool

curl -X POST -H "Authorization: Bearer $SOC_API_TOKEN" -H "Content-Type: application/json" \
  -d '{"status":"acknowledged","note":"probando","actor":"tu-nombre"}' \
  http://10.69.0.40:8080/api/alerts/<id-real>/status
```

Los dos endpoints ya están vivos en producción en el Kali — no hay que desplegar nada más de ese lado. Cualquier cosa que quieran que ajuste del contrato antes de que conecten el frontend, me avisan.
