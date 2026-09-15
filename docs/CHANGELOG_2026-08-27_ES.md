# Changelog — Sentinel // SOC  ·  2026-08-27
### Handoff para Sixto y Tomás (programación)

Hola Sixto y Tomás 👋 — estos son **los cambios que hay que integrar** al proyecto. Son tres:
**(1)** el dashboard ahora lee datos reales, **(2)** arreglo de **zmap** para redes internas, **(3)** nuevo módulo de **tshark** para captura de tráfico. Abajo va el detalle, cómo integrarlo y el plan de pruebas para mañana.

> Contexto: Arturo lleva la parte de seguridad y estos dos arreglos (zmap/tshark) salieron de sus pruebas. nmap ya funcionaba bien.

---

## Resumen de archivos

### 🆕 Nuevos
| Archivo | Qué es |
|---------|--------|
| `kali/zmap-blocklist.conf` | Blocklist propio de zmap que **deja escaneables** las redes privadas (RFC1918). |
| `kali/1b_zmap_discovery.sh` | Descubrimiento rápido interno con zmap usando ese blocklist. |
| `kali/4_traffic_capture.sh` | Captura de tráfico con tshark (reja de autorización **por interfaz**). |
| `kali/traffic_to_alerts.py` | Convierte el tráfico capturado en alertas del dashboard. |
| `kali/ioc_ips.txt` | Lista de IPs maliciosas conocidas (para el módulo de tráfico). |
| `kali/bad_domains.txt` | Lista de dominios maliciosos/sospechosos. |
| `docs/QUICKSTART_LOCAL_ES.md` | Cómo correr el dashboard en una compu (para Arturo). |
| `docs/MODULOS_zmap_tshark_ES.md` | Explicación ES/EN de los dos arreglos. |

### ✏️ Modificados
| Archivo | Cambio |
|---------|--------|
| `dashboard/sentinel_soc.html` | Ahora **lee `data/alerts.json`** (datos reales) con fallback a demo. Ver detalle abajo. |
| `README.md` | Enlaces a las guías nuevas + nota del feed de datos. |

**Sin cambios** en `scripts/*.py` ni en `soc_core.py`: el esquema de alertas sigue igual, así que nada de lo suyo se rompe.

---

## Cambio 1 — Dashboard conectado a datos reales (`dashboard/sentinel_soc.html`)

**Antes:** el dashboard generaba alertas de ejemplo en el navegador (`generateAlerts()`).
**Ahora:** al inicio intenta leer `data/alerts.json`; si lo consigue, usa datos reales y **hace polling cada 5 s**; si no (por ejemplo abierto como `file://`), cae a los datos demo.

Lo que se agregó en el bloque `<script>` (al final del archivo):

- `const DATA_URLS = ['data/alerts.json','../data/alerts.json'];` — rutas candidatas (cubre "servido desde la raíz del proyecto" y "HTML copiado a un web root con `data/` al lado").
- `normalize(raw)` — adapta el JSON de los scripts al dashboard: mapea **`hostname` → `host`** y convierte el **timestamp ISO → epoch (ms)**. El resto de campos ya coinciden.
- `async loadExternal()` — hace `fetch` de las rutas candidatas; devuelve el arreglo normalizado o `null`.
- `pollFile()` — re-lee el archivo, marca como nuevas las alertas con `id` no visto antes.
- `init()` (IIFE al final) — decide el modo: `file` si `loadExternal()` trae datos, si no `demo`.
- El badge de estado muestra **"FEED · alerts.json"** (real) o **"FEED LIVE · demo"**.

> **Importante para producción:** el dashboard necesita servirse por **HTTP** para leer el archivo (por CORS, `file://` no deja hacer `fetch`). En el server Ubuntu esto lo cubre nginx (ya está en `INSTRUCTIONS_EN.md`, sección 7.2). Para probar local: `python3 -m http.server`.
>
> Detalle menor: en modo `file`, Acknowledge/Resolve del panel de detalle son visuales; el próximo poll los vuelve al estado del archivo. Cuando metan backend/DB, ahí se persiste (está en el roadmap).

**Prueba rápida:**
```bash
cd soc-project
python3 scripts/seed_demo_data.py --fresh --count 40
python3 -m http.server 8000
# abrir http://localhost:8000/dashboard/sentinel_soc.html  -> badge "FEED · alerts.json"
```

---

## Cambio 2 — Arreglo de zmap (redes internas)

**Problema:** zmap trae `/etc/zmap/blocklist.conf` que **bloquea RFC1918** (10/8, 172.16/12, 192.168/16). Por eso "no escanea rangos internos" — es su comportamiento por defecto (pensado para Internet público).

**Solución incluida:**
- `kali/zmap-blocklist.conf` — bloquea solo lo especial (loopback, link-local, multicast, reservado) y **deja escaneables las privadas**.
- `kali/1b_zmap_discovery.sh` — barrido de liveness con zmap (`-b` apuntando a ese blocklist), une hosts vivos y produce un archivo que alimenta a `2_port_service_scan.sh`.

**Integración:** solo copiar los dos archivos a `kali/`. Requiere `sudo apt install zmap`.

**Prueba (mañana, en un rango autorizado de laboratorio):**
```bash
cd soc-project/kali
chmod +x 1b_zmap_discovery.sh
./1b_zmap_discovery.sh 10.10.20.0/24
# debe listar hosts vivos internos (antes: 0 con el blocklist por defecto)
./2_port_service_scan.sh results/zmap_live_<stamp>.txt
```
> Recomendación prod: en vez de "bloquear todo menos privadas", usar **allowlist** exacta: `zmap -w allowlist.txt`. Más estricto, no toca nada fuera de alcance.

---

## Cambio 3 — Módulo tshark (captura de tráfico)

**Problema:** tshark **no es escáner**, es capturador; su objetivo es una **interfaz** (`-i eth0`), no una IP. La reja de autorización de los scripts de escaneo valida IPs, por eso lo rechazaba.

**Solución incluida (módulo aparte con su propia reja por interfaz):**
- `kali/4_traffic_capture.sh` — captura en vivo (`-i eth0 -c N` o `-d segundos`) o desde pcap (`-r archivo.pcap`); extrae campos con `tshark -T fields` y llama al parser. Tiene `capture_authorize` (reja por interfaz), **separada** de la reja de IP.
- `kali/traffic_to_alerts.py` — recibe el TSV y levanta alertas (usa `soc_core.emit_alert`, mismo esquema):
  - **Port scan en el cable** (un origen toca muchos puertos) → `port_scan`
  - **Protocolo en texto claro** (Telnet/FTP/POP3/IMAP/SNMP) → `intrusion`
  - **Tráfico a IP maliciosa** (match con `ioc_ips.txt`) → `malware` (critical)
  - **DNS sospechoso** (TLD de alto riesgo o `bad_domains.txt`) → `phishing`
- `kali/ioc_ips.txt`, `kali/bad_domains.txt` — listas de indicadores (alimentar de MISP/AbuseCH).

**Integración:** copiar los 4 archivos a `kali/`. Requiere `sudo apt install tshark` (responder "Yes" para captura sin root, o usar sudo).

**Prueba SIN tocar la red (recomendada para mañana):** el parser se puede probar con un TSV de ejemplo, así validan la lógica antes de capturar en vivo:
```bash
cd soc-project/kali
python3 - <<'PY' > /tmp/traffic.tsv
rows=[f"1699999.1\t10.10.10.66\t10.10.20.5\t{p}\t\tTCP\t\t\t1\t0" for p in range(20,45)]
rows+=["1699999.2\t10.10.10.7\t10.10.20.9\t23\t\tTELNET\t\t\t1\t1",
       "1699999.3\t10.10.10.31\t185.220.101.4\t443\t\tTLS\t\t\t1\t1",
       "1699999.4\t10.10.10.31\t10.10.30.1\t\t53\tDNS\tsecure-login-verify.tk\t\t\t"]
print("\n".join(rows))
PY
python3 traffic_to_alerts.py /tmp/traffic.tsv
# debe levantar: port_scan, cleartext Telnet, IOC IP (critical), DNS sospechoso
```
**Prueba en vivo (en una interfaz autorizada):**
```bash
sudo ./4_traffic_capture.sh -i eth0 -c 2000
```

**Orden de campos del TSV** (lo produce `4_traffic_capture.sh`, por si quieren tocar el parser):
`frame.time_epoch, ip.src, ip.dst, tcp.dstport, udp.dstport, _ws.col.Protocol, dns.qry.name, http.host, tcp.flags.syn, tcp.flags.ack` (separador = tab).

---

## Regla que quedó clara (para no repetir el error)

- **Escáneres** (nmap, zmap): objetivo = **IP/rango** → reja de IP `authorize()` en `kali/lib.sh`.
- **Captura** (tshark): objetivo = **interfaz** → su propia reja `capture_authorize` en `4_traffic_capture.sh`.
- No mezclar: meter una herramienta de captura por la reja de escaneo (o viceversa) es justo lo que causaba el rechazo.

---

## Checklist para mañana

- [ ] `sudo apt install zmap tshark`
- [ ] Copiar los 8 archivos nuevos a sus rutas (`kali/` y `docs/`) y reemplazar `dashboard/sentinel_soc.html` y `README.md`.
- [ ] Probar dashboard con datos reales (`http.server` + badge "FEED · alerts.json").
- [ ] Probar `1b_zmap_discovery.sh` en un rango de lab autorizado.
- [ ] Probar `traffic_to_alerts.py` con el TSV de ejemplo (sin red) y luego captura en vivo en interfaz autorizada.
- [ ] Confirmar que las alertas de zmap/tshark aparecen en el dashboard (todas pasan por `data/alerts.json`).

> ⚖️ zmap, tshark y nmap: correr **solo** sobre redes/interfaces autorizadas **por escrito** por IT. Los tres piden confirmación antes de correr.

Cualquier duda, Arturo tiene el contexto completo y el proyecto está documentado en `docs/`. — 🤝
