# Proyecto SOC — Sentinel // SOC
### Guía en español para el equipo (Arturo + compañeros programadores)

Este documento explica **qué se construyó**, **cómo está organizado** y **cómo desplegarlo** en el servidor Ubuntu de la empresa. Está pensado para que se lo pases directamente a tus dos compañeros que van a llevar la parte de programación.

> **Idioma:** todo el código, la interfaz del dashboard y los mensajes de alerta están en **inglés** (como se pidió). Esta guía y su versión en inglés (`INSTRUCTIONS_EN.md`) explican el mismo contenido.

---

## 1. Qué es este proyecto

Es un **mini-SOC** (Security Operations Center) estilo **Splunk / LetsDefend**: un tablero central donde tú y tus compañeros pueden monitorear, desde sus computadoras, las alertas de seguridad de la empresa en tiempo real.

Detecta y muestra cinco tipos de eventos:

| Tipo | Qué detecta | Script |
|------|-------------|--------|
| **intrusion** | Logins en el dominio, fuerza bruta, accesos desde IPs desconocidas | `login_monitor.py` |
| **port_scan** | Puertos abiertos / servicios expuestos en IPs y subredes | `port_scanner.py` |
| **phishing** | Correos maliciosos (phishing / malware) por headers, enlaces y adjuntos | `phishing_detector.py` |
| **malware** | Archivos maliciosos por hash (IOC), firmas y heurística | `malware_detector.py` |
| **vuln** | Vulnerabilidades de red encontradas con nmap desde Kali | Suite `kali/` |

Cada alerta lleva: **hora exacta, tipo, severidad (normal / medium / critical), IP de origen, hostname y usuario** (cuando se puede saber).

---

## 2. Arquitectura (cómo encaja todo)

```
        KALI LINUX (Arturo)                 SERVIDOR UBUNTU (Dell R730/R740)
   ┌───────────────────────┐          ┌────────────────────────────────────────┐
   │  kali/ (escaneo nmap) │  datos   │  scripts/  (detectores en Python)        │
   │  descubre hosts,      │─────────▶│    port_scanner.py                       │
   │  puertos y vulns      │  alertas │    login_monitor.py                      │
   └───────────────────────┘          │    phishing_detector.py                  │
                                       │    malware_detector.py                   │
                                       │            │                             │
                                       │            ▼   emit_alert()              │
                                       │      soc_core.py  ── escribe ──▶         │
                                       │            │                             │
                                       │            ▼                             │
                                       │   data/alerts.json  (feed común)         │
                                       │            │                             │
                                       │            ▼                             │
                                       │   dashboard/  (web tipo Splunk) ◀────────┼─── tú y tus compañeros
                                       └────────────────────────────────────────┘        (navegador)
```

**La pieza clave es `soc_core.py`.** Todos los scripts llaman a la misma función `emit_alert(...)`, así que todas las alertas quedan en **un solo formato JSON**. Eso significa que:

- El dashboard lee siempre el mismo archivo (`data/alerts.json`).
- El día de mañana pueden cambiar el almacenamiento (base de datos PostgreSQL, o reenviar a **Wazuh / Elastic**, que son los Splunk open-source de verdad) **sin tocar los detectores**.

---

## 3. Estructura de archivos

```
soc-project/
├── dashboard/
│   └── sentinel_soc.html      # El tablero (se abre en el navegador)
├── scripts/                   # Detectores en Python (corren en el server Ubuntu)
│   ├── soc_core.py            # Librería común: esquema de alerta + guardado
│   ├── port_scanner.py        # Escáner de puertos/IPs
│   ├── login_monitor.py       # Monitor de logins / intrusos
│   ├── phishing_detector.py   # Analizador de correos phishing
│   ├── malware_detector.py    # Escáner de malware / IOCs
│   └── seed_demo_data.py      # Genera datos de demostración
├── kali/                      # Suite de escaneo de red (corre en Kali)
│   ├── targets.conf           # Alcance autorizado (subredes/VLANs)
│   ├── lib.sh                 # Funciones comunes
│   ├── 0_run_all.sh           # Corre TODO el flujo y hace el reporte
│   ├── 1_host_discovery.sh    # Descubre hosts vivos
│   ├── 2_port_service_scan.sh # Escaneo de puertos y servicios
│   ├── 3_vuln_scan.sh         # Escaneo de vulnerabilidades (NSE)
│   └── nmap_to_alerts.py      # Convierte resultados nmap → alertas del dashboard
├── data/
│   ├── alerts.json            # Feed que lee el dashboard (se genera solo)
│   ├── alerts.jsonl           # Historial completo (append-only)
│   └── ioc_hashes.txt         # Lista de hashes maliciosos conocidos
└── docs/
    ├── INSTRUCCIONES_ES.md    # Esta guía
    └── INSTRUCTIONS_EN.md     # Versión en inglés
```

---

## 4. Probarlo rápido (en cualquier máquina con Python 3)

```bash
cd soc-project/scripts

# Genera ~44 alertas de ejemplo (todos los tipos y severidades)
python3 seed_demo_data.py --fresh --count 44

# Prueba cada detector en modo demostración:
python3 login_monitor.py --demo         # simula un ataque de fuerza bruta
python3 phishing_detector.py --demo      # analiza un correo phishing de ejemplo
python3 malware_detector.py --demo       # crea y escanea el archivo de prueba EICAR
python3 port_scanner.py 127.0.0.1 --ports 1-1024
```

Luego abre `dashboard/sentinel_soc.html` en el navegador.

> **Nota sobre el prototipo:** el dashboard que se entrega genera sus propios datos de ejemplo dentro del navegador para que se pueda enseñar a los managers **sin necesidad de servidor**. En producción, los compañeros deben cambiar la función `generateAlerts()` por una lectura de `data/alerts.json` (viene comentado en el mismo archivo, sección `<script>`). Los nombres de los campos son idénticos, así que es un cambio pequeño.

---

## 5. Detalle de cada detector (para los programadores)

### `port_scanner.py`
Escanea puertos TCP de una IP, varias IPs o una subred completa (CIDR) y levanta una alerta por cada puerto abierto. La severidad depende del servicio:
- **critical:** Telnet, SMB (445), RDP (3389), FTP, bases de datos expuestas, Redis, Mongo…
- **medium:** SSH, SMTP, LDAP, puertos administrativos…
- **normal:** HTTP/HTTPS.

```bash
python3 port_scanner.py 10.10.20.0/24 --top-ports
python3 port_scanner.py 10.10.20.10 --ports 1-1024 --baseline 22,443
```
`--baseline` = lista de puertos “permitidos”; cualquier puerto abierto que **no** esté en la baseline sube un nivel de severidad (útil para detectar cambios no autorizados).

### `login_monitor.py`
Lee los logs de autenticación y detecta:
- Fuerza bruta (muchos fallos desde una IP en poco tiempo) → **medium/critical**
- Login exitoso justo después de muchos fallos → **critical** (patrón de compromiso)
- Login desde IP nueva/desconocida → escalado
- Login normal → **normal**

```bash
# En el server Ubuntu, siguiendo el log de SSH en vivo:
sudo python3 login_monitor.py --auth-log /var/log/auth.log --follow --known-ips known_ips.txt

# Analizando un export del log de Seguridad de Windows (CSV: time,event_id,user,ip,host):
python3 login_monitor.py --windows-csv security_export.csv
```
Los eventos de Windows soportados: **4624** (login exitoso) y **4625** (login fallido).

### `phishing_detector.py`
Analiza correos `.eml` (RFC-822) de forma **estática** (no abre enlaces, no ejecuta nada). Revisa:
- Autenticación **SPF / DKIM / DMARC** en los headers.
- **From vs Reply-To vs Return-Path** (dominios que no coinciden).
- Enlaces: IP cruda, acortadores, punycode, truco de `@`, texto del enlace que no coincide con el destino real.
- Adjuntos peligrosos (`.exe`, `.scr`, `.js`, `.hta`…), doble extensión (`factura.pdf.exe`), Office con macros.
- Lenguaje típico de phishing (urgencia, credenciales, pagos).

Da un puntaje → severidad (≥8 critical, 4–7 medium, 1–3 normal).

```bash
python3 phishing_detector.py correo_sospechoso.eml
```

### `malware_detector.py`
Escanea archivos o carpetas (**no ejecuta nada**):
- **Hash** MD5/SHA1/SHA256 contra la lista de IOCs (`data/ioc_hashes.txt`).
- Firmas simples (EICAR, PowerShell download cradle, macros con Shell…).
- Tipo real del archivo por magic bytes (detecta un `.pdf` que en realidad es un ejecutable).
- Entropía alta (archivo empaquetado/cifrado).

```bash
python3 malware_detector.py /ruta/a/cuarentena/
```
La lista `data/ioc_hashes.txt` se puede alimentar con hashes de threat intel (AbuseCH, MISP, etc.).

---

## 6. La suite de Kali (escaneo de vulnerabilidades)

Esta parte la corre **Arturo desde su Kali**. **Solo escanear las IPs/subredes/VLANs que IT autorice por escrito.**

1. Edita `kali/targets.conf` y pon las subredes que te den (agrupadas por VLAN).
2. Corre todo el flujo:

```bash
cd soc-project/kali
chmod +x *.sh
sudo ./0_run_all.sh            # descubrimiento → puertos → vulns → reporte
# o más rápido:
FAST=1 sudo ./0_run_all.sh
```

Genera, en `kali/results/`:
- `live_hosts_*.txt` — hosts vivos
- `services_*.nmap` — puertos y servicios
- `vuln_*.nmap` — vulnerabilidades (nmap NSE)
- `REPORT_*.txt` — **resumen legible para IT y managers** ← este es el que sirve para el reporte del proyecto

Además, importa automáticamente los hallazgos al dashboard con `nmap_to_alerts.py`, así que los puertos abiertos y las vulnerabilidades aparecen junto con el resto de alertas.

También puedes correr los pasos por separado:
```bash
sudo ./1_host_discovery.sh 10.10.20.0/24
sudo ./2_port_service_scan.sh results/live_hosts_XXXX.txt
sudo ./3_vuln_scan.sh results/live_hosts_XXXX.txt
python3 nmap_to_alerts.py results/vuln_XXXX.xml --baseline 22,443
```

Requisitos en Kali: `nmap` (viene instalado). Opcional: el script NSE `vulners` para mapear versiones a CVEs.

---

## 7. Dejarlo corriendo para siempre en el servidor Ubuntu

Como el dashboard debe quedar corriendo 24/7 en un Dell R730/R740, la idea es correr los detectores como **servicios de systemd**.

### 7.1 Preparar el servidor
```bash
sudo apt update && sudo apt install -y python3 python3-pip nmap
sudo useradd -r -s /bin/false soc          # usuario de servicio
sudo mkdir -p /opt/soc-project
sudo cp -r soc-project/* /opt/soc-project/
sudo chown -R soc:soc /opt/soc-project
```

### 7.2 Servir el dashboard (opción sencilla con nginx)
```bash
sudo apt install -y nginx
# Copia el HTML a la carpeta web y expón también data/alerts.json:
sudo cp /opt/soc-project/dashboard/sentinel_soc.html /var/www/html/index.html
sudo ln -s /opt/soc-project/data /var/www/html/data
```
Así el equipo entra desde su navegador a `http://IP-DEL-SERVER/`.
(En producción, protéjanlo con HTTPS y login — ver sección 8.)

### 7.3 Servicio para el monitor de logins (ejemplo)
Archivo `/etc/systemd/system/soc-login.service`:
```ini
[Unit]
Description=SOC login/intrusion monitor
After=network.target

[Service]
User=soc
WorkingDirectory=/opt/soc-project/scripts
ExecStart=/usr/bin/python3 login_monitor.py --auth-log /var/log/auth.log --follow --known-ips /opt/soc-project/scripts/known_ips.txt
Restart=always

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now soc-login.service
sudo systemctl status soc-login.service
```

### 7.4 Escaneos periódicos con cron
El escaneo de puertos y la importación de Kali se pueden correr en horario, con `cron`:
```bash
sudo crontab -e
# Escaneo de puertos cada hora:
0 * * * * cd /opt/soc-project/scripts && /usr/bin/python3 port_scanner.py --targets /opt/soc-project/scripts/subnets.txt --top-ports
```

---

## 8. Pendientes / siguientes pasos recomendados (para el reporte con IT y managers)

Este entregable es una **base sólida y funcional**. Para producción de verdad, recomienden en el reporte:

1. **Autenticación en el dashboard** (login por usuario, HTTPS) — hoy es de solo lectura.
2. **Base de datos** (PostgreSQL o SQLite) en lugar de `alerts.json`, o mejor aún, **integrar Wazuh o Elastic Stack** como motor detrás y usar este dashboard como capa de visualización. Wazuh ya trae agentes para Windows/Linux, correlación y cumplimiento.
3. **Agentes en los endpoints** para recoger logs de todas las máquinas (no solo del server).
4. **Feeds de threat intel** reales para `ioc_hashes.txt` (MISP, AbuseCH).
5. **Notificaciones** (correo / Teams / Slack) cuando haya un `critical`.
6. **Retención y respaldo** de `alerts.jsonl` para auditoría.

### Objetivo del proyecto
El fin es tener un **reporte de qué necesita la empresa para mejorar su seguridad**. Los escaneos de Kali (`REPORT_*.txt`) dan justamente eso: lista de puertos que hay que cerrar, servicios inseguros (Telnet/SMB/RDP expuestos), y vulnerabilidades con CVE que hay que parchear. Ese reporte es lo que se lleva a la junta con IT y los managers.

---

## 9. Recordatorio importante (ética y autorización)

Estas herramientas son **defensivas y de auditoría interna**. Escanear redes o analizar correos **solo** se hace sobre la infraestructura de la empresa y **con autorización por escrito** de IT / dirección. Guarden ese permiso; los scripts de Kali incluso piden confirmación de autorización antes de correr.
