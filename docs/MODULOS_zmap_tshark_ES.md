# Módulos adicionales: zmap y tshark
### (ES + EN) — por qué fallaban y cómo quedaron arreglados

Durante las pruebas se detectaron dos herramientas con fallas conocidas. Aquí queda documentado el porqué y la solución que ya viene incluida en el proyecto.

---

## 1. zmap — no escaneaba rangos internos

**Causa / Cause.**
zmap trae por defecto `/etc/zmap/blocklist.conf`, que **bloquea las redes privadas RFC1918** (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Está pensado para escanear Internet público, así que "por diseño" ignora las redes internas de la empresa. / zmap's default blocklist excludes RFC1918 private ranges, so internal subnets are skipped by design.

**Solución / Fix.**
Se agregó un blocklist propio que bloquea **solo** el espacio realmente especial (loopback, link-local, multicast, reservado) y **deja escaneables las redes privadas**:

- `kali/zmap-blocklist.conf` — el blocklist personalizado.
- `kali/1b_zmap_discovery.sh` — descubrimiento rápido interno con zmap usando ese blocklist.

**Uso / Usage:**
```bash
sudo apt install zmap
cd soc-project/kali
./1b_zmap_discovery.sh 10.10.20.0/24
# rango grande + puertos de liveness personalizados:
PORTS="443 445 3389" RATE="8000" ./1b_zmap_discovery.sh 10.10.0.0/16
# el resultado alimenta el escaneo de nmap:
./2_port_service_scan.sh results/zmap_live_<stamp>.txt
```

zmap barre **un puerto a la vez** (por eso el script recorre varios puertos de "está vivo" y une los hosts). Es mucho más rápido que nmap para rangos grandes; luego nmap hace el detalle de servicios/vulnerabilidades sobre los hosts que zmap encontró.

> **Recomendado para producción:** en vez de "bloquear todo menos privadas", usa una **allowlist** exacta con las CIDR autorizadas: `zmap -w allowlist.txt ...`. Es más estricto y evita tocar redes fuera de alcance.

---

## 2. tshark — lo rechazaba la reja de autorización

**Causa / Cause.**
tshark **no es un escáner**: es un **capturador de tráfico**. Su objetivo es una **interfaz** (`-i eth0`), no una IP. La reja de autorización de los scripts de escaneo valida **IPs/rangos**, así que rechazaba a tshark porque "su objetivo no es una IP". Estaba entrando por la puerta equivocada. / tshark is a capture tool whose target is an interface, not an IP, so the IP-based scan authorization gate rejected it.

**Solución / Fix.**
tshark ahora tiene su **propio módulo** con una **reja de autorización basada en interfaz** ("¿tengo permiso de monitorear tráfico en ESTA interfaz/red?"), separada de la de escaneo:

- `kali/4_traffic_capture.sh` — captura en interfaz o desde un `.pcap` y saca los campos.
- `kali/traffic_to_alerts.py` — convierte el tráfico sospechoso en alertas del dashboard.
- `kali/ioc_ips.txt`, `kali/bad_domains.txt` — listas de indicadores (aliméntalas de threat intel).

**Uso / Usage:**
```bash
sudo apt install tshark          # responde "Yes" para captura sin root, o usa sudo
cd soc-project/kali

# Captura en vivo: 2000 paquetes en eth0
sudo ./4_traffic_capture.sh -i eth0 -c 2000
# Captura por tiempo: 60 segundos
sudo ./4_traffic_capture.sh -i eth0 -d 60
# Analizar un pcap existente (sin sudo)
./4_traffic_capture.sh -r captura.pcap
```

**Qué detecta en el tráfico / What it flags:**
- **Port scan en el cable** — un origen que toca muchos puertos distintos (patrón de barrido). → `port_scan`
- **Protocolos en texto claro** — Telnet, FTP, POP3, IMAP, SNMP (exponen credenciales). → `intrusion` (medium)
- **Tráfico hacia IPs maliciosas conocidas** — coincidencia con `ioc_ips.txt`. → `malware` (critical)
- **DNS sospechoso** — consultas a TLDs de alto riesgo (.ru, .tk, .top, .xyz…) o dominios en `bad_domains.txt`. → `phishing` (medium)

Todo se escribe al mismo `data/alerts.json`, así que aparece en el dashboard junto con lo demás.

---

## Regla general que dejó esto claro

**Escáneres** (nmap, zmap) → su objetivo es una **IP / rango** → van por la reja de autorización de IP (`authorize()` en `lib.sh`).
**Captura** (tshark) → su objetivo es una **interfaz** → va por su propia reja (`capture_authorize` en `4_traffic_capture.sh`).

Nunca metas una herramienta de captura por la puerta de los escáneres (y viceversa): es exactamente lo que causaba el rechazo.

> ⚖️ Recordatorio: zmap, tshark y nmap se corren **solo** sobre redes/interfaces que IT autorice **por escrito**. Los tres scripts piden confirmación de autorización antes de correr.
