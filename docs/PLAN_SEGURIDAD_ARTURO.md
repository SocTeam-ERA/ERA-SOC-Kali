# Plan individual — Seguridad y Kali (Arturo)
**Etapa 1: análisis, escaneo y detección de agujeros en la red interna**
**Fecha:** 2026-08-27

Este documento es tu hoja de ruta personal: **qué te toca a ti** (parte de seguridad), **cómo ayudar a Sixto y Tomás** (dev), y los **pasos concretos en Kali** para la Fase A. Tus compañeros llevan el código; tú llevas el criterio de seguridad, el alcance, los IOCs y la ejecución de los escaneos.

> ⚖️ **Regla de oro, antes que todo:** no se toca ninguna red sin **autorización por escrito** de IT/dirección (qué subredes, qué ventana horaria, qué métodos). Ese permiso es tu primer entregable y tu blindaje legal.

---

## 1. Lo que falta de TU lado (seguridad) — para agregar

Estas son cosas que el dev no puede hacer por ti porque requieren criterio de seguridad o gestión con IT:

1. **Redactar la autorización de alcance (scope).** Es lo que desbloquea todo. Debe incluir:
   - Subredes/VLANs autorizadas y las que quedan **fuera** de alcance.
   - **Ventana horaria** (idealmente fuera de horario productivo para los escaneos intrusivos).
   - Métodos permitidos en Etapa 1 (descubrimiento, escaneo de puertos y de vulnerabilidades **no destructivas**; nada de explotación — eso es Etapa 2).
   - Contactos de emergencia de IT (a quién avisar si un escaneo causa un problema).
   - Fecha, responsables y **firma**.
2. **Definir el `scan_scope` real** (los rangos) junto con infra, y cargarlo en el backend.
3. **Curar los indicadores (IOCs).** Esto es contenido de seguridad, no de programación:
   - `data/ioc_hashes.txt` — hashes maliciosos (de MISP / AbuseCH / VirusTotal).
   - `kali/ioc_ips.txt` — IPs maliciosas conocidas.
   - `kali/bad_domains.txt` — dominios de phishing/malware.
   Manténlos actualizados; son los que hacen que las alertas signifiquen algo.
4. **Definir el criterio de severidad** (qué es `critical` vs `medium` vs `normal`) para la escala de 5 niveles del backend. El dev implementa; tú decides el criterio.
5. **Baseline de "known-good"** — qué puertos/servicios son esperados en cada VLAN, para que las alertas no sean puro ruido (el `--baseline` del `port_scanner.py` usa esto).
6. **Runbook de incidente de escaneo** — un mini-procedimiento: "si un host se cae durante un escaneo → detener, avisar a IT (contacto X), documentar". Media página, pero te cubre.
7. **(Etapa 2, ir gestionando):** adaptador WiFi con **modo monitor** para la auditoría WiFi, y ubicación física del sensor.

---

## 2. Cómo ayudar a Sixto y Tomás (dev)

Tú les destrabas cosas que ellos no pueden generar solos:

- **Darles datos reales para probar.** Corre los detectores/escaneos y llena `data/alerts.json` (o la base) para que ellos prueben el feed en vivo y el dashboard con datos de verdad, no inventados.
- **Entregarles el contenido de seguridad:** el `scan_scope`, los IOCs y el criterio de severidad. Sin eso, su backend está vacío de significado.
- **Probar la reja de autorización como atacante.** Intenta lanzar un escaneo a un objetivo **fuera** del `scan_scope` y confirma que el backend lo **rechaza** antes de ejecutar. Eso es QA de seguridad que solo tú vas a pensar en hacer.
- **Auditar el endurecimiento del servidor (secc. 4 del informe).** Cuando lo monten, verifica tú mismo: que el firewall solo deje `443` desde subredes internas/VPN, que el SSH tenga MFA, que no haya secretos en el código, que el acceso externo sea solo por VPN. Eres el más indicado para revisarlo con ojos de atacante.
- **Pasarles el changelog de zmap/tshark** (`CHANGELOG_2026-08-27_ES.md`) para que cierren el punto 3.1.
- **Validar la prueba de punta a punta:** que un escaneo `nmap` real genere una alerta que llegue al dashboard en vivo.

---

## 3. Preparar tu Kali (checklist)

```bash
# Actualizar el sistema
sudo apt update && sudo apt full-upgrade -y

# Herramientas de la Etapa 1 (nmap ya viene; instala el resto)
sudo apt install -y nmap zmap tshark netdiscover masscan whatweb

# Verifica que estén
for t in nmap zmap tshark ip; do command -v $t >/dev/null && echo "OK $t" || echo "FALTA $t"; done

# Documenta tu puesto (lo vas a necesitar para el reporte)
ip a          # tus interfaces e IPs
ip r          # tu gateway y rutas
cat /etc/resolv.conf   # tus DNS
```

Guarda esa salida: **en qué VLAN/subred quedó tu Kali** es el punto de partida del reporte de alcance.

---

## 4. Fase A — Línea base, paso a paso (con la suite que ya tienes)

> Corre esto **solo** sobre los rangos que estén en la autorización por escrito. Los scripts de `kali/` piden confirmación antes de correr.

**Paso 1 — Reconocimiento del puesto** (¿dónde estoy?)
```bash
ip a; ip r; cat /etc/resolv.conf
```

**Paso 2 — Barrido de tu subred local** (¿qué hay junto a mí?)
```bash
cd soc-project/kali
chmod +x *.sh
# pon tu subred local en targets.conf, luego:
sudo ./1_host_discovery.sh 10.10.<tu-subred>.0/24
```

**Paso 3 — Descubrimiento rápido si el rango es grande** (zmap ya arreglado)
```bash
PORTS="443 445 3389 22" ./1b_zmap_discovery.sh 10.10.0.0/16
```

**Paso 4 — Prueba de alcance cruzado (LA prueba clave de segmentación)**
¿Desde tu VLAN llegas a otras subredes que **no deberías** — usuarios, servidores, y sobre todo la **red de administración**? Lo que responde y no debería es el **hallazgo central**.
```bash
# apunta targets.conf (o la CLI) a OTRAS VLANs y mira qué responde
sudo ./1_host_discovery.sh 10.10.20.0/24   # servidores
sudo ./1_host_discovery.sh 10.10.30.0/24   # administración  <-- si contesta, hallazgo
```

**Paso 5 — Prueba de salida (egress)**
¿Tu puesto sale a Internet por puertos arbitrarios? (riesgo de exfiltración). Prueba unos puertos de salida hacia una IP externa controlada/autorizada y anota cuáles pasan.

**Paso 6 — Detalle de servicios y vulnerabilidades** sobre lo alcanzable (coordina ventana con IT):
```bash
sudo ./2_port_service_scan.sh results/live_hosts_<stamp>.txt
sudo ./3_vuln_scan.sh results/live_hosts_<stamp>.txt
# o todo junto:
sudo ./0_run_all.sh
```
Esto genera `results/REPORT_*.txt` e importa las alertas al dashboard.

**Paso 7 — Reporte de alcance (tu primer entregable)**
Estructura sugerida: *"Desde un puerto en la VLAN X se alcanza A, B y C — incluyendo la red de administración, que no debería. Puertos/servicios inseguros encontrados: … Vulnerabilidades: … Recomendaciones: cerrar/segmentar …"*. Ese documento es el que llevas a infra y managers.

---

## 5. Tu secuencia inmediata (orden en que yo lo haría)

1. **Redactar y conseguir firmada la autorización de alcance** (te desbloquea todo).
2. **Preparar el Kali** (checklist secc. 3) y documentar tu puesto.
3. **Cargar `scan_scope` + IOCs + criterio de severidad** y pasárselos al dev.
4. **Apenas el servidor esté en la red:** correr la **Fase A (línea base)** y sacar el **reporte de alcance**.
5. **QA de seguridad:** probar la reja de autorización y auditar el endurecimiento del servidor.
6. **Ir gestionando lo de Etapa 2** (adaptador WiFi modo monitor, acceso SNMP a switches).

---

## 6. Lo que NO te toca ahora (para no dispersarte)
- Explotación / pentesting activo → **Etapa 2**.
- Detectores de tráfico continuo (tshark en vivo, IDS) → **Etapa 2**.
- El código del backend/frontend → es de Sixto y Tomás; tú les das el contenido de seguridad y el QA.

> Recordatorio final: todo escaneo y captura, **solo** sobre lo autorizado por escrito, en la ventana acordada, con IT avisado. Tu valor en la Etapa 1 es el **mapa de segmentación** — ese es el hallazgo que justifica todo lo demás.
