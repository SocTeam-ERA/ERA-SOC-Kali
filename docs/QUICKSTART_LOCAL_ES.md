# Arrancar Sentinel // SOC en tu compu — guía rápida (hoy mismo)

Objetivo: **ver el dashboard funcionando en tu computadora en 5 minutos**, primero con datos de ejemplo y luego con las alertas reales que producen los scripts.

Necesitas: **Python 3** (ya viene en Kali, macOS y casi todo Linux; en Windows instálalo de python.org) y un **navegador**.

Comprueba Python:
```bash
python3 --version      # en Windows quizá sea:  python --version
```

---

## Opción A — Solo mirar el dashboard (lo más rápido)

Descomprime `sentinel-soc.zip` y haz **doble clic** en:
```
soc-project/dashboard/sentinel_soc.html
```
Se abre en el navegador en **modo demo**: genera alertas de ejemplo solo y el botón **LIVE** va agregando más. Arriba a la izquierda verás el badge **“FEED LIVE · demo”**. Ideal para enseñarlo rápido.

> En este modo NO lee los scripts todavía — son datos de muestra dentro del navegador.

---

## Opción B — Dashboard con los datos REALES de los scripts (recomendada)

Aquí el dashboard lee `data/alerts.json`, que es lo que escriben tus detectores. Necesita servirse por HTTP (no `file://`), y para eso Python trae un servidor de una línea.

**1. Abre una terminal en la carpeta del proyecto:**
```bash
cd ruta/donde/descomprimiste/soc-project
```

**2. Genera unas alertas para arrancar (o corre los detectores en modo demo):**
```bash
python3 scripts/seed_demo_data.py --fresh --count 40
# o prueba los detectores reales:
python3 scripts/login_monitor.py --demo
python3 scripts/phishing_detector.py --demo
python3 scripts/malware_detector.py --demo
```

**3. Levanta el servidor web local (déjalo corriendo en esa terminal):**
```bash
python3 -m http.server 8000
```

**4. Abre en el navegador:**
```
http://localhost:8000/dashboard/sentinel_soc.html
```
Ahora el badge de arriba dirá **“FEED · alerts.json”** → está leyendo los datos reales. El dashboard se **refresca solo cada 5 segundos**.

**5. Compruébalo en vivo:** deja el navegador abierto y, en **otra terminal** (misma carpeta), corre:
```bash
python3 scripts/login_monitor.py --demo
```
En unos segundos verás aparecer las alertas nuevas en el stream (con un flash verde). ¡Ese es el pipeline completo funcionando!

Para detener el servidor: `Ctrl-C` en la terminal del paso 3.

---

## Cómo sé en qué modo está

Mira el badge arriba a la izquierda, junto al foquito verde:

| Badge | Significado |
|-------|-------------|
| **FEED · alerts.json** | Leyendo los datos reales de los scripts (Opción B). ✅ |
| **FEED LIVE · demo** | Datos de ejemplo del navegador (Opción A / doble clic). |

---

## Problemas comunes

- **Sigue en “demo” aunque usé la Opción B** → asegúrate de abrir la URL `http://localhost:8000/...`, **no** el archivo directo. Y que exista `data/alerts.json` (corre el paso 2).
- **“command not found: python3”** → en Windows usa `python` en vez de `python3`.
- **El puerto 8000 está ocupado** → usa otro: `python3 -m http.server 8080` y abre `http://localhost:8080/...`.
- **No veo cambios al correr un script** → el refresco es cada 5 s; espera un momento o revisa que el script haya terminado sin error.

> Nota: en modo `alerts.json`, los botones Acknowledge/Resolve del panel de detalle son visuales; al refrescar desde el archivo vuelven al estado del archivo. En producción, el backend guardará ese cambio.

---

## Cuando ya tengas el Kali y las subredes (siguiente paso)

```bash
cd soc-project/kali
chmod +x *.sh
# pon tus subredes autorizadas en targets.conf, luego:
sudo ./0_run_all.sh
```
Eso corre nmap (descubrimiento → puertos → vulnerabilidades), genera el reporte para IT/managers e **importa los hallazgos al mismo `data/alerts.json`**, así que aparecen en el dashboard. Para el escaneo interno rápido con zmap y la captura con tshark, revisa `docs/MODULOS_zmap_tshark_ES.md`.
