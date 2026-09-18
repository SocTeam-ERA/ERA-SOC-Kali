# Pendientes — Sentinel // SOC · 2026-09-16

Lista acumulada durante la sesión de hoy, para retomar mañana.

**Corrección importante (confirmada con el usuario):** `https://soc.era.ca` es interno solamente — el túnel de Cloudflare resuelve dentro de la red/VPN de la oficina, pero a propósito **no** está pensado para acceso público. Se confirmó probando desde datos móviles (fuera de la red de oficina): no carga, como se espera. Si en algún momento alguien externo necesita verlo, la vía es una VPN, no un hostname público. Los puntos de "antes de exponer públicamente" de abajo quedan en espera hasta que eso cambie — no son urgentes para mañana.

## Acceso externo para managers (futuro, no urgente)
- [ ] Cuando algún manager necesite ver el dashboard desde fuera de la oficina, la vía decidida es VPN (no exponerlo públicamente). Falta elegir/armar esa VPN y dar de alta a los managers que la necesiten.

## Si algún día se decide exponerlo fuera de la VPN (no urgente por ahora)
- [ ] Confirmar que los endpoints de escritura (`POST /api/alerts/<id>/status`, `POST /api/assets/<mac>/notes`) exigen key `write` sin excepción, y que nada queda accesible sin auth por depender de estar en red interna. (El código de `soc_api.py` ya lo hace bien — solo confirmarlo de nuevo tras cualquier cambio antes de exponer.)
- [ ] Decidir cómo va a autenticarse el dashboard contra la API sin exponer una key de escritura en el JS público (cualquiera con devtools la vería si se hace ingenuamente).
- [ ] Configurar `SOC_API_CORS` si el dashboard y la API terminan sirviéndose desde orígenes distintos detrás del túnel.

## Dashboard desconectado del backend real
- [x] **Confirmado 2026-09-17: ya no aplica.** Sixto construyó un frontend nuevo (SvelteKit, con login, compilado vía dokploy en el Ubuntu server, publicado en `soc.era.ca`) que sí habla con la API real (`soc_api.py`, puerto 8080) — se verificó end-to-end simulando 13 alertas distintas (una por cada detector: login_monitor, arp, malware, phishing, nmap, port_scanner, nikto, whatweb, vlan_segmentation, traffic_capture, suricata, zeek, osquery) y las 13 aparecieron correctamente en `soc.era.ca` tras iniciar sesión. El viejo `dashboard/sentinel_soc.html` (el que solo leía el archivo estático) quedó obsoleto/reemplazado por este nuevo frontend.
- [ ] Falta confirmar con Sixto: si Acknowledge/Resolve ya persisten de verdad a través del nuevo frontend (llaman a `POST /api/alerts/<id>/status`), o si ese detalle sigue pendiente del lado de él.
- [x] **Corrección 2026-09-17: esto estaba mal dicho.** `dashboard/sentinel_soc.html` SÍ tiene una sección "Asset Inventory" completa (panel + JS) que lee `data/assets.json` y coincide exactamente con el esquema de `soc_core.py` — se verificó leyendo el archivo completo. No falta construir nada aquí. Lo único por confirmar con Sixto: si su nuevo frontend en SvelteKit ya incluye esta misma pantalla o si esa parte todavía no la portó.
- [ ] Confirmar con Sixto cómo maneja la autenticación del nuevo frontend hacia la API (login propio + proxy del lado servidor, o algo distinto) — esto puede ya resolver el punto de "no exponer una key de escritura en el JS público" de la sección de abajo.

## Enriquecimiento de inventario de activos
- [ ] Nuevo parser (al estilo `arp_to_alerts.py`) que lea `dhcp.log` y `http.log` de Zeek para enriquecer cada MAC nueva con el tipo de dispositivo probable (vendor class de DHCP, User-Agent de HTTP), sin depender de correr `nmap -O` manualmente. Surgió de la alerta de hoy de un dispositivo nuevo en la VLAN de oficina (`00:1b:82:71:9d:e3`, vendor "Taiwan Semiconductor Co., Ltd.") donde solo se pudo identificar el fabricante del chip, no el modelo/tipo real.

## Administración
- [ ] Crear los usuarios/logins nuevos del equipo cuando el túnel esté arriba.
- [ ] Revisar y decidir sobre el cambio sin commitear en `kali/traffic_to_alerts.py` (+8 líneas, sin relación con lo anterior).
- [ ] Repaso de punta a punta (Kali, backend, frontend) una vez que `soc.era.ca` esté funcionando, antes de darlo por cerrado.

## 2026-09-18 — AIDE era el mayor generador de ruido de todo el proyecto
- [x] **Resuelto.** Encontrado por el usuario: el dashboard se estaba llenando de alertas "File integrity: ... changed" sin sentido. Investigación reveló que **AIDE representa 6,434 de ~11,367 alertas en todo el histórico del proyecto (~57% de TODO el ruido jamás generado)**, muy por encima de `kali_scan` (4,260). La causa real: la exclusión `!/var/lib/suricata/cache` ya existía en `/etc/aide/aide.conf.d/90_sentinel_soc` (agregada por el compañero el mismo día), pero la base de datos de AIDE seguía rastreando esos archivos de antes de que se agregara la exclusión — un cambio de config no purga retroactivamente lo ya rastreado, hace falta `aide --init` completo.
- Se limpiaron 499 alertas de ruido del snapshot y se corrió `aide --init` dos veces (primero para `suricata/cache`, luego otra vez tras agregar `!/usr/share/applications`, ~29 min cada una). Confirmado: `aide --init` en este sistema escribe directo a `aide.db` (ignora `database_out`/`database_new` de la config) — comportamiento real observado dos veces, no una condición de carrera.
- Se agregó nueva exclusión: `!/usr/share/applications` (accesos directos de menú de escritorio de Kali, churn genuino por regeneración de caché de menús, sin valor de seguridad).
- **Sin excluir a propósito** (pendiente de confirmar el lunes si reaparecen): `/opt/zeek/share` (2,022 hist.), `/opt/zeek/include` (1,543 hist.), `/opt/microsoft/powershell` (725 hist.). Sus fechas reales son de 2015 (archivos de instalación estáticos) — el volumen histórico probablemente vino del mismo bug de "re-alerta para siempre" ya arreglado hoy, no de cambios reales recurrentes. Se decidió NO excluirlos de entrada porque son archivos del propio Zeek/PowerShell — si alguien los modificara de verdad (para cegar la detección), sí queremos enterarnos. Verificar el lunes con: `python3 -c "import json; d=json.load(open('/opt/sentinel-soc/data/alerts.json')); print(sum(1 for a in d if 'suricata/cache' in str(a) or 'usr/share/applications' in str(a)))"` (debe dar 0) y revisar si `/opt/zeek/share`, `/opt/zeek/include`, `/opt/microsoft/powershell` reaparecieron.

## 2026-09-18 — rastreo de puertos cambiado de IP a MAC (cambio grande)
- [x] **Hecho, probado con datos sintéticos, pendiente de verificar con el próximo scan real.** `nmap_to_alerts.py` ahora rastrea el historial de puertos por dirección MAC (vía `data/assets.json`) en vez de por IP — en una red con DHCP, la misma laptop con IP nueva se veía como "host nunca antes visto" (todos sus puertos normales se marcaban "nuevos"). Se probaron los 3 escenarios clave (dispositivo conocido con IP nueva, host sin MAC resoluble, IP vieja reasignada a otro equipo) — todos correctos.
- ~~El cambio usaba un archivo de estado nuevo (`data/port_state_v2.json`)~~ — **revertido el 2026-09-18 por la avalancha descrita al final de este documento**: el script programado vuelve a usar `data/port_state.json`, que ya está en esquema por MAC.
- [ ] Confirmar en unos días que el volumen de "NEW open port" bajó de verdad comparado con los ~356 de los últimos 2 días antes del cambio.
- `data/port_state.json` sigue en uso (ya en esquema por MAC). Conserva ~337 entradas viejas con llave IP pelada (escaneo TCP) y ~278 (UDP) que ya nunca coinciden con nada; son inofensivas y se pueden podar.

## Aparte — investigación de los cortes de SSH
No es de este proyecto de código, pero queda documentado: hoy se cayó varias veces la sesión SSH hacia `kali2` con paquetes TCP RST fabricados desde el propio Kali hacia el cliente. Se descartó Suricata, fail2ban, los timers propios del proyecto, memoria/OOM y CPU steal time. La hipótesis que queda en pie (sin poder confirmarse desde esta VM) es un loop de red a nivel del switch virtual de Proxmox — pendiente de escalar a quien administre esa capa si vuelve a pasar. Mientras tanto: `tcpdump` sigue capturando evidencia en `/home/adelcueto/ssh_diag/`, y `sysstat`/acceso a `journalctl -k` (grupo `adm`) ya quedaron habilitados hoy para diagnosticar mejor la próxima vez. No volvió a pasar desde las 14:44 del 16 de septiembre, pero la causa raíz nunca se confirmó — sigue abierto.

## 2026-09-17 — sesión de limpieza de alertas + hallazgos nuevos

**🔴 Prioridad máxima — sin escalar todavía a IT/red:** el test `5_vlan_segmentation_test.sh` (metodología validada: fuerza cada prueba por el gateway real de la VLAN origen, no por el atajo de este Kali multi-homed) confirmó **30 de 30 pares de VLANs alcanzables — cero segmentación real entre ninguna de las 6 VLANs**, incluyendo Guest/Employee WiFi llegando directo a Management y Wiping. Reporte ya armado y pasado a Alberto para IT (ver artifact "VLAN Segmentation Finding"). Ahora corre solo todas las noches a la 01:00 (`soc-vlan-segmentation.timer`) para detectar cuando se arregle.
- [ ] Escalar el reporte a IT/equipo de red y darle seguimiento.

**Limpieza de ruido/falsos positivos en el feed de alertas (todo comiteado):**
- [x] Puertos cerrados ya no generan alerta (solo log) — `nmap_to_alerts.py`.
- [x] Wording de "RESOLVED" corregido a "No longer detected (unconfirmed)" cuando un hallazgo deja de verse — `nmap_to_alerts.py`.
- [x] 23 alertas de datos de prueba/demo (root desde nodo Tor, etc.) que se colaron en producción, limpiadas del snapshot. Causa: `--demo` de varios scripts no tenía el mismo guard que `seed_demo_data.py` — ya se agregó `confirm_demo_on_live_instance()` compartido a los 4 scripts con modo demo.
- [x] Falso positivo de Suricata: el refresh diario de la lista de nodos Tor (`proxy_check.py --refresh-tor`, este mismo equipo) se detectaba a sí mismo como "uso de Tor". Envuelto en `kali/refresh_tor.sh` con el marcador `mark_scan_start`/`scan_active()` que ya usan los demás scripts.
- [x] `traffic_to_alerts.py`: tráfico loopback (127.0.0.1→127.0.0.1) ya no genera falsa alerta de "cleartext protocol" (mismo patrón que ya existía para port-scan).
- [x] Severidad de "nuevo dispositivo" en la VLAN Wiping bajada de critical a medium — confirmado con el usuario que es un rack de borrado de HDD/NVMe/SAS todavía en construcción, con alta rotación de equipos esperada.
- [x] `zeek_to_alerts.py`: `CaptureLoss::Too_Much_Loss` agregado a la lista de ruido operativo de Zeek (mismo trato que los otros 2 tipos de CaptureLoss ya excluidos).

**Zeek / `eth0` (VLAN Floor) — capacidad de captura:**
- [x] Se intentó arreglar con más procesos worker (`lb_procs` 1→2→3 en `/opt/zeek/etc/node.cfg`) — **no funcionó**, la pérdida volvió a pasar de ~100% en cada intento, y el uso de CPU de cada worker se mantuvo bajo 1% (descarta que sea falta de capacidad).
- [x] Diagnóstico corregido: `CaptureLoss::Too_Much_Loss` mide huecos en secuencias/ACKs de TCP, no una cola de captura saturada — apunta a que `eth0` no está viendo tráfico bidireccional completo de otros hosts, es decir, no es un puerto espejo/SPAN real a nivel del vswitch de Proxmox. Misma familia de problema que la investigación de los cortes de SSH, en la misma interfaz. No se puede arreglar desde este proyecto.
- [ ] Si alguien con acceso a Proxmox revisa la configuración de red, este es el otro punto (junto con el loop de SSH) para preguntarle.

**Nueva cobertura de detección:**
- [x] `chkrootkit` (corría diario, nunca llegaba al dashboard) ya integrado vía `chkrootkit_to_alerts.py` + `soc-chkrootkit-forwarder.timer` (00:30 diario), con filtrado de los 3 falsos positivos esperados en este equipo (dotfiles de gems de `dradis`, scripts de `/tmp/claude-*`, sniffers legítimos de Zeek/Suricata en modo promiscuo).
- [x] Scan profundo de vulnerabilidades (`3_vuln_scan.sh`: nikto, whatweb, categoría `vuln` completa de nmap, SNMP) ya programado semanal (domingo 02:00, `soc-vuln-scan.timer`), reutilizando la lista de hosts ya filtrada sin Guest WiFi del scan regular — antes solo corría manual y llevaba 2 días sin correr.
- [x] `lynis` (también corre diario, tampoco llegaba al dashboard): decisión de **no** conectarlo como alertas (son ~29 sugerencias de hardening que casi no cambian día a día — meterlas todas como alerta recrearía el mismo problema de ruido que se pasó todo el día arreglando). En su lugar, se entregó la lista ya filtrada como backlog de hardening:
  - [ ] SSH: lynis sugiere mover el puerto 22 a uno no estándar (seguridad por oscuridad, bajo valor real) — decisión pendiente del usuario, requiere avisar a todos los que se conectan.
  - [ ] Revisar por qué lynis marca que el nameserver `1.1.1.1` "no responde" (raro, dado que DNS ha funcionado bien toda la sesión).
  - [ ] Evaluar quitar TFTP si no se usa (`INSE-8318`/`INSE-8320`).
  - [ ] Revisar permisos de directorios home (`HOME-9304`).
  - [ ] No hay logging a un servidor externo — si este Kali se cae, se pierden los logs con él (`LOGG-2154`).
- [x] `soc_doctor.py`/`service_watchdog.py` actualizados para vigilar los 3 timers/servicios nuevos de hoy (`soc-chkrootkit-forwarder`, `soc-vuln-scan`, `soc-vlan-segmentation`, `soc-dhcp-fingerprint`).

**Revisión de seguridad de `soc_api.py`:** todo bien salvo un hallazgo, ya arreglado — no había límite de tamaño en el cuerpo de las peticiones POST (riesgo de agotar memoria), ahora limitado a 64KB. Firewall (`ufw`) ya restringe el puerto 8080 solo al backend y la VPN admin — confirmado, no depende únicamente de la API.

**Sin resolver / bloqueado por infraestructura que no existe todavía:**
- [ ] `malware_detector.py`: no hay carpeta compartida que vigilar. Sin acción por ahora.
- [ ] `phishing_detector.py`: no hay fuente de correo todavía — esperando a IT.

**Housekeeping menor, sin acción tomada:**
- [x] **Resuelto 2026-09-17:** la API key en texto plano en `~/.bash_history` (`[old key removed]`) ya no es la key activa — el usuario confirma que se rotó la semana pasada y Tomás ya tiene la key nueva en su backend. Se verificó que la key `legacy` actualmente en uso no coincide con el string expuesto. Sin acción adicional.
- [ ] Hay dos copias completas y viejas del proyecto en el home del usuario (`~/soc-project-new/`, `~/Desktop/soc-project/`), aparte de la de producción en `/opt/sentinel-soc` — desorden, no se tocaron.

## 2026-09-18 (tarde) — marca de escaneo pegada: Suricata/Zeek silenciados ~21 horas

- [x] **Bug encontrado por `soc_doctor.py`:** `5_vlan_segmentation_test.sh` reemplazaba el trap de salida de `mark_scan_start` (línea `trap cleanup_route EXIT`) y luego lo borraba (`trap - EXIT`), así que `mark_scan_end` nunca corría y la línea del escaneo quedaba en `data/scan_in_progress` para siempre. Mientras hay una línea ahí, `scan_active()` devuelve verdadero y se suprimen las alertas de Suricata/Zeek. Dos corridas (2026-09-17 15:08 y 2026-09-18 01:02, la del timer nocturno) dejaron su línea pegada, así que desde el 17 a las 15:08 hasta hoy ~12:45 esas alertas estuvieron silenciadas (no el resto del pipeline).
- [x] Arreglo: el trap ahora encadena ambas limpiezas (`cleanup_route; mark_scan_end`) y al final se restaura `trap mark_scan_end EXIT` en lugar de borrarlo. Las 2 líneas muertas se limpiaron a mano bajo el mismo candado. Se verificará con la corrida nocturna de mañana (01:00): `soc_doctor.py` no debe reportar líneas pegadas.
- [x] Falso positivo de `soc_doctor.py`: `os.kill(pid, 0)` da `PermissionError` con procesos de root (el escaneo programado) y se contaba como "muerto". Ahora se cuenta como vivo.
- [x] Endurecimiento hecho: `scan_active()` (`soc_core.py`, usado por los reenviadores de Suricata y Zeek) y el monitor de tráfico (`4b_traffic_monitor.sh`, vía la nueva `scan_marker_active` en `lib.sh`) ahora ignoran líneas de la marca cuyo PID ya no existe; un PID de root vivo (escaneo programado) cuenta como activo. Probado con marca vacía, solo espacios, PID muerto, PID propio, PID de root, mezcla de muerto+vivo y línea mal formada. **Requiere reiniciar** `soc-zeek-forwarder`, `soc-suricata-forwarder` y `soc-traffic-monitor` para que los procesos largos carguen el código nuevo. Límite conocido: si el sistema reutiliza el PID de un escaneo muerto para otro proceso, esa línea parecería viva.
- [x] Ver la incidencia siguiente: `port_state_v2.json` nunca se creó y no se usará.


## 2026-09-18 (tarde) — avalancha de 1.041 alertas falsas "NEW open port" tras el cambio a MAC

- **Qué pasó:** a las 13:16 (hora local) el escaneo programado emitió **1.041 alertas `NEW open port`** en ~20 segundos (316 críticas, 715 medias, 10 normales), más 86 de `161/udp`. Todas son falsas: los mismos puertos de siempre, vistos como "nuevos" porque el estado previo estaba en esquema por IP y el código nuevo busca por MAC.
- **Causa 1 (error mío, de diseño):** el cambio de nombre a `port_state_v2.json` solo cubría el escaneo TCP. El barrido UDP (`2_port_service_scan.sh`, `udp_state.json`) y los estados de vulnerabilidades (nombre derivado del archivo de estado) siguieron usando los archivos viejos con el esquema viejo, así que esa parte se inundó de todos modos.
- **Causa 2 (error mío, de proceso):** edité `scheduled_scan.sh` a las 12:09, con el ciclo de 12:03 ya corriendo. Bash lee los scripts de forma incremental, así que ese ciclo siguió usando `port_state.json` con el código Python nuevo, en lugar de sembrar `v2` en silencio. Regla: **no editar un script mientras su proceso está corriendo** (o reemplazarlo con archivo nuevo, no en sitio).
- **Estado actual:** el ciclo dejó `port_state.json`/`udp_state.json` ya en esquema por MAC. Se comprobó con un dry-run (emisión de alertas simulada) que repetir el mismo escaneo genera **0 alertas**, y se revirtió `scheduled_scan.sh` a `port_state.json`. El escaneo de las 16:02 debería ser silencioso.
- [x] **Limpieza hecha (decisión del usuario):** 1.026 de las 1.041 alertas se marcaron `resolved` con nota (`actor: claude-code`, registradas en `alert_status_log.jsonl`); se comprobó una por una que ese puerto ya estaba abierto en el estado anterior de esa IP. Las **15 restantes se dejaron abiertas** porque no se pudieron confirmar (hosts sin historial previo): `10.201.4.35`, `10.201.4.64`, `10.69.11.153`/`.74` (135/tcp, críticas), `10.69.14.177`, `192.168.61.2` y `192.168.61.250` (Apple AirTunes, 6 puertos). Revisar a mano. Las copias en el backend de Tomás no se tocaron; las 316 críticas pudieron generar un push de ntfy en lote.
- [ ] Verificar tras el escaneo de las 16:02 que salen ~0 alertas `NEW open port`.

## 2026-09-18 (tarde) — revisión de las 15 alertas abiertas
- [x] Resueltas como ruido (mismos puertos vistos en escaneos anteriores): `10.201.4.35` 80/443 tcp, `10.201.4.64` 22/tcp y 161/udp, `10.69.14.177` 62078/tcp, `192.168.61.2` 123/udp.
- [ ] **Pendientes de confirmar con IT/equipo:** `192.168.61.250` (Hikvision, 6 puertos de cámara IP, nueva hoy en la VLAN de impresoras); `10.69.11.153` (Dell) y `10.69.11.74` (Intel), Windows 11 con 135/tcp; `10.201.4.35` 161/udp (primera vez que aparece SNMP ahí; revisar comunidad SNMP en el escaneo profundo del domingo). Solo las 6 de la cámara siguen visibles en el dashboard; las otras 3 salieron del snapshot por el tope de 500 y solo existen en `alerts.jsonl`.
- [x] **Incidente menor:** las resoluciones hechas a las 13:39 se perdieron del snapshot (`alert_status_log.jsonl` las conserva) — alguien reescribió `alerts.json` con una copia anterior. Se reaplicaron (491 resueltas). Causa confirmada por la otra sesión: varios scripts de archivado de un solo uso (ruido de AIDE, duplicados de segmentación VLAN, alertas de traffic_capture, dedup de vulnerabilidades) reconstruían `alerts.json` desde `alerts.jsonl`, que no guarda los cambios de estado, y dejaban todo en `open`; dos de esas corridas cayeron entre las 14:20 y las 14:40. Regla: cualquier script que reconstruya el snapshot debe conservar `status`, `status_updated` y `status_note` de las alertas que sobreviven. Verificado: las 491 resoluciones siguen intactas (0 diferencias contra `alert_status_log.jsonl`).
- [x] **Causa de fondo arreglada:** el tope del snapshot era 5000 en los servicios de escaneo y 500 en el resto, y la siguiente alerta de otro detector recortaba lo que la ráfaga acababa de agregar. Ahora el valor por defecto en `soc_core.py` es 5000 para todos (los `Environment=SOC_MAX_SNAPSHOT=5000` de las unidades systemd quedaron redundantes pero inofensivos). Requiere reiniciar los servicios de larga duración (`soc-zeek-forwarder`, `soc-suricata-forwarder`, `soc-osquery-forwarder`, `soc-dhcp-fingerprint`, `soc-traffic-monitor`); las unidades `oneshot` lanzan procesos nuevos y toman el valor solas. Costo: `alerts.json` puede crecer hasta ~5,6 MB y cada alerta reescribe el archivo completo.
