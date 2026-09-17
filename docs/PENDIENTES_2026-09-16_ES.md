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
