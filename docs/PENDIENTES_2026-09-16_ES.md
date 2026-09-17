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
No es de este proyecto de código, pero queda documentado: hoy se cayó varias veces la sesión SSH hacia `kali2` con paquetes TCP RST fabricados desde el propio Kali hacia el cliente. Se descartó Suricata, fail2ban, los timers propios del proyecto, memoria/OOM y CPU steal time. La hipótesis que queda en pie (sin poder confirmarse desde esta VM) es un loop de red a nivel del switch virtual de Proxmox — pendiente de escalar a quien administre esa capa si vuelve a pasar. Mientras tanto: `tcpdump` sigue capturando evidencia en `/home/adelcueto/ssh_diag/`, y `sysstat`/acceso a `journalctl -k` (grupo `adm`) ya quedaron habilitados hoy para diagnosticar mejor la próxima vez.
