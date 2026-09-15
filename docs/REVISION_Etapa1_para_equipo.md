# Revisión del Informe de Estado — Etapa 1
**De:** Arturo (Seguridad / auditoría)  ·  **Para:** Sixto, Tomás (dev) y el encargado del proyecto
**Fecha:** 2026-08-27  ·  **Ref:** `INFORME_ESTADO_ETAPA1.md`

---

## Veredicto general
El plan es **sólido, realista y bien secuenciado**. El núcleo (backend con ingreso idempotente de alertas, base unificada, feed en vivo, roles y reja `scan_scope`; dashboard adaptado al contrato real) está bien construido. El mayor riesgo **no es técnico sino de secuencia**: que un bloqueante de *producción* (el login de Google) retrase el trabajo de *seguridad* que ya se puede empezar. Con un reordenamiento menor, arrancamos la auditoría sin esperar a nadie.

## Lo que está especialmente bien
- **La filosofía de auditoría (secc. 5)** — medir desde un puerto normal y pedir accesos *después* según lo encontrado — es la forma correcta de auditar segmentación. El mapa de alcance como primer hallazgo es el entregable de más valor.
- **El endurecimiento (secc. 4)** — VPN-only (WireGuard), HTTPS, MFA en SSH, firewall a subredes internas — está a la altura de que el servidor es un blanco valioso.
- **El "host network mode" para el motor de escaneo** es un catch fino: en red de Docker no vería la red real. Bien anotado.

## Ajustes de prioridad y lo que agregaría
1. **Desacoplar el SSO de Google del arranque de la auditoría.** La Fase A corre con login de desarrollo, en local, con el servidor ya en red. El OAuth (depende de terceros) **no debe estar en la ruta crítica** del primer escaneo.
2. **El motor de reportes (PDF/CSV) es el entregable de la Etapa 1, no un extra.** El reporte de alcance de la Fase A *es* "el reporte de qué mejorar". Debe estar listo cuando salga la línea base.
3. **Adelantar la política de retención si entra `tshark`.** La captura continua genera volumen enorme; la retención tiene que estar *antes*, no después.
4. **Faltan (chicos pero importantes):**
   - **NTP / sincronización de hora** en el servidor — sin timestamps confiables, la correlación y lo forense pierden valor.
   - **Coordinar ventana con IT antes del escaneo de vulnerabilidades** — los scripts NSE intrusivos pueden tumbar equipos frágiles (impresoras, OT). No correrlos en horario productivo.
   - **Tratar la base como dato sensible** — contiene IPs, hostnames y usuarios internos (el mapa de la red). Cuidar backups y accesos.

## zmap / tshark (punto 3.1) — ya resuelto
El diagnóstico y arreglo están en `CHANGELOG_2026-08-27_ES.md`: **zmap** bloquea RFC1918 por su blocklist por defecto (fix: blocklist propio que deja privadas escaneables); **tshark** lo rechazaba la reja porque su objetivo es una **interfaz**, no una IP (fix: módulo aparte con reja por interfaz). Aplica igual si lo integran en el motor del backend.
- **zmap = Etapa 1** (sirve para el barrido de alcance cruzado, Fase A paso 4). Cerrarlo ahora.
- **tshark = Etapa 2** (los detectores de tráfico continuo viven en la secc. 5.3). Dejarlo listo, sin urgencia.

## Orden sugerido de lo inmediato
- **P0 (desbloquea la auditoría):** servidor en la red + `scan_scope` cargado + motor de escaneo en modo red del host. Autorización por escrito del alcance.
- **P0 (paralelo, dev):** cerrar **zmap**; avanzar el **motor de reportes**.
- **P1:** login con Google + endpoint de desactivación de usuarios (producción, no bloquean la Fase A).
- **P1:** Caddy + HTTPS, política de retención, NTP.
- **P2 / Etapa 2:** tshark continuo, IDS, WiFi, SNMP de switches, matriz de segmentación.

**En una línea:** buen plan; empecemos la línea base con lo que ya funciona (nmap + dev login en local) y no dejemos que Google frene el trabajo de seguridad.
