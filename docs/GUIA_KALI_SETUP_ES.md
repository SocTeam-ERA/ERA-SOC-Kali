# Guía — Personalizar Kali como appliance de escaneo y crear la imagen del servidor
**Proyecto:** Sentinel // SOC · **Para:** Arturo (seguridad) · **Fecha:** 2026-08-28

Esta guía te lleva de tu **laptop con Kali bare-metal** hasta una **imagen limpia y reproducible** para instalar en el servidor. Incluye la explicación del problema que tuvieron hoy con Docker y la red, cómo dejar el Kali profesional (endurecido), y cómo convertirlo en imagen para el hipervisor.

---

## 0. Aclaración de arquitectura (importante antes de empezar)

El servidor **no** va a ser multi-arranque (dual-boot) con Ubuntu + Kali + Windows a la vez. Un servidor 24/7 corre **un hipervisor** y encima varias **máquinas virtuales (VMs)**. La arquitectura correcta es:

```
        SERVIDOR FÍSICO (Dell R730/R740)
   ┌──────────────────────────────────────────────┐
   │  HIPERVISOR  (Hyper-V ó Proxmox/KVM)          │
   │  ┌────────────┐ ┌────────────┐ ┌───────────┐  │
   │  │ Ubuntu Srv │ │   KALI     │ │ Windows   │  │
   │  │ SOC backend│ │  (escaneo) │ │ Server    │  │
   │  │ + dashboard│ │  ← tu img  │ │ (permisos)│  │
   │  │ (Docker,   │ │            │ │  opcional │  │
   │  │  debian-   │ │            │ │           │  │
   │  │  slim)     │ │            │ │  Parrot   │  │
   │  └────────────┘ └────────────┘ └── futuro ─┘  │
   │        todas conectadas al vSwitch            │
   └──────────────────────────────────────────────┘
                         │
                 red real de la empresa
```

- **Ubuntu Server** = una VM que corre el backend y el dashboard (los contenedores Docker basados en `debian-slim` que menciona Tomás viven **dentro** de esa VM).
- **Kali** = otra VM, tu motor de escaneo. **Esta es la imagen que vas a crear.**
- **Windows Server / Parrot** = VMs adicionales cuando las necesiten.

**Sobre el hipervisor:** Hyper-V es un rol de **Windows Server** (si el host es Windows, ahí van todas las VMs). Si el host va a ser Linux, el equivalente es **KVM/Proxmox** (Hyper-V no existe en Linux). Pregúntale a IT **qué hipervisor** van a poner, porque define el **formato de la imagen**:
- Hyper-V → **VHDX**
- KVM/Proxmox → **qcow2**

> Recomendación: si van a mezclar Windows + Linux, **Proxmox VE** es el más cómodo y es gratis; si la empresa ya es 100% Microsoft, **Hyper-V sobre Windows Server**. Ambos caminos están cubiertos abajo.

---

## 1. El problema del Docker y la red (por qué Kali va como VM *bridged*)

Hoy los escaneos "se quedaban dentro del Docker con la IP". Esto es esperado y tiene explicación:

Un contenedor Docker por defecto está en una **red bridge NATeada**: recibe una IP privada tipo `172.17.0.x` y todo su tráfico sale **enmascarado** detrás de la IP del host. Para escanear eso es un problema doble:
1. **La IP de origen es la del Docker**, no la real → los logs y la atribución quedan mal.
2. **No puede actuar como host real en la red**: no ve la capa 2 (ARP), no descubre vecinos, y no puede probar de verdad si desde su VLAN alcanza otras — que es **justo lo que necesitas medir** (segmentación).

**La regla:** el scanner necesita una **IP real en la red, a nivel capa 2**. Por eso Kali va como **VM con red *bridged***, no como contenedor NATeado.

**Cómo configurarlo según el hipervisor:**
- **Hyper-V:** crea un **External Virtual Switch** (ligado a la NIC física) y conecta la VM Kali ahí. NO uses "Internal" ni "NAT". En la config del adaptador de la VM, habilita **MAC address spoofing** (necesario para varias técnicas de escaneo/L2). Para probar varias VLANs, configura el **VLAN ID** en el vNIC, o pide a IT un **puerto trunk** al switch virtual.
- **Proxmox/KVM:** usa un **Linux bridge** (`vmbr0`) sobre la NIC física; para varias VLANs, bridge **VLAN-aware** o trunk.

**Si en algún momento corren un escaneo dentro de un contenedor** (no recomendado para la auditoría), la solución mínima es `docker run --network host ...` para que el contenedor comparta la pila de red del host. Pero para la Etapa 1, **usa la VM Kali con bridged** — es lo correcto.

---

## 2. Personalizar el Kali de la laptop (con script reproducible)

**Filosofía profesional:** no personalices a mano haciendo clic. Deja la personalización en un **script** que corres en la laptop hoy y **vuelves a correr** en la VM del servidor → los dos quedan idénticos. Eso es "infraestructura como código" y es lo que hace la imagen confiable y repetible.

**Pasos en la laptop:**

```bash
# 1. Trae el proyecto (descomprime el zip o clónalo)
cd ~/Downloads && unzip sentinel-soc.zip     # o git clone <repo>
cd soc-project/kali

# 2. Corre el script de provisión
chmod +x setup-kali-soc.sh
sudo ./setup-kali-soc.sh
```

El script (`setup-kali-soc.sh`) es **idempotente** (lo puedes correr varias veces) y hace:
- `apt update && full-upgrade` del sistema.
- Instala el toolset: **nmap, ndiff, zmap, masscan, netdiscover, arp-scan, tshark, tcpdump, whatweb, dnsutils, ncat, jq, git, python3**.
- Configura **tshark para captura sin root** (te agrega al grupo `wireshark` y le da capacidades a `dumpcap`).
- Copia el proyecto a **`/opt/sentinel-soc`** y da permisos.
- Deja lista la config de **zmap** con el blocklist interno (recuerda: el blocklist por defecto bloquea las redes privadas).
- Habilita **sincronización de hora** (clave para que los timestamps del SOC sean confiables).
- Al final imprime un **reporte de verificación** con las versiones instaladas.

Para la VM del servidor (headless, sin escritorio) más adelante usarás:
```bash
sudo ./setup-kali-soc.sh --headless    # además quita el entorno gráfico
```

**Verifica** que todo quedó:
```bash
nmap --version; zmap --version; tshark --version
```

---

## 3. Endurecer el Kali como appliance (no es un desktop)

En el servidor, este Kali es un **appliance de escaneo**, un blanco valioso. Endurécelo:

**Usuario y acceso:**
```bash
# Usa un usuario no-root con sudo (no trabajes como root)
# Deshabilita el login de root por SSH y fuerza llaves:
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
# Copia tu llave pública antes de apagar el password:  ssh-copy-id user@kali
```

**Modelo de cuentas (admin / dev / por persona) — least privilege.** El `setup-kali-soc.sh` crea las cuentas del equipo según lo que pongas en `kali/team-users.conf`, con el formato `usuario:rol`:

- **`admin`** → sudo completo. Es la cuenta "donde se maneja todo": administra la máquina y corre los escaneos privilegiados (nmap SYN, zmap, captura con tshark). Ej.: una cuenta `socadmin` y tú (`arturo:admin`).
- **`dev`** → **sin sudo, sin root** (por seguridad). Para Sixto y Tomás: pueden entrar, editar el proyecto (via el grupo compartido `soc`), correr el dashboard, hacer connect-scans y pruebas de conectividad — pero **no** pueden tocar el sistema ni correr escaneos privilegiados. Ese es el usuario dev que pediste.

Ejemplo de `team-users.conf`:
```
socadmin:admin      # cuenta maestra de administración
arturo:admin        # líder de seguridad
sixto:dev           # developer — sin root
tomas:dev           # developer — sin root
```

Cada persona **genera su llave SSH en su propia máquina** (`ssh-keygen -t ed25519`) y te pasa el `.pub`; lo pones en `kali/team_keys/<usuario>.pub` y el script se la instala (login por llave). Si no hay llave, el script les pone una **contraseña temporal aleatoria** que **deben cambiar en el primer login** (se muestra en consola al correr el script — dásela a cada quien en privado). El proyecto queda en el grupo `soc` con permisos de grupo, así los dev editan el código sin ser root.

> Nota de seguridad sobre el rol dev: como scanear necesita root, un `dev` no puede correr escaneos SYN/zmap/tshark — y eso es intencional. Sí puede correr `port_scanner.py` (usa connect, no requiere root), los detectores sobre archivos, el dashboard y pruebas de conectividad (`ping`, `nc`, `curl`).

**Firewall (ufw)** — el scanner necesita **salida libre** (para escanear) pero **entrada restringida**:
```bash
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from <SUBRED_ADMIN> to any port 22 proto tcp   # SSH solo desde administración
sudo ufw enable
```

**Otros:**
- **Hora sincronizada:** ya la habilitó el script (`timedatectl`), verifícala.
- **Actualizaciones:** Kali es *rolling*; actualiza manual y con cuidado (`apt update && apt full-upgrade`) en ventana controlada, no automático.
- **Registro/auditoría:** deja `journald`/`auth.log` activos; el propio `login_monitor.py` puede vigilar el `auth.log` de este Kali.
- **Sin servicios de más:** en modo `--headless` no hay escritorio; revisa `systemctl list-unit-files --state=enabled` y apaga lo que no uses.

---

## 4. Crear la imagen para el servidor — dos caminos

### Camino A — Reconstruir en una VM limpia  ✅ recomendado
Como tu Kali está **bare-metal** en la laptop, clonar ese disco arrastra drivers de la laptop, tamaño completo y basura. Mucho más limpio:

1. En el hipervisor del servidor, crea una **VM Kali nueva** desde el ISO oficial de Kali (instalación mínima).
2. Copia el proyecto y **corre el mismo `setup-kali-soc.sh --headless`**.
3. Endurécela (sección 3) y **generalízala** (sección 5).
4. Esa VM **ya es** tu imagen base; para replicarla, clónala/expórtala como plantilla.

Ventajas: imagen limpia, del tamaño justo, portable, y **versionada** (el script es tu "receta"). Si mañana cambias algo, editas el script y reconstruyes — no re-clonas discos.

### Camino B — Clonar el bare-metal de la laptop
Si de todos modos quieren partir del disco de la laptop:

1. Arranca la laptop con **Clonezilla** (USB live) y captura el disco a un archivo **raw/img**, o con `dd`:
   ```bash
   sudo dd if=/dev/nvme0n1 of=/mnt/ext/kali.raw bs=64M status=progress
   ```
2. Convierte al formato del hipervisor:
   ```bash
   # Hyper-V:
   qemu-img convert -p -O vhdx -o subformat=dynamic kali.raw kali-soc.vhdx
   # KVM/Proxmox:
   qemu-img convert -p -O qcow2 kali.raw kali-soc.qcow2
   ```
3. **Antes de capturar**, corre `generalize-kali.sh` en la laptop (sección 5) para no clonar identidad ni IP fija.

> Caveat del Camino B: el disco trae drivers/firmware de la laptop y nombres de interfaz distintos a la VM; puede requerir ajustes de red en el primer arranque. Por eso el Camino A es más limpio.

---

## 5. "Generalizar" antes de capturar (golden image)

Igual que el *sysprep* de Windows: quitar la identidad única para que cada VM clonada sea distinta y limpia. Corre **al final**, justo antes de apagar y capturar:

```bash
cd /opt/sentinel-soc/kali    # o donde tengas el proyecto
sudo ./generalize-kali.sh
# opcional, para que la imagen comprima mucho mejor:
sudo ZEROFILL=1 ./generalize-kali.sh
sudo poweroff
```

`generalize-kali.sh` limpia: cachés y logs, historial de shell, **llaves de host SSH** (si no, todas las clonas comparten la misma llave = problema de seguridad), **machine-id**, resultados/demo del SOC, y recuerda dejar la red en **DHCP** (no una IP fija horneada en la imagen).

---

## 6. Importar la imagen en el servidor

**Hyper-V:**
1. Copia el `kali-soc.vhdx` al host.
2. Crea una VM **Generación 2**; en Firmware, **desactiva Secure Boot** (o elige la plantilla "Microsoft UEFI/Linux").
3. Adjunta el VHDX como disco existente. Disco **dinámico**, 2–4 vCPU, 4–8 GB RAM.
4. Red: conéctala al **External Virtual Switch** (bridged) — sección 1. MAC spoofing on.

**Proxmox/KVM:**
1. Sube el `kali-soc.qcow2` y crea una VM; importa el disco (`qm importdisk`).
2. Red en el bridge (`vmbr0`), VLAN-aware si aplica.

---

## 7. Primer arranque en el servidor (post-deploy)

Como generalizaste, hay que darle identidad nueva:
```bash
# Regenerar llaves de host SSH
sudo dpkg-reconfigure openssh-server        # o: sudo ssh-keygen -A
# Regenerar machine-id
sudo systemd-machine-id-setup
# Hostname y red
sudo hostnamectl set-hostname kali-soc-01
# IP: DHCP para probar, luego estática en la VLAN de escaneo/administración
```
Luego **verifica y prueba** (contra un objetivo autorizado):
```bash
nmap --version && zmap --version && tshark --version
cd /opt/sentinel-soc/kali
sudo ./1_host_discovery.sh 10.10.<lab>.0/24
```

---

## 8. Checklist

- [ ] Confirmar con IT el **hipervisor** (Hyper-V → VHDX / KVM-Proxmox → qcow2).
- [ ] Correr `setup-kali-soc.sh` en la laptop y verificar versiones.
- [ ] Endurecer (SSH con llaves, ufw, hora sincronizada).
- [ ] Elegir camino de imagen (A recomendado: rebuild en VM).
- [ ] `generalize-kali.sh` antes de capturar.
- [ ] Importar imagen + **red bridged / External switch** + MAC spoofing.
- [ ] Primer arranque: regenerar llaves SSH y machine-id, hostname, IP.
- [ ] Prueba de escaneo autorizada desde la VM (con IP real → ya no NATeado como Docker).

---

## 9. Recordatorio

Nada de escaneos hasta tener la **autorización de alcance firmada** (`Scope_Authorization_Form_EN.docx`). Este Kali es defensivo/auditoría interna; se usa solo sobre lo autorizado por escrito.

> Consejo final: guarda `setup-kali-soc.sh` en el repo del proyecto. Ese script **es** tu documentación de personalización — cualquiera puede reconstruir el Kali idéntico, y si en el futuro agregan una herramienta, se agrega ahí y se vuelve a generar la imagen. Eso es dejarlo "bien profesional".
