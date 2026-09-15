const fs=require('fs');
const {Document,Packer,Paragraph,TextRun,AlignmentType,Table,TableRow,TableCell,
  WidthType,BorderStyle,ShadingType,Header,Footer,PageNumber,VerticalAlign,TabStopType}=require('docx');
const NAVY='1F3864',ACCENT='2E5496',GREY='595959',INK='212121';
const HEADFILL='D9E2F3',ALT='F2F5FA',RULE='B4C6E7',WARN='B00020',WARNBG='FDECEA',CODEBG='0E1A12',CODEINK='D7F7E0',GREEN='1E7A46';
const USABLE=9360;
const boxB={top:{style:BorderStyle.SINGLE,size:4,color:RULE},bottom:{style:BorderStyle.SINGLE,size:4,color:RULE},
  left:{style:BorderStyle.SINGLE,size:4,color:RULE},right:{style:BorderStyle.SINGLE,size:4,color:RULE},
  insideHorizontal:{style:BorderStyle.SINGLE,size:4,color:RULE},insideVertical:{style:BorderStyle.SINGLE,size:4,color:RULE}};
function h(t,o={}){return new Paragraph({spacing:{before:o.before??260,after:o.after??90},
  border:o.rule?{bottom:{style:BorderStyle.SINGLE,size:6,color:RULE,space:4}}:undefined,
  children:[new TextRun({text:t,bold:true,color:NAVY,size:o.size??25,font:'Calibri'})]});}
function p(t,o={}){const ch=Array.isArray(t)?t:[new TextRun({text:t,size:20,color:INK,font:'Calibri'})];
  return new Paragraph({spacing:{after:o.after??110,line:278},children:ch});}
function code(lines){const kids=lines.map(l=>new Paragraph({spacing:{after:24},children:[new TextRun({text:l,font:'Consolas',size:18,color:l.trim().startsWith('#')?'7FA98C':CODEINK})]}));
  return [new Table({columnWidths:[USABLE],width:{size:USABLE,type:WidthType.DXA},
    borders:{top:{style:BorderStyle.SINGLE,size:4,color:'0A140D'},bottom:{style:BorderStyle.SINGLE,size:4,color:'0A140D'},left:{style:BorderStyle.SINGLE,size:4,color:'0A140D'},right:{style:BorderStyle.SINGLE,size:4,color:'0A140D'}},
    rows:[new TableRow({children:[new TableCell({width:{size:USABLE,type:WidthType.DXA},shading:{type:ShadingType.CLEAR,fill:CODEBG,color:'auto'},margins:{top:120,bottom:120,left:160,right:160},children:kids})]})]}),
    new Paragraph({spacing:{after:120},children:[new TextRun({text:'',size:2})]})];}
function cell(t,{w,bold,fill,color,font}={}){return new TableCell({width:{size:w,type:WidthType.DXA},shading:fill?{type:ShadingType.CLEAR,fill,color:'auto'}:undefined,margins:{top:56,bottom:56,left:110,right:110},verticalAlign:VerticalAlign.CENTER,children:[new Paragraph({children:[new TextRun({text:t,bold:!!bold,color:color||INK,size:18,font:font||'Calibri'})]})]});}
const TW=[2400,5560,1400];
function toolTable(rows){
  const trs=[new TableRow({tableHeader:true,children:[cell('Paquete',{w:TW[0],bold:true,fill:NAVY,color:'FFFFFF'}),cell('Para qué sirve',{w:TW[1],bold:true,fill:NAVY,color:'FFFFFF'}),cell('Fase',{w:TW[2],bold:true,fill:NAVY,color:'FFFFFF'})]})];
  rows.forEach((r,i)=>trs.push(new TableRow({children:[cell(r[0],{w:TW[0],bold:true,font:'Consolas',fill:i%2?ALT:undefined,color:'1F3864'}),cell(r[1],{w:TW[1],fill:i%2?ALT:undefined}),cell(r[2],{w:TW[2],fill:i%2?ALT:undefined,bold:true,color:r[2]==='1'?GREEN:GREY})]})));
  return new Table({columnWidths:TW,width:{size:USABLE,type:WidthType.DXA},borders:boxB,rows:trs});}
function warnbox(text,fill,bar){return new Table({columnWidths:[USABLE],width:{size:USABLE,type:WidthType.DXA},
  borders:{top:{style:BorderStyle.SINGLE,size:8,color:bar},bottom:{style:BorderStyle.SINGLE,size:8,color:bar},left:{style:BorderStyle.SINGLE,size:24,color:bar},right:{style:BorderStyle.SINGLE,size:4,color:bar}},
  rows:[new TableRow({children:[new TableCell({width:{size:USABLE,type:WidthType.DXA},shading:{type:ShadingType.CLEAR,fill,color:'auto'},margins:{top:120,bottom:120,left:160,right:160},
    children:[new Paragraph({children:[new TextRun({text,size:20,color:INK,font:'Calibri'})]})]})]})]});}

const titleBar=new Paragraph({spacing:{after:0},border:{bottom:{style:BorderStyle.SINGLE,size:18,color:NAVY,space:6}},
  children:[new TextRun({text:'[ ORGANIZATION NAME ]',bold:true,size:22,color:ACCENT,font:'Calibri'}),new TextRun({text:'   ·   Information Security',size:20,color:GREY,font:'Calibri'})]});

const body=[titleBar,
  new Paragraph({spacing:{before:220,after:40},children:[new TextRun({text:'Sentinel // SOC',bold:true,size:40,color:NAVY,font:'Calibri'})]}),
  new Paragraph({spacing:{after:40},children:[new TextRun({text:'Kali del servidor — herramientas, librerías y personalización',bold:true,size:25,color:ACCENT,font:'Calibri'})]}),
  new Paragraph({spacing:{after:170},children:[new TextRun({text:'Todo lo que lleva el Kali del proyecto y cómo dejarlo listo (Fase 1)',italics:true,size:20,color:GREY,font:'Calibri'})]}),

  warnbox('Lo más importante: NO tienes que instalar nada a mano. El script setup-kali-soc.sh instala TODO esto en un comando. Esta hoja es la referencia de qué lleva y por qué.','E8F1EA','1E7A46'),
  new Paragraph({spacing:{after:80},children:[new TextRun({text:'',size:2})]}),

  h('1.  Instalación — un solo comando',{rule:true}),
  ...code(['cd /opt/sentinel-soc/kali','sudo bash setup-kali-soc.sh','# verifica al final:  nmap --version && zmap --version && tshark --version']),

  h('2.  Herramientas de escaneo y descubrimiento  (el corazón de Fase 1)'),
  toolTable([
    ['nmap','Escaneo de puertos, servicios/versiones, SO y vulnerabilidades (scripts NSE). La herramienta principal.','1'],
    ['ndiff','Compara dos escaneos de nmap (qué cambió entre uno y otro).','1'],
    ['zmap','Barrido ultra rápido de rangos grandes internos (con el blocklist del proyecto).','1'],
    ['masscan','Escáner de puertos alternativo muy veloz para rangos amplios.','1'],
    ['netdiscover','Descubrimiento de hosts por ARP (capa 2) en la red local.','1'],
    ['arp-scan','Descubrimiento/inventario por ARP; útil para ver vecinos reales.','1'],
  ]),

  h('3.  Captura y análisis de tráfico'),
  toolTable([
    ['tshark','Captura y analiza tráfico por interfaz. Base del módulo de captura. Uso ligero en Fase 1, central en Fase 2.','1 / 2'],
    ['tcpdump','Captura de paquetes por línea de comandos (respaldo de tshark).','1 / 2'],
  ]),

  h('4.  Utilidades de red, DNS y web',{rule:true}),
  toolTable([
    ['dnsutils','dig / host / nslookup — resolución y enumeración DNS.','1'],
    ['whatweb','Identifica tecnologías de un sitio/servicio web.','1'],
    ['ncat','Netcat: pruebas de conectividad y de salida (egress).','1'],
    ['net-tools / iproute2','ip, ifconfig, route, ss — ver interfaces, rutas y conexiones.','1'],
    ['curl / wget','Descargas y pruebas HTTP.','1'],
  ]),

  h('5.  Runtime, automatización y acceso'),
  toolTable([
    ['python3 / pip / venv','Corre los detectores y conversores del proyecto (login, phishing, malware, nmap→alertas).','1'],
    ['git','Traer/actualizar el código del proyecto.','1'],
    ['jq','Procesar JSON (alertas, salidas) desde la terminal.','1'],
    ['tmux','Dejar escaneos largos corriendo por SSH (desconectas y no se cortan).','1'],
    ['lsof','Ver archivos y sockets abiertos (diagnóstico).','1'],
    ['openssh-server','Para que el equipo (admin/dev) entre al Kali por SSH.','1'],
    ['ufw','Firewall del propio Kali (entrada restringida, salida libre para escanear).','1'],
    ['systemd-timesyncd','Sincroniza la hora (viene en el sistema). Clave para timestamps confiables.','1'],
  ]),

  h('6.  Librerías de Python — ¿qué hay que instalar con pip?'),
  warnbox('Nada. Los detectores usan solo la librería estándar de Python 3 (json, socket, urllib, hashlib, email, re…). NO necesitas instalar paquetes con pip. Incluso el envío de alertas al backend usa urllib (estándar), no requests. El venv queda preparado por si en el futuro agregan alguna librería.','EEF3FB','2E5496'),
  new Paragraph({spacing:{after:80},children:[new TextRun({text:'',size:2})]}),
  p([new TextRun({text:'Para Fase 2, ',bold:true,size:20,color:INK,font:'Calibri'}),
     new TextRun({text:'si quisieran scripting más avanzado, se podrían agregar (opcional): ',size:20,color:INK,font:'Calibri'}),
     new TextRun({text:'scapy',font:'Consolas',size:18,color:'1F3864'}),
     new TextRun({text:' (paquetes a bajo nivel), ',size:20,color:INK,font:'Calibri'}),
     new TextRun({text:'python-nmap',font:'Consolas',size:18,color:'1F3864'}),
     new TextRun({text:', ',size:20,color:INK,font:'Calibri'}),
     new TextRun({text:'pyshark',font:'Consolas',size:18,color:'1F3864'}),
     new TextRun({text:'. En Fase 1 no hacen falta.',size:20,color:INK,font:'Calibri'})]),

  h('7.  Componentes de integración (para que detecte intrusos y phishing)',{rule:true}),
  p('Los escaneos salen solos de Kali, pero estos dos tipos de alerta necesitan que les llegue la fuente de datos — coordínalo con IT y los devs:'),
  toolTable([
    ['rsyslog (receptor)','Para detectar logins/intrusos del dominio: que los servidores y el Domain Controller envíen sus logs (syslog) al Kali, y el login_monitor los lea.','1'],
    ['Carpeta de correos','Para phishing: un folder donde caigan los .eml sospechosos (reportados o exportados del correo) que analiza phishing_detector.','1'],
    ['Carpeta de cuarentena','Para malware: archivos/hashes que revisa malware_detector.','1'],
  ]),

  h('8.  Personalización — el orden completo'),
  p('Resumen de todo lo que le haces al Kali del servidor para dejarlo listo (cada punto ya tiene su guía):'),
  ...[
    'Desplegar la VM Kali (imagen), red BRIDGED, IP estática, acceso a las VLANs.',
    'Correr sudo bash setup-kali-soc.sh (instala todo lo de arriba + cuentas admin/dev + SSH).',
    'Cargar targets.conf con el alcance autorizado.',
    'Conectar al backend: export SOC_INGEST_URL y SOC_INGEST_TOKEN (ver CONECTAR_BACKEND_ES.md), probar con soc_core.py --test-ingest.',
    'Programar los escaneos 24/7 (cron / systemd timers) + login_monitor como servicio.',
    'Conectar las fuentes de log (rsyslog) y las carpetas de correos/cuarentena.',
    'Endurecer (ufw, SSH con llaves) y sincronizar hora.',
    'Prueba de punta a punta: un escaneo real llega al dashboard.',
  ].map((t,i)=>new Paragraph({bullet:{level:0},spacing:{after:60,line:266},children:[new TextRun({text:t,size:20,color:INK,font:'Calibri'})]})),

  h('9.  Qué NO instalar todavía (es Fase 2)',{rule:true}),
  p('Mantén el Kali del proyecto limpio y defensivo en Fase 1. Estas herramientas ofensivas/IDS entran en Fase 2, cuando haya pentesting y ataques controlados:'),
  toolTable([
    ['suricata / zeek','IDS y análisis de tráfico continuo.','2'],
    ['metasploit-framework','Explotación (pentesting activo).','2'],
    ['nikto / gobuster / dirb','Escaneo de aplicaciones web.','2'],
    ['hydra','Pruebas de fuerza bruta de credenciales (autorizado).','2'],
    ['aircrack-ng','Auditoría WiFi (requiere adaptador con modo monitor).','2'],
    ['snmp / onesixtyone','Revisión de switches/routers por SNMP.','2'],
  ]),
  warnbox('Todas estas herramientas, en Fase 2, solo se usan con autorización por escrito y ventana coordinada con IT. En Fase 1 el foco es defensivo: escanear, detectar y mapear la segmentación.','FDECEA','B00020'),
];

const doc=new Document({creator:'Sentinel SOC',title:'Sentinel SOC — Kali del servidor: herramientas y librerías',
  styles:{default:{document:{run:{font:'Calibri',size:20,color:INK}}}},
  sections:[{properties:{page:{size:{width:12240,height:15840},margin:{top:1080,bottom:1080,left:1440,right:1440}}},
    headers:{default:new Header({children:[new Paragraph({tabStops:[{type:TabStopType.RIGHT,position:USABLE}],
      border:{bottom:{style:BorderStyle.SINGLE,size:4,color:RULE,space:3}},
      children:[new TextRun({text:'Kali del servidor — herramientas y librerías',size:15,color:GREY,font:'Calibri'}),new TextRun({text:'\tCONFIDENCIAL',size:15,bold:true,color:WARN,font:'Calibri'})]})]})},
    footers:{default:new Footer({children:[new Paragraph({tabStops:[{type:TabStopType.RIGHT,position:USABLE}],
      border:{top:{style:BorderStyle.SINGLE,size:4,color:RULE,space:3}},
      children:[new TextRun({text:'Sentinel SOC — Information Security',size:15,color:GREY,font:'Calibri'}),new TextRun({children:['\tPágina ',PageNumber.CURRENT,' de ',PageNumber.TOTAL_PAGES],size:15,color:GREY,font:'Calibri'})]})]})},
    children:body}]});
Packer.toBuffer(doc).then(x=>{fs.writeFileSync('/root/soc-project/docs/Kali_Herramientas_y_Librerias_ES.docx',x);console.log('written',x.length);});
