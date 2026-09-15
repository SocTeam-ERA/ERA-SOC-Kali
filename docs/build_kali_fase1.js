const fs=require('fs');
const {Document,Packer,Paragraph,TextRun,AlignmentType,Table,TableRow,TableCell,
  WidthType,BorderStyle,ShadingType,Header,Footer,PageNumber,VerticalAlign,TabStopType}=require('docx');

const NAVY='1F3864',ACCENT='2E5496',GREY='595959',INK='212121';
const HEADFILL='D9E2F3',ALT='F2F5FA',RULE='B4C6E7',WARN='B00020',WARNBG='FDECEA',CODEBG='0E1A12',CODEINK='D7F7E0';
const USABLE=9360;
const boxB={top:{style:BorderStyle.SINGLE,size:4,color:RULE},bottom:{style:BorderStyle.SINGLE,size:4,color:RULE},
  left:{style:BorderStyle.SINGLE,size:4,color:RULE},right:{style:BorderStyle.SINGLE,size:4,color:RULE},
  insideHorizontal:{style:BorderStyle.SINGLE,size:4,color:RULE},insideVertical:{style:BorderStyle.SINGLE,size:4,color:RULE}};
function h(t,o={}){return new Paragraph({spacing:{before:o.before??260,after:o.after??90},
  border:o.rule?{bottom:{style:BorderStyle.SINGLE,size:6,color:RULE,space:4}}:undefined,
  children:[new TextRun({text:t,bold:true,color:NAVY,size:o.size??25,font:'Calibri'})]});}
function sub(t){return new Paragraph({spacing:{before:130,after:50},children:[new TextRun({text:t,bold:true,color:ACCENT,size:21,font:'Calibri'})]});}
function p(t,o={}){const ch=Array.isArray(t)?t:[new TextRun({text:t,size:20,color:INK,font:'Calibri'})];
  return new Paragraph({spacing:{after:o.after??110,line:278},children:ch});}
function b(text,bold){const parts=[];if(bold)parts.push(new TextRun({text:bold+'  ',bold:true,size:20,color:INK,font:'Calibri'}));
  parts.push(new TextRun({text,size:20,color:INK,font:'Calibri'}));
  return new Paragraph({bullet:{level:0},spacing:{after:60,line:266},children:parts});}
function code(lines){
  const kids=lines.map(l=>new Paragraph({spacing:{after:24},children:[new TextRun({text:l,font:'Consolas',size:18,color:l.trim().startsWith('#')?'7FA98C':CODEINK})]}));
  return [new Table({columnWidths:[USABLE],width:{size:USABLE,type:WidthType.DXA},
    borders:{top:{style:BorderStyle.SINGLE,size:4,color:'0A140D'},bottom:{style:BorderStyle.SINGLE,size:4,color:'0A140D'},left:{style:BorderStyle.SINGLE,size:4,color:'0A140D'},right:{style:BorderStyle.SINGLE,size:4,color:'0A140D'}},
    rows:[new TableRow({children:[new TableCell({width:{size:USABLE,type:WidthType.DXA},shading:{type:ShadingType.CLEAR,fill:CODEBG,color:'auto'},margins:{top:120,bottom:120,left:160,right:160},children:kids})]})]}),
    new Paragraph({spacing:{after:120},children:[new TextRun({text:'',size:2})]})];
}
function warnbox(text){return new Table({columnWidths:[USABLE],width:{size:USABLE,type:WidthType.DXA},
  borders:{top:{style:BorderStyle.SINGLE,size:8,color:WARN},bottom:{style:BorderStyle.SINGLE,size:8,color:WARN},left:{style:BorderStyle.SINGLE,size:24,color:WARN},right:{style:BorderStyle.SINGLE,size:4,color:WARN}},
  rows:[new TableRow({children:[new TableCell({width:{size:USABLE,type:WidthType.DXA},shading:{type:ShadingType.CLEAR,fill:WARNBG,color:'auto'},margins:{top:120,bottom:120,left:160,right:160},
    children:[new Paragraph({children:[new TextRun({text:'⚠  ',bold:true,size:22,color:WARN,font:'Calibri'}),new TextRun({text,size:20,color:'7A1520',font:'Calibri'})]})]})]})]});}
function cell(t,{w,bold,fill,color}={}){return new TableCell({width:{size:w,type:WidthType.DXA},shading:fill?{type:ShadingType.CLEAR,fill,color:'auto'}:undefined,margins:{top:60,bottom:60,left:110,right:110},verticalAlign:VerticalAlign.CENTER,children:[new Paragraph({children:[new TextRun({text:t,bold:!!bold,color:color||INK,size:19,font:'Calibri'})]})]});}
function twocol(header,rows){const W=[3000,6360];
  const trs=[new TableRow({tableHeader:true,children:[cell(header[0],{w:W[0],bold:true,fill:NAVY,color:'FFFFFF'}),cell(header[1],{w:W[1],bold:true,fill:NAVY,color:'FFFFFF'})]})];
  rows.forEach((r,i)=>trs.push(new TableRow({children:[cell(r[0],{w:W[0],bold:true,fill:i%2?ALT:HEADFILL}),cell(r[1],{w:W[1],fill:i%2?ALT:undefined})]})));
  return new Table({columnWidths:W,width:{size:USABLE,type:WidthType.DXA},borders:boxB,rows:trs});}

const titleBar=new Paragraph({spacing:{after:0},border:{bottom:{style:BorderStyle.SINGLE,size:18,color:NAVY,space:6}},
  children:[new TextRun({text:'[ ORGANIZATION NAME ]',bold:true,size:22,color:ACCENT,font:'Calibri'}),new TextRun({text:'   ·   Information Security · era.ca',size:20,color:GREY,font:'Calibri'})]});

const body=[titleBar,
  new Paragraph({spacing:{before:220,after:40},children:[new TextRun({text:'Sentinel // SOC',bold:true,size:40,color:NAVY,font:'Calibri'})]}),
  new Paragraph({spacing:{after:40},children:[new TextRun({text:'Kali en la Fase 1: función, conexión y tus tareas',bold:true,size:25,color:ACCENT,font:'Calibri'})]}),
  new Paragraph({spacing:{after:170},children:[new TextRun({text:'Qué hace Kali, por qué se necesita, cómo se conecta con el dashboard, y qué te toca a ti',italics:true,size:20,color:GREY,font:'Calibri'})]}),

  h('1.  La foto completa — el servidor Dell R740',{rule:true}),
  p('El R740 (2× Xeon Silver 4114, 128 GB RAM, 12 TB) es de sobra para todo. La forma correcta de meter Ubuntu Server y Kali en la misma máquina no es dualboot, sino un hipervisor con dos máquinas virtuales:'),
  ...code([
    '  SERVIDOR DELL R740  (hipervisor: Proxmox VE ó KVM)',
    '  ┌───────────────────────────┐  ┌──────────────────────────┐',
    '  │  VM  UBUNTU SERVER         │  │  VM  KALI LINUX          │',
    '  │  Docker: backend + front  │  │  motor de escaneo        │',
    '  │  + dashboard + base datos │◀─│  nmap · zmap · tshark    │',
    '  │  (lo de Sixto y Tomas)    │  │  + scripts Python (tú)   │',
    '  └───────────────────────────┘  └──────────────────────────┘',
    '          └────────── red de la empresa (VLANs) ──────────┘',
  ]),
  p('Con 128 GB de RAM caben las dos VMs holgadas y sobra para la Fase 2 (Suricata, más VMs). Recomendación de hipervisor: Proxmox VE (gratis, ideal para mezclar Linux/Windows) o KVM sobre el propio Ubuntu.'),

  h('2.  ¿Por qué se necesita Kali? (su función)'),
  p('El dashboard + backend en Ubuntu es el cerebro y la cara: recibe, guarda y muestra las alertas, y maneja el login. Pero por sí mismo NO sale a la red a buscar nada. Alguien tiene que salir activamente a escanear y detectar — ese es Kali.'),
  p([new TextRun({text:'Kali = el motor de escaneo / sensor. ',bold:true,size:20,color:INK,font:'Calibri'}),
     new TextRun({text:'Corre nmap y zmap (puertos, servicios, vulnerabilidades), tshark (tráfico — más para Fase 2) y los detectores de Python (intrusos, phishing, malware). Todo eso genera las alertas.',size:20,color:INK,font:'Calibri'})]),
  p('Honestidad técnica: no es que tenga que ser Kali por magia; se necesita un host Linux con las herramientas y con alcance a la red. Kali es ese host (trae todo listo, es tu entorno de seguridad, y en Fase 2 será tu caja de pentesting). Separarlo del backend además es más seguro. En una frase: Ubuntu muestra, Kali detecta.'),

  h('3.  Cómo se conecta Kali con Python, los scripts y el dashboard',{rule:true}),
  p('Los scripts VIVEN en Kali (en /opt/sentinel-soc). El flujo completo es:'),
  ...code([
    'Kali corre un escaneo (nmap/zmap/tshark)',
    '      │',
    '      ▼   los scripts lo convierten en una alerta',
    'nmap_to_alerts.py / traffic_to_alerts.py / los detectores',
    '      │   (formato común definido en soc_core.py)',
    '      ▼',
    'se ENVIA la alerta al backend  (HTTP POST + token)',
    '      │',
    '      ▼',
    'backend la guarda en la base  →  dashboard la muestra (en vivo)',
  ]),
  p([new TextRun({text:'El punto de conexión clave: ',bold:true,size:20,color:INK,font:'Calibri'}),
     new TextRun({text:'hoy los scripts escriben la alerta a un archivo local (data/alerts.json). Para el sistema real hay que agregar un “forwarder” que haga POST al endpoint de ingesta del backend. Eso lo defines CON Sixto y Tomás: ellos te dan la URL del endpoint y el token; tú conectas la salida de los scripts. (Puedo escribirte ese forwarder en cuanto tengas el endpoint.)',size:20,color:INK,font:'Calibri'})]),

  h('4.  Aclaración sobre era.ca y la red'),
  p('era.ca es el dominio de Google Workspace de la empresa; sirve para el LOGIN del dashboard (SSO). Kali NO necesita “unirse” a ese dominio. Lo que Kali sí necesita:'),
  b('Estar en la red con red bridged e IP estática (no NATeada — ese fue el problema del Docker).'),
  b('Alcance a las VLANs que va a escanear (VLAN IDs / trunk que coordina IT).'),
  p('Tus compañeros necesitan la IP del servidor + la VLAN para llegar al dashboard; tú además necesitas que el Kali alcance lo que va a escanear.'),

  h('5.  De dónde sale cada tipo de alerta (clave para que detecte “todo eso”)',{rule:true}),
  p('Los escaneos de red son automáticos desde Kali, pero intrusos/phishing/malware necesitan que les llegue la fuente de datos. Esto lo coordinas con IT y los devs:'),
  twocol(['Tipo de alerta','De dónde salen los datos'],[
    ['Puertos abiertos / vulnerabilidades','nmap y zmap desde Kali — directo, ya lo tienes.'],
    ['Intrusos / logins del dominio','Los LOGS: auth.log de servidores Linux (SSH) y/o el Security log de Windows (Domain Controller). Hay que hacer que esos logs lleguen a Kali (syslog remoto o export). login_monitor.py los lee.'],
    ['Correos de phishing','Una carpeta/buzón donde se depositen los .eml sospechosos (reportados por usuarios o exportados del correo). phishing_detector.py los analiza.'],
    ['Malware','Archivos/hashes de una carpeta de cuarentena. malware_detector.py los revisa.'],
  ]),

  h('6.  Tus tareas paso a paso (Fase 1)'),
  b('Desplegar la VM Kali en el server (la imagen que armaste): red bridged, IP estática, acceso a las VLANs autorizadas.','1.'),
  b('Verificar la personalización (setup-kali-soc.sh ya corrió): herramientas, cuentas admin/dev, SSH.','2.'),
  b('Cargar targets.conf con el alcance autorizado (scan_scope).','3.'),
  b('Conectar la ingesta al backend: el forwarder que hace POST de cada alerta al endpoint (con Sixto y Tomás).','4.'),
  b('Programar los escaneos 24/7 con cron o systemd timers (descubrimiento + puertos seguido; vulnerabilidades en la ventana coordinada con IT).','5.'),
  b('Dejar el login_monitor.py como servicio systemd (--follow) y conectar las fuentes de log (auth.log / Security log).','6.'),
  b('Prueba de punta a punta: un escaneo real genera una alerta que llega al dashboard en vivo.','7.'),
  b('QA de seguridad (probar que la reja scan_scope rechaza lo no autorizado; auditar el hardening) y producir el reporte de línea base (Fase A).','8.'),

  h('7.  Qué es Fase 2 (no ahora)',{rule:true}),
  p('Deja el Kali listo pero enfócate en la Fase 1. La Fase 2 incluirá: Suricata (IDS) y monitoreo de tráfico continuo, pentesting activo, “ataques” mensuales controlados para medir vulnerabilidades, y la revisión de arquitectura de red y firewalls para mejorar la seguridad. Ahí es donde tshark y las herramientas ofensivas de Kali entran de lleno.'),
  warnbox('Todo escaneo, en Fase 1 y Fase 2, solo sobre lo autorizado por escrito y en la ventana coordinada con IT.'),

  h('Resumen en una frase',{before:240}),
  p('Los devs dejan corriendo el dashboard y el backend en la VM Ubuntu; tú dejas corriendo la VM Kali que los alimenta (escaneos programados + detectores + envío de alertas al backend) y auditas que todo el conjunto sea seguro. Ubuntu muestra, Kali detecta.'),
];

const doc=new Document({creator:'Sentinel SOC',title:'Sentinel SOC — Kali en la Fase 1: función, conexión y tareas',
  styles:{default:{document:{run:{font:'Calibri',size:20,color:INK}}}},
  sections:[{properties:{page:{size:{width:12240,height:15840},margin:{top:1080,bottom:1080,left:1440,right:1440}}},
    headers:{default:new Header({children:[new Paragraph({tabStops:[{type:TabStopType.RIGHT,position:USABLE}],
      border:{bottom:{style:BorderStyle.SINGLE,size:4,color:RULE,space:3}},
      children:[new TextRun({text:'Kali en la Fase 1 — función y tareas',size:15,color:GREY,font:'Calibri'}),new TextRun({text:'\tCONFIDENCIAL',size:15,bold:true,color:WARN,font:'Calibri'})]})]})},
    footers:{default:new Footer({children:[new Paragraph({tabStops:[{type:TabStopType.RIGHT,position:USABLE}],
      border:{top:{style:BorderStyle.SINGLE,size:4,color:RULE,space:3}},
      children:[new TextRun({text:'Sentinel SOC — Information Security',size:15,color:GREY,font:'Calibri'}),new TextRun({children:['\tPágina ',PageNumber.CURRENT,' de ',PageNumber.TOTAL_PAGES],size:15,color:GREY,font:'Calibri'})]})]})},
    children:body}]});
Packer.toBuffer(doc).then(x=>{fs.writeFileSync('/root/soc-project/docs/Guia_Kali_Fase1_ES.docx',x);console.log('written',x.length);});
