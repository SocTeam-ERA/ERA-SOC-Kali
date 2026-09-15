const fs=require('fs');
const {Document,Packer,Paragraph,TextRun,AlignmentType,Table,TableRow,TableCell,
  WidthType,BorderStyle,ShadingType,Header,Footer,PageNumber,VerticalAlign,TabStopType}=require('docx');

const NAVY='1F3864',ACCENT='2E5496',GREY='595959',INK='212121';
const HEADFILL='D9E2F3',RULE='B4C6E7',CODEBG='0E1A12',CODEINK='D7F7E0',WARNBG='FDECEA',WARN='B00020';
const USABLE=9360;

function h(t,o={}){return new Paragraph({spacing:{before:o.before??260,after:o.after??100},
  border:o.rule?{bottom:{style:BorderStyle.SINGLE,size:6,color:RULE,space:4}}:undefined,
  children:[new TextRun({text:t,bold:true,color:NAVY,size:o.size??26,font:'Calibri'})]});}
function p(t,o={}){const ch=Array.isArray(t)?t:[new TextRun({text:t,size:20,color:INK,font:'Calibri'})];
  return new Paragraph({spacing:{after:o.after??110,line:276},children:ch});}
function bullet(t){return new Paragraph({bullet:{level:0},spacing:{after:60,line:264},
  children:[new TextRun({text:t,size:20,color:INK,font:'Calibri'})]});}
// dark code block (one cell, monospace lines)
function code(lines,note){
  const kids=lines.map(l=>new Paragraph({spacing:{after:30},
    children:[new TextRun({text:l,font:'Consolas',size:18,color:l.trim().startsWith('#')?'7FA98C':CODEINK})]}));
  const t=new Table({columnWidths:[USABLE],width:{size:USABLE,type:WidthType.DXA},
    borders:{top:{style:BorderStyle.SINGLE,size:4,color:'0A140D'},bottom:{style:BorderStyle.SINGLE,size:4,color:'0A140D'},
      left:{style:BorderStyle.SINGLE,size:4,color:'0A140D'},right:{style:BorderStyle.SINGLE,size:4,color:'0A140D'}},
    rows:[new TableRow({children:[new TableCell({width:{size:USABLE,type:WidthType.DXA},
      shading:{type:ShadingType.CLEAR,fill:CODEBG,color:'auto'},margins:{top:120,bottom:120,left:160,right:160},
      children:kids})]})]});
  return note?[t,new Paragraph({spacing:{before:40,after:120},children:[new TextRun({text:note,italics:true,size:18,color:GREY,font:'Calibri'})]})]:[t,new Paragraph({spacing:{after:120},children:[new TextRun({text:'',size:2})]})];
}
function warnbox(text){
  return new Table({columnWidths:[USABLE],width:{size:USABLE,type:WidthType.DXA},
    borders:{top:{style:BorderStyle.SINGLE,size:8,color:WARN},bottom:{style:BorderStyle.SINGLE,size:8,color:WARN},
      left:{style:BorderStyle.SINGLE,size:24,color:WARN},right:{style:BorderStyle.SINGLE,size:4,color:WARN}},
    rows:[new TableRow({children:[new TableCell({width:{size:USABLE,type:WidthType.DXA},
      shading:{type:ShadingType.CLEAR,fill:WARNBG,color:'auto'},margins:{top:120,bottom:120,left:160,right:160},
      children:[new Paragraph({children:[new TextRun({text:'⚠  ',bold:true,size:22,color:WARN,font:'Calibri'}),
        new TextRun({text:text,size:20,color:'7A1520',font:'Calibri'})]})]})]})]});
}

const titleBar=new Paragraph({spacing:{after:0},
  border:{bottom:{style:BorderStyle.SINGLE,size:18,color:NAVY,space:6}},
  children:[new TextRun({text:'[ ORGANIZATION NAME ]',bold:true,size:22,color:ACCENT,font:'Calibri'}),
    new TextRun({text:'   ·   Information Security',size:20,color:GREY,font:'Calibri'})]});

const body=[
  titleBar,
  new Paragraph({spacing:{before:220,after:40},children:[new TextRun({text:'Sentinel // SOC',bold:true,size:40,color:NAVY,font:'Calibri'})]}),
  new Paragraph({spacing:{after:40},children:[new TextRun({text:'Guía de pruebas en la red — Día de pruebas',bold:true,size:26,color:ACCENT,font:'Calibri'})]}),
  new Paragraph({spacing:{after:180},children:[new TextRun({text:'Ejemplos de nmap, zmap, tshark y la suite del proyecto para validar el escaneo y la conectividad',italics:true,size:20,color:GREY,font:'Calibri'})]}),

  warnbox('Antes de escanear la red de producción de la empresa: confirma la autorización / el alcance con IT (idealmente la autorización firmada). Empieza por lo de bajo impacto; deja los escaneos de vulnerabilidades para una ventana coordinada. Cambia las IPs de ejemplo (10.10.x.x) por los rangos que te autoricen.'),
  new Paragraph({spacing:{after:80},children:[new TextRun({text:'',size:2})]}),

  h('0.  Preparación',{rule:true}),
  p('Verifica que la laptop tiene red y hora correcta:'),
  ...code(['ping -c 2 8.8.8.8         # ¿hay red?','timedatectl                # ¿hora sincronizada?']),

  h('1.  Reconocimiento del puesto (¿dónde estoy?)'),
  p('Anota esto: define desde qué punto de la red estás midiendo.'),
  ...code(['ip a                       # tus interfaces e IP','ip r                       # gateway y rutas','cat /etc/resolv.conf       # tus DNS'],
    'Guarda la salida — es el punto de partida del reporte de alcance.'),

  h('2.  Pruebas con nmap',{rule:true}),
  p('Descubrimiento de hosts vivos en tu subred (ping sweep, bajo impacto):'),
  ...code(['sudo nmap -sn 10.10.10.0/24']),
  p('Puertos comunes de un host + servicios y versión:'),
  ...code(['sudo nmap -sS -sV --top-ports 100 10.10.10.5']),
  p('Escaneo completo (todos los puertos) + detección de SO:'),
  ...code(['sudo nmap -sS -O -p- 10.10.10.5']),
  p('Escaneo de vulnerabilidades (más ruidoso — coordina ventana con IT):'),
  ...code(['sudo nmap -sV --script vuln 10.10.10.5']),
  p('Guardar resultados en archivo (para el reporte / dashboard):'),
  ...code(['sudo nmap -sS -sV -oA ~/nmap_test 10.10.10.0/24'],
    'Genera nmap_test.nmap / .xml / .gnmap. El .xml lo puedes importar al dashboard.'),

  h('3.  Pruebas con zmap (descubrimiento interno rápido)'),
  p('zmap barre rangos grandes muy rápido. Usa el blocklist del proyecto (el de fábrica bloquea las redes privadas):'),
  ...code(['sudo zmap -p 443 -b ~/soc-project/kali/zmap-blocklist.conf 10.10.0.0/16']),
  p('O más fácil, con el script del proyecto (barre varios puertos de liveness y une los hosts):'),
  ...code(['cd ~/soc-project/kali','PORTS="443 445 22" ./1b_zmap_discovery.sh 10.10.0.0/16']),

  h('4.  Pruebas con tshark (captura de tráfico)'),
  p('Lista tus interfaces:'),
  ...code(['tshark -D']),
  p('Captura rápida de 100 paquetes en tu interfaz (cambia eth0 por la tuya):'),
  ...code(['sudo tshark -i eth0 -c 100']),
  p('Captura 60 segundos a un archivo .pcap:'),
  ...code(['sudo tshark -i eth0 -a duration:60 -w ~/captura.pcap']),
  p('Captura y análisis automático con el módulo del proyecto (saca alertas del tráfico):'),
  ...code(['cd ~/soc-project/kali','sudo ./4_traffic_capture.sh -i eth0 -c 2000']),

  h('5.  Suite completa del proyecto',{rule:true}),
  p('Pon los rangos autorizados en targets.conf y corre todo el flujo (descubrimiento → puertos → vulns → reporte):'),
  ...code(['cd ~/soc-project/kali','nano targets.conf          # escribe tus subredes autorizadas','sudo ./0_run_all.sh'],
    'Genera results/REPORT_*.txt (para IT/managers) e importa los hallazgos al dashboard.'),
  p('Detectores de Python (algunos no necesitan root):'),
  ...code(['cd ~/soc-project/scripts','python3 port_scanner.py 10.10.10.0/24 --top-ports','python3 login_monitor.py --demo']),

  h('6.  Pruebas de conectividad y segmentación (lo que piden tus compañeros)'),
  p('¿Desde tu VLAN alcanzas otras subredes? Lo que responde y no debería es un hallazgo de segmentación:'),
  ...code(['ping -c 2 10.10.20.5              # ¿llego a servidores?','sudo nmap -sn 10.10.20.0/24       # ¿qué responde en servidores?','sudo nmap -sn 10.10.30.0/24       # administración — NO debería responder']),
  p('¿La laptop sale a Internet por puertos arbitrarios? (riesgo de exfiltración):'),
  ...code(['nc -zv 1.1.1.1 443','nc -zv 8.8.8.8 53','nc -zv example.com 4444          # puerto raro: ¿sale?']),

  h('7.  Ver los resultados en el dashboard'),
  p('Sirve el proyecto por HTTP y ábrelo en el navegador; leerá las alertas reales que generaron los escaneos:'),
  ...code(['cd ~/soc-project','python3 -m http.server 8000','# abrir:  http://localhost:8000/dashboard/sentinel_soc.html'],
    'El badge arriba a la izquierda debe decir "FEED · alerts.json" (datos reales).'),

  h('8.  Checklist del día',{rule:true}),
  bullet('Confirmar autorización / alcance con IT antes de escanear producción.'),
  bullet('Reconocimiento del puesto (ip a / ip r) y anotarlo.'),
  bullet('Ping sweep de la subred local (nmap -sn).'),
  bullet('Prueba de alcance cruzado a otras VLANs (¿llego a administración?).'),
  bullet('Escaneo de servicios/versiones de hosts de interés.'),
  bullet('Prueba de egress (¿salgo a Internet por puertos raros?).'),
  bullet('Captura corta con tshark para validar el módulo.'),
  bullet('Ver que las alertas aparezcan en el dashboard.'),
  bullet('Guardar los resultados (results/ y nmap_test.*) para el reporte.'),

  h('9.  Recordatorio'),
  p('Estas herramientas se usan solo sobre la infraestructura de la empresa y con autorización. Coordina los escaneos intrusivos con IT y evita horario productivo en equipos frágiles. Ante cualquier caída de un servicio, detente y avisa a IT.'),
];

const doc=new Document({creator:'Sentinel SOC',title:'Sentinel SOC — Guía de pruebas en la red',
  styles:{default:{document:{run:{font:'Calibri',size:20,color:INK}}}},
  sections:[{properties:{page:{size:{width:12240,height:15840},margin:{top:1080,bottom:1080,left:1440,right:1440}}},
    headers:{default:new Header({children:[new Paragraph({tabStops:[{type:TabStopType.RIGHT,position:USABLE}],
      border:{bottom:{style:BorderStyle.SINGLE,size:4,color:RULE,space:3}},
      children:[new TextRun({text:'Guía de pruebas en la red',size:15,color:GREY,font:'Calibri'}),
        new TextRun({text:'\tCONFIDENCIAL',size:15,bold:true,color:WARN,font:'Calibri'})]})]})},
    footers:{default:new Footer({children:[new Paragraph({tabStops:[{type:TabStopType.RIGHT,position:USABLE}],
      border:{top:{style:BorderStyle.SINGLE,size:4,color:RULE,space:3}},
      children:[new TextRun({text:'Sentinel SOC — Information Security',size:15,color:GREY,font:'Calibri'}),
        new TextRun({children:['\tPágina ',PageNumber.CURRENT,' de ',PageNumber.TOTAL_PAGES],size:15,color:GREY,font:'Calibri'})]})]})},
    children:body}]});
Packer.toBuffer(doc).then(b=>{fs.writeFileSync('/root/soc-project/docs/Guia_Pruebas_Red_ES.docx',b);console.log('written',b.length);});
