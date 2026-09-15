const fs=require('fs');
const {Document,Packer,Paragraph,TextRun,AlignmentType,Table,TableRow,TableCell,
  WidthType,BorderStyle,ShadingType,Header,Footer,PageNumber,VerticalAlign,TabStopType}=require('docx');

const NAVY='1F3864',ACCENT='2E5496',GREY='595959',INK='212121';
const HEADFILL='D9E2F3',ALT='F2F5FA',RULE='B4C6E7',WARN='B00020',WARNBG='FDECEA';
const USABLE=9360;
const boxB={top:{style:BorderStyle.SINGLE,size:4,color:RULE},bottom:{style:BorderStyle.SINGLE,size:4,color:RULE},
  left:{style:BorderStyle.SINGLE,size:4,color:RULE},right:{style:BorderStyle.SINGLE,size:4,color:RULE},
  insideHorizontal:{style:BorderStyle.SINGLE,size:4,color:RULE},insideVertical:{style:BorderStyle.SINGLE,size:4,color:RULE}};

function h(t,o={}){return new Paragraph({spacing:{before:o.before??260,after:o.after??90},
  border:o.rule?{bottom:{style:BorderStyle.SINGLE,size:6,color:RULE,space:4}}:undefined,
  children:[new TextRun({text:t,bold:true,color:NAVY,size:o.size??24,font:'Calibri'})]});}
function p(t){return new Paragraph({spacing:{after:110,line:276},children:[new TextRun({text:t,size:20,color:INK,font:'Calibri'})]});}
function cell(text,{w,bold,fill,color,align,size,font}={}){return new TableCell({width:{size:w,type:WidthType.DXA},
  shading:fill?{type:ShadingType.CLEAR,fill,color:'auto'}:undefined,margins:{top:60,bottom:60,left:110,right:110},
  verticalAlign:VerticalAlign.CENTER,
  children:[new Paragraph({alignment:align,children:[new TextRun({text,bold:!!bold,color:color||INK,size:size||19,font:font||'Calibri'})]})]});}
const W=[620,6740,2000];
function checklist(rows){
  const trs=[new TableRow({tableHeader:true,children:[
    cell('✓',{w:W[0],bold:true,fill:NAVY,color:'FFFFFF',align:AlignmentType.CENTER}),
    cell('Tarea',{w:W[1],bold:true,fill:NAVY,color:'FFFFFF'}),
    cell('Responsable',{w:W[2],bold:true,fill:NAVY,color:'FFFFFF'})]})];
  rows.forEach((r,i)=>trs.push(new TableRow({children:[
    cell('□',{w:W[0],align:AlignmentType.CENTER,size:24,fill:i%2?ALT:undefined}),
    cell(r[0],{w:W[1],fill:i%2?ALT:undefined}),
    cell(r[1],{w:W[2],fill:i%2?ALT:undefined,color:r[1].includes('Tú')?'1F3864':INK,bold:r[1].includes('Tú')})]})));
  return new Table({columnWidths:W,width:{size:USABLE,type:WidthType.DXA},borders:boxB,rows:trs});
}
function warnbox(text){return new Table({columnWidths:[USABLE],width:{size:USABLE,type:WidthType.DXA},
  borders:{top:{style:BorderStyle.SINGLE,size:8,color:WARN},bottom:{style:BorderStyle.SINGLE,size:8,color:WARN},
    left:{style:BorderStyle.SINGLE,size:24,color:WARN},right:{style:BorderStyle.SINGLE,size:4,color:WARN}},
  rows:[new TableRow({children:[new TableCell({width:{size:USABLE,type:WidthType.DXA},
    shading:{type:ShadingType.CLEAR,fill:WARNBG,color:'auto'},margins:{top:120,bottom:120,left:160,right:160},
    children:[new Paragraph({children:[new TextRun({text:'⚠  ',bold:true,size:22,color:WARN,font:'Calibri'}),
      new TextRun({text,size:20,color:'7A1520',font:'Calibri'})]})]})]})]});}
const sp=()=>new Paragraph({spacing:{after:70},children:[new TextRun({text:'',size:2})]});

const titleBar=new Paragraph({spacing:{after:0},border:{bottom:{style:BorderStyle.SINGLE,size:18,color:NAVY,space:6}},
  children:[new TextRun({text:'[ ORGANIZATION NAME ]',bold:true,size:22,color:ACCENT,font:'Calibri'}),
    new TextRun({text:'   ·   Information Security',size:20,color:GREY,font:'Calibri'})]});

const body=[titleBar,
  new Paragraph({spacing:{before:220,after:40},children:[new TextRun({text:'Sentinel // SOC',bold:true,size:40,color:NAVY,font:'Calibri'})]}),
  new Paragraph({spacing:{after:40},children:[new TextRun({text:'Checklist de despliegue 24/7 — Tareas de Seguridad',bold:true,size:26,color:ACCENT,font:'Calibri'})]}),
  new Paragraph({spacing:{after:160},children:[new TextRun({text:'Lo que te toca a ti (Arturo) para que el dashboard funcione con escaneos continuos en el servidor físico',italics:true,size:20,color:GREY,font:'Calibri'})]}),

  p('Flujo objetivo:  KALI escanea  →  genera alertas  →  BACKEND las guarda  →  DASHBOARD las muestra, corriendo 24/7. Los devs (Sixto, Tomás) dejan corriendo el backend y el frontend; tú dejas corriendo el Kali que los alimenta y auditas que todo el conjunto sea seguro.'),
  warnbox('Nada de escaneos en producción sin la Autorización de Alcance firmada y la ventana coordinada con IT.'),
  sp(),

  h('1.  Prerequisitos (antes de tocar el server)',{rule:true}),
  checklist([
    ['Autorización de Alcance firmada (Scope_Authorization_Form)','Tú + IT'],
    ['Definir los rangos/subredes/VLANs autorizados (scan_scope) y pasarlos a los devs','Tú'],
    ['Curar IOCs: ioc_hashes.txt, ioc_ips.txt, bad_domains.txt','Tú'],
    ['Definir el criterio de severidad (critical / medium / normal)','Tú'],
    ['Tener lista la imagen de Kali (creada desde la laptop)','Tú'],
  ]),

  h('2.  Red — lo que hace que funcione 24/7 (y evita el problema de Docker)'),
  checklist([
    ['VM Kali con red BRIDGED (External vSwitch) e IP real — no NATeada','Tú + IT'],
    ['La VM Kali alcanza las VLANs a escanear (VLAN IDs / puerto trunk)','IT'],
    ['IP estática para el Kali (para que backend y equipo lo encuentren)','Tú'],
  ]),

  h('3.  Desplegar el Kali en el servidor'),
  checklist([
    ['Importar la imagen como VM en el hipervisor','Tú + IT'],
    ['Primer arranque: regenerar llaves SSH y machine-id, hostname, IP','Tú'],
    ['Verificar herramientas (nmap/zmap/tshark) + cuentas admin/dev + SSH','Tú'],
    ['Cargar targets.conf con los rangos autorizados','Tú'],
  ]),

  h('4.  Automatización 24/7 (tu parte clave)',{rule:true}),
  checklist([
    ['Programar escaneos recurrentes (cron / systemd timers): descubrimiento + puertos','Tú'],
    ['Programar escaneo de vulnerabilidades en la ventana coordinada con IT','Tú + IT'],
    ['login_monitor.py como servicio systemd (--follow) para logins en vivo','Tú'],
    ['Conectar la salida de los escaneos a la ingesta del backend (endpoint + token)','Con devs'],
  ]),

  h('5.  Integración con el dashboard / backend'),
  checklist([
    ['Prueba de punta a punta: escaneo real → alerta llega al dashboard en vivo','Con devs'],
    ['Verificar que severidad, IP, host y usuario se ven bien en el tablero','Tú'],
  ]),

  h('6.  Seguridad / QA (esto solo lo piensas tú)'),
  checklist([
    ['Probar la reja scan_scope: escanear fuera de alcance → debe rechazarse','Tú'],
    ['Auditar el firewall (solo 443 desde subredes internas / VPN)','Tú'],
    ['Confirmar acceso externo SOLO por VPN + HTTPS (Caddy) + MFA en SSH','Tú'],
    ['Gestión de accesos: cuentas admin/dev, llaves SSH, quién puede qué','Tú'],
  ]),

  h('7.  Operación continua (una vez arriba)',{rule:true}),
  checklist([
    ['Correr la Fase A (línea base) y producir el reporte de alcance','Tú'],
    ['Monitorear alertas a diario con el equipo','Tú + equipo'],
    ['Mantener los IOCs actualizados (threat intel)','Tú'],
    ['Vigilar la retención de la base (que no se llene) y los backups','Con devs'],
    ['Re-escaneos periódicos tras cada remediación','Tú'],
  ]),

  h('Criterio de "listo"',{before:280}),
  p('El despliegue está completo cuando: un escaneo programado corre solo en el Kali, sus alertas llegan al backend y se ven en el dashboard con la severidad correcta, la reja scan_scope rechaza lo no autorizado, y el acceso al sistema es solo por VPN con HTTPS. A partir de ahí, la operación es monitorear y mantener.'),
];

const doc=new Document({creator:'Sentinel SOC',title:'Sentinel SOC — Checklist de despliegue 24/7 (Seguridad)',
  styles:{default:{document:{run:{font:'Calibri',size:20,color:INK}}}},
  sections:[{properties:{page:{size:{width:12240,height:15840},margin:{top:1080,bottom:1080,left:1440,right:1440}}},
    headers:{default:new Header({children:[new Paragraph({tabStops:[{type:TabStopType.RIGHT,position:USABLE}],
      border:{bottom:{style:BorderStyle.SINGLE,size:4,color:RULE,space:3}},
      children:[new TextRun({text:'Checklist de despliegue 24/7 — Seguridad',size:15,color:GREY,font:'Calibri'}),
        new TextRun({text:'\tCONFIDENCIAL',size:15,bold:true,color:WARN,font:'Calibri'})]})]})},
    footers:{default:new Footer({children:[new Paragraph({tabStops:[{type:TabStopType.RIGHT,position:USABLE}],
      border:{top:{style:BorderStyle.SINGLE,size:4,color:RULE,space:3}},
      children:[new TextRun({text:'Sentinel SOC — Information Security',size:15,color:GREY,font:'Calibri'}),
        new TextRun({children:['\tPágina ',PageNumber.CURRENT,' de ',PageNumber.TOTAL_PAGES],size:15,color:GREY,font:'Calibri'})]})]})},
    children:body}]});
Packer.toBuffer(doc).then(b=>{fs.writeFileSync('/root/soc-project/docs/Checklist_Despliegue_24-7_ES.docx',b);console.log('written',b.length);});
