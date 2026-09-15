const fs=require('fs');
const {Document,Packer,Paragraph,TextRun,AlignmentType,Table,TableRow,TableCell,
  WidthType,BorderStyle,ShadingType,Header,Footer,PageNumber,VerticalAlign,TabStopType}=require('docx');
const NAVY='1F3864',ACCENT='2E5496',GREY='595959',INK='212121';
const HEADFILL='D9E2F3',ALT='F2F5FA',RULE='B4C6E7',WARN='B00020',CODEBG='0E1A12',CODEINK='D7F7E0';
const USABLE=9360;
const boxB={top:{style:BorderStyle.SINGLE,size:4,color:RULE},bottom:{style:BorderStyle.SINGLE,size:4,color:RULE},
  left:{style:BorderStyle.SINGLE,size:4,color:RULE},right:{style:BorderStyle.SINGLE,size:4,color:RULE},
  insideHorizontal:{style:BorderStyle.SINGLE,size:4,color:RULE},insideVertical:{style:BorderStyle.SINGLE,size:4,color:RULE}};
function h(t,o={}){return new Paragraph({spacing:{before:o.before??260,after:o.after??90},
  border:o.rule?{bottom:{style:BorderStyle.SINGLE,size:6,color:RULE,space:4}}:undefined,
  children:[new TextRun({text:t,bold:true,color:NAVY,size:o.size??25,font:'Calibri'})]});}
function p(t,o={}){const ch=Array.isArray(t)?t:[new TextRun({text:t,size:20,color:INK,font:'Calibri'})];
  return new Paragraph({spacing:{after:o.after??110,line:278},children:ch});}
function b(t,bold){const parts=[];if(bold)parts.push(new TextRun({text:bold+'  ',bold:true,size:20,color:INK,font:'Calibri'}));
  parts.push(new TextRun({text:t,size:20,color:INK,font:'Calibri'}));return new Paragraph({bullet:{level:0},spacing:{after:60,line:266},children:parts});}
function code(lines){const kids=lines.map(l=>new Paragraph({spacing:{after:24},children:[new TextRun({text:l,font:'Consolas',size:18,color:l.trim().startsWith('#')?'7FA98C':CODEINK})]}));
  return [new Table({columnWidths:[USABLE],width:{size:USABLE,type:WidthType.DXA},
    borders:{top:{style:BorderStyle.SINGLE,size:4,color:'0A140D'},bottom:{style:BorderStyle.SINGLE,size:4,color:'0A140D'},left:{style:BorderStyle.SINGLE,size:4,color:'0A140D'},right:{style:BorderStyle.SINGLE,size:4,color:'0A140D'}},
    rows:[new TableRow({children:[new TableCell({width:{size:USABLE,type:WidthType.DXA},shading:{type:ShadingType.CLEAR,fill:CODEBG,color:'auto'},margins:{top:120,bottom:120,left:160,right:160},children:kids})]})]}),
    new Paragraph({spacing:{after:120},children:[new TextRun({text:'',size:2})]})];}
function cell(t,{w,bold,fill,color,font}={}){return new TableCell({width:{size:w,type:WidthType.DXA},shading:fill?{type:ShadingType.CLEAR,fill,color:'auto'}:undefined,margins:{top:56,bottom:56,left:110,right:110},verticalAlign:VerticalAlign.CENTER,children:[new Paragraph({children:[new TextRun({text:t,bold:!!bold,color:color||INK,size:18,font:font||'Calibri'})]})]});}
function table3(header,rows){const W=[2700,4560,2100];
  const trs=[new TableRow({tableHeader:true,children:header.map((x,i)=>cell(x,{w:W[i],bold:true,fill:NAVY,color:'FFFFFF'}))})];
  rows.forEach((r,i)=>trs.push(new TableRow({children:r.map((x,j)=>cell(x,{w:W[j],fill:i%2?ALT:undefined,bold:j===0}))})));
  return new Table({columnWidths:W,width:{size:USABLE,type:WidthType.DXA},borders:boxB,rows:trs});}

const titleBar=new Paragraph({spacing:{after:0},border:{bottom:{style:BorderStyle.SINGLE,size:18,color:NAVY,space:6}},
  children:[new TextRun({text:'[ ORGANIZATION NAME ]',bold:true,size:22,color:ACCENT,font:'Calibri'}),new TextRun({text:'   ·   Information Security · era.ca',size:20,color:GREY,font:'Calibri'})]});

const body=[titleBar,
  new Paragraph({spacing:{before:220,after:40},children:[new TextRun({text:'Sentinel // SOC',bold:true,size:40,color:NAVY,font:'Calibri'})]}),
  new Paragraph({spacing:{after:40},children:[new TextRun({text:'Cómo acceder al sistema — ver el dashboard y hacer cambios',bold:true,size:25,color:ACCENT,font:'Calibri'})]}),
  new Paragraph({spacing:{after:170},children:[new TextRun({text:'Acceso remoto para el equipo, una vez montado en el servidor',italics:true,size:20,color:GREY,font:'Calibri'})]}),

  h('1.  Ver y usar el dashboard (lo más común)',{rule:true}),
  p('El dashboard es una página web que corre en el servidor. No necesitas SSH ni nada técnico para verlo — solo el navegador:'),
  ...code(['# En el navegador de tu estación:','https://soc.era.ca            (o  https://<IP-del-servidor> )','# Login con tu cuenta de era.ca (Google SSO)']),
  p('Ahí mismo, en la web, haces las acciones normales: ver y filtrar alertas, marcarlas como acknowledged / resolved, y administrar usuarios (si eres admin). Eso no requiere conexión especial.'),

  h('2.  Hacer cambios — depende de qué cambio'),
  table3(['Qué quieres cambiar','Cómo','Quién'],[
    ['Marcar alertas, usuarios','En la propia web (dashboard)','Tú / equipo'],
    ['Escaneos: targets, horarios, IOCs, detectores, forwarder','SSH a la VM de Kali','Tú (Seguridad)'],
    ['Código del dashboard / backend','Editar el repo y redesplegar la VM Ubuntu','Sixto y Tomás'],
  ]),
  p([new TextRun({text:'Para tus cambios (lado Kali), te conectas por SSH desde tu estación:',size:20,color:INK,font:'Calibri'})]),
  ...code([
    'ssh arturo@<IP-del-kali>          # tu cuenta admin (con llave SSH)',
    'cd /opt/sentinel-soc/kali',
    'nano targets.conf                 # ej. cambiar los rangos autorizados',
    'sudo systemctl restart soc-login  # reiniciar un servicio si aplica',
  ]),

  h('3.  Cómo se conectan de forma remota (segura)',{rule:true}),
  p('El sistema es interno y NO está expuesto a Internet. Por eso:'),
  b('Desde la oficina, en la VLAN que alcanza al servidor: directo — navegador para el dashboard, SSH para el Kali.','En la red:'),
  b('Desde fuera (casa, etc.): primero te conectas a la VPN de la empresa (WireGuard); ya "dentro" de la red, entras igual que en la oficina.','Por VPN:'),
  b('Siempre por HTTPS para el dashboard.','Cifrado:'),
  p('Detalle de red a confirmar con IT: que la VLAN de las estaciones alcance la VLAN del servidor (si no, IT abre ese camino o se usa la VPN). Es justo lo que los devs piden con "la IP del servidor y la VLAN".'),

  h('4.  Referencia rápida'),
  table3(['Necesito…','Desde dónde','Cómo'],[
    ['Ver el dashboard','Navegador','https://soc.era.ca (login era.ca)'],
    ['Cambiar escaneos / Kali','Terminal','ssh arturo@<IP-del-kali>'],
    ['Entrar desde fuera de la oficina','VPN primero','WireGuard → luego navegador / SSH'],
    ['Cambiar el dashboard/backend','—','Lo hacen los devs (redeploy Ubuntu)'],
  ]),

  h('Resumen',{before:240}),
  p('Para VER el dashboard: navegador a la IP del server (en la red o por VPN), login con era.ca — nada más. Para cambios de escaneos/Kali: SSH a la VM de Kali desde tu estación. Para cambios del dashboard/backend: los devs redespliegan la VM de Ubuntu. Desde fuera de la oficina, siempre por VPN.'),
];

const doc=new Document({creator:'Sentinel SOC',title:'Sentinel SOC — Cómo acceder al sistema',
  styles:{default:{document:{run:{font:'Calibri',size:20,color:INK}}}},
  sections:[{properties:{page:{size:{width:12240,height:15840},margin:{top:1080,bottom:1080,left:1440,right:1440}}},
    headers:{default:new Header({children:[new Paragraph({tabStops:[{type:TabStopType.RIGHT,position:USABLE}],
      border:{bottom:{style:BorderStyle.SINGLE,size:4,color:RULE,space:3}},
      children:[new TextRun({text:'Cómo acceder al sistema',size:15,color:GREY,font:'Calibri'}),new TextRun({text:'\tCONFIDENCIAL',size:15,bold:true,color:WARN,font:'Calibri'})]})]})},
    footers:{default:new Footer({children:[new Paragraph({tabStops:[{type:TabStopType.RIGHT,position:USABLE}],
      border:{top:{style:BorderStyle.SINGLE,size:4,color:RULE,space:3}},
      children:[new TextRun({text:'Sentinel SOC — Information Security',size:15,color:GREY,font:'Calibri'}),new TextRun({children:['\tPágina ',PageNumber.CURRENT,' de ',PageNumber.TOTAL_PAGES],size:15,color:GREY,font:'Calibri'})]})]})},
    children:body}]});
Packer.toBuffer(doc).then(x=>{fs.writeFileSync('/root/soc-project/docs/Acceso_al_Sistema_ES.docx',x);console.log('written',x.length);});
