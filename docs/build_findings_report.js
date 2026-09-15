const fs = require('fs');
const {
  Document, Packer, Paragraph, TextRun, AlignmentType, Table, TableRow, TableCell,
  WidthType, BorderStyle, ShadingType, Header, Footer, PageNumber, VerticalAlign,
  TabStopType
} = require('docx');

const NAVY='1F3864', ACCENT='2E5496', GREY='595959', INK='212121';
const HEADFILL='D9E2F3', ALTFILL='F2F5FA', RULE='B4C6E7';
const CRIT='B00020', HIGH='C0521B', MED='B7791F', LOW='2E7D32';
const USABLE=9360;
const NONE={style:BorderStyle.NONE,size:0,color:'FFFFFF'};
const noBorders={top:NONE,bottom:NONE,left:NONE,right:NONE};
const boxBorders={
  top:{style:BorderStyle.SINGLE,size:4,color:RULE},bottom:{style:BorderStyle.SINGLE,size:4,color:RULE},
  left:{style:BorderStyle.SINGLE,size:4,color:RULE},right:{style:BorderStyle.SINGLE,size:4,color:RULE},
  insideHorizontal:{style:BorderStyle.SINGLE,size:4,color:RULE},insideVertical:{style:BorderStyle.SINGLE,size:4,color:RULE}};

function h(text,opts={}){return new Paragraph({spacing:{before:opts.before??240,after:opts.after??90},
  border:opts.rule?{bottom:{style:BorderStyle.SINGLE,size:6,color:RULE,space:4}}:undefined,
  children:[new TextRun({text,bold:true,color:NAVY,size:opts.size??24,font:'Calibri'})]});}
function sub(text){return new Paragraph({spacing:{before:140,after:60},children:[new TextRun({text,bold:true,color:ACCENT,size:21,font:'Calibri'})]});}
function p(text,opts={}){const ch=Array.isArray(text)?text:[new TextRun({text,size:20,color:INK,font:'Calibri'})];
  return new Paragraph({spacing:{after:opts.after??120,line:276},alignment:opts.align,children:ch});}
function bullet(text,bold){const parts=[];if(bold)parts.push(new TextRun({text:bold+'  ',bold:true,size:20,color:INK,font:'Calibri'}));
  parts.push(new TextRun({text,size:20,color:INK,font:'Calibri'}));
  return new Paragraph({bullet:{level:0},spacing:{after:60,line:264},children:parts});}
function field(label,w){return new Paragraph({spacing:{after:110},children:[
  new TextRun({text:label+'  ',bold:true,size:20,color:INK,font:'Calibri'}),
  new TextRun({text:'_'.repeat(w||50),color:'9AA0A6',size:20,font:'Calibri'})]});}
function cell(text,{w,bold,fill,color,align,size}={}){return new TableCell({
  width:{size:w,type:WidthType.DXA},
  shading:fill?{type:ShadingType.CLEAR,fill,color:'auto'}:undefined,
  margins:{top:60,bottom:60,left:110,right:110},verticalAlign:VerticalAlign.CENTER,
  children:[new Paragraph({alignment:align,children:[new TextRun({text,bold:!!bold,color:color||INK,size:size||19,font:'Calibri'})]})]});}
function headRow(labels,widths){return new TableRow({tableHeader:true,
  children:labels.map((l,i)=>cell(l,{w:widths[i],bold:true,fill:NAVY,color:'FFFFFF'}))});}
function dataTable(labels,widths,rows,blanks){
  const trs=[headRow(labels,widths)];
  (rows||[]).forEach((r,idx)=>trs.push(new TableRow({children:r.map((t,i)=>cell(t,{w:widths[i],fill:idx%2?ALTFILL:undefined}))})));
  for(let i=0;i<(blanks||0);i++){const idx=(rows?rows.length:0)+i;
    trs.push(new TableRow({children:widths.map(w=>cell('',{w,fill:idx%2?ALTFILL:undefined}))}));}
  return new Table({columnWidths:widths,width:{size:widths.reduce((a,b)=>a+b,0),type:WidthType.DXA},borders:boxBorders,rows:trs});}

// severity summary chips table
function sevSummary(){
  const w=[2340,2340,2340,2340];
  const chip=(label,color)=>new TableRow({children:[
    new TableCell({width:{size:w[0],type:WidthType.DXA},borders:boxBorders,shading:{type:ShadingType.CLEAR,fill:color,color:'auto'},margins:{top:80,bottom:80,left:110,right:110},
      children:[new Paragraph({alignment:AlignmentType.CENTER,children:[new TextRun({text:label,bold:true,color:'FFFFFF',size:20,font:'Calibri'})]})]}),
  ]});
  return new Table({columnWidths:w,width:{size:USABLE,type:WidthType.DXA},borders:boxBorders,rows:[
    new TableRow({children:[
      cell('Critical',{w:w[0],bold:true,fill:CRIT,color:'FFFFFF',align:AlignmentType.CENTER}),
      cell('High',{w:w[1],bold:true,fill:HIGH,color:'FFFFFF',align:AlignmentType.CENTER}),
      cell('Medium',{w:w[2],bold:true,fill:MED,color:'FFFFFF',align:AlignmentType.CENTER}),
      cell('Low',{w:w[3],bold:true,fill:LOW,color:'FFFFFF',align:AlignmentType.CENTER})]}),
    new TableRow({children:[
      cell('___',{w:w[0],bold:true,align:AlignmentType.CENTER,size:26}),
      cell('___',{w:w[1],bold:true,align:AlignmentType.CENTER,size:26}),
      cell('___',{w:w[2],bold:true,align:AlignmentType.CENTER,size:26}),
      cell('___',{w:w[3],bold:true,align:AlignmentType.CENTER,size:26})]}),
  ]});
}

// finding card
function findingCard(n){
  const lw=2000,vw=USABLE-lw;
  const row=(label,val,fill)=>new TableRow({children:[
    cell(label,{w:lw,bold:true,fill:fill||HEADFILL}),
    cell(val||'',{w:vw})]});
  return new Table({columnWidths:[lw,vw],width:{size:USABLE,type:WidthType.DXA},borders:boxBorders,rows:[
    new TableRow({children:[cell(`Finding ${n}`,{w:lw,bold:true,fill:NAVY,color:'FFFFFF'}),cell('Title:  ____________________________________________',{w:vw,fill:NAVY,color:'FFFFFF'})]}),
    row('Severity','Critical  □      High  □      Medium  □      Low  □'),
    row('Category','Segmentation  □   Open port/service  □   Vulnerability  □   Egress  □   Other  □'),
    row('Affected assets',''),
    row('Description',''),
    row('Evidence / tool output',''),
    row('Impact',''),
    row('Recommendation',''),
  ]});
}

const titleBar=new Paragraph({spacing:{after:0},
  border:{bottom:{style:BorderStyle.SINGLE,size:18,color:NAVY,space:6}},
  children:[new TextRun({text:'[ ORGANIZATION NAME ]',bold:true,size:22,color:ACCENT,font:'Calibri'}),
    new TextRun({text:'   ·   Information Security',size:20,color:GREY,font:'Calibri'})]});

const body=[
  titleBar,
  new Paragraph({spacing:{before:220,after:40},children:[new TextRun({text:'Network Security Assessment',bold:true,size:40,color:NAVY,font:'Calibri'})]}),
  new Paragraph({spacing:{after:40},children:[new TextRun({text:'Stage 1 — Baseline & Reachability Findings Report',bold:true,size:26,color:ACCENT,font:'Calibri'})]}),
  new Paragraph({spacing:{after:200},children:[new TextRun({text:'Phase A — Network segmentation & exposure assessment',italics:true,size:20,color:GREY,font:'Calibri'})]}),

  dataTable(['Field','Value','Field','Value'],[2200,2480,2200,2480],[
    ['Document ID','SEC-RPT-2026-01','Version','1.0'],
    ['Project','Sentinel SOC','Report date','____ / ____ / 2026'],
    ['Classification','CONFIDENTIAL','Authorization ref','SEC-AUTH-2026-01'],
    ['Assessment window','','Prepared by',''],
  ],0),

  h('1.  Executive Summary',{rule:true}),
  p('Write 4–6 sentences in plain language for managers and IT leadership: what was assessed, from where, the single most important finding (typically whether network segmentation held or not), and the overall risk posture. Avoid jargon here — the detail lives below.'),
  p([new TextRun({text:'Overall risk rating:   ',bold:true,size:20,color:INK,font:'Calibri'}),
     new TextRun({text:'Critical □   High □   Medium □   Low □',size:20,color:INK,font:'Calibri'})]),
  sub('Findings at a glance'),
  sevSummary(),
  p('',{after:60}),
  bullet('Most significant finding: ________________________________________________','1.'),
  bullet('Second finding: __________________________________________________________','2.'),
  bullet('Third finding: ___________________________________________________________','3.'),

  h('2.  Scope & Methodology'),
  p('This assessment was performed under the written authorization referenced above. Following the agreed approach, measurement began from a standard network position (no infrastructure access requested in advance) to evaluate what is actually reachable from there — reachability itself being the primary finding. No exploitation was performed.'),
  sub('Tools used'),
  p('nmap (host discovery, service/version detection, non-destructive NSE vulnerability scripts); zmap (fast internal-range discovery, configured to allow RFC1918); Sentinel SOC platform for alert capture and reporting.'),

  h('3.  Assessment Position'),
  p('Where the assessment host (Kali) was connected — the vantage point for all reachability results below.'),
  dataTable(['Parameter','Value'],[3200,6160],[
    ['Interface',''],['IP address / mask',''],['Default gateway',''],['DNS server(s)',''],['VLAN / subnet',''],['Date/time connected',''],
  ],0),

  h('4.  Findings — Local Subnet Inventory',{rule:true}),
  p('Live hosts and exposed services discovered in the assessment host’s own subnet.'),
  dataTable(['Host IP','Hostname','OS (guess)','Open ports / services','Notes'],[1700,1900,1500,2660,1600],[],6),

  h('5.  Findings — Cross-Segment Reachability  (segmentation)'),
  p([new TextRun({text:'This is the core of Stage 1. ',bold:true,size:20,color:INK,font:'Calibri'}),
     new TextRun({text:'For each other zone, record whether it is reachable from the assessment position and whether it should be. Anything reachable that should be isolated — especially the management network — is a segmentation finding.',size:20,color:INK,font:'Calibri'})]),
  dataTable(['Target zone / subnet','Reachable?','Ports / paths seen','Expected?','Severity'],[2860,1300,2600,1000,1600],[
    ['Users VLAN','Yes / No','','Yes / No',''],
    ['Servers VLAN','Yes / No','','Yes / No',''],
    ['Management VLAN','Yes / No','','No','']],3),

  h('6.  Findings — Insecure Services & Open Ports'),
  dataTable(['Host','Port/Proto','Service','Risk','Recommendation'],[1700,1400,1760,1300,3200],[],5),

  h('7.  Findings — Vulnerabilities'),
  dataTable(['Host','Port','Finding','CVE','Sev.','Recommendation'],[1500,900,2400,1360,900,2300],[],5),

  h('8.  Findings — Egress / Outbound Exposure'),
  p('Whether the assessment position can reach the Internet over arbitrary ports (data-exfiltration risk). Record which outbound ports succeeded.'),
  dataTable(['Destination tested','Port','Reached?','Notes'],[3000,1360,1400,3600],[],3),

  h('9.  Detailed Findings',{rule:true}),
  p('One card per finding. Duplicate a card for additional findings.'),
  findingCard(1),
  p('',{after:80}),
  findingCard(2),
  p('',{after:80}),
  findingCard(3),

  h('10.  Prioritized Recommendations',{rule:true}),
  p('The action list handed to IT and management. Order by priority.'),
  dataTable(['#','Recommendation','Owner','Priority','Effort'],[520,4400,1640,1240,1560],[],6),

  h('Appendix A — Segmentation Matrix (VLAN × VLAN)',{before:280}),
  p('Reachability between zones. Fill each cell with Y (reachable) / N (blocked) / – (not tested).'),
  dataTable(['From \\ To','Users','Servers','Mgmt','DMZ','Internet'],[2160,1440,1440,1440,1440,1440],[
    ['Users','—','','','',''],['Servers','','—','','',''],['Mgmt','','','—','',''],['DMZ','','','','—','']],0),

  h('Appendix B — Scan Log & Commands'),
  p('Record the exact commands, targets, and timestamps for repeatability and audit (e.g., the contents of kali/results/REPORT_*.txt).'),
  field('nmap/zmap commands run:',60),
  field('Result files:',66),
  field('Operator:',40),

  h('Distribution & Handling',{before:260}),
  p('CONFIDENTIAL — Internal Use Only. Distribute only to the parties named in the authorization. Do not forward externally without written approval.'),
];

const doc=new Document({
  creator:'Sentinel SOC',
  title:'Network Security Assessment — Stage 1 Baseline & Reachability Findings Report',
  styles:{default:{document:{run:{font:'Calibri',size:20,color:INK}}}},
  sections:[{
    properties:{page:{size:{width:12240,height:15840},margin:{top:1080,bottom:1080,left:1440,right:1440}}},
    headers:{default:new Header({children:[new Paragraph({
      tabStops:[{type:TabStopType.RIGHT,position:USABLE}],
      border:{bottom:{style:BorderStyle.SINGLE,size:4,color:RULE,space:3}},
      children:[new TextRun({text:'Stage 1 — Baseline & Reachability Findings',size:15,color:GREY,font:'Calibri'}),
        new TextRun({text:'\tCONFIDENTIAL',size:15,bold:true,color:CRIT,font:'Calibri'})]})]})},
    footers:{default:new Footer({children:[new Paragraph({
      tabStops:[{type:TabStopType.RIGHT,position:USABLE}],
      border:{top:{style:BorderStyle.SINGLE,size:4,color:RULE,space:3}},
      children:[new TextRun({text:'Sentinel SOC — Information Security',size:15,color:GREY,font:'Calibri'}),
        new TextRun({children:['\tPage ',PageNumber.CURRENT,' of ',PageNumber.TOTAL_PAGES],size:15,color:GREY,font:'Calibri'})]})]})},
    children:body,
  }],
});
Packer.toBuffer(doc).then(buf=>{fs.writeFileSync('/root/soc-project/docs/Stage1_Findings_Report_EN.docx',buf);console.log('written',buf.length,'bytes');});
