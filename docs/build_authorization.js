const fs = require('fs');
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
  Header, Footer, PageNumber, VerticalAlign, TabStopType, TabStopPosition
} = require('docx');

// ---- palette ----
const NAVY = '1F3864', ACCENT = '2E5496', GREY = '595959', INK = '212121';
const HEADFILL = 'D9E2F3', ALTFILL = 'F2F5FA', RULE = 'B4C6E7';
const USABLE = 9360; // US Letter minus 1" margins

const NONE = { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' };
const noBorders = { top: NONE, bottom: NONE, left: NONE, right: NONE };

// ---- helpers ----
function h(text, opts = {}) {
  return new Paragraph({
    spacing: { before: opts.before ?? 240, after: opts.after ?? 90 },
    children: [new TextRun({ text, bold: true, color: NAVY, size: opts.size ?? 24, font: 'Calibri' })],
    ...(opts.heading ? { heading: opts.heading } : {}),
    border: opts.rule ? { bottom: { style: BorderStyle.SINGLE, size: 6, color: RULE, space: 4 } } : undefined,
  });
}
function p(runs, opts = {}) {
  const children = Array.isArray(runs) ? runs : [new TextRun({ text: runs, size: 20, color: INK, font: 'Calibri' })];
  return new Paragraph({ spacing: { after: opts.after ?? 120, line: 276 }, alignment: opts.align, children });
}
function bullet(text, bold) {
  const parts = [];
  if (bold) { parts.push(new TextRun({ text: bold + '  ', bold: true, size: 20, color: INK, font: 'Calibri' })); }
  parts.push(new TextRun({ text, size: 20, color: INK, font: 'Calibri' }));
  return new Paragraph({ bullet: { level: 0 }, spacing: { after: 60, line: 264 }, children: parts });
}
function field(label, blankWidth) {
  return new Paragraph({
    spacing: { after: 120 },
    children: [
      new TextRun({ text: label + '  ', bold: true, size: 20, color: INK, font: 'Calibri' }),
      new TextRun({ text: '_'.repeat(blankWidth || 50), color: '9AA0A6', size: 20, font: 'Calibri' }),
    ],
  });
}
function cell(text, { w, bold, fill, color, align, size } = {}) {
  return new TableCell({
    width: { size: w, type: WidthType.DXA },
    shading: fill ? { type: ShadingType.CLEAR, fill, color: 'auto' } : undefined,
    margins: { top: 60, bottom: 60, left: 110, right: 110 },
    verticalAlign: VerticalAlign.CENTER,
    children: [new Paragraph({
      alignment: align,
      children: [new TextRun({ text, bold: !!bold, color: color || INK, size: size || 19, font: 'Calibri' })],
    })],
  });
}
function tableHeaderRow(labels, widths) {
  return new TableRow({
    tableHeader: true,
    children: labels.map((l, i) => cell(l, { w: widths[i], bold: true, fill: NAVY, color: 'FFFFFF' })),
  });
}
function emptyRow(widths, fill) {
  return new TableRow({ children: widths.map(w => cell('', { w, fill })) });
}
function dataTable(labels, widths, dataRows, blankRows) {
  const rows = [tableHeaderRow(labels, widths)];
  (dataRows || []).forEach((r, idx) => {
    rows.push(new TableRow({
      children: r.map((t, i) => cell(t, { w: widths[i], fill: idx % 2 ? ALTFILL : undefined })),
    }));
  });
  for (let i = 0; i < (blankRows || 0); i++) rows.push(emptyRow(widths, ((dataRows ? dataRows.length : 0) + i) % 2 ? ALTFILL : undefined));
  return new Table({
    columnWidths: widths,
    width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA },
    borders: {
      top: { style: BorderStyle.SINGLE, size: 4, color: RULE },
      bottom: { style: BorderStyle.SINGLE, size: 4, color: RULE },
      left: { style: BorderStyle.SINGLE, size: 4, color: RULE },
      right: { style: BorderStyle.SINGLE, size: 4, color: RULE },
      insideHorizontal: { style: BorderStyle.SINGLE, size: 4, color: RULE },
      insideVertical: { style: BorderStyle.SINGLE, size: 4, color: RULE },
    },
    rows,
  });
}
// signature block: signature line + date line, then name/title fields
function signatureBlock(roleLabel) {
  const half = 4560, gap = 240;
  const lineCell = (label) => new TableCell({
    width: { size: half, type: WidthType.DXA }, borders: noBorders,
    children: [
      new Paragraph({ spacing: { before: 260 },
        border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: INK, space: 2 } },
        children: [new TextRun({ text: ' ', size: 18 })] }),
      new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text: label, size: 16, color: GREY, font: 'Calibri' })] }),
    ],
  });
  return [
    new Paragraph({ spacing: { before: 200, after: 40 }, children: [new TextRun({ text: roleLabel, bold: true, size: 20, color: ACCENT, font: 'Calibri' })] }),
    new Table({
      columnWidths: [half, gap, half],
      width: { size: half * 2 + gap, type: WidthType.DXA },
      borders: { top: NONE, bottom: NONE, left: NONE, right: NONE, insideHorizontal: NONE, insideVertical: NONE },
      rows: [new TableRow({ children: [lineCell('Signature'), new TableCell({ width: { size: gap, type: WidthType.DXA }, borders: noBorders, children: [new Paragraph('')] }), lineCell('Date')] })],
    }),
    new Paragraph({ spacing: { before: 120 }, children: [
      new TextRun({ text: 'Printed name:  ', bold: true, size: 19, color: INK, font: 'Calibri' }),
      new TextRun({ text: '_'.repeat(34), color: '9AA0A6', size: 19, font: 'Calibri' }),
      new TextRun({ text: '     Title:  ', bold: true, size: 19, color: INK, font: 'Calibri' }),
      new TextRun({ text: '_'.repeat(24), color: '9AA0A6', size: 19, font: 'Calibri' }),
    ] }),
  ];
}

// ---- title block ----
const titleBar = new Paragraph({
  spacing: { after: 0 },
  border: { bottom: { style: BorderStyle.SINGLE, size: 18, color: NAVY, space: 6 } },
  children: [new TextRun({ text: '[ ORGANIZATION NAME ]', bold: true, size: 22, color: ACCENT, font: 'Calibri' }),
             new TextRun({ text: '   ·   Information Security', size: 20, color: GREY, font: 'Calibri' })],
});
const title = new Paragraph({
  spacing: { before: 220, after: 40 },
  children: [new TextRun({ text: 'Network Security Assessment', bold: true, size: 40, color: NAVY, font: 'Calibri' })],
});
const subtitle = new Paragraph({
  spacing: { after: 60 },
  children: [new TextRun({ text: 'Scope Authorization & Rules of Engagement', bold: true, size: 26, color: ACCENT, font: 'Calibri' })],
});
const stageLine = new Paragraph({
  spacing: { after: 200 },
  children: [new TextRun({ text: 'Stage 1 — Internal Network Analysis, Scanning & Vulnerability Assessment', italics: true, size: 20, color: GREY, font: 'Calibri' })],
});

// metadata table
const metaWidths = [2200, 2480, 2200, 2480];
const metaTable = new Table({
  columnWidths: metaWidths,
  width: { size: USABLE, type: WidthType.DXA },
  borders: {
    top: { style: BorderStyle.SINGLE, size: 4, color: RULE }, bottom: { style: BorderStyle.SINGLE, size: 4, color: RULE },
    left: { style: BorderStyle.SINGLE, size: 4, color: RULE }, right: { style: BorderStyle.SINGLE, size: 4, color: RULE },
    insideHorizontal: { style: BorderStyle.SINGLE, size: 4, color: RULE }, insideVertical: { style: BorderStyle.SINGLE, size: 4, color: RULE },
  },
  rows: [
    new TableRow({ children: [cell('Document ID', { w: metaWidths[0], bold: true, fill: HEADFILL }), cell('SEC-AUTH-2026-01', { w: metaWidths[1] }), cell('Version', { w: metaWidths[2], bold: true, fill: HEADFILL }), cell('1.0', { w: metaWidths[3] })] }),
    new TableRow({ children: [cell('Project', { w: metaWidths[0], bold: true, fill: HEADFILL }), cell('Sentinel SOC', { w: metaWidths[1] }), cell('Effective date', { w: metaWidths[2], bold: true, fill: HEADFILL }), cell('____ / ____ / 2026', { w: metaWidths[3] })] }),
    new TableRow({ children: [cell('Classification', { w: metaWidths[0], bold: true, fill: HEADFILL }), cell('CONFIDENTIAL — Internal Use Only', { w: metaWidths[1], bold: true, color: 'B00020' }), cell('Valid through', { w: metaWidths[2], bold: true, fill: HEADFILL }), cell('____ / ____ / 2026', { w: metaWidths[3] })] }),
  ],
});

// ---- build body ----
const body = [
  titleBar, title, subtitle, stageLine, metaTable,

  h('1.  Purpose', { rule: true }),
  p('This document formally authorizes the named security assessment team to conduct a defensive, internal security assessment of the organization’s own network infrastructure, and defines the agreed rules of engagement. The objective of Stage 1 is to identify open ports, insecure services, basic vulnerabilities, and — above all — to evaluate how the network is segmented (VLANs, subnets, and routing between them). Active exploitation and penetration testing are explicitly out of scope for Stage 1 and are deferred to a separately authorized Stage 2.'),

  h('2.  Parties'),
  field('Authorizing organization:', 46),
  field('Business sponsor / approving manager:', 40),
  field('IT / Infrastructure owner:', 46),
  field('Assessment lead (Security):', 44),
  p([new TextRun({ text: 'The assessment team acts in good faith and strictly within the scope and schedule defined below. Any activity outside this scope requires prior written authorization.', size: 20, color: INK, font: 'Calibri' })]),

  h('3.  Scope — Authorized Targets', { rule: true }),
  p('The following networks are IN SCOPE for this assessment. List every authorized range, subnet, and VLAN. Only assets the organization owns and is authorized to test may be listed.'),
  dataTable(
    ['#', 'Description / Zone', 'IP Range or CIDR', 'VLAN', 'Notes'],
    [520, 3000, 2600, 1040, 2200],
    [], 6),
  p(''),
  p([new TextRun({ text: 'Explicitly OUT OF SCOPE ', bold: true, color: 'B00020', size: 20, font: 'Calibri' }), new TextRun({ text: '(must not be scanned or touched):', size: 20, color: INK, font: 'Calibri' })]),
  dataTable(['#', 'Excluded system / range', 'Reason'], [520, 5000, 3840], [], 4),

  h('4.  Authorized Activities'),
  bullet('Host discovery / liveness sweeps (ICMP, ARP, TCP SYN) across in-scope ranges.'),
  bullet('TCP/UDP port scanning and service / version detection (e.g., nmap, zmap for internal discovery).'),
  bullet('Non-destructive vulnerability scanning (e.g., nmap NSE “vuln” scripts) on reachable hosts.'),
  bullet('Cross-segment reachability testing to evaluate VLAN / subnet isolation (the segmentation audit).'),
  bullet('Passive traffic observation on an authorized interface (read-only; no injection).'),
  bullet('Documentation of findings into the assessment platform (Sentinel SOC).'),

  h('5.  Prohibited Activities (Stage 1)'),
  bullet('Exploitation of vulnerabilities, privilege escalation, or installation of any tooling on target hosts.', 'No exploitation.'),
  bullet('Denial-of-service, stress, or flooding tests of any kind.', 'No disruption.'),
  bullet('Password brute-forcing, credential capture, or offline cracking.', 'No credentials.'),
  bullet('Social engineering, phishing of staff, or physical intrusion.', 'No social eng.'),
  bullet('Accessing, copying, altering, or deleting business data.', 'No data access.'),
  bullet('Scanning any system not listed as in scope.', 'No out-of-scope.'),

  h('6.  Authorized Tools'),
  p('nmap, zmap (internal-range configuration), tshark (passive capture, Stage 2), and the Sentinel SOC detection scripts. Any additional tool must be approved in writing before use.'),

  h('7.  Schedule & Time Window', { rule: true }),
  dataTable(['Parameter', 'Value'], [3200, 6160], [
    ['Assessment start date', ''],
    ['Assessment end date', ''],
    ['Permitted scanning hours', 'e.g., 19:00 – 06:00 (outside business hours)'],
    ['Blackout periods (no scanning)', ''],
    ['Intrusive vuln scans coordinated with IT?', 'Yes  □     Scheduled window: ______________'],
  ], 0),

  h('8.  Authorized Personnel'),
  dataTable(['Name', 'Role', 'Email / Phone'], [3200, 2960, 3200], [], 4),

  h('9.  Emergency Contacts & Stop Conditions'),
  p('If any system becomes unstable or unavailable during the assessment, the team will immediately stop the activity, notify the contacts below, and document the event. Scanning resumes only after IT confirms it is safe to proceed.'),
  field('Primary IT emergency contact (name / phone):', 34),
  field('Secondary contact (name / phone):', 42),
  bullet('Stop immediately if a host or service goes down, if unexpected production impact is observed, or on request from IT.', 'Stop conditions:'),

  h('10.  Data Handling & Confidentiality'),
  p('All assessment output (host inventories, open ports, vulnerabilities, network maps) is CONFIDENTIAL and reveals the internal structure of the network. It will be stored only on authorized systems, shared only with the parties to this authorization, and retained per the organization’s data-retention policy. Findings will not be disclosed to any third party without written approval.'),

  h('11.  Risk Acknowledgment'),
  p('The parties acknowledge that network scanning carries an inherent, low but non-zero risk of service disruption, particularly against fragile or legacy devices. The assessment team will use non-destructive settings and coordinate intrusive scans with IT. By signing below, the authorizing organization accepts this residual risk and confirms it owns, or is duly authorized to test, every in-scope target.'),

  h('12.  Authorization & Signatures', { rule: true }),
  p([new TextRun({ text: 'By signing, each party confirms they have read, understood, and approved the scope and rules of engagement defined in this document.', size: 20, color: INK, font: 'Calibri' })]),
  ...signatureBlock('Approving Manager / Business Sponsor'),
  ...signatureBlock('IT / Infrastructure Owner'),
  ...signatureBlock('Assessment Lead (Security)'),

  h('Appendix A — Revision History', { before: 320 }),
  dataTable(['Version', 'Date', 'Author', 'Change'], [1400, 1800, 2560, 3600], [['1.0', '', '', 'Initial authorization']], 2),
];

const doc = new Document({
  creator: 'Sentinel SOC',
  title: 'Network Security Assessment — Scope Authorization & Rules of Engagement',
  styles: { default: { document: { run: { font: 'Calibri', size: 20, color: INK } } } },
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1080, bottom: 1080, left: 1440, right: 1440 } } },
    headers: { default: new Header({ children: [new Paragraph({
      tabStops: [{ type: TabStopType.RIGHT, position: USABLE }],
      border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: RULE, space: 3 } },
      children: [
        new TextRun({ text: 'Scope Authorization & Rules of Engagement', size: 15, color: GREY, font: 'Calibri' }),
        new TextRun({ text: '\tCONFIDENTIAL', size: 15, bold: true, color: 'B00020', font: 'Calibri' }),
      ] })] }) },
    footers: { default: new Footer({ children: [new Paragraph({
      tabStops: [{ type: TabStopType.RIGHT, position: USABLE }],
      border: { top: { style: BorderStyle.SINGLE, size: 4, color: RULE, space: 3 } },
      children: [
        new TextRun({ text: 'Sentinel SOC — Information Security', size: 15, color: GREY, font: 'Calibri' }),
        new TextRun({ children: ['\tPage ', PageNumber.CURRENT, ' of ', PageNumber.TOTAL_PAGES], size: 15, color: GREY, font: 'Calibri' }),
      ] })] }) },
    children: body,
  }],
});

Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync('/root/soc-project/docs/Scope_Authorization_Form_EN.docx', buf);
  console.log('written', buf.length, 'bytes');
});
