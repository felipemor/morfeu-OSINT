export interface SecurityControlItem {
  id: string;
  name: string;
  category: string;
  domain: string;
  benefit: string;
  description: string;
  mitre_technique: string;
  standard_ref: string;
  severity_if_failed: string;
  status: string;
  target_tested?: string;
  last_tested_at?: string;
  evidence_hash?: string;
  check_summary?: string;
  latency_ms?: number;
}

export function generateClientSideSecurityControlsPdf(
  controls: SecurityControlItem[],
  targetUrl: string,
  lang: 'pt' | 'en' = 'pt'
) {
  const isPt = lang === 'pt';
  const title = isPt
    ? 'LAUDO TÉCNICO E EXECUTIVO DE AUDITORIA DE CONTROLES DE SEGURANÇA'
    : 'TECHNICAL & EXECUTIVE SECURITY CONTROLS AUDIT REPORT';

  const dateStr = new Date().toLocaleString(isPt ? 'pt-BR' : 'en-US');
  const passedCount = controls.filter(c => c.status === 'PASSED').length;
  const failedCount = controls.filter(c => c.status === 'FAILED').length;
  const adherence = Math.round((passedCount / (controls.length || 1)) * 100);

  const htmlContent = `
<!DOCTYPE html>
<html lang="${lang}">
<head>
  <meta charset="utf-8" />
  <title>${title} - 32 Controles</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');
    
    @page {
      size: A4;
      margin: 12mm 15mm 12mm 15mm;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background-color: #0b0f19;
      color: #f1f5f9;
      line-height: 1.5;
      font-size: 11px;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
      padding: 20px;
    }

    .header-banner {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid #00e676;
      padding-bottom: 15px;
      margin-bottom: 20px;
    }

    .brand-title {
      font-size: 18px;
      font-weight: 800;
      color: #00e676;
      font-family: 'JetBrains Mono', monospace;
    }

    .brand-sub {
      font-size: 11px;
      color: #94a3b8;
      margin-top: 2px;
    }

    .meta-badge {
      background: #111827;
      border: 1px solid #1e293b;
      padding: 6px 12px;
      border-radius: 6px;
      text-align: right;
    }

    .meta-badge .sec-level {
      font-size: 10px;
      font-weight: 700;
      color: #ff4757;
      text-transform: uppercase;
    }

    .section-title {
      font-size: 13px;
      font-weight: 700;
      color: #38bdf8;
      border-left: 4px solid #00e676;
      padding-left: 10px;
      margin-top: 20px;
      margin-bottom: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 10px;
      margin-bottom: 20px;
    }

    .kpi-card {
      background: #111827;
      border: 1px solid #1e2d45;
      padding: 12px;
      border-radius: 8px;
    }

    .kpi-label {
      font-size: 10px;
      color: #94a3b8;
      text-transform: uppercase;
      font-weight: 600;
    }

    .kpi-value {
      font-size: 18px;
      font-weight: 800;
      color: #f8fafc;
      margin-top: 4px;
    }

    .kpi-value.danger { color: #ff4757; }
    .kpi-value.warning { color: #ffa502; }
    .kpi-value.success { color: #00e676; }

    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 20px;
      background: #111827;
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid #1e2d45;
    }

    th, td {
      padding: 7px 10px;
      text-align: left;
      font-size: 10px;
      border-bottom: 1px solid #1e2d45;
    }

    th {
      background: #0f172a;
      color: #94a3b8;
      text-transform: uppercase;
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.5px;
    }

    .badge {
      display: inline-block;
      padding: 2px 5px;
      border-radius: 4px;
      font-size: 9px;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
    }

    .badge-critical { background: rgba(255, 71, 87, 0.2); color: #ff4757; border: 1px solid rgba(255, 71, 87, 0.4); }
    .badge-high { background: rgba(255, 165, 2, 0.2); color: #ffa502; border: 1px solid rgba(255, 165, 2, 0.4); }
    .badge-medium { background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); }
    .badge-success { background: rgba(0, 230, 118, 0.2); color: #00e676; border: 1px solid rgba(0, 230, 118, 0.4); }

    .footer {
      margin-top: 30px;
      border-top: 1px solid #1e2d45;
      padding-top: 12px;
      font-size: 10px;
      color: #64748b;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .no-print {
      margin-bottom: 15px;
      background: #1e293b;
      padding: 10px 15px;
      border-radius: 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .btn-print {
      background: #00e676;
      color: #0b0f19;
      font-weight: 700;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 12px;
    }

    @media print {
      .no-print { display: none !important; }
      body { padding: 0; background: #0b0f19 !important; }
    }
  </style>
</head>
<body>
  <div class="no-print">
    <span>💡 <strong>Visualização de Impressão / Salvar PDF:</strong> Clique no botão ao lado para salvar diretamente em PDF.</span>
    <button class="btn-print" onclick="window.print()">🖨️ Salvar como PDF / Imprimir</button>
  </div>

  <div class="header-banner">
    <div>
      <div class="brand-title">🛡️ morfeusec OSINT — Security Controls &amp; Compliance</div>
      <div class="brand-sub">${title} • Matriz de 32 Controles Ofensivos &amp; Regulatórios</div>
    </div>
    <div class="meta-badge">
      <div class="sec-level">ESTRITAMENTE CONFIDENCIAL</div>
      <div style="font-size: 10px; color: #94a3b8; margin-top: 2px;">Data: ${dateStr}</div>
    </div>
  </div>

  <div class="section-title">1. Resumo Executivo da Auditoria</div>
  <table>
    <tr>
      <th style="width: 25%;">Alvo Auditado</th>
      <td style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #38bdf8;">${targetUrl}</td>
      <th style="width: 20%;">Total de Controles</th>
      <td>${controls.length} Controles Ativos</td>
    </tr>
    <tr>
      <th>Aderência Geral</th>
      <td><span class="badge ${adherence >= 80 ? 'badge-success' : 'badge-high'}">${adherence}% Conforme</span></td>
      <th>Auditor Responsável</th>
      <td>Felipe Costa (fsec.costa@gmail.com)</td>
    </tr>
  </table>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-label">Controles Auditados</div>
      <div class="kpi-value">${controls.length}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Controles Conformes</div>
      <div class="kpi-value success">${passedCount}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Apontamentos / Falhas</div>
      <div class="kpi-value ${failedCount > 0 ? 'danger' : 'success'}">${failedCount}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Aderência BACEN / NIST</div>
      <div class="kpi-value success">${adherence}%</div>
    </div>
  </div>

  <div class="section-title">2. Matriz Detalhada dos 32 Controles de Segurança</div>
  <table>
    <thead>
      <tr>
        <th style="width: 10%;">ID</th>
        <th style="width: 28%;">Controle &amp; Descrição</th>
        <th style="width: 16%;">Norma / Padrão</th>
        <th style="width: 16%;">MITRE ATT&CK</th>
        <th style="width: 10%; text-align: center;">Gravidade</th>
        <th style="width: 10%; text-align: right;">Status</th>
      </tr>
    </thead>
    <tbody>
      ${controls.map((c) => `
        <tr>
          <td style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #38bdf8;">${c.id}</td>
          <td>
            <div style="font-weight: 700; color: #f8fafc;">${c.name}</div>
            <div style="font-size: 9px; color: #94a3b8; margin-top: 2px;">${c.description}</div>
          </td>
          <td style="color: #cbd5e1;">${c.standard_ref}</td>
          <td style="font-family: 'JetBrains Mono', monospace; color: #94a3b8;">${c.mitre_technique}</td>
          <td style="text-align: center;">
            <span class="badge ${c.severity_if_failed === 'CRITICAL' ? 'badge-critical' : c.severity_if_failed === 'HIGH' ? 'badge-high' : 'badge-medium'}">
              ${c.severity_if_failed}
            </span>
          </td>
          <td style="text-align: right;">
            <span class="badge ${c.status === 'PASSED' ? 'badge-success' : 'badge-critical'}">
              ${c.status === 'PASSED' ? 'CONFORME' : 'FALHOU'}
            </span>
          </td>
        </tr>
      `).join('')}
    </tbody>
  </table>

  <div class="footer">
    <div><strong>morfeusec OSINT</strong> — Enterprise Offensive Intelligence &amp; Controls Compliance</div>
    <div>Escrito por Felipe Costa - fsec.costa@gmail.com</div>
  </div>

  <script>
    window.onload = function() {
      setTimeout(function() {
        window.print();
      }, 500);
    };
  </script>
</body>
</html>
  `;

  const reportWindow = window.open('', '_blank');
  if (reportWindow) {
    reportWindow.document.open();
    reportWindow.document.write(htmlContent);
    reportWindow.document.close();
  } else {
    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `laudo_controles_seguranca_${new Date().toISOString().slice(0, 10)}.html`;
    a.click();
    URL.revokeObjectURL(url);
  }
}
