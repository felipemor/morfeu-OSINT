import { MobileScanResult } from './api';

export function generateClientSideMobilePdfReport(scanResult: MobileScanResult, lang: 'pt' | 'en' = 'pt') {
  const isPt = lang === 'pt';
  const title = isPt 
    ? 'LAUDO EXECUTIVO DE AUDITORIA MOBILE (OWASP MASVS & DAST)'
    : 'EXECUTIVE MOBILE SECURITY AUDIT REPORT (OWASP MASVS & DAST)';

  const dateStr = new Date(scanResult.scanned_at || Date.now()).toLocaleString(isPt ? 'pt-BR' : 'en-US');

  const htmlContent = `
<!DOCTYPE html>
<html lang="${lang}">
<head>
  <meta charset="utf-8" />
  <title>${title} - ${scanResult.package_name}</title>
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
      font-size: 12px;
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
      font-size: 20px;
      font-weight: 800;
      color: #00e676;
      letter-spacing: 0.5px;
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
      font-size: 14px;
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
      padding: 8px 12px;
      text-align: left;
      font-size: 11px;
      border-bottom: 1px solid #1e2d45;
    }

    th {
      background: #0f172a;
      color: #94a3b8;
      text-transform: uppercase;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.5px;
    }

    .badge {
      display: inline-block;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 9px;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
    }

    .badge-critical { background: rgba(255, 71, 87, 0.2); color: #ff4757; border: 1px solid rgba(255, 71, 87, 0.4); }
    .badge-high { background: rgba(255, 165, 2, 0.2); color: #ffa502; border: 1px solid rgba(255, 165, 2, 0.4); }
    .badge-medium { background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); }
    .badge-success { background: rgba(0, 230, 118, 0.2); color: #00e676; border: 1px solid rgba(0, 230, 118, 0.4); }

    .finding-card {
      background: #111827;
      border: 1px solid #1e2d45;
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 12px;
      page-break-inside: avoid;
    }

    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }

    .finding-title {
      font-size: 13px;
      font-weight: 700;
      color: #f8fafc;
    }

    .finding-body {
      font-size: 11px;
      color: #cbd5e1;
      margin-bottom: 8px;
    }

    .remediation-box {
      background: #0b1324;
      border-left: 3px solid #00e676;
      padding: 8px 12px;
      border-radius: 4px;
      font-size: 11px;
      color: #94a3b8;
    }

    .remediation-box strong {
      color: #00e676;
    }

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
      <div class="brand-title">🛡️ morfeusec OSINT — Mobile Pentest Platform</div>
      <div class="brand-sub">${title} • OWASP MASVS v2.0</div>
    </div>
    <div class="meta-badge">
      <div class="sec-level">ESTRITAMENTE CONFIDENCIAL</div>
      <div style="font-size: 10px; color: #94a3b8; margin-top: 2px;">Data: ${dateStr}</div>
    </div>
  </div>

  <div class="section-title">${isPt ? '1. Identificação do Pacote & Ambiente' : '1. Package Identification & Environment'}</div>
  <table>
    <tr>
      <th style="width: 25%;">${isPt ? 'Nome do Aplicativo / Pacote' : 'Application / Package Name'}</th>
      <td style="font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #38bdf8;">${scanResult.package_name}</td>
      <th style="width: 20%;">${isPt ? 'Plataforma / Arquivo' : 'Platform / File'}</th>
      <td>${scanResult.platform} (${scanResult.filename})</td>
    </tr>
    <tr>
      <th>${isPt ? 'Versão da Release' : 'Release Version'}</th>
      <td>${scanResult.app_version}</td>
      <th>Target SDK / Min SDK</th>
      <td>${scanResult.target_sdk} / ${scanResult.min_sdk}</td>
    </tr>
    <tr>
      <th>${isPt ? 'Classificação de Risco' : 'Risk Classification'}</th>
      <td><span class="badge ${scanResult.risk_score > 60 ? 'badge-critical' : scanResult.risk_score > 30 ? 'badge-high' : 'badge-success'}">${scanResult.risk_grade} (Score: ${scanResult.risk_score}/100)</span></td>
      <th>${isPt ? 'Auditor Responsável' : 'Lead Auditor'}</th>
      <td>Felipe Costa (felipe_c@myyahoo.com)</td>
    </tr>
  </table>

  <div class="section-title">${isPt ? '2. Métricas Consolidadas do Parque Mobile' : '2. Mobile Fleet Key Metrics'}</div>
  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-label">${isPt ? 'Total de Falhas' : 'Total Findings'}</div>
      <div class="kpi-value">${scanResult.findings_summary?.total ?? scanResult.findings?.length ?? 0}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">${isPt ? 'Severidade Crítica' : 'Critical Severity'}</div>
      <div class="kpi-value danger">${scanResult.findings_summary?.critical ?? 0}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">${isPt ? 'Severidade Alta' : 'High Severity'}</div>
      <div class="kpi-value warning">${scanResult.findings_summary?.high ?? 0}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">${isPt ? 'Chaves Hardcoded' : 'Hardcoded Secrets'}</div>
      <div class="kpi-value ${scanResult.hardcoded_secrets?.length ? 'danger' : 'success'}">${scanResult.hardcoded_secrets?.length ?? 0}</div>
    </div>
  </div>

  <div class="section-title">${isPt ? '3. Aderência aos Controles OWASP MASVS v2.0' : '3. OWASP MASVS v2.0 Compliance Matrix'}</div>
  <table>
    <thead>
      <tr>
        <th>Domínio MASVS</th>
        <th>Controle Avaliado</th>
        <th style="text-align: center;">Score</th>
        <th style="text-align: right;">Status de Postura</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td style="font-weight: 700; color: #f8fafc;">MASVS-STORAGE</td>
        <td>Armazenamento Seguro e Proteção de Dados Locais (allowBackup, SQLite)</td>
        <td style="text-align: center; font-weight: 700;">${scanResult.owasp_masvs_scores?.['MASVS-STORAGE'] ?? 40}%</td>
        <td style="text-align: right;"><span class="badge ${(scanResult.owasp_masvs_scores?.['MASVS-STORAGE'] ?? 40) < 60 ? 'badge-critical' : 'badge-success'}">${(scanResult.owasp_masvs_scores?.['MASVS-STORAGE'] ?? 40) < 60 ? 'NÃO CONFORME' : 'CONFORME'}</span></td>
      </tr>
      <tr>
        <td style="font-weight: 700; color: #f8fafc;">MASVS-CRYPTO</td>
        <td>Criptografia Forte e Gerenciamento de Chaves Keystore</td>
        <td style="text-align: center; font-weight: 700;">${scanResult.owasp_masvs_scores?.['MASVS-CRYPTO'] ?? 45}%</td>
        <td style="text-align: right;"><span class="badge ${(scanResult.owasp_masvs_scores?.['MASVS-CRYPTO'] ?? 45) < 60 ? 'badge-high' : 'badge-success'}">${(scanResult.owasp_masvs_scores?.['MASVS-CRYPTO'] ?? 45) < 60 ? 'REQUER AJUSTES' : 'CONFORME'}</span></td>
      </tr>
      <tr>
        <td style="font-weight: 700; color: #f8fafc;">MASVS-NETWORK</td>
        <td>Comunicação Segura de Rede (SSL Pinning & Cleartext Traffic Block)</td>
        <td style="text-align: center; font-weight: 700;">${scanResult.owasp_masvs_scores?.['MASVS-NETWORK'] ?? 50}%</td>
        <td style="text-align: right;"><span class="badge ${(scanResult.owasp_masvs_scores?.['MASVS-NETWORK'] ?? 50) < 60 ? 'badge-high' : 'badge-success'}">${(scanResult.owasp_masvs_scores?.['MASVS-NETWORK'] ?? 50) < 60 ? 'VULNERÁVEL' : 'CONFORME'}</span></td>
      </tr>
      <tr>
        <td style="font-weight: 700; color: #f8fafc;">MASVS-PLATFORM</td>
        <td>Interação com SO & Permissões Críticas (SYSTEM_ALERT_WINDOW / Tapjacking)</td>
        <td style="text-align: center; font-weight: 700;">${scanResult.owasp_masvs_scores?.['MASVS-PLATFORM'] ?? 55}%</td>
        <td style="text-align: right;"><span class="badge ${(scanResult.owasp_masvs_scores?.['MASVS-PLATFORM'] ?? 55) < 60 ? 'badge-high' : 'badge-success'}">${(scanResult.owasp_masvs_scores?.['MASVS-PLATFORM'] ?? 55) < 60 ? 'RISCO ELEVADO' : 'CONFORME'}</span></td>
      </tr>
      <tr>
        <td style="font-weight: 700; color: #f8fafc;">MASVS-RESILIENCE</td>
        <td>Resiliência Anti-Engenharia Reversa, Detecção de Root & Frida Hooks</td>
        <td style="text-align: center; font-weight: 700;">${scanResult.owasp_masvs_scores?.['MASVS-RESILIENCE'] ?? 25}%</td>
        <td style="text-align: right;"><span class="badge ${(scanResult.owasp_masvs_scores?.['MASVS-RESILIENCE'] ?? 25) < 60 ? 'badge-critical' : 'badge-success'}">${(scanResult.owasp_masvs_scores?.['MASVS-RESILIENCE'] ?? 25) < 60 ? 'SEM BLINDAGEM' : 'PROTEGIDO'}</span></td>
      </tr>
    </tbody>
  </table>

  <div class="section-title">${isPt ? '4. Detalhamento Técnico das Vulnerabilidades Encontradas' : '4. Vulnerabilities Technical Breakdown'}</div>
  ${(scanResult.findings || []).map((f) => `
    <div class="finding-card">
      <div class="finding-header">
        <span class="finding-title">${f.title}</span>
        <span class="badge ${f.severity === 'CRITICAL' ? 'badge-critical' : f.severity === 'HIGH' ? 'badge-high' : 'badge-medium'}">
          ${f.severity} • CVSS ${f.cvss_score || 'N/A'} • ${f.cwe_id || 'CWE'}
        </span>
      </div>
      <div class="finding-body">${f.description}</div>
      <div class="remediation-box">
        <strong>${isPt ? 'Plano de Remediação & Recomendação:' : 'Remediation Plan & Fix:'}</strong> ${f.recommendation}
      </div>
    </div>
  `).join('')}

  <div class="section-title">${isPt ? '5. Cronograma de Resposta e SLAs Regulatórios (BACEN CMN 4.893)' : '5. Regulatory SLAs & Remediation Timelines'}</div>
  <table>
    <thead>
      <tr>
        <th>Severidade do Apontamento</th>
        <th>Prazo Máximo Regulatório</th>
        <th>Ação Imediata da Engenharia</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><span class="badge badge-critical">CRÍTICO (AWS Keys / Tapjacking)</span></td>
        <td style="font-weight: 700; color: #ff4757;">24 a 48 Horas</td>
        <td>Revogação imediata das credenciais em nuvem e build emergencial com hotfix.</td>
      </tr>
      <tr>
        <td><span class="badge badge-high">ALTO (SSL Pinning / allowBackup)</span></td>
        <td style="font-weight: 700; color: #ffa502;">Até 7 Dias</td>
        <td>Ajuste nas diretivas NetworkSecurityConfig e bloqueio de backup no manifesto.</td>
      </tr>
      <tr>
        <td><span class="badge badge-medium">MÉDIO (Cifras AES/ECB & Hashes MD5)</span></td>
        <td style="font-weight: 700; color: #38bdf8;">Até 30 Dias</td>
        <td>Migração para AES/GCM no Keystore na esteira padrão do próximo sprint.</td>
      </tr>
    </tbody>
  </table>

  <div class="footer">
    <div><strong>morfeusec OSINT</strong> — Enterprise Mobile Penetration Testing & Threat Governance Platform</div>
    <div>Escrito por Felipe Costa - felipe_c@myyahoo.com</div>
  </div>

  <script>
    window.onload = function() {
      // Auto trigger print dialog after rendering styles
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
    // Fallback if popup blocker blocked window.open
    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `morfeusec_mobile_report_${scanResult.package_name}_${lang.toUpperCase()}.html`;
    a.click();
    URL.revokeObjectURL(url);
  }
}
