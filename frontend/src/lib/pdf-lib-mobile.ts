import { PDFDocument, rgb, StandardFonts } from 'pdf-lib';
import { MobileScanResult } from './api';

export async function generateMobilePentestPdfBlob(
  scanResult: MobileScanResult,
  lang: 'pt' | 'en' = 'pt'
): Promise<Uint8Array> {
  const pdfDoc = await PDFDocument.create();
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const fontRegular = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontMono = await pdfDoc.embedFont(StandardFonts.Courier);

  const isPt = lang === 'pt';
  const bgDark = rgb(8 / 255, 13 / 255, 26 / 255);
  const cardDark = rgb(15 / 255, 23 / 255, 42 / 255);
  const cyan = rgb(0 / 255, 230 / 255, 118 / 255);
  const blue = rgb(56 / 255, 189 / 255, 248 / 255);
  const textWhite = rgb(248 / 255, 250 / 255, 252 / 255);
  const textMuted = rgb(148 / 255, 163 / 255, 184 / 255);
  const borderCol = rgb(30 / 255, 45 / 255, 69 / 255);
  const danger = rgb(1, 0.28, 0.34);

  // Page 1: Overview & MASVS Matrix
  const page1 = pdfDoc.addPage([595.28, 841.89]);
  const { width, height } = page1.getSize();

  // Background
  page1.drawRectangle({ x: 0, y: 0, width, height, color: bgDark });

  // Top header line
  page1.drawLine({
    start: { x: 36, y: height - 30 },
    end: { x: width - 36, y: height - 30 },
    thickness: 1,
    color: cyan,
  });

  page1.drawText('morfeusec OSINT — MOBILE SECURITY AUDIT DOSSIER (OWASP MASVS & DAST)', {
    x: 36,
    y: height - 24,
    size: 7,
    font: fontBold,
    color: cyan,
  });

  page1.drawText('BACEN CMN 4.893 & NIST SP 800-115', {
    x: width - 180,
    y: height - 24,
    size: 7,
    font: fontRegular,
    color: textMuted,
  });

  let y = height - 55;

  page1.drawText(
    isPt ? 'LAUDO EXECUTIVO DE AUDITORIA MOBILE (OWASP MASVS v2.0)' : 'EXECUTIVE MOBILE SECURITY AUDIT REPORT (OWASP MASVS v2.0)',
    { x: 36, y, size: 13, font: fontBold, color: cyan }
  );
  y -= 15;

  page1.drawText(
    `Pacote: ${scanResult.package_name} | Versão: ${scanResult.app_version} | Emissão: ${new Date().toLocaleString('pt-BR')}`,
    { x: 36, y, size: 8, font: fontRegular, color: textMuted }
  );
  y -= 25;

  // Scope Info Box
  page1.drawRectangle({
    x: 36,
    y: y - 75,
    width: width - 72,
    height: 75,
    color: cardDark,
    borderColor: borderCol,
    borderWidth: 1,
  });

  page1.drawText(`Aplicativo: ${scanResult.package_name}`, { x: 48, y: y - 20, size: 8.5, font: fontBold, color: blue });
  page1.drawText(`Plataforma: ${scanResult.platform} (${scanResult.filename})`, { x: 48, y: y - 35, size: 8, font: fontRegular, color: textWhite });
  page1.drawText(`Target SDK: ${scanResult.target_sdk} | Min SDK: ${scanResult.min_sdk}`, { x: 48, y: y - 50, size: 8, font: fontRegular, color: textMuted });
  page1.drawText(`Classificação: Grau ${scanResult.risk_grade} (Score: ${scanResult.risk_score}/100)`, { x: 48, y: y - 65, size: 8, font: fontBold, color: scanResult.risk_score > 60 ? danger : cyan });

  page1.drawText('Auditor: Felipe Costa (felipe_c@myyahoo.com)', { x: width - 250, y: y - 20, size: 8, font: fontBold, color: textWhite });
  page1.drawText('Metodologia: SAST/DAST & Reverse Eng.', { x: width - 250, y: y - 35, size: 8, font: fontRegular, color: textMuted });
  page1.drawText('Padrão: OWASP MASVS L1/L2', { x: width - 250, y: y - 50, size: 8, font: fontRegular, color: cyan });

  y -= 95;

  // KPIs
  const kpis = [
    { label: 'TOTAL DE FALHAS', val: `${scanResult.findings_summary?.total || scanResult.findings?.length || 0}`, color: textWhite },
    { label: 'CRÍTICAS (SLA 24H)', val: `${scanResult.findings_summary?.critical || 0}`, color: danger },
    { label: 'ALTAS (SLA 7D)', val: `${scanResult.findings_summary?.high || 0}`, color: rgb(1, 0.65, 0) },
    { label: 'CHAVES EXPOSTAS', val: `${scanResult.hardcoded_secrets?.length || 0}`, color: (scanResult.hardcoded_secrets?.length || 0) > 0 ? danger : cyan },
  ];

  const boxW = 125;
  kpis.forEach((k, idx) => {
    const bx = 36 + idx * (boxW + 7);
    page1.drawRectangle({
      x: bx,
      y: y - 45,
      width: boxW,
      height: 45,
      color: cardDark,
      borderColor: borderCol,
      borderWidth: 1,
    });
    page1.drawText(k.label, { x: bx + 8, y: y - 16, size: 7, font: fontBold, color: textMuted });
    page1.drawText(k.val, { x: bx + 8, y: y - 36, size: 12, font: fontBold, color: k.color });
  });

  y -= 65;

  // MASVS Scores Table
  page1.drawText('ADERÊNCIA AOS CONTROLES OWASP MASVS v2.0', { x: 36, y, size: 9, font: fontBold, color: blue });
  y -= 15;

  const masvsRows = [
    { code: 'MASVS-STORAGE', name: 'Armazenamento Seguro e Proteção de Dados (allowBackup, SQLite)', score: scanResult.owasp_masvs_scores?.['MASVS-STORAGE'] ?? 40 },
    { code: 'MASVS-CRYPTO', name: 'Criptografia Forte e Gerenciamento de Chaves Keystore', score: scanResult.owasp_masvs_scores?.['MASVS-CRYPTO'] ?? 45 },
    { code: 'MASVS-NETWORK', name: 'Comunicação Segura de Rede (SSL Pinning & Cleartext Block)', score: scanResult.owasp_masvs_scores?.['MASVS-NETWORK'] ?? 50 },
    { code: 'MASVS-PLATFORM', name: 'Interação com SO & Permissões Críticas (Overlay Tapjacking)', score: scanResult.owasp_masvs_scores?.['MASVS-PLATFORM'] ?? 55 },
    { code: 'MASVS-RESILIENCE', name: 'Anti-Engenharia Reversa, Detecção de Root & Frida Hooks', score: scanResult.owasp_masvs_scores?.['MASVS-RESILIENCE'] ?? 25 },
  ];

  for (const m of masvsRows) {
    page1.drawRectangle({
      x: 36,
      y: y - 24,
      width: width - 72,
      height: 24,
      color: cardDark,
      borderColor: borderCol,
      borderWidth: 0.5,
    });

    page1.drawText(m.code, { x: 44, y: y - 16, size: 7.5, font: fontBold, color: blue });
    page1.drawText(m.name, { x: 145, y: y - 16, size: 7.5, font: fontRegular, color: textWhite });
    page1.drawText(`${m.score}%`, { x: width - 110, y: y - 16, size: 8, font: fontBold, color: m.score >= 70 ? cyan : danger });
    page1.drawText(m.score >= 70 ? 'CONFORME' : 'NÃO CONFORME', { x: width - 80, y: y - 16, size: 7, font: fontBold, color: m.score >= 70 ? cyan : danger });

    y -= 27;
  }

  y -= 15;

  // Findings Breakdown Section
  page1.drawText('VULNERABILIDADES & FALHAS DE SEGURANÇA DETECTADAS', { x: 36, y, size: 9, font: fontBold, color: blue });
  y -= 15;

  const findings = scanResult.findings || [];
  for (let i = 0; i < Math.min(findings.length, 4); i++) {
    const f = findings[i];
    const cardH = 50;
    page1.drawRectangle({
      x: 36,
      y: y - cardH,
      width: width - 72,
      height: cardH,
      color: bgDark,
      borderColor: borderCol,
      borderWidth: 1,
    });

    const isCrit = f.severity === 'CRITICAL';
    page1.drawText(f.title, { x: 44, y: y - 15, size: 8, font: fontBold, color: textWhite });
    page1.drawText(`${f.severity} • CVSS ${f.cvss_score || 'N/A'} • ${f.cwe_id || 'CWE'}`, { x: width - 180, y: y - 15, size: 7, font: fontBold, color: isCrit ? danger : rgb(1, 0.65, 0) });

    const safeDesc = (f.description || '').length > 90 ? (f.description || '').slice(0, 90) + '...' : (f.description || '');
    page1.drawText(safeDesc, { x: 44, y: y - 28, size: 7, font: fontRegular, color: textMuted });

    const safeFix = (f.recommendation || '').length > 80 ? (f.recommendation || '').slice(0, 80) + '...' : (f.recommendation || '');
    page1.drawText(`Correção: ${safeFix}`, { x: 44, y: y - 40, size: 7, font: fontRegular, color: cyan });

    y -= cardH + 8;
  }

  // Footer on Page 1
  page1.drawLine({ start: { x: 36, y: 36 }, end: { x: width - 36, y: 36 }, thickness: 0.8, color: borderCol });
  page1.drawText('ESTRITAMENTE CONFIDENCIAL • Escrito por Felipe Costa - felipe_c@myyahoo.com', { x: 36, y: 26, size: 7, font: fontRegular, color: textMuted });
  page1.drawText('Página 1 de 1', { x: width - 90, y: 26, size: 7, font: fontRegular, color: textMuted });

  return await pdfDoc.save();
}
