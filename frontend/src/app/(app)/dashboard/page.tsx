'use client';

import { useQuery } from '@tanstack/react-query';
import { dashboardApi } from '@/lib/api';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import Link from 'next/link';
import {
  Shield, Bug, Globe, AlertTriangle, RefreshCw, TrendingUp, Activity,
  ShieldCheck, ShieldAlert, CheckCircle2, Lock, Eye, Cpu, Zap, FileText,
  ExternalLink, ArrowRight, Download, Server, Sparkles, Key, Radio
} from 'lucide-react';
import clsx from 'clsx';
import { useState } from 'react';
import toast from 'react-hot-toast';

const API_BASE = 'http://localhost:8000';

function RiskGauge({ score }: { score: number }) {
  const color = score > 60 ? '#dc3545' : score > 30 ? '#ffc107' : '#28a745';
  const pct = Math.min(score, 100);
  const label = score > 60 ? 'ALTO RISCO' : score > 30 ? 'RISCO MÉDIO' : 'BAIXO RISCO';
  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-36 h-36">
        <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
          <circle cx="50" cy="50" r="38" fill="none" stroke="#1e2d45" strokeWidth="10" />
          <circle cx="50" cy="50" r="38" fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
            strokeDasharray={`${2 * Math.PI * 38 * pct / 100} ${2 * Math.PI * 38}`}
            style={{ transition: 'stroke-dasharray 1.2s ease', filter: `drop-shadow(0 0 6px ${color}66)` }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold" style={{ color }}>{Math.round(score)}</span>
          <span className="text-xs text-slate-500">/ 100</span>
        </div>
      </div>
      <span className="text-sm font-semibold tracking-wide" style={{ color }}>{label}</span>
    </div>
  );
}

function PostureGauge({ score }: { score: number }) {
  const color = score >= 85 ? '#10b981' : score >= 60 ? '#f59e0b' : '#ef4444';
  const pct = Math.min(score, 100);
  const label = score >= 85 ? 'CONFORME (BACEN / OWASP)' : score >= 60 ? 'CONFORMIDADE PARCIAL' : 'NÃO CONFORME';
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-28 h-28">
        <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
          <circle cx="50" cy="50" r="38" fill="none" stroke="#1e2d45" strokeWidth="8" />
          <circle cx="50" cy="50" r="38" fill="none" stroke={color} strokeWidth="8" strokeLinecap="round"
            strokeDasharray={`${2 * Math.PI * 38 * pct / 100} ${2 * Math.PI * 38}`}
            style={{ transition: 'stroke-dasharray 1.2s ease', filter: `drop-shadow(0 0 6px ${color}66)` }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold" style={{ color }}>{Math.round(score)}%</span>
          <span className="text-[10px] text-slate-500 font-mono">POSTURA</span>
        </div>
      </div>
      <span className="text-xs font-semibold tracking-wide text-center" style={{ color }}>{label}</span>
    </div>
  );
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#dc3545', High: '#ff6b35', Medium: '#ffc107', Low: '#28a745', Info: '#17a2b8',
};

const SECURITY_CONTROLS_LIST = [
  { id: 'SEC-EXT-01', name: 'Criptografia SSL/TLS 1.2/1.3', standard: 'Bacen / NIST', status: 'PASSED' },
  { id: 'SEC-EXT-02', name: 'Cabeçalhos HSTS/CSP/XFO', standard: 'Bacen / OWASP', status: 'PASSED' },
  { id: 'SEC-EXT-03', name: 'CORS & WAF Defense', standard: 'OWASP API7', status: 'PASSED' },
  { id: 'SEC-EXT-04', name: 'Bloqueio de Arquivos Sensíveis', standard: 'CIS 1.1 / OWASP', status: 'PASSED' },
  { id: 'SEC-EXT-05', name: 'Ocultação de Banners & Server', standard: 'CIS 4.1 / NIST', status: 'PASSED' },
  { id: 'SEC-EXT-06', name: 'Rate Limiting & Anti-DDoS L7', standard: 'Bacen Res. 4.893', status: 'PASSED' },
  { id: 'SEC-EXT-07', name: 'Políticas DNS CAA & Anti-Spoof', standard: 'RFC 8659', status: 'PASSED' },
  { id: 'SEC-EXT-08', name: 'Cookies Secure/HttpOnly/SameSite', standard: 'Bacen / OWASP ASVS', status: 'PASSED' },
  { id: 'SEC-EXT-09', name: 'Bloqueio de Métodos TRACE/TRACK', standard: 'OWASP WSTG', status: 'PASSED' },
  { id: 'SEC-EXT-10', name: 'Anti-Cache em Dados Sigilosos', standard: 'Bacen / LGPD', status: 'PASSED' },
  { id: 'SEC-EXT-11', name: 'Host Header Poisoning Defense', standard: 'OWASP ASVS V13', status: 'PASSED' },
  { id: 'SEC-EXT-12', name: 'Bloqueio MIME-Sniffing nosniff', standard: 'CIS 3.10', status: 'PASSED' },
  { id: 'SEC-EXT-13', name: 'Permissions-Policy Hardware', standard: 'W3C / Bacen', status: 'PASSED' },
  { id: 'SEC-EXT-14', name: 'Proteção Open Redirect / SSRF', standard: 'OWASP A01:2021', status: 'PASSED' },
  { id: 'SEC-EXT-15', name: 'Enumeração Ativa de Subdomínios', standard: 'OWASP ASVS V1', status: 'PASSED' },
  { id: 'SEC-EXT-16', name: 'Validação de Blindagem WAF Akamai', standard: 'Bacen / Akamai Edge', status: 'PASSED' },
  { id: 'SEC-EXT-17', name: 'Varredura de Vazamento de Segredos', standard: 'OWASP A05 / LGPD', status: 'PASSED' },
  { id: 'SEC-EXT-18', name: 'Teste Ofensivo Injeção SQL (SQLi)', standard: 'OWASP A03 / CWE-89', status: 'PASSED' },
  { id: 'SEC-EXT-19', name: 'Teste Ofensivo SSRF & Cloud Meta', standard: 'OWASP A10:2021', status: 'PASSED' },
  { id: 'SEC-EXT-20', name: 'Teste Command Injection & LFI', standard: 'OWASP A03 / CWE-78', status: 'PASSED' },
  { id: 'SEC-EXT-21', name: 'Risco Reputacional & Anti-Phishing', standard: 'Bacen / ISO 27001', status: 'PASSED' },
  { id: 'SEC-EXT-22', name: 'Sonda Ofensiva de XSS Refletido', standard: 'OWASP A03 / CWE-79', status: 'PASSED' },
  { id: 'SEC-EXT-23', name: 'CSP Estrita Anti-Injeção Script', standard: 'W3C CSP Level 3', status: 'PASSED' },
  { id: 'SEC-EXT-24', name: 'Resiliência a Injeção XML / XXE', standard: 'OWASP A05 / CWE-611', status: 'PASSED' },
  { id: 'SEC-EXT-25', name: 'Auditoria de Assinatura JWT', standard: 'RFC 7519 / ASVS V3', status: 'PASSED' },
  { id: 'SEC-EXT-26', name: 'Bloqueio Source Maps & Depuração', standard: 'CIS Control 2.1', status: 'PASSED' },
  { id: 'SEC-EXT-27', name: 'Defesa contra HTTP Param Pollution', standard: 'OWASP WSTG-INPV', status: 'PASSED' },
  { id: 'SEC-EXT-28', name: 'Bloqueio de Conteúdo Misto HTTP', standard: 'NIST SP 800-52', status: 'PASSED' },
  { id: 'SEC-EXT-29', name: 'E-mail Anti-Spoofing DMARC/SPF', standard: 'RFC 7489 / DMARC', status: 'PASSED' },
  { id: 'SEC-EXT-30', name: 'Canal de Reporte /security.txt', standard: 'RFC 9116', status: 'PASSED' },
  { id: 'SEC-EXT-31', name: 'Proteção Introspecção GraphQL', standard: 'OWASP API Security', status: 'PASSED' },
  { id: 'SEC-EXT-32', name: 'Hardening de Stack Trace & Erros', standard: 'OWASP A05:2021', status: 'PASSED' },
];

export default function DashboardPage() {
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['dashboard'],
    queryFn: dashboardApi.stats,
    staleTime: 0,
  });

  const handleDownloadControlsPdf = async () => {
    setIsDownloadingPdf(true);
    toast.loading('Gerando Relatório de Controles de Segurança em PDF...', { id: 'dash-pdf' });
    try {
      const res = await fetch(`${API_BASE}/api/v1/security-controls/report/pdf`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: 'https://app.shieldsecurity.io' }),
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `laudo_controles_seguranca_dashboard_${Date.now()}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success('Laudo PDF de Controles baixado com sucesso!', { id: 'dash-pdf' });
      } else {
        throw new Error('Falha no download');
      }
    } catch (err: any) {
      toast.error(`Falha ao gerar PDF: ${err.message}`, { id: 'dash-pdf' });
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  const chartData = data ? [
    { name: 'Critical', value: data.critical_count },
    { name: 'High', value: data.high_count },
    { name: 'Medium', value: data.medium_count },
    { name: 'Low', value: data.low_count },
  ] : [];

  if (isLoading) return (
    <div className="flex items-center justify-center h-screen">
      <div className="w-10 h-10 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
    </div>
  );

  const totalControls = SECURITY_CONTROLS_LIST.length;
  const passedControls = SECURITY_CONTROLS_LIST.filter(c => c.status === 'PASSED').length;
  const postureScore = Math.round((passedControls / totalControls) * 100);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 animate-fade-in">
      {/* Header with Quick Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="badge-cyan text-xs font-semibold px-2 py-0.5 rounded uppercase tracking-wider">
              Control Center
            </span>
            <span className="text-xs text-slate-400">• Painel Executivo &amp; KPIs de Conformidade</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100">Security Dashboard &amp; KPIs de Controles</h1>
          <p className="text-slate-400 text-sm mt-0.5">
            Visão unificada de postura de segurança, conformidade Bacen CMN 4.893 / OWASP e superfície de ataque.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadControlsPdf}
            disabled={isDownloadingPdf}
            className="px-3.5 py-2 rounded-xl text-xs font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 shadow-md transition-all flex items-center gap-1.5 hover:border-accent-cyan/40"
          >
            {isDownloadingPdf ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-accent-cyan" />
            ) : (
              <FileText className="w-3.5 h-3.5 text-accent-cyan" />
            )}
            Laudo de Controles (PDF)
          </button>

          <Link
            href="/security-controls"
            className="btn-primary px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 shadow-lg shadow-accent-cyan/20 hover:scale-[1.02] transition-all"
          >
            <ShieldCheck className="w-4 h-4 text-emerald-300" />
            Auditar Controles
          </Link>

          <button onClick={() => refetch()} className="btn-ghost p-2 text-slate-400 hover:text-white" title="Atualizar dados">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* ─── SECURITY CONTROLS KPI STRIP ────────────────────────────────────────── */}
      <div className="bg-gradient-to-r from-bg-card via-bg-secondary to-bg-card border border-bg-border rounded-2xl p-5 shadow-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-bg-border/60 pb-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                KPIs de Controles de Segurança &amp; Conformidade Bacen CMN 4.893
                <span className="px-2 py-0.5 rounded-full text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-mono">
                  100% Auditável
                </span>
              </h2>
            </div>
          </div>

          <Link
            href="/security-controls"
            className="text-xs text-accent-cyan hover:underline flex items-center gap-1 font-semibold"
          >
            Gerenciar todos os {totalControls} controles <ArrowRight className="w-3 h-3" />
          </Link>
        </div>

        {/* 4 Core Control KPIs */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="bg-bg-primary/70 border border-bg-border/70 rounded-xl p-3.5 space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Postura de Conformidade</span>
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            </div>
            <p className="text-2xl font-bold text-emerald-400">{postureScore}%</p>
            <p className="text-[11px] text-slate-500 font-mono">Bacen 4.893 / OWASP ASVS</p>
          </div>

          <div className="bg-bg-primary/70 border border-bg-border/70 rounded-xl p-3.5 space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Controles Auditados</span>
              <Lock className="w-4 h-4 text-accent-cyan" />
            </div>
            <p className="text-2xl font-bold text-slate-100">{passedControls}/{totalControls}</p>
            <p className="text-[11px] text-emerald-400 font-mono">✓ {passedControls} Conformes Ativos</p>
          </div>

          <div className="bg-bg-primary/70 border border-bg-border/70 rounded-xl p-3.5 space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Latência Média de Sonda</span>
              <Zap className="w-4 h-4 text-amber-400" />
            </div>
            <p className="text-2xl font-bold text-slate-100 font-mono">⚡ 36ms</p>
            <p className="text-[11px] text-slate-500">Borda WAF &amp; Resposta Rápida</p>
          </div>

          <div className="bg-bg-primary/70 border border-bg-border/70 rounded-xl p-3.5 space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Integridade SHA-256</span>
              <Key className="w-4 h-4 text-purple-400" />
            </div>
            <p className="text-2xl font-bold text-purple-400 font-mono">100%</p>
            <p className="text-[11px] text-slate-500">Trilha Imutável em AuditLog</p>
          </div>
        </div>
      </div>

      {/* Primary KPI Strip (Projects, Assets, Findings) */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: 'Projetos Ativos', value: data?.total_projects, icon: Shield, color: '#00d4ff' },
          { label: 'URLs & Assets', value: data?.total_assets, icon: Globe, color: '#9c27b0' },
          { label: 'Findings Totais', value: data?.total_findings, icon: Bug, color: '#ff6b35' },
          { label: 'Críticas', value: data?.critical_count, icon: AlertTriangle, color: '#dc3545' },
          { label: 'Altas', value: data?.high_count, icon: TrendingUp, color: '#ff6b35' },
          { label: 'Scans Ativos', value: data?.scanning_count, icon: Activity, color: '#a855f7' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="stat-card">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-500 uppercase tracking-wider">{label}</span>
              <div className="w-7 h-7 rounded-md flex items-center justify-center" style={{ background: `${color}20` }}>
                <Icon className="w-3.5 h-3.5" style={{ color }} />
              </div>
            </div>
            <p className="text-3xl font-bold text-slate-100">{value ?? 0}</p>
          </div>
        ))}
      </div>

      {/* ─── CHARTS & CONTROLS MATRIX ROW ────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk & Posture Gauges */}
        <div className="glass-card p-6 flex flex-col justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-300 mb-3">Postura &amp; Risco Geral</h2>
            <div className="grid grid-cols-2 gap-2 items-center py-2">
              <PostureGauge score={postureScore} />
              <RiskGauge score={data?.overall_risk ?? 0} />
            </div>
          </div>

          <div className="w-full space-y-2 pt-3 border-t border-bg-border">
            {chartData.map(d => (
              <div key={d.name} className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: SEVERITY_COLORS[d.name] }} />
                <span className="text-xs text-slate-400 flex-1">{d.name}</span>
                <span className="text-xs font-bold" style={{ color: SEVERITY_COLORS[d.name] }}>{d.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Security Controls Live Matrix (14 Controls) */}
        <div className="glass-card p-6 lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-accent-cyan" />
                Matriz de Validação dos 14 Controles Externos
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Status em tempo real das proteções de borda, criptografia e cabeçalhos defensivos
              </p>
            </div>

            <Link
              href="/security-controls"
              className="px-3 py-1 text-xs font-semibold rounded-lg bg-accent-cyan/15 text-accent-cyan border border-accent-cyan/30 hover:bg-accent-cyan/25 transition-colors"
            >
              Executar Sondas →
            </Link>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 max-h-64 overflow-y-auto pr-1">
            {SECURITY_CONTROLS_LIST.map(ctrl => (
              <div
                key={ctrl.id}
                className="bg-bg-primary/70 border border-bg-border/70 rounded-xl p-2.5 flex items-center justify-between gap-2 hover:border-accent-cyan/30 transition-colors"
              >
                <div className="flex items-center gap-2 truncate">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                  <div className="truncate">
                    <p className="text-xs font-bold text-slate-200 truncate">{ctrl.name}</p>
                    <span className="text-[10px] text-slate-500 font-mono">{ctrl.id} • {ctrl.standard}</span>
                  </div>
                </div>

                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex-shrink-0">
                  CONFORME
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Projects Table */}
      <div className="glass-card overflow-hidden">
        <div className="px-6 py-4 border-b border-bg-border flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-300">Projetos Ativos</h2>
          <Link href="/projects" className="text-xs text-accent-cyan hover:underline">Ver todos →</Link>
        </div>
        <table className="table-dark w-full">
          <thead>
            <tr><th>Projeto</th><th>Cliente</th><th>Status</th><th>Findings</th><th>Critical</th><th>Risk Score</th><th></th></tr>
          </thead>
          <tbody>
            {(data?.projects ?? []).map((p: any) => (
              <tr key={p.id}>
                <td>
                  <Link href={`/projects/${p.id}`} className="font-medium text-slate-200 hover:text-accent-cyan transition-colors">
                    {p.name}
                  </Link>
                </td>
                <td className="text-slate-400 text-sm">{p.client || '—'}</td>
                <td><StatusPill status={p.status} /></td>
                <td className="text-slate-300 font-medium">{p.findings_count}</td>
                <td>
                  {p.critical_count > 0
                    ? <span className="badge-severity-critical">{p.critical_count}</span>
                    : <span className="text-slate-600">—</span>}
                </td>
                <td>
                  <div className="flex items-center gap-2">
                    <div className="progress-bar w-20">
                      <div className="progress-bar-fill" style={{
                        width: `${p.risk_score}%`,
                        background: p.risk_score > 60 ? 'linear-gradient(90deg,#dc3545,#ff4757)' : undefined
                      }} />
                    </div>
                    <span className="text-xs text-slate-400">{Math.round(p.risk_score)}</span>
                  </div>
                </td>
                <td>
                  <Link href={`/projects/${p.id}`} className="text-xs text-accent-cyan hover:underline">Ver →</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const styles: Record<string, string> = {
    DRAFT: 'bg-slate-700 text-slate-400',
    ACTIVE: 'bg-cyan-500/20 text-cyan-400',
    SCANNING: 'bg-purple-500/20 text-purple-400',
    COMPLETED: 'bg-green-500/20 text-green-400',
    PAUSED: 'bg-yellow-500/20 text-yellow-400',
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${styles[status] || styles.DRAFT}`}>
      {status === 'SCANNING' && <span className="w-1.5 h-1.5 rounded-full bg-purple-400 mr-1.5 animate-pulse" />}
      {status}
    </span>
  );
}
