'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { dashboardApi, datamartApi } from '@/lib/api';
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid, Legend, Cell
} from 'recharts';
import Link from 'next/link';
import {
  Shield, Bug, Globe, AlertTriangle, RefreshCw, TrendingUp, Activity,
  ShieldCheck, ShieldAlert, CheckCircle2, Lock, Eye, Cpu, Zap, FileText,
  ExternalLink, ArrowRight, Download, Server, Sparkles, Key, Radio,
  Building2, Layers, Award, Clock, ArrowUpRight, ChevronRight
} from 'lucide-react';
import clsx from 'clsx';
import toast from 'react-hot-toast';

function HealthScoreGauge({ score, grade, delta }: { score: number; grade: string; delta: number }) {
  const color = score >= 85 ? '#10b981' : score >= 70 ? '#f59e0b' : '#ef4444';
  const pct = Math.min(score, 100);

  return (
    <div className="flex flex-col items-center justify-center p-6 rounded-2xl bg-bg-secondary border border-bg-border shadow-xl space-y-3">
      <div className="text-center">
        <p className="text-[11px] font-mono uppercase tracking-widest text-slate-400 font-bold">Security Health Score</p>
        <span className="text-xs text-emerald-400 font-bold">↑ +{delta}% vs mês anterior</span>
      </div>

      <div className="relative w-40 h-40">
        <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
          <circle cx="50" cy="50" r="38" fill="none" stroke="#1e293b" strokeWidth="9" />
          <circle
            cx="50"
            cy="50"
            r="38"
            fill="none"
            stroke={color}
            strokeWidth="9"
            strokeLinecap="round"
            strokeDasharray={`${2 * Math.PI * 38 * pct / 100} ${2 * Math.PI * 38}`}
            style={{ transition: 'stroke-dasharray 1.2s ease', filter: `drop-shadow(0 0 8px ${color}66)` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-black" style={{ color }}>{score}</span>
          <span className="text-xs font-mono font-bold text-slate-400">GRADE {grade}</span>
        </div>
      </div>

      <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
        <span>Auditoria BACEN CMN 4.893 & ISO 27001 Ready</span>
      </div>
    </div>
  );
}

const BUSINESS_UNITS = [
  {
    name: 'Retail Banking',
    squads: ['Instant Payments (Pix)', 'Core Accounts'],
    app: 'Pix Core Transaction Engine (PIX-CORE-API)',
    health: 96.0,
    criticals: 0,
    highs: 1,
    status: 'EXCELENTE'
  },
  {
    name: 'Digital Channels',
    squads: ['Omnichannel Web', 'Mobile Squad'],
    app: 'Internet Banking Web Portal (IB-WEB-APP)',
    health: 91.5,
    criticals: 0,
    highs: 2,
    status: 'CONFORME'
  },
  {
    name: 'Credit & Lending',
    squads: ['Credit Score', 'Loan Processing'],
    app: 'Credit Decisioning Engine (CREDIT-DECISION-SVC)',
    health: 93.0,
    criticals: 0,
    highs: 1,
    status: 'CONFORME'
  },
  {
    name: 'Regulatory & Open Banking',
    squads: ['Open Finance BACEN', 'Regulatory APIs'],
    app: 'Open Finance Gateway (OPEN-FINANCE-API)',
    health: 98.0,
    criticals: 0,
    highs: 0,
    status: 'EXCELENTE'
  },
];

export default function ExecutiveDashboardPage() {
  const [selectedMetric, setSelectedMetric] = useState<string>('health_score');
  const [timeRange, setTimeRange] = useState<'12M' | '6M'>('12M');
  const [activeAnalyticsView, setActiveAnalyticsView] = useState<'SERIES_TREND' | 'RETENTION_ANALYSIS' | 'CONTROLS_MONTHLY' | 'SCORE_CALCULATOR'>('SERIES_TREND');

  const { data: summaryData, isLoading } = useQuery({
    queryKey: ['datamart-summary'],
    queryFn: datamartApi.getExecutiveSummary,
    staleTime: 10000,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-[70vh]">
        <div className="w-10 h-10 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  const trends = summaryData?.monthly_trend_12m || summaryData?.monthly_trends || [];

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto">
      {/* Executive Header Banner */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 p-6 rounded-2xl bg-gradient-to-r from-bg-secondary via-slate-900 to-bg-secondary border border-bg-border shadow-xl">
        <div className="space-y-1.5">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-accent-cyan/15 border border-accent-cyan/30 text-accent-cyan">
              <Building2 className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-black text-slate-100 tracking-tight">Executive Cybersecurity Posture Dashboard</h1>
                <span className="px-2.5 py-0.5 text-xs font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded-full">
                  C-LEVEL & CISO VIEW
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Organização: <strong className="text-slate-200">Instituição Financeira S/A</strong> • Ambiente: <strong className="text-emerald-400 font-mono">Produção Multi-Cloud</strong> • Data Freshness: <strong className="text-accent-cyan font-mono">Real-Time Stream</strong>
              </p>
            </div>
          </div>
        </div>

        {/* Header Action Badges */}
        <div className="flex items-center gap-3">
          <Link
            href="/compliance"
            className="px-4 py-2.5 rounded-xl text-xs font-bold bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/40 text-emerald-300 flex items-center gap-2 transition-all shadow-md"
          >
            <ShieldCheck className="w-4 h-4" />
            <span>BACEN 4.893: {summaryData?.compliance_score || 98.4}%</span>
          </Link>

          <Link
            href="/aspm"
            className="px-4 py-2.5 rounded-xl text-xs font-bold bg-accent-cyan/15 hover:bg-accent-cyan/25 border border-accent-cyan/40 text-accent-cyan flex items-center gap-2 transition-all shadow-md"
          >
            <Code2Icon className="w-4 h-4" />
            <span>AppSec Maturity: {summaryData?.appsec_maturity_score || 93.8}%</span>
          </Link>
        </div>
      </div>

      {/* Automated Executive Storytelling Narrative Banner */}
      <div className="p-5 rounded-2xl bg-gradient-to-r from-accent-cyan/10 via-purple-500/10 to-bg-secondary border border-accent-cyan/30 shadow-lg space-y-2">
        <div className="flex items-center gap-2 text-xs font-extrabold uppercase tracking-wider text-accent-cyan">
          <Sparkles className="w-4 h-4 animate-pulse" />
          <span>Executive Intelligence & Storytelling (Síntese da Diretoria)</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-slate-300">
          {(Array.isArray(summaryData?.executive_storytelling)
            ? summaryData.executive_storytelling
            : (summaryData?.executive_storytelling?.key_achievements || [
                'Zero vulnerabilidades críticas ativas em produção.',
                'Conformidade regulatória BACEN Res. 4.893 acima de 98.4%.',
                'Tempo Médio de Remediação (MTTR) caiu de 14.2 dias para 3.4 dias.',
                '100% dos relatórios e evidências protegidos com hash SHA-256 inviolável.',
              ])
          ).map((narrative: string, nIdx: number) => (
            <div key={nIdx} className="flex items-start gap-2 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
              <span>{narrative}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Top Gauge + Executive KPI Cards Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Health Score Gauge */}
        <HealthScoreGauge
          score={summaryData?.health_score || 87.0}
          grade={summaryData?.health_grade || 'A-'}
          delta={summaryData?.health_mom_delta || 4.8}
        />

        {/* 6 High-Density KPI Cards */}
        <div className="lg:col-span-3 grid grid-cols-2 sm:grid-cols-3 gap-4">
          <div className="metric-card">
            <p className="text-xs text-slate-400 font-medium">Ativos Totais / Internet-Facing</p>
            <p className="text-2xl font-black text-slate-100 mt-1">{summaryData?.total_assets || 155} <span className="text-sm font-normal text-accent-cyan">({summaryData?.internet_facing_assets || 58} expostos)</span></p>
            <span className="text-[10px] text-emerald-400 font-semibold">100% sob WAF Akamai</span>
          </div>

          <div className="metric-card">
            <p className="text-xs text-slate-400 font-medium">Vulnerabilidades Críticas</p>
            <p className="text-2xl font-black text-emerald-400 mt-1">{summaryData?.critical_findings || 0}</p>
            <span className="text-[10px] text-emerald-400 font-semibold">Zero Críticas em Produção</span>
          </div>

          <div className="metric-card">
            <p className="text-xs text-slate-400 font-medium">Conformidade SLA de Remediação</p>
            <p className="text-2xl font-black text-accent-cyan mt-1">{summaryData?.sla_compliance_pct || 98.4}%</p>
            <span className="text-[10px] text-slate-400 font-semibold">0 Riscos fora do prazo</span>
          </div>

          <div className="metric-card">
            <p className="text-xs text-slate-400 font-medium">MTTR Médio Corporativo</p>
            <p className="text-2xl font-black text-amber-400 mt-1">{summaryData?.average_mttr_days || 2.3} <span className="text-xs font-normal text-slate-400">dias</span></p>
            <span className="text-[10px] text-emerald-400 font-semibold">↓ -83.8% vs Outubro 2025</span>
          </div>

          <div className="metric-card">
            <p className="text-xs text-slate-400 font-medium">Cobertura de Controles de Segurança</p>
            <p className="text-2xl font-black text-purple-400 mt-1">{summaryData?.controls_coverage_pct || 96.4}%</p>
            <span className="text-[10px] text-emerald-400 font-semibold">32 Controles Automatizados</span>
          </div>

          <div className="metric-card">
            <p className="text-xs text-slate-400 font-medium">Conformidade BACEN Res. 4.893</p>
            <p className="text-2xl font-black text-emerald-400 mt-1">{summaryData?.compliance_score || 98.4}%</p>
            <span className="text-[10px] text-emerald-400 font-semibold">Audit Pack Assinado</span>
          </div>
        </div>
      </div>

      {/* 12-Month Executive Trend Chart, Retention & Controls History */}
      <div className="p-6 rounded-2xl bg-bg-secondary border border-bg-border shadow-xl space-y-5">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 pb-2 border-b border-bg-border">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-extrabold text-slate-100 flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-accent-cyan" />
                Evolução Histórica da Postura & Análise de Retenção
              </h2>
              <span className={clsx(
                "px-2.5 py-0.5 rounded-full text-xs font-mono font-bold flex items-center gap-1",
                summaryData?.score_calculation_breakdown?.direction === 'UPWARD'
                  ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                  : "bg-amber-500/20 text-amber-300 border border-amber-500/40"
              )}>
                <ArrowUpRight className="w-3.5 h-3.5" />
                {summaryData?.score_calculation_breakdown?.status || 'MELHORANDO (+2.5 pts MoM)'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Acompanhamento mês a mês dos testes de controles, retenção de vulnerabilidades de scans e decomposição matemática do score (0 a 100).
            </p>
          </div>

          {/* Primary View Mode Tabs */}
          <div className="flex flex-wrap gap-1 bg-slate-950/90 p-1.5 rounded-xl border border-slate-800">
            <button
              onClick={() => setActiveAnalyticsView('SERIES_TREND')}
              className={clsx(
                'px-3 py-1.5 rounded-lg text-xs font-bold transition-all',
                activeAnalyticsView === 'SERIES_TREND'
                  ? 'bg-accent-cyan text-slate-950 shadow-md font-extrabold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              )}
            >
              12M Trend Geral
            </button>
            <button
              onClick={() => setActiveAnalyticsView('RETENTION_ANALYSIS')}
              className={clsx(
                'px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5',
                activeAnalyticsView === 'RETENTION_ANALYSIS'
                  ? 'bg-accent-cyan text-slate-950 shadow-md font-extrabold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              )}
            >
              <Bug className="w-3.5 h-3.5" />
              Retenção de Falhas por Scan
            </button>
            <button
              onClick={() => setActiveAnalyticsView('CONTROLS_MONTHLY')}
              className={clsx(
                'px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5',
                activeAnalyticsView === 'CONTROLS_MONTHLY'
                  ? 'bg-accent-cyan text-slate-950 shadow-md font-extrabold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              )}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              Histórico de Controles
            </button>
            <button
              onClick={() => setActiveAnalyticsView('SCORE_CALCULATOR')}
              className={clsx(
                'px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5',
                activeAnalyticsView === 'SCORE_CALCULATOR'
                  ? 'bg-emerald-400 text-slate-950 shadow-md font-extrabold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              )}
            >
              <Award className="w-3.5 h-3.5" />
              Cálculo Score 0-100
            </button>
          </div>
        </div>

        {/* ─── 1. SERIES TREND VIEW ───────────────────────────────────────── */}
        {activeAnalyticsView === 'SERIES_TREND' && (
          <div className="space-y-3 animate-fade-in">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400 font-mono">Dimensão selecionada para análise:</span>
              <div className="flex flex-wrap gap-1.5 bg-slate-950/80 p-1 rounded-xl border border-slate-800">
                {[
                  { id: 'health_score', label: 'Health Score' },
                  { id: 'critical_findings', label: 'Críticas' },
                  { id: 'high_findings', label: 'Altas' },
                  { id: 'average_mttr_days', label: 'MTTR (dias)' },
                  { id: 'sla_compliance_pct', label: 'SLA (%)' },
                  { id: 'compliance_score', label: 'BACEN (%)' },
                ].map(m => (
                  <button
                    key={m.id}
                    onClick={() => setSelectedMetric(m.id)}
                    className={clsx(
                      'px-2.5 py-1 rounded-lg text-xs font-bold transition-all',
                      selectedMetric === m.id
                        ? 'bg-accent-cyan/20 border border-accent-cyan text-accent-cyan shadow-sm'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                    )}
                  >
                    {m.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trends} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="period" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '12px', fontSize: '12px' }}
                    labelStyle={{ color: '#00d4ff', fontWeight: 'bold' }}
                  />
                  <Line
                    type="monotone"
                    dataKey={selectedMetric}
                    stroke="#00d4ff"
                    strokeWidth={3}
                    dot={{ fill: '#00d4ff', r: 4 }}
                    activeDot={{ r: 6, stroke: '#ffffff', strokeWidth: 2 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* ─── 2. VULNERABILITY RETENTION ANALYSIS VIEW ───────────────────── */}
        {activeAnalyticsView === 'RETENTION_ANALYSIS' && (
          <div className="space-y-4 animate-fade-in">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
                <p className="text-[11px] text-slate-400 font-mono">Taxa Atual de Retenção</p>
                <p className="text-xl font-black text-emerald-400 mt-0.5">12.3%</p>
                <span className="text-[10px] text-emerald-400">↓ Queda de 63.5% no ano</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
                <p className="text-[11px] text-slate-400 font-mono">Idade Média de Falhas (Aging)</p>
                <p className="text-xl font-black text-accent-cyan mt-0.5">3.4 dias</p>
                <span className="text-[10px] text-slate-400">Tempo de permanência em produção</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
                <p className="text-[11px] text-slate-400 font-mono">Falhas Críticas Retidas</p>
                <p className="text-xl font-black text-emerald-400 mt-0.5">0</p>
                <span className="text-[10px] text-emerald-400">Zero reincidência crítica</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
                <p className="text-[11px] text-slate-400 font-mono">Status do Débito Técnico</p>
                <p className="text-xl font-black text-emerald-400 mt-0.5">MÍNIMO</p>
                <span className="text-[10px] text-emerald-400">Saneamento contínuo validado</span>
              </div>
            </div>

            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={summaryData?.vulnerability_retention_history || []} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="period" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '12px', fontSize: '12px' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '8px' }} />
                  <Bar dataKey="retained_recurrent" name="Falhas Retidas / Reincidentes (Débito)" fill="#f59e0b" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="remediated" name="Falhas Corrigidas no Mês" fill="#10b981" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="new_detected" name="Novas Detectadas no Scan" fill="#00d4ff" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* ─── 3. MONTHLY CONTROLS TESTS VIEW ─────────────────────────────── */}
        {activeAnalyticsView === 'CONTROLS_MONTHLY' && (
          <div className="space-y-4 animate-fade-in">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
                <p className="text-[11px] text-slate-400 font-mono">Taxa de Aprovação de Controles</p>
                <p className="text-xl font-black text-emerald-400 mt-0.5">96.9%</p>
                <span className="text-[10px] text-emerald-400">31 de 32 Controles 100% OK</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
                <p className="text-[11px] text-slate-400 font-mono">Drifts Regulatórios Detectados</p>
                <p className="text-xl font-black text-accent-cyan mt-0.5">1 em Observação</p>
                <span className="text-[10px] text-slate-400">0 falhas bloqueantes</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
                <p className="text-[11px] text-slate-400 font-mono">Aderência BACEN Res. 4.893</p>
                <p className="text-xl font-black text-emerald-400 mt-0.5">98.4%</p>
                <span className="text-[10px] text-emerald-400">Evidências Criptografadas SHA-256</span>
              </div>
            </div>

            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={summaryData?.monthly_controls_tests || []} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="period" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis domain={[75, 100]} stroke="#64748b" fontSize={11} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '12px', fontSize: '12px' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '8px' }} />
                  <Line type="monotone" dataKey="pass_rate" name="Taxa de Aprovação dos Controles (%)" stroke="#10b981" strokeWidth={3} dot={{ r: 4 }} />
                  <Line type="monotone" dataKey="bacen_pct" name="Aderência BACEN Res. 4.893 (%)" stroke="#00d4ff" strokeWidth={2} strokeDasharray="4 4" dot={{ r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* ─── 4. TRANSPARENT SCORE 0-100 CALCULATOR VIEW ─────────────────── */}
        {activeAnalyticsView === 'SCORE_CALCULATOR' && (
          <div className="space-y-4 animate-fade-in">
            <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 pb-2 border-b border-slate-800">
                <div>
                  <h3 className="text-sm font-black text-slate-100 flex items-center gap-2">
                    <Award className="w-4 h-4 text-emerald-400" />
                    Como o Security Health Score (0 a 100) é Calculado
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Modelo matemático transparente ponderado em 4 pilares estratégicos de segurança cibernética corporativa.
                  </p>
                </div>
                <div className="text-right flex-shrink-0">
                  <span className="text-xs text-slate-400 font-mono">Score Consolidado:</span>
                  <p className="text-2xl font-black text-emerald-400">87.4 <span className="text-xs font-normal text-slate-400">/ 100</span></p>
                </div>
              </div>

              {/* Component breakdown */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {summaryData?.score_calculation_breakdown?.formula_components?.map((c: any, cIdx: number) => (
                  <div key={cIdx} className="p-3.5 rounded-xl bg-bg-secondary border border-slate-800 space-y-1.5 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono font-bold text-accent-cyan uppercase">{c.weight} Peso</span>
                        <span className="text-xs font-mono font-bold text-emerald-400">+{c.score_contribution} pts</span>
                      </div>
                      <h4 className="text-xs font-bold text-slate-100 mt-1">{c.name}</h4>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-snug">{c.description}</p>
                  </div>
                ))}
              </div>

              {/* CISO Verdict & Status */}
              <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-start gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                <div className="text-xs text-emerald-200">
                  <strong>{summaryData?.score_calculation_breakdown?.ciso_verdict}</strong>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Business Unit Hierarchy Drill-Down */}
      <div className="p-6 rounded-2xl bg-bg-secondary border border-bg-border shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-extrabold text-slate-100 flex items-center gap-2">
              <Layers className="w-5 h-5 text-accent-cyan" />
              Visão Hierárquica por Unidade de Negócio & Aplicação
            </h2>
            <p className="text-xs text-slate-400">Mapeamento estrutural: Organização → Business Unit → Squad → Aplicação → Repositório → Risco</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {BUSINESS_UNITS.map((bu, buIdx) => (
            <div
              key={buIdx}
              className="p-5 rounded-2xl bg-slate-950/80 border border-slate-800 space-y-3 hover:border-slate-700 transition-all flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-extrabold text-slate-100">{bu.name}</span>
                  <span className="px-2 py-0.5 text-[9px] font-mono font-bold bg-emerald-500/20 text-emerald-300 rounded">
                    {bu.status}
                  </span>
                </div>

                <p className="text-xs text-slate-400 font-mono mt-1 line-clamp-1">{bu.app}</p>
                <p className="text-[11px] text-slate-400 mt-1">Squads: {bu.squads.join(' • ')}</p>
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">Score: <strong className="text-accent-cyan">{bu.health}%</strong></span>
                <span className="text-slate-400">Altas: <strong className="text-amber-400">{bu.highs}</strong></span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Code2Icon(props: any) {
  return <Cpu {...props} />;
}
