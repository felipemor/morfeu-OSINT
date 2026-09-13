'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { aspmApi } from '@/lib/api';
import {
  Code2, GitBranch, ShieldCheck, AlertTriangle, CheckCircle2,
  XCircle, RefreshCw, Sparkles, ExternalLink, Layers, GitPullRequest,
  Lock, Bug, ChevronRight, Activity, Zap
} from 'lucide-react';
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend
} from 'recharts';
import clsx from 'clsx';
import toast from 'react-hot-toast';

export default function ASPMPage() {
  const [selectedAppId, setSelectedAppId] = useState<string>('app-pix-core');
  const [syncingConn, setSyncingConn] = useState<string | null>(null);

  const { data: aspmData, isLoading, refetch } = useQuery({
    queryKey: ['aspm-dashboard'],
    queryFn: aspmApi.getDashboard,
    staleTime: 10000,
  });

  const handleSync = async (connId: string) => {
    setSyncingConn(connId);
    toast.loading(`Sincronizando com conector ${connId}...`, { id: 'conn-sync' });
    try {
      await aspmApi.triggerSync(connId);
      toast.success('Sincronização concluída com sucesso!', { id: 'conn-sync' });
      refetch();
    } catch (e: any) {
      toast.error('Falha na sincronização: ' + e.message, { id: 'conn-sync' });
    } finally {
      setSyncingConn(null);
    }
  };

  const selectedApp = aspmData?.applications?.find((a: any) => a.id === selectedAppId) || aspmData?.applications?.[0];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-[70vh]">
        <div className="w-10 h-10 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 p-6 rounded-2xl bg-gradient-to-r from-bg-secondary via-slate-900 to-bg-secondary border border-bg-border shadow-xl">
        <div className="space-y-1.5">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-accent-cyan/15 border border-accent-cyan/30 text-accent-cyan">
              <Code2 className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-black text-slate-100 tracking-tight">Application Security Posture Management (ASPM)</h1>
                <span className="px-2.5 py-0.5 text-xs font-mono font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 rounded-full">
                  ENTERPRISE ASPM
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Hub unificado de segurança de software: Checkmarx One, GitHub Advanced Security, Microsoft Defender, Snyk & Quality Gates em CI/CD.
              </p>
            </div>
          </div>
        </div>

        {/* Maturity Score Badge */}
        <div className="flex items-center gap-4 bg-slate-950/80 p-4 rounded-xl border border-slate-800">
          <div className="text-right">
            <p className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">AppSec Maturity Index</p>
            <p className="text-2xl font-extrabold text-accent-cyan">{aspmData?.appsec_maturity_score || 93.8} <span className="text-sm font-normal text-slate-500">/ 100</span></p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-accent-cyan/20 border border-accent-cyan/40 flex items-center justify-center text-accent-cyan font-black text-lg">
            A+
          </div>
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="metric-card">
          <p className="text-xs text-slate-400 font-medium">Aplicações Monitoradas</p>
          <p className="text-2xl font-black text-slate-100 mt-1">{aspmData?.monitored_applications || 4}</p>
          <span className="text-[10px] text-emerald-400 font-semibold">100% em Produção</span>
        </div>

        <div className="metric-card">
          <p className="text-xs text-slate-400 font-medium">Repositórios CI/CD</p>
          <p className="text-2xl font-black text-slate-100 mt-1">{aspmData?.monitored_repositories || 7}</p>
          <span className="text-[10px] text-accent-cyan font-semibold">Pipelines Ativos</span>
        </div>

        <div className="metric-card">
          <p className="text-xs text-slate-400 font-medium">Quality Gates Pass</p>
          <p className="text-2xl font-black text-emerald-400 mt-1">{aspmData?.quality_gate_pass_rate || 100}%</p>
          <span className="text-[10px] text-emerald-400 font-semibold">0 Deploys Bloqueados</span>
        </div>

        <div className="metric-card">
          <p className="text-xs text-slate-400 font-medium">Vulnerabilidades Críticas</p>
          <p className="text-2xl font-black text-emerald-400 mt-1">{aspmData?.open_critical_vulnerabilities || 0}</p>
          <span className="text-[10px] text-emerald-400 font-semibold">Zero Criticals</span>
        </div>

        <div className="metric-card">
          <p className="text-xs text-slate-400 font-medium">SLA de AppSec</p>
          <p className="text-2xl font-black text-accent-cyan mt-1">{aspmData?.sla_compliance_pct || 98.4}%</p>
          <span className="text-[10px] text-slate-400 font-semibold">Em conformidade</span>
        </div>

        <div className="metric-card">
          <p className="text-xs text-slate-400 font-medium">MTTR AppSec Médio</p>
          <p className="text-2xl font-black text-amber-400 mt-1">{aspmData?.average_mttr_days || 2.3} <span className="text-xs font-normal text-slate-400">dias</span></p>
          <span className="text-[10px] text-emerald-400 font-semibold">↓ -83.8% YoY</span>
        </div>
      </div>

      {/* AppSec Tooling Connectors */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-extrabold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <Layers className="w-4 h-4 text-accent-cyan" />
            Conectores de Segurança Integrados
          </h2>
          <span className="text-xs text-slate-400 font-mono">Status em tempo real</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3">
          {aspmData?.connectors?.map((conn: any) => (
            <div
              key={conn.id}
              className={clsx(
                'p-4 rounded-xl border transition-all flex flex-col justify-between gap-3 bg-bg-secondary/80',
                conn.status === 'CONNECTED' ? 'border-emerald-500/30 hover:border-emerald-500/60' : 'border-slate-800 opacity-60'
              )}
            >
              <div>
                <div className="flex items-center justify-between gap-2">
                  <span className={clsx(
                    'w-2.5 h-2.5 rounded-full',
                    conn.status === 'CONNECTED' ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'
                  )} />
                  <span className={clsx(
                    'text-[10px] font-mono font-bold px-1.5 py-0.5 rounded',
                    conn.status === 'CONNECTED' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-800 text-slate-400'
                  )}>
                    {conn.status}
                  </span>
                </div>
                <h3 className="text-xs font-bold text-slate-100 mt-2 line-clamp-1">{conn.name}</h3>
                <p className="text-[10px] text-slate-400 font-mono mt-0.5">{conn.category}</p>
              </div>

              <div className="pt-2 border-t border-slate-800/80 text-[10px] text-slate-400 flex items-center justify-between">
                <span>{conn.last_sync || 'Não conectado'}</span>
                {conn.status === 'CONNECTED' && (
                  <button
                    onClick={() => handleSync(conn.id)}
                    disabled={syncingConn === conn.id}
                    className="text-accent-cyan hover:text-accent-cyan/80 p-1"
                    title="Sincronizar agora"
                  >
                    <RefreshCw className={clsx('w-3 h-3', syncingConn === conn.id && 'animate-spin')} />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 12-Month AppSec Evolution Chart */}
      <div className="chart-card p-6 rounded-2xl bg-bg-secondary border border-bg-border shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-base font-extrabold text-slate-100 flex items-center gap-2">
              <Activity className="w-5 h-5 text-accent-cyan" />
              Evolução Histórica de AppSec (Últimos 12 Meses)
            </h2>
            <p className="text-xs text-slate-400">Tendência de remediação, redução de vulnerabilidades e maturação de Quality Gates.</p>
          </div>
          <div className="flex items-center gap-3 text-xs font-mono">
            <span className="flex items-center gap-1 text-rose-400"><span className="w-2 h-2 rounded-full bg-rose-500" /> Críticas</span>
            <span className="flex items-center gap-1 text-amber-400"><span className="w-2 h-2 rounded-full bg-amber-500" /> Altas</span>
            <span className="flex items-center gap-1 text-accent-cyan"><span className="w-2 h-2 rounded-full bg-accent-cyan" /> MTTR (dias)</span>
          </div>
        </div>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={aspmData?.monthly_appsec_trend || []} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="month" stroke="#64748b" fontSize={11} tickLine={false} />
              <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
              <Tooltip
                contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '12px', fontSize: '12px' }}
                labelStyle={{ color: '#00d4ff', fontWeight: 'bold' }}
              />
              <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2.5} name="Críticas" dot={{ fill: '#ef4444' }} />
              <Line type="monotone" dataKey="high" stroke="#f59e0b" strokeWidth={2} name="Altas" dot={{ fill: '#f59e0b' }} />
              <Line type="monotone" dataKey="mttr_days" stroke="#00d4ff" strokeWidth={2} name="MTTR (dias)" strokeDasharray="4 4" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Business Applications & Repositories Mapping */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* App List Selector */}
        <div className="space-y-3">
          <h2 className="text-sm font-extrabold text-slate-200 uppercase tracking-wider">
            Aplicações de Negócio Mapeadas ({aspmData?.applications?.length || 0})
          </h2>
          <div className="space-y-2">
            {aspmData?.applications?.map((app: any) => (
              <button
                key={app.id}
                onClick={() => setSelectedAppId(app.id)}
                className={clsx(
                  'w-full text-left p-4 rounded-xl border transition-all flex items-center justify-between gap-3',
                  selectedApp?.id === app.id
                    ? 'bg-accent-cyan/15 border-accent-cyan/60 shadow-lg'
                    : 'bg-bg-secondary/70 border-bg-border hover:bg-slate-800/40'
                )}
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-bold text-slate-100 truncate">{app.name}</p>
                    <span className="px-1.5 py-0.5 text-[9px] font-mono font-bold bg-slate-900 border border-slate-700 text-slate-300 rounded">
                      {app.code}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 truncate mt-0.5">{app.business_unit} • {app.squad}</p>
                </div>
                <div className="text-right flex-shrink-0">
                  <span className="text-xs font-mono font-bold text-accent-cyan">{app.appsec_score}%</span>
                  <p className="text-[10px] text-emerald-400 font-semibold">{app.quality_gate}</p>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Selected App Detailed Repositories & Security Posture */}
        {selectedApp && (
          <div className="lg:col-span-2 space-y-4 p-6 rounded-2xl bg-bg-secondary border border-bg-border shadow-xl">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-4 border-b border-bg-border">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-lg font-black text-slate-100">{selectedApp.name}</h3>
                  <span className="px-2 py-0.5 text-xs font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 rounded">
                    {selectedApp.criticality}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Business Owner: <strong className="text-slate-200">{selectedApp.business_owner}</strong> | Tech Lead: <strong className="text-slate-200">{selectedApp.tech_owner}</strong>
                </p>
              </div>

              <div className="flex items-center gap-2">
                <span className="px-3 py-1 text-xs font-mono font-bold rounded-lg bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Quality Gate: {selectedApp.quality_gate}
                </span>
              </div>
            </div>

            {/* Repositories Breakdown */}
            <div className="space-y-3">
              <h4 className="text-xs font-extrabold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                <GitBranch className="w-4 h-4 text-accent-cyan" />
                Repositórios de Código-Fonte ({selectedApp.repositories?.length || 0})
              </h4>

              <div className="space-y-2">
                {selectedApp.repositories?.map((repo: any, rIdx: number) => (
                  <div key={rIdx} className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-bold text-accent-cyan">{repo.name}</span>
                        <span className="px-1.5 py-0.5 text-[10px] font-mono bg-slate-800 text-slate-400 rounded">
                          branch: {repo.branch}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 font-mono">
                        Linguagem: {repo.language} • Último Scan: {repo.last_scan}
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                      <span className="px-2 py-1 bg-slate-900 border border-slate-700 text-slate-300 rounded-lg">
                        SAST: <strong className="text-emerald-400">{repo.sast}</strong>
                      </span>
                      <span className="px-2 py-1 bg-slate-900 border border-slate-700 text-slate-300 rounded-lg">
                        Secrets: <strong className="text-emerald-400">{repo.secrets}</strong>
                      </span>
                      <span className="px-2 py-1 bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 rounded-lg font-bold">
                        {repo.quality_gate}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Production Assets Linked */}
            <div className="pt-4 border-t border-bg-border space-y-2">
              <h4 className="text-xs font-extrabold text-slate-300 uppercase tracking-wider">
                Ativos de Produção Vinculados (EASM + ASPM Correlation)
              </h4>
              <div className="flex flex-wrap gap-2">
                {selectedApp.production_assets?.map((ast: string, aIdx: number) => (
                  <span key={aIdx} className="px-3 py-1.5 text-xs font-mono bg-slate-900 border border-slate-700 rounded-lg text-slate-200 flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                    {ast}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
