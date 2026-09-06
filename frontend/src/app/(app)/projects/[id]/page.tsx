'use client';
import { useParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { projectsApi, findingsApi, assetsApi, scansApi } from '@/lib/api';
import { useState } from 'react';
import { Bug, Globe, Activity, FileText, Shield, AlertTriangle } from 'lucide-react';
import Link from 'next/link';
import clsx from 'clsx';

type Tab = 'overview' | 'findings' | 'assets' | 'scan';

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [tab, setTab] = useState<Tab>('overview');

  const { data: project } = useQuery({ queryKey: ['project', id], queryFn: () => projectsApi.get(id) });
  const { data: findings = [] } = useQuery({ queryKey: ['findings', id], queryFn: () => findingsApi.list({ project_id: id }) });
  const { data: assets = [] } = useQuery({ queryKey: ['assets', id], queryFn: () => assetsApi.list(id) });
  const { data: scan } = useQuery({ queryKey: ['scan', id], queryFn: () => scansApi.getLatest(id) });

  const critCount = findings.filter((f: any) => f.severity === 'CRITICAL' && !f.is_false_positive).length;
  const highCount = findings.filter((f: any) => f.severity === 'HIGH' && !f.is_false_positive).length;
  const openCount = findings.filter((f: any) => f.status === 'OPEN').length;
  const fixedCount = findings.filter((f: any) => f.status === 'FIXED').length;

  const bySeverity = [
    { label: 'Critical', count: critCount, color: '#dc3545' },
    { label: 'High', count: highCount, color: '#ff6b35' },
    { label: 'Medium', count: findings.filter((f: any) => f.severity === 'MEDIUM').length, color: '#ffc107' },
    { label: 'Low', count: findings.filter((f: any) => f.severity === 'LOW').length, color: '#28a745' },
    { label: 'Info', count: findings.filter((f: any) => f.severity === 'INFO').length, color: '#17a2b8' },
  ];

  return (
    <div className="flex flex-col min-h-screen animate-fade-in">
      {/* Header */}
      <div className="px-6 py-4 border-b border-bg-border bg-bg-secondary/50 flex items-center gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 text-xs text-slate-500 mb-1">
            <Link href="/projects" className="hover:text-accent-cyan transition-colors">Projetos</Link>
            <span>/</span>
            <span className="text-slate-300">{project?.name}</span>
          </div>
          <h1 className="text-xl font-bold text-slate-100 truncate">{project?.name ?? '...'}</h1>
          <p className="text-sm text-slate-400">{project?.client || 'Interno'} · {project?.business_unit}</p>
        </div>
        <StatusBadge status={project?.status ?? ''} />
      </div>

      {/* Tabs */}
      <div className="px-6 border-b border-bg-border bg-bg-secondary/30">
        <div className="flex gap-1">
          {(['overview', 'findings', 'assets', 'scan'] as Tab[]).map(t => (
            <button key={t} onClick={() => setTab(t)}
              className={clsx('px-4 py-3 text-sm font-medium capitalize transition-all border-b-2 -mb-px',
                tab === t ? 'border-accent-cyan text-accent-cyan' : 'border-transparent text-slate-400 hover:text-slate-200')}>
              {t === 'findings' && <>{t} {findings.length > 0 && <span className="ml-1 text-xs opacity-60">({findings.length})</span>}</>}
              {t !== 'findings' && t}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 p-6">
        {/* OVERVIEW */}
        {tab === 'overview' && (
          <div className="max-w-5xl space-y-6">
            {/* KPIs */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: 'Total Findings', value: findings.length, color: '#ff6b35' },
                { label: 'Critical', value: critCount, color: critCount > 0 ? '#dc3545' : '#28a745' },
                { label: 'Open', value: openCount, color: openCount > 0 ? '#ff6b35' : '#28a745' },
                { label: 'Fixed', value: fixedCount, color: '#28a745' },
              ].map(({ label, value, color }) => (
                <div key={label} className="stat-card">
                  <span className="text-xs text-slate-400">{label}</span>
                  <p className="text-3xl font-bold" style={{ color }}>{value}</p>
                </div>
              ))}
            </div>

            {/* Severity breakdown */}
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-4">Distribuição por Severidade</h3>
              <div className="space-y-3">
                {bySeverity.map(s => (
                  <div key={s.label} className="flex items-center gap-3">
                    <span className="text-xs w-14 text-slate-400">{s.label}</span>
                    <div className="flex-1 bg-bg-border rounded-full h-2 overflow-hidden">
                      <div className="h-full rounded-full transition-all duration-700"
                        style={{ width: findings.length ? `${(s.count / findings.length) * 100}%` : '0%', background: s.color, boxShadow: `0 0 8px ${s.color}66` }} />
                    </div>
                    <span className="text-xs font-bold w-6 text-right" style={{ color: s.color }}>{s.count}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Description */}
            {project?.description && (
              <div className="glass-card p-5">
                <h3 className="text-sm font-semibold text-slate-300 mb-2">Descrição</h3>
                <p className="text-sm text-slate-400">{project.description}</p>
              </div>
            )}
          </div>
        )}

        {/* FINDINGS */}
        {tab === 'findings' && (
          <div className="max-w-6xl glass-card overflow-hidden">
            <table className="table-dark">
              <thead><tr><th>Finding</th><th>Severidade</th><th>Confiança</th><th>OWASP</th><th>Status</th></tr></thead>
              <tbody>
                {findings.map((f: any) => (
                  <tr key={f.id}>
                    <td>
                      <p className="font-medium text-slate-200">{f.title}</p>
                      <p className="text-xs text-slate-500 truncate max-w-sm">{f.affected_url}</p>
                    </td>
                    <td><SevBadge s={f.severity} /></td>
                    <td><span className="text-xs text-slate-400">{f.confidence}%</span></td>
                    <td><span className="text-xs text-slate-400 max-w-xs truncate block">{f.owasp_category || '—'}</span></td>
                    <td>
                      <span className={clsx('text-xs px-2 py-0.5 rounded',
                        f.status === 'OPEN' ? 'bg-red-500/20 text-red-300' :
                        f.status === 'FIXED' ? 'bg-green-500/20 text-green-300' :
                        f.status === 'RETEST_PENDING' ? 'bg-purple-500/20 text-purple-300' :
                        'bg-slate-700 text-slate-400')}>
                        {f.status}
                      </span>
                    </td>
                  </tr>
                ))}
                {findings.length === 0 && <tr><td colSpan={5} className="text-center text-slate-500 py-8">Nenhum finding neste projeto</td></tr>}
              </tbody>
            </table>
          </div>
        )}

        {/* ASSETS */}
        {tab === 'assets' && (
          <div className="max-w-5xl glass-card overflow-hidden">
            <table className="table-dark">
              <thead><tr><th>Asset</th><th>Tipo</th><th>IP</th><th>Tecnologias</th><th>Criticidade</th></tr></thead>
              <tbody>
                {assets.map((a: any) => (
                  <tr key={a.id}>
                    <td>
                      <p className="font-medium text-slate-200 font-mono text-sm">{a.value}</p>
                      {a.title && <p className="text-xs text-slate-500">{a.title}</p>}
                    </td>
                    <td><span className="text-xs bg-slate-700 text-slate-300 px-2 py-0.5 rounded">{a.asset_type}</span></td>
                    <td><span className="font-mono text-xs text-slate-400">{a.ip_address || '—'}</span></td>
                    <td>
                      <div className="flex flex-wrap gap-1">
                        {a.technologies.slice(0, 3).map((t: string) => (
                          <span key={t} className="text-xs bg-accent-cyan/10 text-accent-cyan px-1.5 py-0.5 rounded">{t}</span>
                        ))}
                      </div>
                    </td>
                    <td>
                      <span className={clsx('text-xs px-2 py-0.5 rounded font-medium',
                        a.business_criticality === 'CRITICAL' ? 'bg-red-500/20 text-red-300' :
                        a.business_criticality === 'HIGH' ? 'bg-orange-500/20 text-orange-300' :
                        'bg-slate-700 text-slate-400')}>
                        {a.business_criticality}
                      </span>
                    </td>
                  </tr>
                ))}
                {assets.length === 0 && <tr><td colSpan={5} className="text-center text-slate-500 py-8">Nenhum asset descoberto</td></tr>}
              </tbody>
            </table>
          </div>
        )}

        {/* SCAN */}
        {tab === 'scan' && (
          <div className="max-w-2xl space-y-4">
            {scan ? (
              <div className="glass-card p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-slate-200">Último Scan</h3>
                  <StatusBadge status={scan.status} />
                </div>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div><p className="text-slate-500 text-xs">Modo</p><p className="text-slate-200 font-medium">{scan.mode}</p></div>
                  <div><p className="text-slate-500 text-xs">Fase Atual</p><p className="text-slate-200 font-medium">{scan.current_phase}</p></div>
                  <div><p className="text-slate-500 text-xs">Assets</p><p className="text-slate-200 font-medium">{scan.assets_discovered}</p></div>
                  <div><p className="text-slate-500 text-xs">Endpoints</p><p className="text-slate-200 font-medium">{scan.endpoints_found}</p></div>
                  <div><p className="text-slate-500 text-xs">Iniciado</p><p className="text-slate-200 font-medium">{new Date(scan.started_at).toLocaleString('pt-BR')}</p></div>
                  <div><p className="text-slate-500 text-xs">Concluído</p><p className="text-slate-200 font-medium">{scan.completed_at ? new Date(scan.completed_at).toLocaleString('pt-BR') : '—'}</p></div>
                </div>
                <div>
                  <div className="flex justify-between text-xs text-slate-400 mb-1">
                    <span>Progresso</span><span>{scan.progress}%</span>
                  </div>
                  <div className="progress-bar">
                    <div className="progress-bar-fill" style={{ width: `${scan.progress}%` }} />
                  </div>
                </div>
              </div>
            ) : (
              <div className="glass-card p-12 text-center">
                <Activity className="w-10 h-10 text-slate-600 mx-auto mb-3" />
                <p className="text-slate-400">Nenhum scan encontrado para este projeto</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function SevBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    CRITICAL: 'badge-severity-critical', HIGH: 'badge-severity-high',
    MEDIUM: 'badge-severity-medium', LOW: 'badge-severity-low', INFO: 'badge-severity-info',
  };
  return <span className={cls[s] || cls.INFO}>{s}</span>;
}

function StatusBadge({ status }: { status: string }) {
  const s: Record<string, string> = {
    DRAFT: 'bg-slate-700 text-slate-400', ACTIVE: 'bg-cyan-500/20 text-cyan-400',
    SCANNING: 'bg-purple-500/20 text-purple-400', COMPLETED: 'bg-green-500/20 text-green-400',
    RUNNING: 'bg-purple-500/20 text-purple-400', FAILED: 'bg-red-500/20 text-red-400',
  };
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium ${s[status] || s.DRAFT}`}>
      {(status === 'SCANNING' || status === 'RUNNING') && <span className="w-1.5 h-1.5 rounded-full bg-purple-400 mr-1.5 animate-pulse" />}
      {status}
    </span>
  );
}
