'use client';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { findingsApi, type Finding } from '@/lib/api';
import { useState } from 'react';
import { Bug, ChevronDown, ChevronUp, Trash2, Plus, X, AlertTriangle } from 'lucide-react';
import clsx from 'clsx';
import toast from 'react-hot-toast';
import VulnerabilitySubNav from '@/components/layout/VulnerabilitySubNav';

const SCANNER_URL = 'http://localhost:8000';
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const STATUSES = ['OPEN', 'IN_PROGRESS', 'RETEST_PENDING', 'FIXED', 'ACCEPTED'];

interface NewFindingForm {
  title: string; severity: string; status: string; owasp_category: string;
  cwe_id: string; cvss_score: string; affected_url: string; affected_asset: string;
  description: string; recommendation: string; business_impact: string; steps_to_reproduce: string;
}

const BLANK_FORM: NewFindingForm = {
  title: '', severity: 'HIGH', status: 'OPEN', owasp_category: '',
  cwe_id: '', cvss_score: '7.0', affected_url: '', affected_asset: '',
  description: '', recommendation: '', business_impact: '', steps_to_reproduce: '',
};

export default function FindingsPage() {
  const [sevFilter, setSevFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [form, setForm] = useState<NewFindingForm>(BLANK_FORM);
  const queryClient = useQueryClient();

  const { data: findings = [], isLoading, error } = useQuery({
    queryKey: ['all-findings', sevFilter, statusFilter],
    queryFn: () => findingsApi.list({ severity: sevFilter || undefined, status: statusFilter || undefined }),
  });

  const deleteFinding = useMutation({
    mutationFn: async (id: string) => {
      return await findingsApi.delete(id);
    },
    onSuccess: () => {
      toast.success('Finding excluído com sucesso');
      queryClient.invalidateQueries({ queryKey: ['all-findings'] });
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
    },
    onError: (e: any) => toast.error(`Erro ao deletar: ${e.message || 'Falha na operação'}`),
  });

  const addFinding = useMutation({
    mutationFn: async (f: NewFindingForm) => {
      return await findingsApi.create({
        ...f,
        cvss_score: parseFloat(f.cvss_score) || 0,
      });
    },
    onSuccess: () => {
      toast.success('Finding adicionado com sucesso');
      queryClient.invalidateQueries({ queryKey: ['all-findings'] });
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
      setShowAddModal(false);
      setForm(BLANK_FORM);
    },
    onError: (e: any) => toast.error(`Falha ao adicionar: ${e.message}`),
  });

  const activeFindings = findings.filter((f: Finding) => f.is_false_positive !== true);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-5 animate-fade-in">
      <VulnerabilitySubNav />
      <div className="flex items-center justify-between">

        <div>
          <h1 className="text-2xl font-bold text-slate-100">Findings</h1>
          <p className="text-slate-400 text-sm mt-0.5">{activeFindings.length} findings across all projects</p>
        </div>
        <button onClick={() => setShowAddModal(true)} className="btn-primary flex items-center gap-2 text-sm">
          <Plus className="w-4 h-4" /> Add Finding
        </button>
      </div>

      <div className="flex gap-3 flex-wrap">
        <select value={sevFilter} onChange={e => setSevFilter(e.target.value)} className="input-field w-auto">
          <option value="">All Severities</option>
          {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="input-field w-auto">
          <option value="">All Statuses</option>
          {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        {(sevFilter || statusFilter) && (
          <button onClick={() => { setSevFilter(''); setStatusFilter(''); }} className="btn-ghost text-xs">Clear filters</button>
        )}
      </div>

      {error && (
        <div className="glass-card p-4 border border-red-500/30 text-red-400 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          Failed to load findings. Verify the JSON data file is valid.
        </div>
      )}

      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="w-8 h-8 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <div className="glass-card overflow-hidden">
          <table className="table-dark">
            <thead>
              <tr><th>Finding</th><th>Project</th><th>Severity</th><th>CVSS</th><th>OWASP</th><th>Status</th><th></th><th>Action</th></tr>
            </thead>
            <tbody>
              {activeFindings.map((f: Finding) => (
                <>
                  <tr key={f.id} className="cursor-pointer group" onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
                    <td>
                      <div className="flex items-center gap-2">
                        <Bug className="w-3.5 h-3.5 text-slate-600 flex-shrink-0" />
                        <div>
                          <p className="font-medium text-slate-200 max-w-xs">{f.title}</p>
                          <p className="text-xs text-slate-500 truncate max-w-xs">{f.affected_asset || f.affected_url}</p>
                        </div>
                      </div>
                    </td>
                    <td><span className="text-xs text-slate-400">{f.project_id?.replace('proj-', '#') || '-'}</span></td>
                    <td><SevBadge s={f.severity} /></td>
                    <td>
                      <span className={clsx('text-xs font-bold',
                        (f.cvss_score ?? 0) >= 9 ? 'text-accent-red' : (f.cvss_score ?? 0) >= 7 ? 'text-accent-orange' :
                        (f.cvss_score ?? 0) >= 4 ? 'text-accent-yellow' : 'text-accent-green')}>
                        {f.cvss_score?.toFixed(1) ?? '-'}
                      </span>
                    </td>
                    <td><span className="text-xs text-slate-400 max-w-xs truncate block">{f.owasp_category?.split('-')[0]?.trim() || '-'}</span></td>
                    <td>
                      <span className={clsx('text-xs px-2 py-0.5 rounded',
                        f.status === 'OPEN' ? 'bg-red-500/20 text-red-300' :
                        f.status === 'FIXED' ? 'bg-green-500/20 text-green-300' :
                        f.status === 'RETEST_PENDING' ? 'bg-purple-500/20 text-purple-300' :
                        f.status === 'IN_PROGRESS' ? 'bg-blue-500/20 text-blue-300' :
                        'bg-slate-700 text-slate-400')}>
                        {f.status}
                      </span>
                    </td>
                    <td>{expanded === f.id ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}</td>
                    <td onClick={e => e.stopPropagation()}>
                      <button
                        onClick={() => deleteFinding.mutate(f.id)}
                        className="p-1.5 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors opacity-0 group-hover:opacity-100"
                        title="Delete finding"
                      ><Trash2 className="w-4 h-4" /></button>
                    </td>
                  </tr>
                  {expanded === f.id && (
                    <tr key={f.id + '-exp'}>
                      <td colSpan={8} className="p-0">
                        <div className="bg-bg-primary/70 border-t border-bg-border p-6 space-y-6 text-sm">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div className="space-y-4">
                              <div><h4 className="text-xs font-semibold text-slate-400 uppercase mb-1.5">Description</h4><p className="text-slate-300 leading-relaxed">{f.description}</p></div>
                              {f.business_impact && <div><h4 className="text-xs font-semibold text-slate-400 uppercase mb-1.5">Business Impact</h4><p className="text-slate-300 leading-relaxed">{f.business_impact}</p></div>}
                              {f.steps_to_reproduce && <div><h4 className="text-xs font-semibold text-slate-400 uppercase mb-1.5">Steps to Reproduce</h4><pre className="text-xs text-slate-300 font-mono bg-black/30 rounded p-3 overflow-auto whitespace-pre-wrap">{f.steps_to_reproduce}</pre></div>}
                            </div>
                            <div className="space-y-4">
                              <div><h4 className="text-xs font-semibold text-slate-400 uppercase mb-1.5">Recommendation</h4><p className="text-slate-300 leading-relaxed">{f.recommendation}</p></div>
                              {f.developer_recommendation && <div><h4 className="text-xs font-semibold text-slate-400 uppercase mb-1.5">Developer Note</h4><pre className="text-xs text-accent-cyan/80 font-mono bg-black/30 rounded p-3 overflow-auto whitespace-pre-wrap">{f.developer_recommendation}</pre></div>}
                              <div className="grid grid-cols-2 gap-3 text-xs">
                                {[['CWE', f.cwe_id || '-'], ['CVSS', f.cvss_score?.toFixed(1) || '-'], ['Confidence', (f.confidence ?? '-') + '%'], ['Affected URL', f.affected_url || '-']].map(([label, val]) => (
                                  <div key={label as string} className="bg-bg-card rounded-lg p-3"><p className="text-slate-500 mb-0.5">{label}</p><p className="text-slate-200 font-medium truncate">{val}</p></div>
                                ))}
                              </div>
                            </div>
                          </div>

                          {/* PASSO A PASSO COMPLETO DE REMEDIAÇÃO */}
                          <div className="bg-slate-900/80 border border-emerald-500/30 rounded-xl p-5 space-y-3 shadow-lg">
                            <div className="flex items-center justify-between border-b border-emerald-500/20 pb-2.5">
                              <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-2">
                                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping inline-block" />
                                🛠️ Passo a Passo Completo de Remediação / Resolution Steps
                              </h4>
                              <span className="text-[10px] bg-emerald-500/10 text-emerald-300 px-2 py-0.5 rounded border border-emerald-500/30 font-mono">Verified Action Plan</span>
                            </div>
                            <div className="space-y-2.5 pt-1">
                              {f.remediation_steps && f.remediation_steps.length > 0 ? (
                                f.remediation_steps.map((step: string, idx: number) => (
                                  <div key={idx} className="flex items-start gap-3 bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400 font-mono font-bold text-xs flex items-center justify-center border border-emerald-500/40">
                                      {idx + 1}
                                    </span>
                                    <p className="text-xs text-slate-200 leading-relaxed font-sans mt-0.5">{step}</p>
                                  </div>
                                ))
                              ) : (
                                [
                                  `Passo 1: Isolar o endpoint afetado (${f.affected_url || f.affected_asset || 'Alvo'}) para evitar exploração.`,
                                  `Passo 2: Aplicar a correção descrita: ${f.recommendation || 'Atualizar as configurações de segurança.'}`,
                                  `Passo 3: Se houver código de desenvolvedor, aplicar a nota técnica: ${f.developer_recommendation || 'Injetar os cabeçalhos/filtros devidos.'}`,
                                  `Passo 4: Executar o Retest automatizado na plataforma para confirmar a transição do status para FIXED.`
                                ].map((step: string, idx: number) => (
                                  <div key={idx} className="flex items-start gap-3 bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400 font-mono font-bold text-xs flex items-center justify-center border border-emerald-500/40">
                                      {idx + 1}
                                    </span>
                                    <p className="text-xs text-slate-200 leading-relaxed font-sans mt-0.5">{step}</p>
                                  </div>
                                ))
                              )}
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
              {activeFindings.length === 0 && !isLoading && (
                <tr><td colSpan={8} className="text-center text-slate-500 py-10">No findings found</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-bg-secondary border border-bg-border rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between p-5 border-b border-bg-border">
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2"><Plus className="w-4 h-4 text-accent-cyan" /> Add Manual Finding</h2>
              <button onClick={() => setShowAddModal(false)} className="text-slate-500 hover:text-slate-300"><X className="w-5 h-5" /></button>
            </div>
            <div className="p-5 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="col-span-2"><label className="block text-xs text-slate-400 mb-1">Title *</label><input className="input-field" value={form.title} onChange={e => setForm(p => ({ ...p, title: e.target.value }))} placeholder="e.g. SQL Injection in login endpoint" /></div>
                <div><label className="block text-xs text-slate-400 mb-1">Severity</label><select className="input-field" value={form.severity} onChange={e => setForm(p => ({ ...p, severity: e.target.value }))}>{SEVERITIES.map(s => <option key={s}>{s}</option>)}</select></div>
                <div><label className="block text-xs text-slate-400 mb-1">Status</label><select className="input-field" value={form.status} onChange={e => setForm(p => ({ ...p, status: e.target.value }))}>{STATUSES.map(s => <option key={s}>{s}</option>)}</select></div>
                <div><label className="block text-xs text-slate-400 mb-1">CVSS Score</label><input type="number" step="0.1" min="0" max="10" className="input-field" value={form.cvss_score} onChange={e => setForm(p => ({ ...p, cvss_score: e.target.value }))} /></div>
                <div><label className="block text-xs text-slate-400 mb-1">CWE ID</label><input className="input-field" placeholder="CWE-89" value={form.cwe_id} onChange={e => setForm(p => ({ ...p, cwe_id: e.target.value }))} /></div>
                <div><label className="block text-xs text-slate-400 mb-1">Affected URL</label><input className="input-field" placeholder="https://..." value={form.affected_url} onChange={e => setForm(p => ({ ...p, affected_url: e.target.value }))} /></div>
                <div><label className="block text-xs text-slate-400 mb-1">Affected Asset</label><input className="input-field" placeholder="api.example.com" value={form.affected_asset} onChange={e => setForm(p => ({ ...p, affected_asset: e.target.value }))} /></div>
                <div className="col-span-2"><label className="block text-xs text-slate-400 mb-1">OWASP Category</label><input className="input-field" placeholder="A03:2021 - Injection" value={form.owasp_category} onChange={e => setForm(p => ({ ...p, owasp_category: e.target.value }))} /></div>
                <div className="col-span-2"><label className="block text-xs text-slate-400 mb-1">Description *</label><textarea rows={3} className="input-field" value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} placeholder="Technical description..." /></div>
                <div className="col-span-2"><label className="block text-xs text-slate-400 mb-1">Business Impact</label><textarea rows={2} className="input-field" value={form.business_impact} onChange={e => setForm(p => ({ ...p, business_impact: e.target.value }))} placeholder="Business impact..." /></div>
                <div className="col-span-2"><label className="block text-xs text-slate-400 mb-1">Recommendation *</label><textarea rows={2} className="input-field" value={form.recommendation} onChange={e => setForm(p => ({ ...p, recommendation: e.target.value }))} placeholder="Remediation steps..." /></div>
                <div className="col-span-2"><label className="block text-xs text-slate-400 mb-1">Steps to Reproduce</label><textarea rows={3} className="input-field font-mono text-xs" value={form.steps_to_reproduce} onChange={e => setForm(p => ({ ...p, steps_to_reproduce: e.target.value }))} placeholder="1. Step one" /></div>
              </div>
              <div className="flex justify-end gap-3 pt-2 border-t border-bg-border">
                <button onClick={() => setShowAddModal(false)} className="btn-ghost text-sm">Cancel</button>
                <button onClick={() => { if (!form.title.trim() || !form.description.trim() || !form.recommendation.trim()) { toast.error('Title, description and recommendation are required'); return; } addFinding.mutate(form); }} disabled={addFinding.isPending} className="btn-primary text-sm">
                  {addFinding.isPending ? 'Saving...' : 'Save Finding'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SevBadge({ s }: { s: string }) {
  const cls: Record<string, string> = { CRITICAL: 'badge-severity-critical', HIGH: 'badge-severity-high', MEDIUM: 'badge-severity-medium', LOW: 'badge-severity-low', INFO: 'badge-severity-info' };
  return <span className={cls[s] || cls.INFO}>{s}</span>;
}
