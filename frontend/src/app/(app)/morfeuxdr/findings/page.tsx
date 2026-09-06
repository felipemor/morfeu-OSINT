'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Bug, Search, Filter, ShieldAlert, CheckCircle2, AlertTriangle, Eye, Edit3, X, RefreshCw } from 'lucide-react';
import { morfeuXdrApi } from '@/lib/api';
import toast from 'react-hot-toast';

export default function FindingsPage() {
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  // Status Mutation Modal
  const [selectedFinding, setSelectedFinding] = useState<any>(null);
  const [newStatus, setNewStatus] = useState('INVESTIGATING');
  const [reason, setReason] = useState('');

  const loadFindings = async () => {
    setLoading(true);
    try {
      const data = await morfeuXdrApi.getFindings({
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        search: search || undefined
      });
      setFindings(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, [severityFilter, statusFilter]);

  const handleUpdateStatus = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFinding) return;
    try {
      await morfeuXdrApi.updateFindingStatus(selectedFinding.id, newStatus, reason);
      toast.success(`Status da finding ${selectedFinding.finding_number} atualizado para ${newStatus}! Log de auditoria registrado.`);
      setSelectedFinding(null);
      loadFindings();
    } catch (err) {
      toast.error('Erro ao atualizar status.');
    }
  };

  return (
    <div className="space-y-4">
      {/* Controls Bar */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Buscar por título, host, IP ou ID..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && loadFindings()}
              className="pl-9 pr-4 py-1.5 text-xs bg-bg-secondary border border-bg-border rounded-lg text-slate-200 focus:outline-none focus:border-red-500 w-64"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 text-xs bg-bg-secondary border border-bg-border rounded-lg text-slate-200 focus:outline-none focus:border-red-500"
          >
            <option value="">Todas as Severidades</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 text-xs bg-bg-secondary border border-bg-border rounded-lg text-slate-200 focus:outline-none focus:border-red-500"
          >
            <option value="">Todos os Status</option>
            <option value="NEW">NEW</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="CONFIRMED">CONFIRMED</option>
            <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="SUPPRESSED">SUPPRESSED</option>
          </select>

          <button
            onClick={loadFindings}
            className="px-3 py-1.5 text-xs font-semibold bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg transition-all"
          >
            Filtrar
          </button>
        </div>

        <button onClick={loadFindings} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200">
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Recarregar
        </button>
      </div>

      {/* Findings Table */}
      <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/60 border-b border-bg-border text-slate-400 uppercase font-semibold text-[10px] tracking-wider">
              <tr>
                <th className="p-3.5">ID / Severidade</th>
                <th className="p-3.5">Título da Detecção</th>
                <th className="p-3.5">Host / IP / Agente</th>
                <th className="p-3.5">Regra Wazuh / MITRE</th>
                <th className="p-3.5">Risk Score</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5 text-right">Ações</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bg-border/60 text-slate-200">
              {findings.map((f) => {
                const isCritical = f.severity === 'CRITICAL';
                return (
                  <tr key={f.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="p-3.5">
                      <div className="font-mono font-bold text-slate-100">{f.finding_number}</div>
                      <span className={`px-2 py-0.5 text-[9px] font-extrabold rounded uppercase border ${
                        isCritical
                          ? 'bg-red-500/20 text-red-400 border-red-500/40'
                          : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                      }`}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="p-3.5">
                      <div className="font-bold text-slate-100">{f.title}</div>
                      <p className="text-[10px] text-slate-400 line-clamp-1">{f.description}</p>
                    </td>
                    <td className="p-3.5">
                      <div className="font-bold text-slate-200">{f.hostname}</div>
                      <div className="font-mono text-[10px] text-slate-400">{f.ip}</div>
                    </td>
                    <td className="p-3.5 font-mono text-[10px]">
                      <div className="text-slate-300 font-bold">Rule #{f.rule_id}</div>
                      <div className="text-red-400 font-semibold">{f.mitre_technique || 'T1110'}</div>
                    </td>
                    <td className="p-3.5 font-mono font-black text-red-400 text-sm">
                      {f.risk_score}
                    </td>
                    <td className="p-3.5">
                      <span className="px-2 py-0.5 text-[10px] font-bold bg-slate-800 text-slate-200 border border-slate-700 rounded uppercase">
                        {f.status}
                      </span>
                    </td>
                    <td className="p-3.5 text-right flex items-center justify-end gap-2">
                      <Link
                        href={`/morfeuxdr/investigation?id=${f.id}`}
                        className="p-1.5 text-slate-400 hover:text-red-400 bg-bg-secondary rounded border border-bg-border"
                        title="Investigar Finding"
                      >
                        <Eye className="w-4 h-4" />
                      </Link>
                      <button
                        onClick={() => { setSelectedFinding(f); setNewStatus(f.status); }}
                        className="p-1.5 text-slate-400 hover:text-accent-cyan bg-bg-secondary rounded border border-bg-border"
                        title="Alterar Status (Auditado)"
                      >
                        <Edit3 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Status Transition Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <form onSubmit={handleUpdateStatus} className="bg-bg-card border border-bg-border rounded-xl p-6 w-full max-w-md space-y-4">
            <div className="flex justify-between items-center border-b border-bg-border pb-3">
              <h3 className="text-sm font-bold text-slate-100">Transição de Status — {selectedFinding.finding_number}</h3>
              <button type="button" onClick={() => setSelectedFinding(null)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Novo Status</label>
                <select
                  value={newStatus}
                  onChange={(e) => setNewStatus(e.target.value)}
                  className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 font-semibold"
                >
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="CONFIRMED">CONFIRMED</option>
                  <option value="FALSE_POSITIVE">FALSE_POSITIVE (Exige Justificativa)</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="SUPPRESSED">SUPPRESSED</option>
                  <option value="ACCEPTED_RISK">ACCEPTED_RISK</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Justificativa / Motivo (Registrado na Auditoria)</label>
                <textarea
                  rows={3}
                  required
                  placeholder="Descreva a razão técnica para a mudança de status..."
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  className="w-full p-2.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 focus:outline-none focus:border-red-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button type="button" onClick={() => setSelectedFinding(null)} className="px-3 py-1.5 text-xs text-slate-400">
                Cancelar
              </button>
              <button type="submit" className="px-4 py-1.5 text-xs font-bold bg-red-500 text-slate-950 rounded-lg hover:bg-red-400">
                Salvar & Registrar Auditoria
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
