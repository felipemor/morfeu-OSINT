'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { correlationApi } from '@/lib/api';
import {
  Network, ShieldAlert, ShieldCheck, ArrowRight, Layers,
  Sliders, Plus, CheckCircle2, Clock, AlertTriangle, FileText,
  Lock, Sparkles, Send, Eye
} from 'lucide-react';
import clsx from 'clsx';
import toast from 'react-hot-toast';
import VulnerabilitySubNav from '@/components/layout/VulnerabilitySubNav';

export default function CorrelationPage() {
  const [isRiskModalOpen, setIsRiskModalOpen] = useState(false);
  const [selectedChainId, setSelectedChainId] = useState<string>('CORR-2026-PIX-001');

  // Risk Acceptance Form State
  const [findingId, setFindingId] = useState('FND-000389');
  const [justification, setJustification] = useState('');
  const [compensatingControls, setCompensatingControls] = useState('');
  const [riskLevel, setRiskLevel] = useState('MEDIUM');
  const [expirationDate, setExpirationDate] = useState('2026-12-31');

  const { data: matrixData, isLoading, refetch } = useQuery({
    queryKey: ['correlation-matrix'],
    queryFn: correlationApi.getMatrix,
    staleTime: 10000,
  });

  const handleSubmitRiskAcceptance = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!justification || !compensatingControls) {
      toast.error('Preencha a justificativa e os controles compensatórios.');
      return;
    }

    toast.loading('Registrando solicitação formal de aceite de risco...', { id: 'ra-sub' });
    try {
      await correlationApi.requestRiskAcceptance({
        finding_id: findingId,
        title: 'Aceite de Risco Formal — Comitê de Governança',
        business_justification: justification,
        compensating_controls: compensatingControls,
        risk_level: riskLevel,
        expiration_date: expirationDate,
      });
      toast.success('Aceite de Risco submetido com sucesso para aprovação do CISO!', { id: 'ra-sub' });
      setIsRiskModalOpen(false);
      setJustification('');
      setCompensatingControls('');
      refetch();
    } catch (err: any) {
      toast.error('Erro ao registrar: ' + err.message, { id: 'ra-sub' });
    }
  };

  const selectedChain = matrixData?.correlated_chains?.find((c: any) => c.correlation_id === selectedChainId) || matrixData?.correlated_chains?.[0];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-[70vh]">
        <div className="w-10 h-10 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto">
      <VulnerabilitySubNav />
      {/* Header Banner */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 p-6 rounded-2xl bg-gradient-to-r from-bg-secondary via-slate-900 to-bg-secondary border border-bg-border shadow-xl">
        <div className="space-y-1.5">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-purple-500/15 border border-purple-500/30 text-purple-400">
              <Network className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-black text-slate-100 tracking-tight">Security Correlation & Risk Engine</h1>
                <span className="px-2.5 py-0.5 text-xs font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30 rounded-full">
                  MULTI-PLANE GRAPH
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Correlacionamento unificado: Ativo → Domínio → Aplicação → Repositório → Finding → Controle → Requisito Regulatório → Risco de Negócio.
              </p>
            </div>
          </div>
        </div>

        {/* Action Button */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsRiskModalOpen(true)}
            className="px-4 py-2.5 rounded-xl font-bold text-xs bg-accent-cyan/15 hover:bg-accent-cyan/25 border border-accent-cyan/40 text-accent-cyan flex items-center gap-2 transition-all shadow-md"
          >
            <Plus className="w-4 h-4" />
            <span>Solicitar Aceite de Risco (Risk Acceptance)</span>
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="metric-card">
          <p className="text-xs text-slate-400 font-medium">Entidades Correlacionadas</p>
          <p className="text-2xl font-black text-slate-100 mt-1">{matrixData?.total_correlated_entities || 48}</p>
          <span className="text-[10px] text-accent-cyan font-semibold">100% dos nós mapeados</span>
        </div>

        <div className="metric-card">
          <p className="text-xs text-slate-400 font-medium">Riscos Críticos de Negócio</p>
          <p className="text-2xl font-black text-emerald-400 mt-1">{matrixData?.critical_business_risks || 0}</p>
          <span className="text-[10px] text-emerald-400 font-semibold">Mitigados na Borda</span>
        </div>

        <div className="metric-card">
          <p className="text-xs text-slate-400 font-medium">Score Médio de Risco</p>
          <p className="text-2xl font-black text-accent-cyan mt-1">{matrixData?.average_risk_score || 24.5} <span className="text-xs font-normal text-slate-500">/ 100</span></p>
          <span className="text-[10px] text-emerald-400 font-semibold">Baixa Exposição Residual</span>
        </div>

        <div className="metric-card">
          <p className="text-xs text-slate-400 font-medium">Aceites de Risco Ativos</p>
          <p className="text-2xl font-black text-purple-400 mt-1">{matrixData?.active_risk_acceptances || 1}</p>
          <span className="text-[10px] text-slate-400 font-semibold">Aprovados pelo CISO</span>
        </div>
      </div>

      {/* Correlated Chain Selector & Graph Visualizer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Chain List */}
        <div className="space-y-3">
          <h2 className="text-sm font-extrabold text-slate-200 uppercase tracking-wider">
            Cadeias de Risco Correlacionadas
          </h2>
          <div className="space-y-2">
            {matrixData?.correlated_chains?.map((chain: any) => (
              <button
                key={chain.correlation_id}
                onClick={() => setSelectedChainId(chain.correlation_id)}
                className={clsx(
                  'w-full text-left p-4 rounded-xl border transition-all flex flex-col justify-between gap-2',
                  selectedChain?.correlation_id === chain.correlation_id
                    ? 'bg-purple-500/15 border-purple-500/60 shadow-lg'
                    : 'bg-bg-secondary/70 border-bg-border hover:bg-slate-800/40'
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-accent-cyan">{chain.correlation_id}</span>
                  <span className={clsx(
                    'px-2 py-0.5 text-[9px] font-mono font-bold rounded',
                    chain.business_risk_level === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300' :
                    chain.business_risk_level === 'HIGH' ? 'bg-amber-500/20 text-amber-300' :
                    'bg-emerald-500/20 text-emerald-300'
                  )}>
                    Risco: {chain.business_risk_level}
                  </span>
                </div>
                <h3 className="text-sm font-bold text-slate-100 line-clamp-1">{chain.chain_title}</h3>
                <p className="text-xs text-slate-400">{chain.business_service} • {chain.business_unit}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Right: Interactive Multi-Plane Visual Flow */}
        {selectedChain && (
          <div className="lg:col-span-2 space-y-6 p-6 rounded-2xl bg-bg-secondary border border-bg-border shadow-xl">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-4 border-b border-bg-border">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-lg font-black text-slate-100">{selectedChain.chain_title}</h3>
                  <span className="px-2 py-0.5 text-xs font-mono font-bold bg-slate-800 text-slate-300 rounded">
                    {selectedChain.criticality}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Business Owner: <strong className="text-slate-200">{selectedChain.business_owner}</strong> | Tech Lead: <strong className="text-slate-200">{selectedChain.tech_owner}</strong>
                </p>
              </div>

              <div className="text-right">
                <p className="text-[10px] font-mono text-slate-400 uppercase">Risco de Negócio Residual</p>
                <p className="text-2xl font-black text-emerald-400">{selectedChain.business_risk_score} <span className="text-xs text-slate-500">/ 100</span></p>
              </div>
            </div>

            {/* Step-by-Step Multi-Plane Node Chain */}
            <div className="space-y-3">
              <h4 className="text-xs font-extrabold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Layers className="w-4 h-4 text-purple-400" />
                Trilha de Correlação Determinística (7 Camadas)
              </h4>

              <div className="space-y-2">
                {selectedChain.nodes?.map((node: any, nIdx: number) => (
                  <div
                    key={nIdx}
                    className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between gap-3 relative"
                  >
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <span className="w-6 h-6 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/40 text-xs font-bold flex items-center justify-center flex-shrink-0">
                        {nIdx + 1}
                      </span>
                      <div className="min-w-0 flex-1">
                        <span className="text-[10px] font-mono uppercase text-purple-400 font-bold">{node.type}</span>
                        <p className="text-xs font-semibold text-slate-200 truncate">{node.label}</p>
                      </div>
                    </div>

                    <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-slate-900 text-slate-400 border border-slate-700 rounded flex-shrink-0">
                      {node.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Compensating Controls & Mitigation */}
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-emerald-300">
                <ShieldCheck className="w-4 h-4" />
                <span>Controles Compensatórios Ativos (Redução de Impacto):</span>
              </div>
              <ul className="list-disc list-inside text-xs text-slate-300 space-y-1 font-mono">
                {selectedChain.compensating_controls?.map((cc: string, ccIdx: number) => (
                  <li key={ccIdx}>{cc}</li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>

      {/* Risk Acceptance Registry Table */}
      <div className="p-6 rounded-2xl bg-bg-secondary border border-bg-border space-y-4">
        <h2 className="text-base font-extrabold text-slate-100 flex items-center gap-2">
          <Clock className="w-5 h-5 text-accent-cyan" />
          Registro de Aceites de Risco Formal (Risk Acceptance Registry)
        </h2>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="p-3">ID Aceite</th>
                <th className="p-3">Finding Relacionado</th>
                <th className="p-3">Unidade de Negócio</th>
                <th className="p-3">Controle Compensatório</th>
                <th className="p-3">Aprovador</th>
                <th className="p-3">Expiração</th>
                <th className="p-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium text-slate-300">
              {matrixData?.risk_acceptance_registry?.map((ra: any) => (
                <tr key={ra.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="p-3 font-mono text-accent-cyan font-bold">{ra.id}</td>
                  <td className="p-3 font-mono">{ra.finding_id} — {ra.title}</td>
                  <td className="p-3">{ra.business_unit}</td>
                  <td className="p-3 text-slate-400">{ra.compensating_controls}</td>
                  <td className="p-3">{ra.approver}</td>
                  <td className="p-3 font-mono text-amber-400">{ra.days_until_expiration} dias restantes</td>
                  <td className="p-3">
                    <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded">
                      {ra.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal: Formal Risk Acceptance Form */}
      {isRiskModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-lg bg-bg-secondary border border-bg-border rounded-2xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-bg-border">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-amber-400" />
                <h3 className="text-base font-extrabold text-slate-100">Solicitação de Aceite de Risco</h3>
              </div>
              <button onClick={() => setIsRiskModalOpen(false)} className="text-slate-400 hover:text-slate-200">✕</button>
            </div>

            <form onSubmit={handleSubmitRiskAcceptance} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">ID do Finding</label>
                <input
                  type="text"
                  value={findingId}
                  onChange={e => setFindingId(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-slate-100 font-mono"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Justificativa de Negócio</label>
                <textarea
                  rows={3}
                  value={justification}
                  onChange={e => setJustification(e.target.value)}
                  placeholder="Ex: Conexão legada opera em rede interna dedicada sob VPN IPSec e controle de acesso estrito..."
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-slate-100"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Controles Compensatórios Implementados</label>
                <textarea
                  rows={2}
                  value={compensatingControls}
                  onChange={e => setCompensatingControls(e.target.value)}
                  placeholder="Ex: Regras de Microsegmentação eBPF ativas + Certificado mTLS dedicado..."
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-slate-100"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Nível de Risco</label>
                  <select
                    value={riskLevel}
                    onChange={e => setRiskLevel(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-slate-100 font-mono"
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Data de Expiração</label>
                  <input
                    type="date"
                    value={expirationDate}
                    onChange={e => setExpirationDate(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 font-mono"
                    required
                  />
                </div>
              </div>

              <div className="pt-3 border-t border-bg-border flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsRiskModalOpen(false)}
                  className="px-4 py-2 rounded-xl text-slate-400 hover:bg-slate-800"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl font-bold bg-accent-cyan hover:bg-accent-cyan/80 text-slate-950 flex items-center gap-1.5"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>Submeter ao CISO</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
