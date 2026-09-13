'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { findingsApi, type Finding } from '@/lib/api';
import {
  Wrench, CheckCircle2, Copy, Shield, Terminal, ArrowRight,
  AlertTriangle, CheckSquare, Search, Filter, Bug, BookOpen, ExternalLink, RefreshCw
} from 'lucide-react';
import clsx from 'clsx';
import toast from 'react-hot-toast';
import VulnerabilitySubNav from '@/components/layout/VulnerabilitySubNav';

export default function RemediationPage() {
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState('');
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  const { data: findings = [], isLoading, refetch } = useQuery({
    queryKey: ['all-findings-remediation', sevFilter],
    queryFn: () => findingsApi.list({ severity: sevFilter || undefined }),
  });

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copiado para a área de transferência!`);
  };

  const filteredFindings = findings.filter((f: Finding) => {
    if (f.is_false_positive) return false;
    if (!search) return true;
    return (
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.cwe_id?.toLowerCase().includes(search.toLowerCase()) ||
      f.affected_asset?.toLowerCase().includes(search.toLowerCase())
    );
  });

  const activeFinding = filteredFindings.find(f => f.id === selectedFindingId) || filteredFindings[0];

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 animate-fade-in">
      <VulnerabilitySubNav />
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/90 border border-emerald-500/30 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute -right-10 -bottom-10 w-48 h-48 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="space-y-1.5 z-10">
          <div className="flex items-center gap-2 text-emerald-400 font-mono text-xs font-bold uppercase tracking-wider">
            <Wrench className="w-4 h-4" /> Guia Técnico de Resolução & Remediation Playbooks
          </div>
          <h1 className="text-2xl font-extrabold text-slate-100">Passo a Passo Completo de Remediação</h1>
          <p className="text-sm text-slate-400 max-w-2xl">
            Siga os procedimentos operacionais padrão (SOP) passo a passo com trechos de código prontos para corrigir vulnerabilidades, hardening de servidores e conformidade BACEN / OWASP.
          </p>
        </div>

        <div className="flex items-center gap-3 z-10">
          <button
            onClick={() => refetch()}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-xl border border-slate-700 flex items-center gap-2 transition-all"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Atualizar
          </button>
        </div>
      </div>

      {/* Control Filters */}
      <div className="flex flex-col sm:flex-row items-center gap-3">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
          <input
            type="text"
            placeholder="Buscar por vulnerabilidade, CWE, OWASP ou URL..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="input-field pl-10 w-full"
          />
        </div>
        <select
          value={sevFilter}
          onChange={e => setSevFilter(e.target.value)}
          className="input-field w-full sm:w-48"
        >
          <option value="">Todas as Severidades</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
          <option value="INFO">INFO</option>
        </select>
      </div>

      {/* Main Content Layout */}
      {isLoading ? (
        <div className="flex justify-center py-20">
          <div className="w-10 h-10 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : filteredFindings.length === 0 ? (
        <div className="glass-card p-12 text-center space-y-3">
          <CheckSquare className="w-12 h-12 text-emerald-400 mx-auto opacity-75" />
          <h3 className="text-lg font-bold text-slate-200">Nenhuma vulnerabilidade pendente de remediação</h3>
          <p className="text-slate-400 text-sm max-w-md mx-auto">
            Nenhum achado encontrado para os filtros selecionados. Altere os critérios de busca ou execute um novo scan.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Finding Selector */}
          <div className="lg:col-span-4 space-y-3">
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider px-1">
              Vulnerabilidades ({filteredFindings.length})
            </h3>
            <div className="space-y-2 max-h-[700px] overflow-y-auto pr-1">
              {filteredFindings.map((f: Finding) => {
                const isSelected = activeFinding?.id === f.id;
                return (
                  <div
                    key={f.id}
                    onClick={() => setSelectedFindingId(f.id)}
                    className={clsx(
                      'p-4 rounded-xl border transition-all cursor-pointer space-y-2',
                      isSelected
                        ? 'bg-slate-900 border-emerald-500/60 shadow-lg shadow-emerald-500/5 ring-1 ring-emerald-500/40'
                        : 'bg-bg-card/70 border-bg-border hover:border-slate-700 hover:bg-slate-900/50'
                    )}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span className={clsx('text-[10px] font-extrabold px-2 py-0.5 rounded uppercase border',
                        f.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-300 border-red-500/40' :
                        f.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border-orange-500/40' :
                        f.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                        'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      )}>
                        {f.severity}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">{f.cwe_id || 'CWE-DEF'}</span>
                    </div>

                    <h4 className="text-sm font-semibold text-slate-200 line-clamp-2 leading-snug">
                      {f.title}
                    </h4>

                    <p className="text-xs text-slate-400 truncate font-mono">
                      {f.affected_url || f.affected_asset || 'Infraestrutura Externa'}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Column: Detailed Step-by-Step Remediation Plan */}
          {activeFinding && (
            <div className="lg:col-span-8 space-y-6">
              {/* Finding Summary Banner */}
              <div className="bg-bg-card border border-bg-border rounded-2xl p-6 space-y-4 shadow-xl">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-bg-border pb-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono text-slate-400">{activeFinding.owasp_category || 'OWASP Top 10'}</span>
                      <span className="text-xs text-slate-600">•</span>
                      <span className="text-xs font-mono text-slate-400">{activeFinding.cwe_id || 'CWE'}</span>
                    </div>
                    <h2 className="text-xl font-bold text-slate-100">{activeFinding.title}</h2>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-slate-400 uppercase">CVSS:</span>
                    <span className="text-base font-extrabold font-mono text-amber-400 bg-amber-500/10 px-3 py-1 rounded-lg border border-amber-500/30">
                      {activeFinding.cvss_score?.toFixed(1) || '5.0'}
                    </span>
                  </div>
                </div>

                {/* Technical Overview */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800 space-y-1">
                    <p className="text-slate-500 uppercase font-semibold text-[10px]">Alvo Afetado</p>
                    <p className="text-slate-200 font-mono break-all">{activeFinding.affected_url || activeFinding.affected_asset || 'N/A'}</p>
                  </div>
                  <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800 space-y-1">
                    <p className="text-slate-500 uppercase font-semibold text-[10px]">Status de Correção</p>
                    <p className="text-emerald-400 font-bold uppercase flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                      {activeFinding.status} (Pronto para Aplicação)
                    </p>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Descrição Técnica</h4>
                  <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/40 p-3 rounded-xl border border-slate-800/80">
                    {activeFinding.description}
                  </p>
                </div>
              </div>

              {/* STEP BY STEP RESOLUTION CARD */}
              <div className="bg-slate-900 border-2 border-emerald-500/40 rounded-2xl p-6 space-y-6 shadow-2xl relative overflow-hidden">
                <div className="flex items-center justify-between border-b border-emerald-500/30 pb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
                      <CheckSquare className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-base font-extrabold text-slate-100 flex items-center gap-2">
                        Passo a Passo Completo para Resolução
                      </h3>
                      <p className="text-xs text-emerald-400/90 font-mono">Procedimento Operacional Padrão de Mitigação (SOP)</p>
                    </div>
                  </div>
                  <span className="text-xs font-mono bg-emerald-500/20 text-emerald-300 px-3 py-1 rounded-full border border-emerald-500/40 font-semibold">
                    Plano Verificado
                  </span>
                </div>

                {/* Steps List */}
                <div className="space-y-4">
                  {activeFinding.remediation_steps && activeFinding.remediation_steps.length > 0 ? (
                    activeFinding.remediation_steps.map((step: string, idx: number) => (
                      <div key={idx} className="flex items-start gap-4 bg-slate-950/80 p-4 rounded-xl border border-slate-800 hover:border-emerald-500/30 transition-all">
                        <div className="flex-shrink-0 w-8 h-8 rounded-xl bg-emerald-500/20 text-emerald-400 font-mono font-bold text-sm flex items-center justify-center border border-emerald-500/40 shadow-inner">
                          {idx + 1}
                        </div>
                        <div className="flex-1 space-y-1">
                          <p className="text-xs font-bold text-emerald-300 uppercase tracking-wide">Passo {idx + 1}</p>
                          <p className="text-xs text-slate-200 leading-relaxed font-sans">{step}</p>
                        </div>
                      </div>
                    ))
                  ) : (
                    [
                      `Passo 1: Isolar o endpoint afetado (${activeFinding.affected_url || 'Alvo'}) para contenção imediata.`,
                      `Passo 2: Aplicar a correção recomendada: ${activeFinding.recommendation || 'Atualizar as configurações de cabeçalho e segurança perimétrica.'}`,
                      `Passo 3: Se houver código de suporte, injetar as diretivas técnicas de desenvolvedor.`,
                      `Passo 4: Executar o Retest automatizado para confirmação do status FIXED.`
                    ].map((step: string, idx: number) => (
                      <div key={idx} className="flex items-start gap-4 bg-slate-950/80 p-4 rounded-xl border border-slate-800">
                        <div className="flex-shrink-0 w-8 h-8 rounded-xl bg-emerald-500/20 text-emerald-400 font-mono font-bold text-sm flex items-center justify-center border border-emerald-500/40">
                          {idx + 1}
                        </div>
                        <div className="flex-1 space-y-1">
                          <p className="text-xs font-bold text-emerald-300 uppercase tracking-wide">Passo {idx + 1}</p>
                          <p className="text-xs text-slate-200 leading-relaxed font-sans">{step}</p>
                        </div>
                      </div>
                    ))
                  )}
                </div>

                {/* Developer Configuration Snippet Codeblock */}
                {activeFinding.developer_recommendation && (
                  <div className="space-y-2 pt-2 border-t border-emerald-500/20">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-accent-cyan uppercase tracking-wider flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5" /> Trecho de Código / Snippet Pronto para Aplicação
                      </span>
                      <button
                        onClick={() => copyToClipboard(activeFinding.developer_recommendation!, 'Snippet de Configuração')}
                        className="btn-ghost text-xs py-1 px-2 flex items-center gap-1.5 text-accent-cyan hover:text-cyan-300"
                      >
                        <Copy className="w-3.5 h-3.5" /> Copiar Snippet
                      </button>
                    </div>
                    <pre className="text-xs text-emerald-300/90 font-mono bg-slate-950 border border-slate-800 p-4 rounded-xl overflow-x-auto whitespace-pre-wrap leading-relaxed shadow-inner">
                      {activeFinding.developer_recommendation}
                    </pre>
                  </div>
                )}
              </div>

              {/* General Hardening Reference Box */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3 text-xs">
                <h4 className="font-bold text-slate-300 flex items-center gap-2">
                  <BookOpen className="w-4 h-4 text-emerald-400" /> Referências de Segurança e Frameworks Oficiais
                </h4>
                <p className="text-slate-400 leading-relaxed">
                  As diretivas de remediação deste guia estão alinhadas aos padrões **OWASP Top 10 (v2021)**, **NIST SP 800-53 (Rev. 5)** e resolução **BACEN Res. 4.893/2021** para conformidade do setor financeiro.
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
