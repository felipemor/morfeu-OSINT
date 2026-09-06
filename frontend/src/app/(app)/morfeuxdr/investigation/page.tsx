'use client';
import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { SearchCode, Clock, ShieldAlert, FileText, CheckCircle2, User, Terminal, Code, Cpu, ScrollText } from 'lucide-react';
import { morfeuXdrApi } from '@/lib/api';

function InvestigationContent() {
  const searchParams = useSearchParams();
  const findingId = searchParams.get('id') || 'fnd-default';
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeRawTab, setActiveRawTab] = useState<'NORMALIZED' | 'RAW'>('NORMALIZED');

  useEffect(() => {
    async function load() {
      try {
        const res = await morfeuXdrApi.getInvestigation(findingId);
        setData(res);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [findingId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500" />
      </div>
    );
  }

  const finding = data?.finding;
  const whyMatters = data?.why_this_matters;

  return (
    <div className="space-y-6">
      {/* Header Info */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-bg-border pb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 text-[10px] font-extrabold bg-red-500/20 text-red-400 border border-red-500/40 rounded uppercase">
                {finding?.severity || 'CRITICAL'} — RISCO {finding?.risk_score}
              </span>
              <span className="font-mono text-xs text-slate-400">{finding?.finding_number}</span>
              <span className="font-mono text-xs text-accent-cyan">[{finding?.correlation_id}]</span>
            </div>
            <h2 className="text-lg font-bold text-slate-100 mt-1">{finding?.title}</h2>
          </div>

          <div className="flex items-center gap-3">
            <span className="px-3 py-1 text-xs font-bold bg-slate-800 text-slate-200 border border-slate-700 rounded uppercase">
              {finding?.status}
            </span>
          </div>
        </div>

        {/* Why This Matters Box */}
        <div className="p-4 rounded-lg bg-red-950/20 border border-red-500/30 space-y-2 text-xs">
          <h4 className="font-bold text-red-400 text-sm flex items-center gap-2">
            <ShieldAlert className="w-4 h-4" /> Por que isso é importante? (Why This Matters)
          </h4>
          <p className="text-slate-300"><strong className="text-slate-100">Motivo da Detecção:</strong> {whyMatters?.why_detected}</p>
          <p className="text-slate-300"><strong className="text-slate-100">Impacto Potencial:</strong> {whyMatters?.impact}</p>
          <p className="text-slate-300"><strong className="text-slate-100">Ação Recomendada:</strong> {whyMatters?.recommended_action}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Timeline & Evidence */}
        <div className="lg:col-span-2 space-y-6">
          {/* Attack Timeline */}
          <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-4">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Clock className="w-4 h-4 text-accent-cyan" /> Timeline Investigativa de Eventos
            </h3>

            <div className="space-y-4 relative pl-4 border-l-2 border-slate-800">
              {data?.timeline?.map((item: any, idx: number) => (
                <div key={idx} className="relative space-y-1">
                  <span className="w-2.5 h-2.5 rounded-full bg-accent-cyan absolute -left-[21px] top-1" />
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-accent-cyan font-bold">{item.time}</span>
                    <span className="text-[10px] font-mono bg-slate-800 text-slate-400 px-2 py-0.5 rounded">{item.type}</span>
                  </div>
                  <p className="text-xs text-slate-200 font-semibold">{item.event}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Event Raw vs Normalized Viewer */}
          <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-bg-border pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Code className="w-4 h-4 text-purple-400" /> Inspeção de Payload do Evento
              </h3>
              <div className="flex gap-2">
                <button
                  onClick={() => setActiveRawTab('NORMALIZED')}
                  className={`px-3 py-1 text-xs font-semibold rounded ${
                    activeRawTab === 'NORMALIZED' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40' : 'text-slate-400'
                  }`}
                >
                  MorfeuEvent Normalizado
                </button>
                <button
                  onClick={() => setActiveRawTab('RAW')}
                  className={`px-3 py-1 text-xs font-semibold rounded ${
                    activeRawTab === 'RAW' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40' : 'text-slate-400'
                  }`}
                >
                  Raw Wazuh JSON
                </button>
              </div>
            </div>

            <pre className="p-4 rounded-lg bg-slate-950 font-mono text-xs text-slate-300 overflow-x-auto border border-bg-border leading-relaxed">
              {activeRawTab === 'NORMALIZED'
                ? JSON.stringify(finding, null, 2)
                : JSON.stringify(finding?.raw_event, null, 2)}
            </pre>
          </div>
        </div>

        {/* Right Column: Entities & Audit Trail */}
        <div className="space-y-6">
          {/* Affected Entities */}
          <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-3">
            <h3 className="text-sm font-bold text-slate-100">Entidades Afetadas</h3>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-bg-border/40">
                <span className="text-slate-400">Host:</span>
                <span className="font-bold text-slate-200">{finding?.hostname}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-bg-border/40">
                <span className="text-slate-400">IP:</span>
                <span className="font-mono text-slate-300">{finding?.ip}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-bg-border/40">
                <span className="text-slate-400">Usuário:</span>
                <span className="font-bold text-red-400">{finding?.username || 'root'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-bg-border/40">
                <span className="text-slate-400">Processo:</span>
                <span className="font-mono text-slate-300">{finding?.process || 'sshd'}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-400">MITRE Technique:</span>
                <span className="font-mono font-bold text-accent-cyan">{finding?.mitre_technique}</span>
              </div>
            </div>
          </div>

          {/* Audit Trail */}
          <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-3">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <ScrollText className="w-4 h-4 text-slate-400" /> Trilha de Auditoria (Append-Only)
            </h3>

            <div className="space-y-2 text-xs">
              {data?.audit_trail?.map((audit: any) => (
                <div key={audit.id} className="p-2.5 rounded bg-bg-secondary border border-bg-border/60 space-y-1">
                  <div className="flex justify-between text-[10px] font-mono text-slate-400">
                    <span>{audit.actor}</span>
                    <span>{new Date(audit.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <p className="font-bold text-slate-200 text-[11px]">{audit.action}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function InvestigationPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500" />
      </div>
    }>
      <InvestigationContent />
    </Suspense>
  );
}

