'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { AlertCircle, ShieldAlert, ArrowRight, Layers, Eye } from 'lucide-react';
import { morfeuXdrApi } from '@/lib/api';

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<any[]>([]);

  useEffect(() => {
    async function load() {
      try {
        const data = await morfeuXdrApi.getIncidents();
        setIncidents(data);
      } catch (e) {
        console.error(e);
      }
    }
    load();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-bold text-slate-100">Incidentes de Segurança Correlacionados</h2>
        <p className="text-xs text-slate-400">
          Grupos de alertas e findings correlacionados por tempo, entidade e vetor de ataque sob um único ID de incidente.
        </p>
      </div>

      <div className="space-y-4">
        {incidents.map((inc) => (
          <div key={inc.id} className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-4 relative overflow-hidden">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-bg-border pb-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 text-[10px] font-extrabold bg-red-500/20 text-red-400 border border-red-500/40 rounded uppercase">
                    SEVERIDADE {inc.severity}
                  </span>
                  <span className="font-mono text-xs text-slate-400">{inc.incident_number}</span>
                  <span className="font-mono text-xs text-accent-cyan">[{inc.correlation_id}]</span>
                </div>
                <h3 className="text-base font-bold text-slate-100">{inc.title}</h3>
                <p className="text-xs text-slate-400">{inc.description}</p>
              </div>

              <div className="flex items-center gap-4">
                <div className="text-right text-xs">
                  <span className="text-slate-400 block text-[10px]">Score de Risco:</span>
                  <span className="font-mono text-lg font-black text-red-400">{inc.risk_score}</span>
                </div>

                <Link
                  href="/morfeuxdr/investigation"
                  className="flex items-center gap-2 px-4 py-2 text-xs font-bold bg-red-500 text-slate-950 rounded-lg hover:bg-red-400 transition-all flex-shrink-0"
                >
                  <Eye className="w-4 h-4" /> Investigar Incidente
                </Link>
              </div>
            </div>

            {/* Techniques & Impacted Assets */}
            <div className="flex flex-wrap items-center justify-between gap-4 text-xs">
              <div className="space-y-1">
                <span className="text-slate-400 block text-[10px]">Técnicas MITRE Identificadas:</span>
                <div className="flex flex-wrap gap-1.5">
                  {inc.mitre_techniques?.map((t: string, idx: number) => (
                    <span key={idx} className="px-2 py-0.5 text-[10px] font-mono bg-slate-800 text-slate-300 rounded border border-slate-700">
                      {t}
                    </span>
                  ))}
                </div>
              </div>

              <div className="text-right">
                <span className="text-slate-400 block text-[10px]">Responsável Atribuído:</span>
                <span className="font-semibold text-slate-200">{inc.assigned_to}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
