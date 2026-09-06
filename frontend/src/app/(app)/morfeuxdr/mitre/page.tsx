'use client';
import { useEffect, useState } from 'react';
import { Grid, ShieldCheck, Bug } from 'lucide-react';
import { morfeuXdrApi } from '@/lib/api';

export default function MitreMatrixPage() {
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    async function load() {
      try {
        const res = await morfeuXdrApi.getMitreMatrix();
        setData(res);
      } catch (e) {
        console.error(e);
      }
    }
    load();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-bold text-slate-100">Matriz de Cobertura MITRE ATT&CK</h2>
        <p className="text-xs text-slate-400">
          Mapeamento de técnicas detectadas pelo Wazuh Engine e regras ativas no MorfeuXDR.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {data?.tactics?.map((tactic: any, idx: number) => (
          <div key={idx} className="bg-bg-card border border-bg-border rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between border-b border-bg-border pb-2">
              <h3 className="text-xs font-bold text-slate-100 uppercase">{tactic.name}</h3>
              <span className="px-2 py-0.5 text-[10px] font-mono bg-red-500/10 text-red-400 border border-red-500/30 rounded font-bold">
                {tactic.count} Regras
              </span>
            </div>

            <div className="space-y-1.5 text-xs">
              <span className="text-[10px] font-semibold text-slate-400 block">Técnicas com Detecção Ativa:</span>
              {tactic.detected_techniques?.map((tech: string, i: number) => (
                <div key={i} className="p-2 rounded bg-bg-secondary text-[11px] font-mono text-slate-200 border border-bg-border">
                  {tech}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
