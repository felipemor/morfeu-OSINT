'use client';
import { useEffect, useState } from 'react';
import { GitGraph, User, Server, Terminal, Globe, Bug, ShieldAlert } from 'lucide-react';
import { morfeuXdrApi } from '@/lib/api';

export default function EntityGraphPage() {
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    async function load() {
      try {
        const res = await morfeuXdrApi.getEntityGraph();
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
        <h2 className="text-base font-bold text-slate-100">Gráfico de Relacionamento de Entidades</h2>
        <p className="text-xs text-slate-400">
          Mapeamento visual de conexões entre Usuários, Hosts, Processos, IPs e Findings do MorfeuXDR.
        </p>
      </div>

      <div className="bg-bg-card border border-bg-border rounded-xl p-6 min-h-[450px] relative flex flex-col justify-between">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          {data?.nodes?.map((node: any) => (
            <div key={node.id} className="bg-bg-secondary border border-bg-border rounded-xl p-4 space-y-2 relative overflow-hidden">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 text-[9px] font-extrabold bg-slate-800 text-slate-300 rounded uppercase">
                  {node.type}
                </span>
                <span className="font-mono text-xs font-bold text-red-400">Risco: {node.risk}</span>
              </div>
              <h4 className="text-sm font-bold text-slate-100 truncate">{node.label}</h4>
              <p className="text-[10px] text-slate-400">Conectado a incidentes ativos no SOC</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
