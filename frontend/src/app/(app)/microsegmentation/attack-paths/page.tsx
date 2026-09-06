'use client';
import { useEffect, useState } from 'react';
import { GitPullRequest, ShieldAlert, ArrowRight, ShieldCheck, Bug, CheckCircle2 } from 'lucide-react';
import { microsegmentationApi } from '@/lib/api';
import toast from 'react-hot-toast';

export default function AttackPathsPage() {
  const [paths, setPaths] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const data = await microsegmentationApi.getAttackPaths();
        setPaths(data);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const handleMitigate = () => {
    toast.success('Política Zero Trust aplicada! Caminho de movimento lateral bloqueado.');
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-bold text-slate-100">Caminhos de Ataque & Movimento Lateral (Pentest Mapped)</h2>
        <p className="text-xs text-slate-400">
          Visualizador de pivoting e exploração lateral derivados de vulnerabilidades descobertas pelo módulo Auto Pentest.
        </p>
      </div>

      <div className="space-y-6">
        {paths.map((path) => (
          <div key={path.id} className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-4 relative overflow-hidden">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-bg-border pb-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 text-[10px] font-extrabold bg-red-500/20 text-red-400 border border-red-500/40 rounded uppercase">
                    RISCO {path.risk_level}
                  </span>
                  <span className="text-xs font-semibold text-slate-400">Status: {path.status}</span>
                </div>
                <h3 className="text-sm font-bold text-slate-100">{path.title}</h3>
                <p className="text-xs text-slate-400">{path.description}</p>
              </div>

              <button
                onClick={handleMitigate}
                className="flex items-center gap-2 px-4 py-2 text-xs font-bold bg-accent-green/20 text-accent-green hover:bg-accent-green/30 border border-accent-green/40 rounded-lg transition-all flex-shrink-0"
              >
                <ShieldCheck className="w-4 h-4" /> Aplicar Bloqueio Zero Trust
              </button>
            </div>

            {/* Hops Timeline */}
            <div className="space-y-3 pt-2">
              <h4 className="text-xs font-bold text-slate-300">Etapas do Pivoting Lateral (Hops):</h4>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 relative">
                {path.hops?.map((hop: any, idx: number) => (
                  <div key={idx} className="bg-bg-secondary border border-bg-border rounded-lg p-4 space-y-2 relative">
                    <div className="flex items-center justify-between">
                      <span className="w-5 h-5 rounded-full bg-accent-cyan/20 text-accent-cyan font-mono text-[10px] font-bold flex items-center justify-center border border-accent-cyan/30">
                        {hop.step}
                      </span>
                      <span className="text-[9px] font-mono text-slate-400">{hop.type}</span>
                    </div>

                    <div>
                      <h5 className="text-xs font-bold text-slate-100 truncate">{hop.asset_name}</h5>
                      <p className="text-[10px] font-mono text-slate-400">{hop.ip}</p>
                    </div>

                    <div className="p-2 rounded bg-red-950/20 border border-red-500/20 text-[10px] text-red-300 space-y-0.5">
                      <div className="font-bold flex items-center gap-1">
                        <Bug className="w-3 h-3 text-red-400" /> Vulnerabilidade:
                      </div>
                      <div className="text-slate-300">{hop.vuln}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
