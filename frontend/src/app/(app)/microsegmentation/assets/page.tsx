'use client';
import { useEffect, useState } from 'react';
import { Boxes, Shield, Server, Database, Smartphone, CheckCircle2, AlertTriangle } from 'lucide-react';
import { microsegmentationApi } from '@/lib/api';

export default function AssetsPage() {
  const [assets, setAssets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const data = await microsegmentationApi.getAssets();
        setAssets(data);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-slate-100">Inventário de Ativos & Workloads Monitorados</h2>
          <p className="text-xs text-slate-400">Ativos com agentes de microsegmentação ou coleta eBPF ativa.</p>
        </div>
        <span className="px-3 py-1 text-xs font-semibold bg-bg-card border border-bg-border rounded-lg text-accent-cyan">
          Total: {assets.length} Ativos
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {assets.map((asset) => (
          <div key={asset.id} className="bg-bg-card border border-bg-border rounded-xl p-5 space-y-3 relative overflow-hidden">
            <div className="flex items-start justify-between">
              <div className="space-y-1">
                <span className="px-2 py-0.5 text-[9px] font-extrabold bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/30 rounded uppercase">
                  {asset.asset_type}
                </span>
                <h3 className="text-sm font-bold text-slate-100">{asset.name}</h3>
                <p className="text-xs font-mono text-slate-400">{asset.ip_address}</p>
              </div>

              <span className={`w-3 h-3 rounded-full ${asset.status === 'HEALTHY' ? 'bg-accent-green' : 'bg-red-500 animate-ping'}`} />
            </div>

            <div className="pt-2 border-t border-bg-border/60 space-y-1 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400">Zona:</span>
                <span className="font-semibold text-slate-200">{asset.zone_name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Namespace:</span>
                <span className="font-mono text-slate-300">{asset.namespace || 'default'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Sistema / Imagem:</span>
                <span className="text-slate-300">{asset.os_info}</span>
              </div>
              <div className="flex justify-between pt-1">
                <span className="text-slate-400">Pontuação de Risco:</span>
                <span className={`font-mono font-bold ${asset.risk_score > 30 ? 'text-amber-400' : 'text-accent-cyan'}`}>
                  {asset.risk_score} / 100
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
