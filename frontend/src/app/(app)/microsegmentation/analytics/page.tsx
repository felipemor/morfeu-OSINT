'use client';
import { useEffect, useState } from 'react';
import { BarChart3, Activity, PieChart, ShieldAlert } from 'lucide-react';
import { microsegmentationApi } from '@/lib/api';

export default function AnalyticsPage() {
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    async function load() {
      try {
        const res = await microsegmentationApi.getAnalytics();
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
        <h2 className="text-base font-bold text-slate-100">Analytics de Tráfego & Detecção de Anomalias</h2>
        <p className="text-xs text-slate-400">
          Métricas de consumo de largura de banda, distribuição de protocolos e histórico de anomalias.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Protocol Breakdown */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-4">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <PieChart className="w-4 h-4 text-accent-cyan" /> Distribuição de Protocolos
          </h3>

          <div className="space-y-3">
            {data?.top_protocols?.map((p: any, idx: number) => (
              <div key={idx} className="space-y-1">
                <div className="flex justify-between text-xs font-semibold">
                  <span className="text-slate-300">{p.protocol}</span>
                  <span className="text-accent-cyan">{p.percentage}%</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div className="bg-accent-cyan h-full rounded-full" style={{ width: `${p.percentage}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Traffic Volume Timeline */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-4">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-purple-400" /> Volume de Tráfego (Permitido vs Bloqueado MB)
          </h3>

          <div className="space-y-3 pt-2">
            {data?.traffic_volume_over_time?.map((item: any, idx: number) => (
              <div key={idx} className="flex items-center justify-between text-xs py-1.5 border-b border-bg-border/40 font-mono">
                <span className="text-slate-400">{item.time}</span>
                <div className="flex items-center gap-4">
                  <span className="text-accent-cyan">Permitido: {item.allowed_mb} MB</span>
                  <span className="text-red-400 font-bold">Bloqueado: {item.blocked_mb} MB</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
