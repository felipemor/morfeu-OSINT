'use client';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  BarChart2, Flame, GitGraph, ShieldAlert, Cpu, Terminal, RefreshCw, Layers
} from 'lucide-react';
import { useState } from 'react';
import { grafanaAnalyticsApi } from '@/lib/api';
import toast from 'react-hot-toast';

const tabs = [
  { name: 'Grafana Dashboard', href: '/grafana-analytics', icon: BarChart2 },
  { name: 'Attack Graph Correlator', href: '/grafana-analytics/attack-graph', icon: GitGraph },
  { name: 'Honeypot Decoy Center', href: '/grafana-analytics/honeypot', icon: Flame },
  { name: 'Prometheus Metrics', href: '/grafana-analytics/metrics', icon: Cpu },
  { name: 'Correlation Rules', href: '/grafana-analytics/rules', icon: Layers },
];

export default function GrafanaAnalyticsLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [seeding, setSeeding] = useState(false);

  const handleSeedDemo = async () => {
    setSeeding(true);
    try {
      await grafanaAnalyticsApi.seedDemo();
      toast.success('Dados do Grafana & Honeypot recarregados!');
      window.location.reload();
    } catch (e) {
      toast.error('Erro ao reiniciar dados.');
    } finally {
      setSeeding(false);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-bg-card border border-bg-border rounded-xl p-5 shadow-lg relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-full bg-gradient-to-l from-orange-500/10 to-transparent pointer-events-none" />
        <div className="space-y-1 z-10">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-orange-500/10 border border-orange-500/30 text-orange-500">
              <BarChart2 className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold text-slate-100 tracking-tight">Grafana Security Analytics & Honeypot Correlator</h1>
                <span className="px-2 py-0.5 text-[10px] font-extrabold bg-orange-500/20 text-orange-400 border border-orange-500/40 rounded uppercase tracking-wider">
                  PROMETHEUS & GRAFANA ENGINE
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Correlação unificada em tempo real: Pentest Vulnerabilities ➔ eBPF Microsegmentation ➔ Wazuh XDR ➔ Honeypot Decoys.
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row items-center gap-3 z-10">
          <div className="px-3 py-1.5 rounded-lg bg-orange-500/10 border border-orange-500/30 text-orange-400 text-xs font-semibold flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-orange-400 animate-ping" />
            <span>GRAFANA & PROMETHEUS ONLINE</span>
          </div>
          <button
            onClick={handleSeedDemo}
            disabled={seeding}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-semibold bg-bg-secondary hover:bg-slate-800 text-slate-300 border border-bg-border rounded-lg transition-all"
            title="Recarregar dados do Grafana"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${seeding ? 'animate-spin' : ''}`} />
            Reiniciar Dados Demo
          </button>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="border-b border-bg-border/80 overflow-x-auto scrollbar-none">
        <nav className="flex space-x-1 min-w-max pb-1">
          {tabs.map((tab) => {
            const isActive = pathname === tab.href;
            const Icon = tab.icon;
            return (
              <Link
                key={tab.href}
                href={tab.href}
                className={`flex items-center gap-2 px-3.5 py-2 text-xs font-medium rounded-t-lg transition-all ${
                  isActive
                    ? 'bg-orange-500/10 text-orange-400 border-b-2 border-orange-500 shadow-[0_2px_10px_rgba(249,115,22,0.15)] font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-orange-400' : 'text-slate-400'}`} />
                <span>{tab.name}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Tab View Content */}
      <div>{children}</div>
    </div>
  );
}
