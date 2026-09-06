'use client';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard, Network, ArrowRightLeft, Boxes, ShieldCheck,
  GitPullRequest, Grid, PlaySquare, BarChart3, Cable, Settings, RefreshCw, DownloadCloud
} from 'lucide-react';
import { useState } from 'react';
import { microsegmentationApi } from '@/lib/api';
import toast from 'react-hot-toast';

const tabs = [
  { name: 'Overview', href: '/microsegmentation', icon: LayoutDashboard },
  { name: 'Instalação & eBPF', href: '/microsegmentation/onboarding', icon: DownloadCloud },
  { name: 'Network Map', href: '/microsegmentation/network-map', icon: Network },
  { name: 'Flows', href: '/microsegmentation/flows', icon: ArrowRightLeft },
  { name: 'Assets', href: '/microsegmentation/assets', icon: Boxes },
  { name: 'Policies', href: '/microsegmentation/policies', icon: ShieldCheck },
  { name: 'Attack Paths', href: '/microsegmentation/attack-paths', icon: GitPullRequest },
  { name: 'Segmentation', href: '/microsegmentation/segmentation', icon: Grid },
  { name: 'Simulations', href: '/microsegmentation/simulations', icon: PlaySquare },
  { name: 'Analytics', href: '/microsegmentation/analytics', icon: BarChart3 },
  { name: 'Integrations', href: '/microsegmentation/integrations', icon: Cable },
  { name: 'Settings', href: '/microsegmentation/settings', icon: Settings },
];

export default function MicrosegmentationLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [seeding, setSeeding] = useState(false);

  const handleSeedDemo = async () => {
    setSeeding(true);
    try {
      await microsegmentationApi.seedDemo();
      toast.success('Dados de demonstração enterprise inicializados com sucesso!');
      window.location.reload();
    } catch (e) {
      toast.error('Erro ao reiniciar dados de demonstração.');
    } finally {
      setSeeding(false);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-bg-card border border-bg-border rounded-xl p-5 shadow-lg relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-full bg-gradient-to-l from-accent-cyan/10 to-transparent pointer-events-none" />
        <div className="space-y-1 z-10">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan">
              <Network className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold text-slate-100 tracking-tight">Microsegmentação Híbrida & Zero Trust</h1>
                <span className="px-2 py-0.5 text-[10px] font-extrabold bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/40 rounded uppercase tracking-wider">
                  ENTERPRISE GUARDICORE LEVEL
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Observabilidade de tráfego eBPF em tempo real, prevenção de movimento lateral e aplicação de políticas Zero Trust em K8s, VMs e Cloud.
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row items-center gap-3 z-10">
          <div className="px-3 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-accent-cyan text-xs font-semibold flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-accent-cyan animate-ping" />
            <span>MODO DEMO SIMULADO</span>
          </div>
          <button
            onClick={handleSeedDemo}
            disabled={seeding}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-semibold bg-bg-secondary hover:bg-slate-800 text-slate-300 border border-bg-border rounded-lg transition-all"
            title="Resetar ambiente com dados enterprise estilo Akamai Guardicore"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${seeding ? 'animate-spin' : ''}`} />
            Reiniciar Dados Demo
          </button>
        </div>
      </div>

      {/* Explicit Notice Banner */}
      <div className="p-3.5 rounded-xl bg-cyan-950/20 border border-cyan-500/30 text-xs text-cyan-200/90 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-start gap-2.5">
          <span className="px-2 py-0.5 text-[9px] font-extrabold bg-cyan-500/20 text-accent-cyan border border-cyan-500/40 rounded uppercase mt-0.5">
            INFORMAÇÃO ARQUITETURAL
          </span>
          <p>
            <strong>Você está visualizando um ambiente de demonstração simulado (Demo Dataset).</strong> Os fluxos eBPF, ativos K8s e integrações exibidos nesta aba são dados simulados para permitir a validação e navegação nas 11 sub-telas sem depender de um cluster Cilium/eBPF físico instalado previamente.
          </p>
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
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
                    ? 'bg-accent-cyan/10 text-accent-cyan border-b-2 border-accent-cyan shadow-[0_2px_10px_rgba(0,212,255,0.15)] font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-accent-cyan' : 'text-slate-400'}`} />
                <span>{tab.name}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Main Tab Content */}
      <div>{children}</div>
    </div>
  );
}
