'use client';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  ShieldAlert, LayoutDashboard, Bug, AlertCircle, SearchCode, GitGraph,
  Grid, Cpu, Zap, CheckSquare, BarChart3, ScrollText, Settings, RefreshCw, DownloadCloud
} from 'lucide-react';
import { useState } from 'react';
import { morfeuXdrApi } from '@/lib/api';
import toast from 'react-hot-toast';

const tabs = [
  { name: 'Overview (SOC)', href: '/morfeuxdr', icon: LayoutDashboard },
  { name: 'Instalação de Agentes', href: '/morfeuxdr/onboarding', icon: DownloadCloud },
  { name: 'Findings', href: '/morfeuxdr/findings', icon: Bug },
  { name: 'Incidents', href: '/morfeuxdr/incidents', icon: AlertCircle },
  { name: 'Investigation', href: '/morfeuxdr/investigation', icon: SearchCode },
  { name: 'Entity Graph', href: '/morfeuxdr/entity-graph', icon: GitGraph },
  { name: 'MITRE ATT&CK', href: '/morfeuxdr/mitre', icon: Grid },
  { name: 'Wazuh Modules', href: '/morfeuxdr/wazuh-modules', icon: Cpu },
  { name: 'Active Response', href: '/morfeuxdr/active-response', icon: Zap },
  { name: 'Compliance', href: '/morfeuxdr/compliance', icon: CheckSquare },
  { name: 'Executive View', href: '/morfeuxdr/executive', icon: BarChart3 },
  { name: 'Audit Logs', href: '/morfeuxdr/audit-logs', icon: ScrollText },
  { name: 'Settings', href: '/morfeuxdr/settings', icon: Settings },
];

export default function MorfeuXDRLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [seeding, setSeeding] = useState(false);

  const handleSeedDemo = async () => {
    setSeeding(true);
    try {
      await morfeuXdrApi.seedDemo();
      toast.success('Dados de demonstração SOC MorfeuXDR inicializados!');
      window.location.reload();
    } catch (e) {
      toast.error('Erro ao reiniciar dados.');
    } finally {
      setSeeding(false);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-bg-card border border-bg-border rounded-xl p-5 shadow-lg relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-full bg-gradient-to-l from-red-500/10 to-transparent pointer-events-none" />
        <div className="space-y-1 z-10">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold text-slate-100 tracking-tight">MorfeuXDR</h1>
                <span className="px-2 py-0.5 text-[10px] font-extrabold bg-slate-800 text-slate-300 border border-slate-700 rounded uppercase tracking-wider">
                  POWERED BY WAZUH XDR ENGINE
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Plataforma corporativa de detecção estendida, correlação de incidentes, triagem de findings e investigação SOC.
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row items-center gap-3 z-10">
          <div className="px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-semibold flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
            <span>MODO DEMO SIMULADO</span>
          </div>
          <button
            onClick={handleSeedDemo}
            disabled={seeding}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-semibold bg-bg-secondary hover:bg-slate-800 text-slate-300 border border-bg-border rounded-lg transition-all"
            title="Recarregar dataset de demonstração SOC"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${seeding ? 'animate-spin' : ''}`} />
            Reiniciar Dados Demo
          </button>
        </div>
      </div>

      {/* Explicit Notice Banner explaining why data appears without real installation */}
      <div className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-500/30 text-xs text-amber-200/90 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-start gap-2.5">
          <span className="px-2 py-0.5 text-[9px] font-extrabold bg-amber-500/20 text-amber-300 border border-amber-500/40 rounded uppercase mt-0.5">
            INFORMAÇÃO ARQUITETURAL
          </span>
          <p>
            <strong>Você está visualizando dados de demonstração corporativa (Demo Dataset).</strong> Os eventos, agentes e alertas exibidos nas abas são cenários simulados para demonstração de capacidades. Nenhuma instalação física ou agente real foi detectado ainda. Para conectar a um servidor Wazuh real, acesse a aba <strong>Settings</strong>.
          </p>
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
                    ? 'bg-red-500/10 text-red-400 border-b-2 border-red-500 shadow-[0_2px_10px_rgba(239,68,68,0.15)] font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-red-400' : 'text-slate-400'}`} />
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
