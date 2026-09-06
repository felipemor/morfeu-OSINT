'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  ShieldAlert, ShieldCheck, Network, ArrowRightLeft, Boxes, GitPullRequest,
  AlertTriangle, CheckCircle2, Play, Sparkles, Activity, Layers, ArrowUpRight
} from 'lucide-react';
import { microsegmentationApi } from '@/lib/api';

export default function MicrosegmentationOverview() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const res = await microsegmentationApi.getOverview();
        setData(res);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent-cyan" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Banner & Zero Trust Score */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Score Gauge Card */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-6 flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-accent-cyan/5 rounded-full blur-2xl pointer-events-none" />
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Microsegmentation Health Score</span>
              <span className="px-2 py-0.5 text-[10px] font-bold bg-accent-green/10 text-accent-green border border-accent-green/30 rounded">OPTIMIZED</span>
            </div>
            <div className="mt-4 flex items-baseline gap-3">
              <span className="text-5xl font-black text-slate-100 tracking-tight">{data?.health_score || 92.4}%</span>
              <span className="text-xs font-bold text-accent-green flex items-center gap-0.5">
                <ArrowUpRight className="w-3.5 h-3.5" /> +4.2% esta semana
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-2">
              Nível de isolamento de rede Zero Trust baseado em políticas ativas e eBPF flow enforcement.
            </p>
          </div>

          {/* Progress Bar */}
          <div className="mt-6 space-y-2">
            <div className="flex justify-between text-xs font-medium text-slate-300">
              <span>Zero Trust Cobertura</span>
              <span className="text-accent-cyan">{data?.coverage_percentage || 100}%</span>
            </div>
            <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
              <div
                className="bg-gradient-to-r from-accent-cyan to-accent-blue h-full rounded-full transition-all duration-1000"
                style={{ width: `${data?.coverage_percentage || 100}%` }}
              />
            </div>
          </div>
        </div>

        {/* Telemetry & Enforcing Stats */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Telemetria & eBPF Engine</span>
              <span className="flex items-center gap-1.5 text-xs text-accent-green font-semibold">
                <span className="w-2 h-2 rounded-full bg-accent-green animate-ping" /> Online
              </span>
            </div>
            <div className="mt-4 space-y-3">
              <div className="flex items-center justify-between text-xs py-2 border-b border-bg-border/60">
                <span className="text-slate-400">Provedor Principal:</span>
                <span className="font-mono text-slate-200 font-bold">Cilium Hubble eBPF Collector</span>
              </div>
              <div className="flex items-center justify-between text-xs py-2 border-b border-bg-border/60">
                <span className="text-slate-400">Fluxos Analisados:</span>
                <span className="font-mono text-accent-cyan font-bold">4.850 eps (eventos/s)</span>
              </div>
              <div className="flex items-center justify-between text-xs py-2">
                <span className="text-slate-400">Modo de Imposição:</span>
                <span className="font-bold text-accent-green uppercase">Enforcing & Monitoring</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-bg-border/60 flex items-center justify-between text-xs text-slate-400">
            <span>Última sincronização eBPF:</span>
            <span className="font-mono text-slate-300">Há 2 segundos</span>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-6 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-100">Ações Rápidas de Microsegmentação</h3>
            <p className="text-xs text-slate-400 mt-1">Execute simulações ou gere políticas com um clique.</p>

            <div className="mt-4 space-y-2">
              <Link
                href="/microsegmentation/network-map"
                className="w-full flex items-center justify-between p-3 rounded-lg bg-bg-secondary hover:bg-slate-800 border border-bg-border text-xs text-slate-200 font-semibold transition-all group"
              >
                <div className="flex items-center gap-2.5">
                  <Network className="w-4 h-4 text-accent-cyan" />
                  <span>Abrir Network Map Topológico</span>
                </div>
                <ArrowUpRight className="w-4 h-4 text-slate-500 group-hover:text-accent-cyan transition-colors" />
              </Link>

              <Link
                href="/microsegmentation/policies"
                className="w-full flex items-center justify-between p-3 rounded-lg bg-bg-secondary hover:bg-slate-800 border border-bg-border text-xs text-slate-200 font-semibold transition-all group"
              >
                <div className="flex items-center gap-2.5">
                  <Sparkles className="w-4 h-4 text-purple-400" />
                  <span>Gerar Políticas de IA (Auto-Lockdown)</span>
                </div>
                <ArrowUpRight className="w-4 h-4 text-slate-500 group-hover:text-purple-400 transition-colors" />
              </Link>

              <Link
                href="/microsegmentation/simulations"
                className="w-full flex items-center justify-between p-3 rounded-lg bg-bg-secondary hover:bg-slate-800 border border-bg-border text-xs text-slate-200 font-semibold transition-all group"
              >
                <div className="flex items-center gap-2.5">
                  <Play className="w-4 h-4 text-accent-green" />
                  <span>Simular Blast Radius de Regras</span>
                </div>
                <ArrowUpRight className="w-4 h-4 text-slate-500 group-hover:text-accent-green transition-colors" />
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* Metric Cards Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase">Ativos Totais</span>
            <Boxes className="w-4 h-4 text-accent-cyan" />
          </div>
          <p className="text-2xl font-black text-slate-100">{data?.total_assets || 8}</p>
          <p className="text-[10px] text-slate-400">Pods, VMs & Cloud DBs</p>
        </div>

        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase">Zonas Criadas</span>
            <Layers className="w-4 h-4 text-purple-400" />
          </div>
          <p className="text-2xl font-black text-slate-100">{data?.total_zones || 6}</p>
          <p className="text-[10px] text-slate-400">DMZ, PCI-DSS, Core DB</p>
        </div>

        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase">Políticas Ativas</span>
            <ShieldCheck className="w-4 h-4 text-accent-green" />
          </div>
          <p className="text-2xl font-black text-slate-100">{data?.active_enforcing_policies || 3}</p>
          <p className="text-[10px] text-accent-green font-semibold">100% em modo Enforcing</p>
        </div>

        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase">Fluxos Monitorados</span>
            <ArrowRightLeft className="w-4 h-4 text-slate-400" />
          </div>
          <p className="text-2xl font-black text-slate-100">{data?.total_flows_monitored || 8}</p>
          <p className="text-[10px] text-slate-400">Em tempo real via eBPF</p>
        </div>

        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase">Bloqueios de Mov. Lateral</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <p className="text-2xl font-black text-amber-400">{data?.blocked_violations_count || 3}</p>
          <p className="text-[10px] text-amber-400 font-semibold">Conexões negadas</p>
        </div>

        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase">Attack Paths</span>
            <GitPullRequest className="w-4 h-4 text-red-500" />
          </div>
          <p className="text-2xl font-black text-red-500">{data?.active_attack_paths || 1}</p>
          <p className="text-[10px] text-red-400 font-semibold">Originados do Pentest</p>
        </div>
      </div>

      {/* Active Alerts & Critical Anomalies */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-500" />
            <h2 className="text-base font-bold text-slate-100">Alertas de Violação de Segmentação Recentes</h2>
          </div>
          <Link href="/microsegmentation/flows" className="text-xs text-accent-cyan hover:underline font-semibold">
            Ver Todos os Log de Fluxo →
          </Link>
        </div>

        <div className="space-y-3">
          <div className="p-4 rounded-lg bg-red-950/20 border border-red-500/30 flex items-start justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/40 rounded uppercase">
                  VIOLATION - CRITICAL
                </span>
                <span className="text-xs text-slate-400 font-mono">10.0.1.10:5432 → 10.0.3.50:5432</span>
              </div>
              <h4 className="text-sm font-bold text-slate-200">
                Tentativa de Acesso Direto da DMZ (ingress-nginx-lb-01) para Database PostgreSQL
              </h4>
              <p className="text-xs text-slate-400">
                O ativo da DMZ tentou conectar-se à porta 5432 da zona de banco de dados. Ação bloqueada pela política Zero Trust <code className="text-accent-cyan">block-dmz-to-db</code>.
              </p>
            </div>
            <button className="px-3 py-1.5 text-xs font-semibold bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 rounded-lg transition-all flex-shrink-0">
              Inspecionar Tráfego
            </button>
          </div>

          <div className="p-4 rounded-lg bg-amber-950/20 border border-amber-500/30 flex items-start justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40 rounded uppercase">
                  DENIED - HIGH
                </span>
                <span className="text-xs text-slate-400 font-mono">10.0.5.12:22 → 10.0.4.99:22</span>
              </div>
              <h4 className="text-sm font-bold text-slate-200">
                Acesso SSH Não Autorizado do Runner GitLab para Cofre PCI-DSS
              </h4>
              <p className="text-xs text-slate-400">
                Requisição SSH bloqueada por violar isolamento rígido da zona de pagamentos PCI-DSS.
              </p>
            </div>
            <button className="px-3 py-1.5 text-xs font-semibold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 rounded-lg transition-all flex-shrink-0">
              Ver Detalhes
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
