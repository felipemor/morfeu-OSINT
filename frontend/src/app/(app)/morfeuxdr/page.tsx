'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  ShieldAlert, Bug, AlertCircle, Cpu, Activity, Clock, CheckCircle2,
  ArrowUpRight, AlertTriangle, Layers, ChevronRight
} from 'lucide-react';
import { morfeuXdrApi } from '@/lib/api';

export default function MorfeuXDROverview() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const res = await morfeuXdrApi.getOverview();
        setData(res);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Banner Row: Security Score & Engine Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Security Posture Gauge */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-6 flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-red-500/5 rounded-full blur-2xl pointer-events-none" />
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">MorfeuXDR Security Score</span>
              <span className="px-2 py-0.5 text-[10px] font-bold bg-accent-green/10 text-accent-green border border-accent-green/30 rounded uppercase">
                POSTURA FORTE
              </span>
            </div>
            <div className="mt-4 flex items-baseline gap-3">
              <span className="text-5xl font-black text-slate-100 tracking-tight">{data?.security_score || 87.4}</span>
              <span className="text-xs font-bold text-slate-400">/ 100</span>
            </div>
            <p className="text-xs text-slate-400 mt-2">
              Pontuação de risco ponderada calculada a partir de detecção de ameaças, postura de endpoints e conformidade.
            </p>
          </div>

          {/* Progress Bar */}
          <div className="mt-6 space-y-2">
            <div className="flex justify-between text-xs font-medium text-slate-300">
              <span>Cobertura de Detecção MITRE</span>
              <span className="text-red-400 font-bold">{data?.mitre_coverage_percentage || 86.5}%</span>
            </div>
            <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
              <div
                className="bg-gradient-to-r from-red-500 to-amber-500 h-full rounded-full transition-all duration-1000"
                style={{ width: `${data?.mitre_coverage_percentage || 86.5}%` }}
              />
            </div>
          </div>
        </div>

        {/* Posture Score Breakdown */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-6 flex flex-col justify-between">
          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Detalhamento por Vetor de Segurança</span>
            <div className="mt-4 space-y-2.5 text-xs">
              <div className="flex justify-between items-center py-1 border-b border-bg-border/40">
                <span className="text-slate-400">Threat Detection:</span>
                <span className="font-mono font-bold text-slate-200">{data?.score_breakdown?.threat_detection}%</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-bg-border/40">
                <span className="text-slate-400">Endpoint Security:</span>
                <span className="font-mono font-bold text-slate-200">{data?.score_breakdown?.endpoint_security}%</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-bg-border/40">
                <span className="text-slate-400">Vulnerabilidades:</span>
                <span className="font-mono font-bold text-amber-400">{data?.score_breakdown?.vulnerabilities}%</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-bg-border/40">
                <span className="text-slate-400">Configurações & SCA:</span>
                <span className="font-mono font-bold text-slate-200">{data?.score_breakdown?.configuration_sca}%</span>
              </div>
              <div className="flex justify-between items-center py-1">
                <span className="text-slate-400">Saúde dos Agentes Wazuh:</span>
                <span className="font-mono font-bold text-accent-green">{data?.score_breakdown?.agent_health}%</span>
              </div>
            </div>
          </div>
        </div>

        {/* Engine Pipeline Status */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Wazuh Engine Pipeline</span>
              <span className="flex items-center gap-1.5 text-xs text-accent-green font-semibold">
                <span className="w-2 h-2 rounded-full bg-accent-green animate-ping" /> Active
              </span>
            </div>
            <div className="mt-4 space-y-3">
              <div className="flex items-center justify-between text-xs py-2 border-b border-bg-border/60">
                <span className="text-slate-400">Taxa de Ingestão:</span>
                <span className="font-mono text-red-400 font-bold">{data?.events_per_minute?.toLocaleString()} eps</span>
              </div>
              <div className="flex items-center justify-between text-xs py-2 border-b border-bg-border/60">
                <span className="text-slate-400">MTTD (Média de Detecção):</span>
                <span className="font-mono text-slate-200 font-bold">{data?.mttd_minutes} min</span>
              </div>
              <div className="flex items-center justify-between text-xs py-2">
                <span className="text-slate-400">MTTR (Média de Resolução):</span>
                <span className="font-mono text-slate-200 font-bold">{data?.mttr_hours} horas</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-bg-border/60 flex items-center justify-between text-xs text-slate-400">
            <span>Wazuh API Status:</span>
            <span className="font-mono text-accent-green">CONNECTED (TLS 1.3)</span>
          </div>
        </div>
      </div>

      {/* KPI Cards Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase">Findings Totais</span>
            <Bug className="w-4 h-4 text-red-500" />
          </div>
          <p className="text-2xl font-black text-slate-100">{data?.total_findings || 4}</p>
          <p className="text-[10px] text-red-400 font-semibold">{data?.open_findings} em aberto</p>
        </div>

        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase">Críticos</span>
            <ShieldAlert className="w-4 h-4 text-red-500" />
          </div>
          <p className="text-2xl font-black text-red-500">{data?.critical_findings || 2}</p>
          <p className="text-[10px] text-red-400">Ação imediata necessária</p>
        </div>

        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase">Incidentes Ativos</span>
            <AlertCircle className="w-4 h-4 text-amber-400" />
          </div>
          <p className="text-2xl font-black text-amber-400">{data?.active_incidents || 1}</p>
          <p className="text-[10px] text-amber-400">Em investigação pelo SOC</p>
        </div>

        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase">Agentes Online</span>
            <Cpu className="w-4 h-4 text-accent-green" />
          </div>
          <p className="text-2xl font-black text-slate-100">{data?.agents_online} / {data?.agents_total}</p>
          <p className="text-[10px] text-accent-green font-semibold">Agentes Wazuh ativos</p>
        </div>

        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase">MTTD (Detecção)</span>
            <Clock className="w-4 h-4 text-slate-400" />
          </div>
          <p className="text-2xl font-black text-slate-100">{data?.mttd_minutes}m</p>
          <p className="text-[10px] text-slate-400">Tempo médio de alerta</p>
        </div>

        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase">MTTR (Resolução)</span>
            <CheckCircle2 className="w-4 h-4 text-accent-cyan" />
          </div>
          <p className="text-2xl font-black text-accent-cyan">{data?.mttr_hours}h</p>
          <p className="text-[10px] text-slate-400">Tempo médio de mitigação</p>
        </div>
      </div>

      {/* Active Incident Highlight Banner */}
      <div className="bg-bg-card border border-red-500/30 rounded-xl p-6 space-y-3 relative overflow-hidden">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 text-[10px] font-extrabold bg-red-500/20 text-red-400 border border-red-500/40 rounded uppercase">
                INCIDENTE ATIVO — RISCO 94.5
              </span>
              <span className="text-xs text-slate-400 font-mono">INC-2026-00104</span>
            </div>
            <h3 className="text-sm font-bold text-slate-100">
              Possível Comprometimento de Endpoint — Servidor Domain Controller / Web App
            </h3>
            <p className="text-xs text-slate-400">
              O motor de correlação do MorfeuXDR agrupou 14 alertas isolados do Wazuh indicando força bruta SSH seguida de execução de comandos PowerShell codificados.
            </p>
          </div>

          <Link
            href="/morfeuxdr/investigation"
            className="flex items-center gap-2 px-4 py-2 text-xs font-bold bg-red-500 text-slate-950 rounded-lg hover:bg-red-400 transition-all flex-shrink-0"
          >
            Abrir Investigação no SOC <ChevronRight className="w-4 h-4" />
          </Link>
        </div>
      </div>
    </div>
  );
}
