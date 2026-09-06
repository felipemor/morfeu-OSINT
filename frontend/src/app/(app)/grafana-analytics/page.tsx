'use client';

import React, { useEffect, useState } from 'react';
import {
  BarChart2,
  Flame,
  Cpu,
  ExternalLink,
  ShieldAlert,
  Activity,
  Smartphone,
  LayoutDashboard,
  Layers,
  Zap,
  Sliders,
  Terminal,
  ShieldCheck,
  Globe,
  Database,
  Lock
} from 'lucide-react';
import clsx from 'clsx';
import { grafanaAnalyticsApi } from '@/lib/api';
import DashboardPage from '../dashboard/page';
import MobileExecutiveDashboardPage from '../mobile-dashboard/page';
import HoneypotPage from './honeypot/page';
import AttackGraphPage from './attack-graph/page';
import MetricsPage from './metrics/page';
import CorrelationRulesPage from './rules/page';

type MainCategory = 'dashboards' | 'threats' | 'telemetry';

export default function GrafanaDashboardPage() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  // Main Category Tab State
  const [mainCategory, setMainCategory] = useState<MainCategory>('dashboards');

  // Sub-Tab States
  const [dashboardsSubTab, setDashboardsSubTab] = useState<'executive' | 'mobile'>('executive');
  const [threatsSubTab, setThreatsSubTab] = useState<'honeypot' | 'graph'>('honeypot');
  const [telemetrySubTab, setTelemetrySubTab] = useState<'metrics' | 'rules'>('metrics');

  useEffect(() => {
    async function load() {
      try {
        const res = await grafanaAnalyticsApi.getOverview();
        setData(res);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 animate-fade-in">
      {/* Sleek Top Header Bar with Live Docker Servers & Links */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 shadow-lg">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
            <span className="text-slate-400">Docker Prometheus:</span>
            <a
              href="http://localhost:9090"
              target="_blank"
              rel="noopener noreferrer"
              className="text-orange-400 font-bold hover:underline flex items-center gap-1"
            >
              http://localhost:9090 <ExternalLink className="h-3 w-3" />
            </a>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono">
            <span className="h-2 w-2 rounded-full bg-blue-400 animate-ping" />
            <span className="text-slate-400">Docker Grafana:</span>
            <a
              href="http://localhost:3300"
              target="_blank"
              rel="noopener noreferrer"
              className="text-accent-cyan font-bold hover:underline flex items-center gap-1"
            >
              http://localhost:3300 <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <a
            href="http://localhost:3300"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2 text-xs font-bold bg-gradient-to-r from-orange-500 to-amber-500 hover:from-orange-400 hover:to-amber-400 text-slate-950 rounded-lg transition-all shadow-md shadow-orange-500/20"
          >
            <ExternalLink className="w-4 h-4" /> Servidor Grafana Dedicated (Porta 3300)
          </a>
        </div>
      </div>

      {/* ─── LEVEL 1: MAIN CATEGORY TABS ─────────────────────────────────────── */}
      <div className="bg-bg-card/80 border border-bg-border rounded-xl p-2 flex flex-wrap gap-2 shadow-sm">
        <button
          onClick={() => setMainCategory('dashboards')}
          className={clsx(
            'flex-1 min-w-[200px] py-3 px-4 rounded-lg font-bold text-xs transition-all flex items-center justify-center gap-2 border',
            mainCategory === 'dashboards'
              ? 'bg-orange-500/15 border-orange-500/50 text-orange-400 shadow-md'
              : 'bg-bg-primary/50 border-transparent text-slate-400 hover:text-slate-200 hover:bg-bg-primary'
          )}
        >
          <BarChart2 className="w-4 h-4 text-orange-400" />
          1. Dashboards Executivos &amp; Analytics
        </button>

        <button
          onClick={() => setMainCategory('threats')}
          className={clsx(
            'flex-1 min-w-[200px] py-3 px-4 rounded-lg font-bold text-xs transition-all flex items-center justify-center gap-2 border',
            mainCategory === 'threats'
              ? 'bg-purple-500/15 border-purple-500/50 text-purple-400 shadow-md'
              : 'bg-bg-primary/50 border-transparent text-slate-400 hover:text-slate-200 hover:bg-bg-primary'
          )}
        >
          <ShieldAlert className="w-4 h-4 text-purple-400" />
          2. Detecção de Ameaças &amp; Decepção (Honeypot/XDR)
        </button>

        <button
          onClick={() => setMainCategory('telemetry')}
          className={clsx(
            'flex-1 min-w-[200px] py-3 px-4 rounded-lg font-bold text-xs transition-all flex items-center justify-center gap-2 border',
            mainCategory === 'telemetry'
              ? 'bg-emerald-500/15 border-emerald-500/50 text-emerald-400 shadow-md'
              : 'bg-bg-primary/50 border-transparent text-slate-400 hover:text-slate-200 hover:bg-bg-primary'
          )}
        >
          <Activity className="w-4 h-4 text-emerald-400" />
          3. Telemetria &amp; Automação (Prometheus)
        </button>
      </div>

      {/* ─── LEVEL 2: THEMATIC SUB-TABS ───────────────────────────────────────── */}

      {/* CATEGORY 1: DASHBOARDS EXECUTIVOS */}
      {mainCategory === 'dashboards' && (
        <div className="space-y-4">
          <div className="flex border-b border-bg-border gap-2 overflow-x-auto">
            <button
              onClick={() => setDashboardsSubTab('executive')}
              className={clsx(
                'px-4 py-2 text-xs font-bold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap',
                dashboardsSubTab === 'executive'
                  ? 'border-orange-500 text-orange-400 bg-orange-500/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              )}
            >
              <LayoutDashboard className="w-4 h-4 text-orange-400" />
              Visão Global Executiva (Web &amp; Rede)
            </button>

            <button
              onClick={() => setDashboardsSubTab('mobile')}
              className={clsx(
                'px-4 py-2 text-xs font-bold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap',
                dashboardsSubTab === 'mobile'
                  ? 'border-orange-500 text-orange-400 bg-orange-500/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              )}
            >
              <Smartphone className="w-4 h-4 text-accent-cyan" />
              Mobile Security Analytics (APK/iOS MASVS)
            </button>
          </div>

          {dashboardsSubTab === 'executive' && (
            <div className="space-y-4">
              <div className="bg-slate-900/60 border border-slate-800 px-4 py-2.5 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                <div>
                  <span className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">
                    Tema: Postura Global de Vulnerabilidades Web, Rede
                  </span>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    <strong>Origem dos Dados:</strong> Controles de Segurança, Scans OWASP ZAP/Nmap, Microsegmentação eBPF e Wazuh XDR.
                  </p>
                </div>
              </div>
              <DashboardPage />
            </div>
          )}

          {dashboardsSubTab === 'mobile' && (
            <div className="space-y-4">
              <div className="bg-slate-900/60 border border-slate-800 px-4 py-2.5 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                <div>
                  <span className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">
                    Tema: Postura de Segurança MÓVEL — Binários APK/iOS &amp; OWASP MASVS L1/L2
                  </span>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    <strong>Origem dos Dados:</strong> Scanner Mobile Pentest SAST/DAST Engine, Descompilação Bytecode e Keystore Auditor.
                  </p>
                </div>
              </div>
              <MobileExecutiveDashboardPage />
            </div>
          )}
        </div>
      )}

      {/* CATEGORY 2: THREAT DETECTION & DECEPTION */}
      {mainCategory === 'threats' && (
        <div className="space-y-4">
          <div className="flex border-b border-bg-border gap-2 overflow-x-auto">
            <button
              onClick={() => setThreatsSubTab('honeypot')}
              className={clsx(
                'px-4 py-2 text-xs font-bold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap',
                threatsSubTab === 'honeypot'
                  ? 'border-purple-500 text-purple-400 bg-purple-500/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              )}
            >
              <Flame className="w-4 h-4 text-orange-500" />
              Honeypot Decoy Center &amp; Instalação Remota
            </button>

            <button
              onClick={() => setThreatsSubTab('graph')}
              className={clsx(
                'px-4 py-2 text-xs font-bold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap',
                threatsSubTab === 'graph'
                  ? 'border-purple-500 text-purple-400 bg-purple-500/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              )}
            >
              <Layers className="w-4 h-4 text-purple-400" />
              Attack Graph Correlator (Vetor Crítico #1)
            </button>
          </div>

          {threatsSubTab === 'honeypot' && <HoneypotPage />}
          {threatsSubTab === 'graph' && <AttackGraphPage />}
        </div>
      )}

      {/* CATEGORY 3: TELEMETRY & AUTOMATION */}
      {mainCategory === 'telemetry' && (
        <div className="space-y-4">
          <div className="flex border-b border-bg-border gap-2 overflow-x-auto">
            <button
              onClick={() => setTelemetrySubTab('metrics')}
              className={clsx(
                'px-4 py-2 text-xs font-bold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap',
                telemetrySubTab === 'metrics'
                  ? 'border-emerald-500 text-emerald-400 bg-emerald-500/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              )}
            >
              <Activity className="w-4 h-4 text-emerald-400" />
              Prometheus Metrics Explorer
            </button>

            <button
              onClick={() => setTelemetrySubTab('rules')}
              className={clsx(
                'px-4 py-2 text-xs font-bold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap',
                telemetrySubTab === 'rules'
                  ? 'border-emerald-500 text-emerald-400 bg-emerald-500/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              )}
            >
              <Sliders className="w-4 h-4 text-blue-400" />
              Regras de Correlação Unificada
            </button>
          </div>

          {telemetrySubTab === 'metrics' && <MetricsPage />}
          {telemetrySubTab === 'rules' && <CorrelationRulesPage />}
        </div>
      )}
    </div>
  );
}
