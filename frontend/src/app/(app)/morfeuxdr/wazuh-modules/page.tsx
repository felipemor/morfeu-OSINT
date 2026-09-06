'use client';
import { useEffect, useState } from 'react';
import { Cpu, ShieldCheck, CheckCircle2, AlertTriangle, Database, FolderGit2, Bug } from 'lucide-react';
import { morfeuXdrApi } from '@/lib/api';

export default function WazuhModulesPage() {
  const [agents, setAgents] = useState<any[]>([]);

  useEffect(() => {
    async function load() {
      try {
        const data = await morfeuXdrApi.getWazuhAgents();
        setAgents(data);
      } catch (e) {
        console.error(e);
      }
    }
    load();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-bold text-slate-100">Módulos do Engine Wazuh & Agentes Ativos</h2>
        <p className="text-xs text-slate-400">
          Status de telemetria de HIDS/SIEM, SCA, FIM, Syscollector e Vulnerability Detection.
        </p>
      </div>

      {/* Modules Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex justify-between items-center text-xs font-bold text-slate-400">
            <span>SCA (Config Assessment)</span>
            <CheckCircle2 className="w-4 h-4 text-accent-green" />
          </div>
          <p className="text-xl font-bold text-slate-100">88.2% Pass</p>
          <p className="text-[10px] text-slate-400">Auditoria CIS Benchmark</p>
        </div>

        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex justify-between items-center text-xs font-bold text-slate-400">
            <span>FIM (File Integrity)</span>
            <FolderGit2 className="w-4 h-4 text-accent-cyan" />
          </div>
          <p className="text-1xl font-bold text-slate-100">1 Alteração</p>
          <p className="text-[10px] text-slate-400">Monitoramento /etc/shadow</p>
        </div>

        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex justify-between items-center text-xs font-bold text-slate-400">
            <span>Vulnerability Detector</span>
            <Bug className="w-4 h-4 text-red-500" />
          </div>
          <p className="text-xl font-bold text-red-400">1 CVE Crítica</p>
          <p className="text-[10px] text-slate-400">Apache RCE CVE-2021-41773</p>
        </div>

        <div className="bg-bg-card border border-bg-border rounded-xl p-4 space-y-1">
          <div className="flex justify-between items-center text-xs font-bold text-slate-400">
            <span>Syscollector</span>
            <Database className="w-4 h-4 text-purple-400" />
          </div>
          <p className="text-xl font-bold text-slate-100">Ativo</p>
          <p className="text-[10px] text-slate-400">Hardware, pacotes e portas</p>
        </div>
      </div>

      {/* Agents Table */}
      <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden shadow-lg">
        <div className="p-4 border-b border-bg-border font-bold text-sm text-slate-100">
          Inventário de Agentes Wazuh Registrados ({agents.length})
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/60 border-b border-bg-border text-slate-400 uppercase font-semibold text-[10px] tracking-wider">
              <tr>
                <th className="p-3.5">ID Agente</th>
                <th className="p-3.5">Hostname</th>
                <th className="p-3.5">Endereço IP</th>
                <th className="p-3.5">Sistema Operacional</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5">Score de Risco</th>
                <th className="p-3.5">Último Keepalive</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bg-border/60 text-slate-200">
              {agents.map((ag) => (
                <tr key={ag.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="p-3.5 font-mono font-bold text-slate-300">#{ag.wazuh_agent_id}</td>
                  <td className="p-3.5 font-bold text-slate-100">{ag.name}</td>
                  <td className="p-3.5 font-mono">{ag.ip}</td>
                  <td className="p-3.5 text-slate-300">{ag.os_name}</td>
                  <td className="p-3.5">
                    <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase border ${
                      ag.status === 'ONLINE'
                        ? 'bg-accent-green/10 text-accent-green border-accent-green/30'
                        : 'bg-red-500/10 text-red-400 border-red-500/30'
                    }`}>
                      {ag.status}
                    </span>
                  </td>
                  <td className="p-3.5 font-mono font-bold text-amber-400">{ag.risk_score}</td>
                  <td className="p-3.5 font-mono text-[10px] text-slate-400">
                    {ag.last_keepalive ? new Date(ag.last_keepalive).toLocaleTimeString() : 'Agora'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
