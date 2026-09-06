'use client';
import { useState } from 'react';
import { PlaySquare, AlertTriangle, CheckCircle2, Shield, Play } from 'lucide-react';
import { microsegmentationApi } from '@/lib/api';

export default function SimulationsPage() {
  const [port, setPort] = useState<number>(5432);
  const [action, setAction] = useState<string>('DENY');
  const [result, setResult] = useState<any>(null);
  const [running, setRunning] = useState(false);

  const handleRunSimulation = async () => {
    setRunning(true);
    try {
      const res = await microsegmentationApi.runSimulation({ port, action });
      setResult(res);
    } catch (e) {
      console.error(e);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-bold text-slate-100">Blast Radius Simulator — Teste de Impacto Dry-Run</h2>
        <p className="text-xs text-slate-400">
          Simule o impacto de um bloqueio de porta/zona antes de aplicar em produção para garantir zero downtimes não planejados.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Simulator Parameters */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-4">
          <h3 className="text-sm font-bold text-slate-100">Parâmetros da Regra Proposta</h3>

          <div className="space-y-3 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">Porta Alvo para Bloqueio</label>
              <input
                type="number"
                value={port}
                onChange={(e) => setPort(Number(e.target.value))}
                className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Ação Simulada</label>
              <select
                value={action}
                onChange={(e) => setAction(e.target.value)}
                className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100"
              >
                <option value="DENY">DENY (Bloquear Tráfego)</option>
                <option value="ALLOW">ALLOW (Permitir Tráfego)</option>
              </select>
            </div>

            <button
              onClick={handleRunSimulation}
              disabled={running}
              className="w-full flex items-center justify-center gap-2 py-2 text-xs font-bold bg-accent-cyan text-slate-950 rounded-lg hover:bg-cyan-400 transition-all mt-4"
            >
              <Play className={`w-4 h-4 ${running ? 'animate-spin' : ''}`} />
              Executar Simulação Blast Radius
            </button>
          </div>
        </div>

        {/* Simulation Output Card */}
        <div className="lg:col-span-2 bg-bg-card border border-bg-border rounded-xl p-6 space-y-4">
          <h3 className="text-sm font-bold text-slate-100">Resultado da Análise de Impacto</h3>

          {result ? (
            <div className="space-y-4">
              <div className={`p-4 rounded-lg border flex items-start gap-3 ${
                result.safety_verdict === 'SAFE_TO_ENFORCE'
                  ? 'bg-accent-green/10 border-accent-green/30 text-accent-green'
                  : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
              }`}>
                {result.safety_verdict === 'SAFE_TO_ENFORCE' ? (
                  <CheckCircle2 className="w-5 h-5 flex-shrink-0 mt-0.5" />
                ) : (
                  <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                )}
                <div>
                  <h4 className="font-bold text-sm">{result.safety_verdict}</h4>
                  <p className="text-xs mt-0.5">{result.recommendation}</p>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4 text-xs">
                <div className="bg-bg-secondary p-3 rounded-lg border border-bg-border">
                  <span className="text-slate-400 block text-[10px]">Fluxos Avaliados:</span>
                  <span className="text-lg font-bold text-slate-100">{result.total_flows_evaluated}</span>
                </div>
                <div className="bg-bg-secondary p-3 rounded-lg border border-bg-border">
                  <span className="text-slate-400 block text-[10px]">Conexões Interrompidas:</span>
                  <span className="text-lg font-bold text-amber-400">{result.impacted_active_connections}</span>
                </div>
                <div className="bg-bg-secondary p-3 rounded-lg border border-bg-border">
                  <span className="text-slate-400 block text-[10px]">Serviços Afetados:</span>
                  <span className="text-lg font-bold text-slate-100">{result.services_broken_count}</span>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-48 text-center text-slate-500 text-xs">
              <PlaySquare className="w-8 h-8 stroke-1 text-slate-600 mb-2" />
              Configure a porta e clique em executar para ver o impacto em tempo real.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
