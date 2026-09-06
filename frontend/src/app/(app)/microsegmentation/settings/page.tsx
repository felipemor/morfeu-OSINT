'use client';
import { useState } from 'react';
import { Settings, Save, ShieldAlert, Sliders } from 'lucide-react';
import toast from 'react-hot-toast';

export default function SettingsPage() {
  const [autoDiscover, setAutoDiscover] = useState(true);
  const [defaultMode, setDefaultMode] = useState('MONITORING');

  const handleSave = () => {
    toast.success('Configurações de microsegmentação salvas!');
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h2 className="text-base font-bold text-slate-100">Configurações Globais do Módulo de Microsegmentação</h2>
        <p className="text-xs text-slate-400">
          Ajuste as políticas padrão de autodescoberta e limiares de alerta.
        </p>
      </div>

      <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-6">
        <div className="space-y-4 text-xs">
          <div className="flex items-center justify-between py-2 border-b border-bg-border/60">
            <div>
              <h4 className="font-bold text-slate-200">Autodescoberta de Ativos (K8s & Agent Discovery)</h4>
              <p className="text-slate-400">Adiciona automaticamente novos Pods e VMs ao inventário ao detectar novos fluxos eBPF.</p>
            </div>
            <input
              type="checkbox"
              checked={autoDiscover}
              onChange={(e) => setAutoDiscover(e.target.checked)}
              className="w-4 h-4 accent-accent-cyan cursor-pointer"
            />
          </div>

          <div className="flex items-center justify-between py-2 border-b border-bg-border/60">
            <div>
              <h4 className="font-bold text-slate-200">Modo de Imposição Padrão para Novas Regras</h4>
              <p className="text-slate-400">Regras recomendadas iniciam em modo monitoramento antes de aplicar bloqueio total.</p>
            </div>
            <select
              value={defaultMode}
              onChange={(e) => setDefaultMode(e.target.value)}
              className="px-3 py-1.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 font-semibold"
            >
              <option value="MONITORING">MONITORING (Seguro)</option>
              <option value="ENFORCING">ENFORCING (Estrito)</option>
            </select>
          </div>
        </div>

        <div className="flex justify-end pt-2">
          <button
            onClick={handleSave}
            className="flex items-center gap-2 px-4 py-2 text-xs font-bold bg-accent-cyan text-slate-950 rounded-lg hover:bg-cyan-400 transition-all"
          >
            <Save className="w-4 h-4" /> Salvar Configurações
          </button>
        </div>
      </div>
    </div>
  );
}
