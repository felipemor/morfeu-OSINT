'use client';
import { useState } from 'react';
import { Settings, Save, ShieldCheck, Key } from 'lucide-react';
import toast from 'react-hot-toast';

export default function XDRSettingsPage() {
  const [wazuhUrl, setWazuhUrl] = useState('https://wazuh-manager.sec.internal:55000');
  const [wazuhUser, setWazuhUser] = useState('wazuh-api-user');
  const [xdrEnabled, setXdrEnabled] = useState(true);
  const [correlationEnabled, setCorrelationEnabled] = useState(true);

  const handleSave = () => {
    toast.success('Configurações do MorfeuXDR salvas com sucesso!');
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h2 className="text-base font-bold text-slate-100">Configurações MorfeuXDR & Engine Wazuh</h2>
        <p className="text-xs text-slate-400">
          Gerenciamento de credenciais da API do Wazuh Manager e Feature Flags da plataforma.
        </p>
      </div>

      <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-6">
        <div className="space-y-4 text-xs">
          <h3 className="font-bold text-slate-200 border-b border-bg-border pb-2 text-sm flex items-center gap-2">
            <Key className="w-4 h-4 text-red-500" /> Credenciais da API Wazuh Manager
          </h3>

          <div>
            <label className="block text-slate-400 mb-1">URL da API Wazuh Manager</label>
            <input
              type="text"
              value={wazuhUrl}
              onChange={(e) => setWazuhUrl(e.target.value)}
              className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 font-mono"
            />
          </div>

          <div>
            <label className="block text-slate-400 mb-1">Usuário da API</label>
            <input
              type="text"
              value={wazuhUser}
              onChange={(e) => setWazuhUser(e.target.value)}
              className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 font-mono"
            />
          </div>

          <h3 className="font-bold text-slate-200 border-b border-bg-border pb-2 text-sm pt-4 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-accent-cyan" /> Feature Flags do MorfeuXDR
          </h3>

          <div className="flex items-center justify-between py-2 border-b border-bg-border/60">
            <div>
              <h4 className="font-bold text-slate-200">MORFEUXDR_ENABLED</h4>
              <p className="text-slate-400">Habilita a aba e os serviços do MorfeuXDR.</p>
            </div>
            <input
              type="checkbox"
              checked={xdrEnabled}
              onChange={(e) => setXdrEnabled(e.target.checked)}
              className="w-4 h-4 accent-red-500 cursor-pointer"
            />
          </div>

          <div className="flex items-center justify-between py-2 border-b border-bg-border/60">
            <div>
              <h4 className="font-bold text-slate-200">CORRELATION_ENGINE_ENABLED</h4>
              <p className="text-slate-400">Habilita o motor de correlação de múltiplos alertas do Wazuh em incidentes unificados.</p>
            </div>
            <input
              type="checkbox"
              checked={correlationEnabled}
              onChange={(e) => setCorrelationEnabled(e.target.checked)}
              className="w-4 h-4 accent-red-500 cursor-pointer"
            />
          </div>
        </div>

        <div className="flex justify-end pt-2">
          <button
            onClick={handleSave}
            className="flex items-center gap-2 px-4 py-2 text-xs font-bold bg-red-500 text-slate-950 rounded-lg hover:bg-red-400 transition-all"
          >
            <Save className="w-4 h-4" /> Salvar Configurações
          </button>
        </div>
      </div>
    </div>
  );
}
