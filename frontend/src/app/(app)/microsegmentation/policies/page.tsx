'use client';
import { useEffect, useState } from 'react';
import { ShieldCheck, Plus, Sparkles, FileCode, CheckCircle2, Play, Eye } from 'lucide-react';
import { microsegmentationApi } from '@/lib/api';
import toast from 'react-hot-toast';

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedYaml, setSelectedYaml] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [generatingAi, setGeneratingAi] = useState(false);

  // Form State
  const [title, setTitle] = useState('');
  const [portRange, setPortRange] = useState('443');
  const [protocol, setProtocol] = useState('TCP');
  const [action, setAction] = useState('ALLOW');
  const [enforcementMode, setEnforcementMode] = useState('MONITORING');

  const loadPolicies = async () => {
    setLoading(true);
    try {
      const data = await microsegmentationApi.getPolicies();
      setPolicies(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPolicies();
  }, []);

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await microsegmentationApi.createPolicy({
        title,
        port_range: portRange,
        protocol,
        action,
        enforcement_mode: enforcementMode
      });
      toast.success('Política de microsegmentação criada com sucesso!');
      setShowCreateModal(false);
      loadPolicies();
    } catch (err) {
      toast.error('Erro ao criar política.');
    }
  };

  const handleGenerateAi = async () => {
    setGeneratingAi(true);
    try {
      await microsegmentationApi.generateAiPolicy();
      toast.success('Política recomendada por IA gerada com sucesso!');
      loadPolicies();
    } catch (e) {
      toast.error('Erro ao gerar política por IA.');
    } finally {
      setGeneratingAi(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-slate-100">Policy Engine — Motor de Regras Zero Trust</h2>
          <p className="text-xs text-slate-400">Crie, audite e imponha regras de tráfego com exportação YAML Cilium/Guardicore.</p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleGenerateAi}
            disabled={generatingAi}
            className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 rounded-lg transition-all"
          >
            <Sparkles className={`w-3.5 h-3.5 ${generatingAi ? 'animate-spin' : ''}`} />
            Auto-Gerar Regra por IA
          </button>

          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold bg-accent-cyan text-slate-950 font-bold rounded-lg hover:bg-cyan-400 transition-all"
          >
            <Plus className="w-4 h-4" /> Nova Política
          </button>
        </div>
      </div>

      {/* Policy Table */}
      <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/60 border-b border-bg-border text-slate-400 uppercase font-semibold text-[10px] tracking-wider">
              <tr>
                <th className="p-3.5">Título da Política</th>
                <th className="p-3.5">Zona Origem</th>
                <th className="p-3.5">Zona Destino</th>
                <th className="p-3.5">Portas / Protocolo</th>
                <th className="p-3.5">Ação</th>
                <th className="p-3.5">Modo de Imposição</th>
                <th className="p-3.5">Hits Monit.</th>
                <th className="p-3.5 text-right">Ações / YAML</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bg-border/60 text-slate-200">
              {policies.map((p) => (
                <tr key={p.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="p-3.5">
                    <div className="font-bold text-slate-100">{p.title}</div>
                    {p.auto_generated && (
                      <span className="text-[9px] text-purple-400 font-semibold flex items-center gap-1 mt-0.5">
                        <Sparkles className="w-3 h-3" /> Gerada por IA
                      </span>
                    )}
                  </td>
                  <td className="p-3.5 font-semibold text-slate-300">{p.source_zone_name}</td>
                  <td className="p-3.5 font-semibold text-accent-cyan">{p.destination_zone_name}</td>
                  <td className="p-3.5 font-mono font-bold">:{p.port_range} ({p.protocol})</td>
                  <td className="p-3.5">
                    <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase border ${
                      p.action === 'ALLOW'
                        ? 'bg-accent-green/10 text-accent-green border-accent-green/30'
                        : 'bg-red-500/10 text-red-400 border-red-500/30'
                    }`}>
                      {p.action}
                    </span>
                  </td>
                  <td className="p-3.5">
                    <span className="px-2 py-0.5 text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700 rounded uppercase">
                      {p.enforcement_mode}
                    </span>
                  </td>
                  <td className="p-3.5 font-mono">{p.hits_count?.toLocaleString() || 0}</td>
                  <td className="p-3.5 text-right">
                    <button
                      onClick={() => setSelectedYaml(p.yaml_config)}
                      className="p-1.5 text-slate-400 hover:text-accent-cyan bg-bg-secondary rounded border border-bg-border"
                      title="Ver YAML Cilium / Guardicore"
                    >
                      <FileCode className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* YAML Viewer Modal */}
      {selectedYaml && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-bg-card border border-bg-border rounded-xl p-6 w-full max-w-2xl space-y-4">
            <div className="flex justify-between items-center border-b border-bg-border pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <FileCode className="w-4 h-4 text-accent-cyan" /> Configuração YAML (Cilium / Akamai Guardicore Spec)
              </h3>
              <button onClick={() => setSelectedYaml(null)} className="text-slate-400 hover:text-slate-200 text-xs">
                Fechar [ESC]
              </button>
            </div>

            <pre className="p-4 rounded-lg bg-slate-950 font-mono text-xs text-accent-cyan overflow-x-auto border border-bg-border leading-relaxed">
              {selectedYaml}
            </pre>
          </div>
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <form onSubmit={handleCreatePolicy} className="bg-bg-card border border-bg-border rounded-xl p-6 w-full max-w-md space-y-4">
            <h3 className="text-sm font-bold text-slate-100">Criar Nova Política de Microsegmentação</h3>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Título da Regra</label>
                <input
                  type="text"
                  required
                  placeholder="Ex: Lock DMZ to Auth Service"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Porta / Intervalo</label>
                  <input
                    type="text"
                    required
                    placeholder="443, 8080"
                    value={portRange}
                    onChange={(e) => setPortRange(e.target.value)}
                    className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 focus:outline-none focus:border-accent-cyan"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Protocolo</label>
                  <select
                    value={protocol}
                    onChange={(e) => setProtocol(e.target.value)}
                    className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 focus:outline-none focus:border-accent-cyan"
                  >
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="gRPC">gRPC</option>
                    <option value="HTTP">HTTP</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Ação</label>
                  <select
                    value={action}
                    onChange={(e) => setAction(e.target.value)}
                    className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 focus:outline-none focus:border-accent-cyan"
                  >
                    <option value="ALLOW">ALLOW</option>
                    <option value="DENY">DENY</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Modo de Imposição</label>
                  <select
                    value={enforcementMode}
                    onChange={(e) => setEnforcementMode(e.target.value)}
                    className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 focus:outline-none focus:border-accent-cyan"
                  >
                    <option value="MONITORING">MONITORING</option>
                    <option value="ENFORCING">ENFORCING</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
              >
                Cancelar
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 text-xs font-bold bg-accent-cyan text-slate-950 rounded-lg hover:bg-cyan-400"
              >
                Salvar Política
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
