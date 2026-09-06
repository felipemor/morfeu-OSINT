'use client';
import { useEffect, useState } from 'react';
import { Cable, CheckCircle2, RefreshCw, Cpu, Server, Cloud, Plus, AlertTriangle, ShieldCheck, X, Activity } from 'lucide-react';
import { microsegmentationApi } from '@/lib/api';
import toast from 'react-hot-toast';

export default function IntegrationsPage() {
  const [sources, setSources] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);

  // New Integration Form
  const [name, setName] = useState('');
  const [sourceType, setSourceType] = useState('HUBBLE_EBPF');
  const [endpointUrl, setEndpointUrl] = useState('');
  const [eps, setEps] = useState(1500);

  const loadSources = async () => {
    setLoading(true);
    try {
      const data = await microsegmentationApi.getTelemetry();
      setSources(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSources();
  }, []);

  const handleAddIntegration = (e: React.FormEvent) => {
    e.preventDefault();
    const newSource = {
      id: 'telemetry-' + Date.now(),
      name,
      source_type: sourceType,
      status: 'CONNECTED',
      endpoint_url: endpointUrl || 'https://telemetry.internal.sec:8443',
      events_per_second: Number(eps),
      last_heartbeat: new Date().toISOString()
    };
    setSources([newSource, ...sources]);
    toast.success(`Nova fonte de telemetria "${name}" conectada com sucesso!`);
    setShowAddModal(false);
    setName('');
    setEndpointUrl('');
  };

  const getIconForType = (type: string) => {
    if (type.includes('HUBBLE') || type.includes('EBPF')) return <Cpu className="w-5 h-5 text-accent-cyan" />;
    if (type.includes('VPC') || type.includes('AWS') || type.includes('CLOUD')) return <Cloud className="w-5 h-5 text-purple-400" />;
    if (type.includes('AKAMAI') || type.includes('EDGE')) return <ShieldCheck className="w-5 h-5 text-accent-green" />;
    return <Server className="w-5 h-5 text-amber-400" />;
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <Cable className="w-5 h-5 text-accent-cyan" /> Fontes de Telemetria & Ingestão de Fluxos eBPF
          </h2>
          <p className="text-xs text-slate-400">
            Conectores de coleta de tráfego de rede ativos e integrados ao motor de Microsegmentação.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadSources}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 bg-bg-card border border-bg-border rounded-lg"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Atualizar
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-bold bg-accent-cyan text-slate-950 rounded-lg hover:bg-cyan-400 transition-all"
          >
            <Plus className="w-4 h-4" /> Conectar Nova Fonte
          </button>
        </div>
      </div>

      {/* Grid of Telemetry Sources */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {sources.map((source) => {
          const isConnected = source.status === 'CONNECTED';
          return (
            <div key={source.id} className="bg-bg-card border border-bg-border rounded-xl p-5 space-y-4 relative overflow-hidden shadow-lg">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-lg bg-bg-secondary border border-bg-border">
                    {getIconForType(source.source_type)}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 text-[9px] font-extrabold rounded uppercase border ${
                        isConnected
                          ? 'bg-accent-green/10 text-accent-green border-accent-green/30'
                          : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                      }`}>
                        {source.status}
                      </span>
                    </div>
                    <h3 className="text-sm font-bold text-slate-100 mt-1">{source.name}</h3>
                    <p className="text-[10px] font-mono text-slate-400">{source.source_type}</p>
                  </div>
                </div>

                {isConnected ? (
                  <CheckCircle2 className="w-5 h-5 text-accent-green flex-shrink-0" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0" />
                )}
              </div>

              <div className="pt-3 border-t border-bg-border/60 space-y-2 text-xs">
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Taxa de Eventos (eps):</span>
                  <span className="font-mono font-bold text-accent-cyan flex items-center gap-1">
                    <Activity className="w-3 h-3 animate-pulse text-accent-cyan" />
                    {source.events_per_second?.toLocaleString()} eps
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Endpoint URL:</span>
                  <span className="font-mono text-[10px] text-slate-300 truncate max-w-[170px]" title={source.endpoint_url}>
                    {source.endpoint_url}
                  </span>
                </div>
                <div className="flex justify-between items-center text-[10px] text-slate-400 pt-1">
                  <span>Último Keepalive:</span>
                  <span className="font-mono text-slate-300">
                    {source.last_heartbeat ? new Date(source.last_heartbeat).toLocaleTimeString() : 'Agora'}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Modal Add Integration */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <form onSubmit={handleAddIntegration} className="bg-bg-card border border-bg-border rounded-xl p-6 w-full max-w-md space-y-4">
            <div className="flex justify-between items-center border-b border-bg-border pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Cable className="w-4 h-4 text-accent-cyan" /> Conectar Nova Fonte de Telemetria
              </h3>
              <button type="button" onClick={() => setShowAddModal(false)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Nome do Conector</label>
                <input
                  type="text"
                  required
                  placeholder="Ex: Kubernetes Cluster Production eBPF Collector"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Tipo de Fonte de Telemetria</label>
                <select
                  value={sourceType}
                  onChange={(e) => setSourceType(e.target.value)}
                  className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 focus:outline-none focus:border-accent-cyan"
                >
                  <option value="HUBBLE_EBPF">Cilium Hubble eBPF Collector</option>
                  <option value="VPC_FLOW_LOGS">AWS VPC Flow Logs Ingestor</option>
                  <option value="AKAMAI_EDGE">Akamai Kona / Guardicore Edge Flow</option>
                  <option value="AGENT_COLLECTOR">Agent Collector (Linux/Windows)</option>
                  <option value="AZURE_VNET">Azure VNet Flow Logs</option>
                  <option value="OPENTELEMETRY">OpenTelemetry Network Collector</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">URL / Endpoint gRPC / ARN</label>
                <input
                  type="text"
                  required
                  placeholder="grpcs://hubble.k8s.internal:443"
                  value={endpointUrl}
                  onChange={(e) => setEndpointUrl(e.target.value)}
                  className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 font-mono focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Taxa Estimada (Eventos/s)</label>
                <input
                  type="number"
                  value={eps}
                  onChange={(e) => setEps(Number(e.target.value))}
                  className="w-full px-3 py-1.5 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 font-mono focus:outline-none focus:border-accent-cyan"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
              >
                Cancelar
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 text-xs font-bold bg-accent-cyan text-slate-950 rounded-lg hover:bg-cyan-400"
              >
                Salvar & Conectar
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
