'use client';
import { useEffect, useState } from 'react';
import { ArrowRightLeft, Search, Filter, ShieldAlert, CheckCircle2, AlertTriangle, RefreshCw } from 'lucide-react';
import { microsegmentationApi } from '@/lib/api';

export default function FlowsPage() {
  const [flows, setFlows] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('');

  const loadFlows = async () => {
    setLoading(true);
    try {
      const data = await microsegmentationApi.getFlows({
        action: actionFilter || undefined,
        protocol: protocolFilter || undefined,
        search: search || undefined
      });
      setFlows(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFlows();
  }, [actionFilter, protocolFilter]);

  return (
    <div className="space-y-4">
      {/* Header & Controls */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Filtrar por IP, ativo ou processo..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && loadFlows()}
              className="pl-9 pr-4 py-1.5 text-xs bg-bg-secondary border border-bg-border rounded-lg text-slate-200 focus:outline-none focus:border-accent-cyan w-64"
            />
          </div>

          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="px-3 py-1.5 text-xs bg-bg-secondary border border-bg-border rounded-lg text-slate-200 focus:outline-none focus:border-accent-cyan"
          >
            <option value="">Todas as Ações (ALLOW, DENY, VIOLATION)</option>
            <option value="ALLOW">ALLOW (Permitido)</option>
            <option value="DENY">DENY (Bloqueado)</option>
            <option value="VIOLATION">VIOLATION (Violação de Segmentação)</option>
          </select>

          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            className="px-3 py-1.5 text-xs bg-bg-secondary border border-bg-border rounded-lg text-slate-200 focus:outline-none focus:border-accent-cyan"
          >
            <option value="">Todos os Protocolos</option>
            <option value="TCP">TCP</option>
            <option value="gRPC">gRPC</option>
            <option value="HTTPS">HTTPS</option>
            <option value="mTLS">mTLS</option>
            <option value="SSH">SSH</option>
          </select>

          <button
            onClick={loadFlows}
            className="px-3 py-1.5 text-xs font-semibold bg-accent-cyan/10 hover:bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/30 rounded-lg transition-all"
          >
            Buscar
          </button>
        </div>

        <button
          onClick={loadFlows}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Atualizar Logs
        </button>
      </div>

      {/* Flows Table */}
      <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/60 border-b border-bg-border text-slate-400 uppercase font-semibold text-[10px] tracking-wider">
              <tr>
                <th className="p-3.5">Status / Ação</th>
                <th className="p-3.5">Origem (Source)</th>
                <th className="p-3.5">Destino (Target)</th>
                <th className="p-3.5">Porta / Protocolo</th>
                <th className="p-3.5">Processo</th>
                <th className="p-3.5">Volume (Bytes)</th>
                <th className="p-3.5">Fonte de Telemetria</th>
                <th className="p-3.5">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bg-border/60 text-slate-200">
              {flows.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center p-8 text-slate-500">
                    Nenhum registro de fluxo encontrado.
                  </td>
                </tr>
              ) : (
                flows.map((flow) => {
                  const isAllow = flow.action === 'ALLOW';
                  const isViolation = flow.action === 'VIOLATION';
                  return (
                    <tr key={flow.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="p-3.5">
                        <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase border ${
                          isAllow
                            ? 'bg-accent-green/10 text-accent-green border-accent-green/30'
                            : isViolation
                            ? 'bg-red-500/20 text-red-400 border-red-500/40 animate-pulse'
                            : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                        }`}>
                          {flow.action}
                        </span>
                      </td>
                      <td className="p-3.5">
                        <div className="font-bold text-slate-100">{flow.source_name}</div>
                        <div className="font-mono text-[10px] text-slate-400">{flow.source_ip}</div>
                      </td>
                      <td className="p-3.5">
                        <div className="font-bold text-slate-100">{flow.destination_name}</div>
                        <div className="font-mono text-[10px] text-slate-400">{flow.destination_ip}</div>
                      </td>
                      <td className="p-3.5">
                        <span className="font-mono font-bold text-accent-cyan">:{flow.destination_port}</span>
                        <span className="text-slate-400 text-[10px] ml-1">({flow.protocol})</span>
                      </td>
                      <td className="p-3.5 font-mono text-slate-300">{flow.process_name || 'k8s-pod'}</td>
                      <td className="p-3.5 font-mono">{flow.byte_count?.toLocaleString()} B</td>
                      <td className="p-3.5 font-mono text-[10px] text-slate-400">{flow.telemetry_source}</td>
                      <td className="p-3.5 font-mono text-[10px] text-slate-400">
                        {flow.timestamp ? new Date(flow.timestamp).toLocaleTimeString() : 'Agora'}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
