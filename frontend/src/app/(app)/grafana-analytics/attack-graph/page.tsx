'use client';
import { useEffect, useState } from 'react';
import { GitGraph, ShieldAlert, AlertTriangle, CheckCircle2, Flame, RefreshCw, ZoomIn, ZoomOut } from 'lucide-react';
import { grafanaAnalyticsApi } from '@/lib/api';

export default function AttackGraphPage() {
  const [graphData, setGraphData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState<any>(null);

  const loadGraph = async () => {
    setLoading(true);
    try {
      const data = await grafanaAnalyticsApi.getAttackGraph();
      setGraphData(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadGraph();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-500" />
      </div>
    );
  }

  // Node position calculation for topology SVG
  const nodePositions: Record<string, { x: number; y: number }> = {};
  (graphData?.nodes || []).forEach((node: any, idx: number) => {
    const col = idx % 3;
    const row = Math.floor(idx / 3);
    nodePositions[node.id] = { x: 120 + col * 280, y: 80 + row * 160 };
  });

  const criticalSummary = graphData?.critical_path_summary;

  return (
    <div className="space-y-4">
      {/* Header Info */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-bg-card border border-bg-border rounded-xl p-4">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <GitGraph className="w-5 h-5 text-orange-500" /> Attack Graph Correlator — Vetor Crítico de Ataque #1
          </h2>
          <p className="text-xs text-slate-400">
            Mapeamento topológico de correlação em tempo real: Honeypot Probes ➔ Pentest CVEs ➔ Fluxo eBPF ➔ Wazuh XDR Alerts.
          </p>
        </div>

        <button onClick={loadGraph} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200">
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Atualizar Grafo
        </button>
      </div>

      {/* #1 Critical Attack Vector Alert Banner */}
      {criticalSummary && (
        <div className="p-4 rounded-xl bg-red-950/30 border border-red-500/50 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 text-[10px] font-extrabold bg-red-500/30 text-red-300 border border-red-500/60 rounded uppercase animate-pulse">
                VETOR CRÍTICO #1 MAIS IMPACTANTE — RISCO {criticalSummary.risk_score}
              </span>
              <span className="text-xs font-mono text-slate-300">IP Atacante: {criticalSummary.attacker_ip}</span>
            </div>
            <h3 className="text-sm font-bold text-slate-100">{criticalSummary.title}</h3>
            <p className="text-xs text-slate-300">{criticalSummary.verdict}</p>
          </div>

          <button className="px-4 py-2 text-xs font-bold bg-red-500 text-slate-950 rounded-lg hover:bg-red-400 transition-all flex-shrink-0">
            Bloquear Vetor Crítico
          </button>
        </div>
      )}

      {/* Topology SVG Map & Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3 bg-bg-card border border-bg-border rounded-xl p-4 min-h-[500px] relative overflow-hidden flex flex-col justify-between">
          <div className="absolute top-3 left-4 flex items-center gap-4 text-[11px] font-semibold text-slate-400 z-10 bg-bg-primary/80 backdrop-blur px-3 py-1.5 rounded-lg border border-bg-border">
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-0.5 bg-red-500 rounded animate-pulse" /> Vetor Crítico #1 (Neon Red)</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-0.5 bg-slate-500 rounded" /> Conexão Secundária</span>
          </div>

          <div className="w-full h-full overflow-auto p-4 min-w-[900px] min-h-[460px] relative">
            <svg className="w-full h-[460px] absolute inset-0 pointer-events-none">
              <defs>
                <marker id="arrow-critical" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#ff1744" />
                </marker>
                <marker id="arrow-normal" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" />
                </marker>
              </defs>

              {/* Edges */}
              {(graphData?.edges || []).map((edge: any) => {
                const srcPos = nodePositions[edge.source];
                const tgtPos = nodePositions[edge.target];
                if (!srcPos || !tgtPos) return null;

                const isCrit = edge.is_critical_path;
                const strokeColor = isCrit ? '#ff1744' : '#475569';

                return (
                  <g key={edge.id}>
                    <line
                      x1={srcPos.x + 90}
                      y1={srcPos.y + 35}
                      x2={tgtPos.x + 90}
                      y2={tgtPos.y + 35}
                      stroke={strokeColor}
                      strokeWidth={isCrit ? '3' : '1.5'}
                      strokeDasharray={isCrit ? '6 6' : '0'}
                      className={isCrit ? 'animate-pulse' : ''}
                      markerEnd={isCrit ? 'url(#arrow-critical)' : 'url(#arrow-normal)'}
                    />
                    <text
                      x={(srcPos.x + tgtPos.x) / 2 + 90}
                      y={(srcPos.y + tgtPos.y) / 2 + 30}
                      fill={strokeColor}
                      fontSize="10"
                      fontWeight="bold"
                      textAnchor="middle"
                    >
                      {edge.relation} ({edge.protocol_port})
                    </text>
                  </g>
                );
              })}
            </svg>

            {/* Nodes */}
            <div className="relative z-10">
              {(graphData?.nodes || []).map((node: any) => {
                const pos = nodePositions[node.id] || { x: 100, y: 100 };
                const isSelected = selectedNode?.id === node.id;
                const isCrit = node.is_critical_vector;

                return (
                  <div
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    style={{
                      position: 'absolute',
                      left: `${pos.x}px`,
                      top: `${pos.y}px`,
                      width: '220px'
                    }}
                    className={`bg-bg-card border-l-4 rounded-xl p-3.5 shadow-xl cursor-pointer transition-all ${
                      isCrit
                        ? 'border-l-red-500 border-y border-r border-red-500/50 shadow-[0_0_15px_rgba(255,23,68,0.3)]'
                        : 'border-l-slate-600 border-y border-r border-bg-border'
                    } ${isSelected ? 'ring-2 ring-orange-500 scale-105 z-20' : ''}`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className={`text-[9px] font-extrabold uppercase px-1.5 py-0.5 rounded ${
                        isCrit ? 'bg-red-500/20 text-red-400' : 'bg-slate-800 text-slate-300'
                      }`}>
                        {node.type}
                      </span>
                      <span className="font-mono text-[10px] font-bold text-red-400">{node.risk_score}</span>
                    </div>

                    <h4 className="text-xs font-bold text-slate-100 truncate">{node.label}</h4>
                    <p className="text-[10px] font-mono text-slate-400 mt-0.5">{node.ip}</p>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Node Inspector Panel */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-5 space-y-4">
          {selectedNode ? (
            <div className="space-y-4">
              <div className="border-b border-bg-border pb-3">
                <span className="text-[10px] font-extrabold text-orange-400 uppercase tracking-wider">Nó do Grafo Selecionado</span>
                <h3 className="text-sm font-bold text-slate-100">{selectedNode.label}</h3>
              </div>

              <div className="space-y-2 text-xs">
                <div className="flex justify-between py-1 border-b border-bg-border/40">
                  <span className="text-slate-400">Tipo:</span>
                  <span className="font-bold text-slate-200">{selectedNode.type}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-bg-border/40">
                  <span className="text-slate-400">Endereço IP:</span>
                  <span className="font-mono text-slate-200">{selectedNode.ip}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-400">Vetor Crítico #1:</span>
                  <span className={`font-bold ${selectedNode.is_critical_vector ? 'text-red-400' : 'text-slate-400'}`}>
                    {selectedNode.is_critical_vector ? 'SIM (CRÍTICO)' : 'NÃO'}
                  </span>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-64 text-center text-slate-500 space-y-2">
              <GitGraph className="w-10 h-10 stroke-1 text-slate-600" />
              <p className="text-xs">Clique em qualquer nó do grafo para inspecionar vulnerabilidades e vetores de ataque.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
