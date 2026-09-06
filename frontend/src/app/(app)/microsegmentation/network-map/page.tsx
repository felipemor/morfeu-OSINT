'use client';
import { useEffect, useState, useRef } from 'react';
import {
  Network, ShieldAlert, Boxes, Database, Globe, Smartphone,
  Sliders, Search, ZoomIn, ZoomOut, Maximize2, Shield, AlertTriangle, CheckCircle2, X, RefreshCw
} from 'lucide-react';
import { microsegmentationApi } from '@/lib/api';
import toast from 'react-hot-toast';

export default function NetworkMapPage() {
  const [mapData, setMapData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedZoneFilter, setSelectedZoneFilter] = useState('ALL');
  const [selectedActionFilter, setSelectedActionFilter] = useState('ALL');
  const [zoomLevel, setZoomLevel] = useState(1);

  const fetchMap = async () => {
    setLoading(true);
    try {
      const data = await microsegmentationApi.getNetworkMap();
      setMapData(data);
    } catch (e) {
      toast.error('Erro ao carregar mapa de rede.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMap();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent-cyan" />
      </div>
    );
  }

  const filteredNodes = (mapData?.nodes || []).filter((node: any) => {
    const matchesSearch = node.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          node.ip.includes(searchQuery);
    const matchesZone = selectedZoneFilter === 'ALL' || node.zone_id === selectedZoneFilter;
    return matchesSearch && matchesZone;
  });

  const getZoneColor = (zoneId: string) => {
    const zone = mapData?.zones?.find((z: any) => z.id === zoneId);
    return zone?.color || '#00d4ff';
  };

  const getZoneName = (zoneId: string) => {
    const zone = mapData?.zones?.find((z: any) => z.id === zoneId);
    return zone?.name || 'Unassigned Zone';
  };

  // Node position calculation for SVG layout
  const getNodePos = (index: number, total: number) => {
    const col = index % 4;
    const row = Math.floor(index / 4);
    const x = 120 + col * 260;
    const y = 100 + row * 180;
    return { x, y };
  };

  const nodePositions: Record<string, { x: number; y: number }> = {};
  (mapData?.nodes || []).forEach((node: any, idx: number) => {
    nodePositions[node.id] = getNodePos(idx, mapData.nodes.length);
  });

  return (
    <div className="space-y-4">
      {/* Control Bar */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Buscar por ativo ou IP..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 pr-4 py-1.5 text-xs bg-bg-secondary border border-bg-border rounded-lg text-slate-200 focus:outline-none focus:border-accent-cyan w-64"
            />
          </div>

          {/* Zone Filter */}
          <select
            value={selectedZoneFilter}
            onChange={(e) => setSelectedZoneFilter(e.target.value)}
            className="px-3 py-1.5 text-xs bg-bg-secondary border border-bg-border rounded-lg text-slate-200 focus:outline-none focus:border-accent-cyan"
          >
            <option value="ALL">Todas as Zonas ({mapData?.zones?.length || 0})</option>
            {mapData?.zones?.map((z: any) => (
              <option key={z.id} value={z.id}>{z.name}</option>
            ))}
          </select>

          {/* Action Filter */}
          <select
            value={selectedActionFilter}
            onChange={(e) => setSelectedActionFilter(e.target.value)}
            className="px-3 py-1.5 text-xs bg-bg-secondary border border-bg-border rounded-lg text-slate-200 focus:outline-none focus:border-accent-cyan"
          >
            <option value="ALL">Todos os Fluxos (ALLOW & DENY)</option>
            <option value="ALLOW">Apenas Permitidos (ALLOW)</option>
            <option value="VIOLATION">Apenas Violações / Bloqueios</option>
          </select>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setZoomLevel(Math.max(0.7, zoomLevel - 0.1))}
            className="p-1.5 text-slate-400 hover:text-slate-200 bg-bg-secondary border border-bg-border rounded-lg"
            title="Zoom Out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <span className="text-xs font-mono text-slate-400 w-12 text-center">{Math.round(zoomLevel * 100)}%</span>
          <button
            onClick={() => setZoomLevel(Math.min(1.4, zoomLevel + 0.1))}
            className="p-1.5 text-slate-400 hover:text-slate-200 bg-bg-secondary border border-bg-border rounded-lg"
            title="Zoom In"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={fetchMap}
            className="p-1.5 text-slate-400 hover:text-slate-200 bg-bg-secondary border border-bg-border rounded-lg"
            title="Recarregar Mapa"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Main Map & Inspector Sidebar */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* SVG Interactive Topology Canvas */}
        <div className="lg:col-span-3 bg-bg-card border border-bg-border rounded-xl p-4 min-h-[550px] relative overflow-hidden flex flex-col justify-between">
          <div className="absolute top-3 left-4 flex items-center gap-4 text-[11px] font-semibold text-slate-400 z-10 bg-bg-primary/80 backdrop-blur px-3 py-1.5 rounded-lg border border-bg-border">
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-0.5 bg-accent-cyan rounded" /> Fluxo Permitido (ALLOW)</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-0.5 bg-amber-400 rounded" /> Negado (DENY)</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-0.5 bg-red-500 rounded animate-pulse" /> Violação Zero Trust</span>
          </div>

          <div className="w-full h-full overflow-auto cursor-grab active:cursor-grabbing p-4">
            <div
              style={{ transform: `scale(${zoomLevel})`, transformOrigin: 'top left' }}
              className="transition-transform duration-200 min-w-[1000px] min-h-[500px] relative"
            >
              <svg className="w-full h-[520px] absolute inset-0 pointer-events-none">
                <defs>
                  <marker id="arrow-allow" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#00d4ff" />
                  </marker>
                  <marker id="arrow-violation" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#ff1744" />
                  </marker>
                </defs>

                {/* Flow Lines */}
                {(mapData?.edges || []).map((edge: any) => {
                  const srcPos = nodePositions[edge.source_id];
                  const tgtPos = nodePositions[edge.target_id];

                  if (!srcPos || !tgtPos) return null;

                  if (selectedActionFilter === 'ALLOW' && edge.action !== 'ALLOW') return null;
                  if (selectedActionFilter === 'VIOLATION' && edge.action === 'ALLOW') return null;

                  const isViolation = edge.action === 'VIOLATION' || edge.action === 'DENY';
                  const strokeColor = isViolation ? '#ff1744' : '#00d4ff';

                  return (
                    <g key={edge.id}>
                      <line
                        x1={srcPos.x + 90}
                        y1={srcPos.y + 40}
                        x2={tgtPos.x + 90}
                        y2={tgtPos.y + 40}
                        stroke={strokeColor}
                        strokeWidth={isViolation ? '2.5' : '1.5'}
                        strokeDasharray={isViolation ? '4 4' : '6 6'}
                        className={isViolation ? 'animate-pulse' : ''}
                        markerEnd={isViolation ? 'url(#arrow-violation)' : 'url(#arrow-allow)'}
                      />
                      <text
                        x={(srcPos.x + tgtPos.x) / 2 + 90}
                        y={(srcPos.y + tgtPos.y) / 2 + 35}
                        fill={strokeColor}
                        fontSize="10"
                        fontWeight="bold"
                        textAnchor="middle"
                        className="bg-bg-card px-1 rounded"
                      >
                        :{edge.port} ({edge.protocol})
                      </text>
                    </g>
                  );
                })}
              </svg>

              {/* Node Cards overlay */}
              <div className="relative z-10">
                {filteredNodes.map((node: any) => {
                  const pos = nodePositions[node.id] || { x: 100, y: 100 };
                  const isSelected = selectedNode?.id === node.id;
                  const zoneColor = getZoneColor(node.zone_id);

                  return (
                    <div
                      key={node.id}
                      onClick={() => setSelectedNode(node)}
                      style={{
                        position: 'absolute',
                        left: `${pos.x}px`,
                        top: `${pos.y}px`,
                        width: '210px',
                        borderLeftColor: zoneColor
                      }}
                      className={`bg-bg-card border-l-4 border-y border-r border-bg-border rounded-xl p-3.5 shadow-xl hover:border-accent-cyan cursor-pointer transition-all ${
                        isSelected ? 'ring-2 ring-accent-cyan scale-105 z-20' : ''
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-[9px] font-extrabold uppercase px-1.5 py-0.5 rounded bg-slate-800 text-slate-300" style={{ color: zoneColor }}>
                          {node.type}
                        </span>
                        <span className={`w-2 h-2 rounded-full ${node.status === 'HEALTHY' ? 'bg-accent-green' : 'bg-red-500 animate-ping'}`} />
                      </div>

                      <h4 className="text-xs font-bold text-slate-100 truncate">{node.name}</h4>
                      <p className="text-[10px] font-mono text-slate-400 mt-0.5">{node.ip}</p>

                      <div className="mt-2 pt-2 border-t border-bg-border/60 flex items-center justify-between text-[10px]">
                        <span className="text-slate-400">Risk Score:</span>
                        <span className={`font-mono font-bold ${node.risk_score > 30 ? 'text-amber-400' : 'text-accent-cyan'}`}>
                          {node.risk_score}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Node Inspector Panel */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-5 space-y-4">
          {selectedNode ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-bg-border pb-3">
                <div>
                  <span className="text-[10px] font-extrabold text-accent-cyan uppercase tracking-wider">Ativo Inspecionado</span>
                  <h3 className="text-sm font-bold text-slate-100 truncate">{selectedNode.name}</h3>
                </div>
                <button onClick={() => setSelectedNode(null)} className="text-slate-400 hover:text-slate-200">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-2 text-xs">
                <div className="flex justify-between py-1 border-b border-bg-border/40">
                  <span className="text-slate-400">IP:</span>
                  <span className="font-mono text-slate-200 font-bold">{selectedNode.ip}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-bg-border/40">
                  <span className="text-slate-400">Tipo:</span>
                  <span className="text-slate-200">{selectedNode.type}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-bg-border/40">
                  <span className="text-slate-400">Zona de Segurança:</span>
                  <span className="font-semibold text-accent-cyan">{getZoneName(selectedNode.zone_id)}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-bg-border/40">
                  <span className="text-slate-400">Namespace K8s:</span>
                  <span className="font-mono text-slate-300">{selectedNode.namespace || 'default'}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-400">Risk Score:</span>
                  <span className="font-bold text-amber-400">{selectedNode.risk_score}</span>
                </div>
              </div>

              {/* Connected Flows */}
              <div className="space-y-2 pt-2 border-t border-bg-border">
                <h4 className="text-xs font-bold text-slate-200">Fluxos de Rede Conectados</h4>
                <div className="space-y-1.5 max-h-48 overflow-y-auto">
                  {(mapData?.edges || [])
                    .filter((e: any) => e.source_id === selectedNode.id || e.target_id === selectedNode.id)
                    .map((e: any) => (
                      <div key={e.id} className="p-2 rounded bg-bg-secondary text-[10px] space-y-0.5">
                        <div className="flex justify-between items-center font-bold">
                          <span className={e.action === 'ALLOW' ? 'text-accent-cyan' : 'text-red-400'}>
                            {e.source_name} → {e.target_name}
                          </span>
                          <span className="font-mono">{e.port}/{e.protocol}</span>
                        </div>
                        <div className="flex justify-between text-slate-400">
                          <span>Ação: {e.action}</span>
                          <span>{e.bytes} bytes</span>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-64 text-center text-slate-500 space-y-2">
              <Network className="w-10 h-10 stroke-1 text-slate-600" />
              <p className="text-xs">Clique em qualquer ativo no mapa para inspecionar fluxos, zonas e portas ativas.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
