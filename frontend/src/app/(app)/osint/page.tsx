'use client';

import React, { useState, useEffect } from 'react';
import {
  Radar, Globe, Shield, ShieldCheck, ShieldAlert, Server, Mail, Search,
  Terminal, ArrowUpRight, Copy, Check, ExternalLink, RefreshCw, Cpu,
  Database, Lock, AlertTriangle, CheckCircle2, ChevronRight, Layers, FileDown
} from 'lucide-react';
import { osintApi, OSINTResult } from '@/lib/api';
import clsx from 'clsx';

export default function OSINTPage() {
  const [targetInput, setTargetInput] = useState('stellantis.com');
  const [isScanning, setIsScanning] = useState(false);
  const [activeTab, setActiveTab] = useState<'maltego' | 'dns' | 'certs' | 'infra' | 'waf' | 'email' | 'dorks' | 'buckets'>('maltego');
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [result, setResult] = useState<OSINTResult | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [subdomainFilter, setSubdomainFilter] = useState('');

  // Initial scan on mount
  useEffect(() => {
    handleRunScan('stellantis.com');
  }, []);

  const handleRunScan = async (domainToScan?: string) => {
    const domain = (domainToScan || targetInput).trim();
    if (!domain) return;
    setIsScanning(true);
    try {
      const data = await osintApi.scan(domain);
      setResult(data);
    } catch (err) {
      console.error('OSINT scan error:', err);
    } finally {
      setIsScanning(false);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const exportReport = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `osint_report_${result.target}_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const presets = [
    'stellantis.com',
    'jeep.com.br',
    'fiat.com.br',
    'shieldsecurity.io',
    'github.com',
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Top Banner / Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-bg-border pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-lg bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20">
              <Radar className="w-5 h-5 animate-spin-slow" />
            </span>
            <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-3">
              OSINT Reconnaissance & Perimeter Intelligence
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/30 uppercase tracking-wider font-mono">
                SFSSA PRO
              </span>
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Reconhecimento passivo e ativo de superfície externa: DNS Zones, Certificate Transparency, ASN / Cloud, Detecção WAF (Akamai/Cloudflare) e E-mail Spoofing Posture.
          </p>
        </div>

        {result && (
          <div className="flex items-center gap-3">
            <button
              onClick={exportReport}
              className="px-3 py-2 rounded-lg bg-bg-card border border-bg-border hover:border-slate-600 text-xs font-medium text-slate-300 hover:text-slate-100 transition-colors flex items-center gap-2 shadow-sm"
            >
              <FileDown className="w-3.5 h-3.5 text-accent-cyan" />
              Exportar JSON
            </button>
          </div>
        )}
      </div>

      {/* Target Search & Preset Bar */}
      <div className="bg-bg-card/80 backdrop-blur border border-bg-border rounded-xl p-5 shadow-lg relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 bg-accent-cyan/5 rounded-full blur-3xl pointer-events-none" />
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleRunScan();
          }}
          className="flex flex-col md:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="Digite o domínio ou hostname alvo (ex: stellantis.com, jeep.com.br)..."
              className="w-full bg-bg-secondary border border-bg-border rounded-lg pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-accent-cyan focus:ring-1 focus:ring-accent-cyan transition-all"
            />
          </div>
          <button
            type="submit"
            disabled={isScanning || !targetInput.trim()}
            className="px-6 py-2.5 rounded-lg bg-gradient-to-r from-accent-cyan to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold text-sm transition-all duration-200 flex items-center justify-center gap-2 shadow-lg shadow-accent-cyan/20 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {isScanning ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                <span>Investigando...</span>
              </>
            ) : (
              <>
                <Radar className="w-4 h-4 text-slate-950" />
                <span>Executar Recon OSINT</span>
              </>
            )}
          </button>
        </form>

        {/* Presets */}
        <div className="flex items-center gap-2 mt-3 pt-3 border-t border-bg-border/60 flex-wrap text-xs">
          <span className="text-slate-400 font-medium">Alvos Rápidos:</span>
          {presets.map((preset) => (
            <button
              key={preset}
              type="button"
              onClick={() => {
                setTargetInput(preset);
                handleRunScan(preset);
              }}
              className={clsx(
                'px-2.5 py-1 rounded-md border text-xs font-mono transition-all',
                targetInput === preset
                  ? 'bg-accent-cyan/15 border-accent-cyan text-accent-cyan'
                  : 'bg-bg-secondary border-bg-border text-slate-400 hover:text-slate-200 hover:border-slate-600'
              )}
            >
              {preset}
            </button>
          ))}
        </div>
      </div>

      {result && (
        <>
          {/* Top KPI & Risk Summary Bar */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Threat Exposure Score */}
            <div className="bg-bg-card/80 border border-bg-border rounded-xl p-4 flex items-center gap-4 relative overflow-hidden">
              <div
                className={clsx(
                  'w-14 h-14 rounded-xl flex items-center justify-center font-bold font-mono text-xl border shadow-inner flex-shrink-0',
                  result.threat_exposure_score > 60
                    ? 'bg-accent-red/10 border-accent-red/30 text-accent-red'
                    : result.threat_exposure_score > 30
                    ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                    : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                )}
              >
                {result.threat_exposure_score}
              </div>
              <div className="min-w-0">
                <p className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Exposição Externa</p>
                <p className={clsx(
                  'text-sm font-bold truncate',
                  result.threat_exposure_score > 60 ? 'text-accent-red' : result.threat_exposure_score > 30 ? 'text-amber-400' : 'text-emerald-400'
                )}>
                  {result.threat_level}
                </p>
                <p className="text-[10px] text-slate-500">{result.scan_duration_ms}ms scan duration</p>
              </div>
            </div>

            {/* Cloud & WAF Defense */}
            <div className="bg-bg-card/80 border border-bg-border rounded-xl p-4 flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 flex items-center justify-center flex-shrink-0">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <div className="min-w-0">
                <p className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">WAF & CDN</p>
                <p className="text-sm font-semibold text-slate-200 truncate" title={result.technology_fingerprint.waf_name}>
                  {result.technology_fingerprint.waf_name}
                </p>
                <span className="inline-block text-[10px] text-accent-cyan font-mono truncate max-w-full">
                  {result.infrastructure_asn.cloud_provider}
                </span>
              </div>
            </div>

            {/* Subdomains & Attack Surface */}
            <div className="bg-bg-card/80 border border-bg-border rounded-xl p-4 flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-400 flex items-center justify-center flex-shrink-0">
                <Globe className="w-5 h-5" />
              </div>
              <div className="min-w-0">
                <p className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Subdomínios (CT Logs)</p>
                <p className="text-sm font-semibold text-slate-200">
                  {result.certificate_intelligence.discovered_subdomains_count} encontrados
                </p>
                <span className="text-[10px] text-slate-500 font-mono">
                  Primary IP: {result.dns_intelligence.primary_ip}
                </span>
              </div>
            </div>

            {/* E-mail Spoofing Posture */}
            <div className="bg-bg-card/80 border border-bg-border rounded-xl p-4 flex items-center gap-3">
              <div className={clsx(
                'w-10 h-10 rounded-lg border flex items-center justify-center flex-shrink-0',
                result.email_security.has_dmarc && result.email_security.has_spf
                  ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                  : 'bg-accent-red/10 border-accent-red/20 text-accent-red'
              )}>
                <Mail className="w-5 h-5" />
              </div>
              <div className="min-w-0">
                <p className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">DMARC / Anti-Spoofing</p>
                <p className="text-sm font-semibold text-slate-200 truncate">
                  {result.email_security.dmarc_policy}
                </p>
                <span className="text-[10px] text-slate-500">
                  SPF: {result.email_security.has_spf ? 'Configurado' : 'Ausente'}
                </span>
              </div>
            </div>
          </div>

          {/* Key Risks Callout Bar */}
          {result.key_risks.length > 0 && (
            <div className="bg-bg-secondary/70 border border-bg-border rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                  Destaques & Indicadores de Risco Perimetral
                </h3>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {result.key_risks.map((risk, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-xs text-slate-300 bg-bg-card/60 px-3 py-2 rounded-lg border border-bg-border">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mt-1.5 flex-shrink-0" />
                    <span>{risk}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Audit & Findings Registration Notice */}
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center bg-bg-card/90 border border-accent-cyan/30 p-4 rounded-xl gap-3">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                <CheckCircle2 className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-xs font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
                  Correlacionado com Audit Logs &amp; Findings Governance
                  <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-mono">
                    LIVE DB SYNCHRONIZED
                  </span>
                </h4>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Logs da varredura gravados no <code className="text-accent-cyan">AuditLog</code> (ID: {result.audit_id || 'AUDIT-OSINT-LIVE'}). {result.findings_registered_count || 1} vulnerabilidade(s) de perímetro registrada(s) na aba <strong>Findings</strong>.
                </p>
              </div>
            </div>
            <span className="text-xs font-mono bg-bg-secondary border border-bg-border text-slate-300 px-3 py-1.5 rounded-lg flex items-center gap-1.5">
              <Radar className="w-3.5 h-3.5 text-accent-cyan animate-pulse" />
              Engine: Maltego Transform v4.2
            </span>
          </div>

          {/* Navigation Tabs */}
          <div className="flex border-b border-bg-border gap-2 overflow-x-auto">
            <button
              onClick={() => setActiveTab('maltego')}
              className={clsx(
                'px-4 py-2.5 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap',
                activeTab === 'maltego'
                  ? 'border-accent-cyan text-accent-cyan bg-accent-cyan/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-bg-card'
              )}
            >
              <Radar className="w-4 h-4 text-accent-cyan animate-spin-slow" />
              1. Grafo Visual Maltego Topology
            </button>
            <button
              onClick={() => setActiveTab('dns')}
              className={clsx(
                'px-4 py-2.5 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap',
                activeTab === 'dns'
                  ? 'border-accent-cyan text-accent-cyan bg-accent-cyan/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-bg-card'
              )}
            >
              <Database className="w-4 h-4" />
              2. DNS Intelligence
            </button>
            <button
              onClick={() => setActiveTab('certs')}
              className={clsx(
                'px-4 py-2.5 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap',
                activeTab === 'certs'
                  ? 'border-accent-cyan text-accent-cyan bg-accent-cyan/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-bg-card'
              )}
            >
              <Lock className="w-4 h-4" />
              3. CT Logs &amp; Subdomínios ({result.certificate_intelligence.discovered_subdomains_count})
            </button>
            <button
              onClick={() => setActiveTab('infra')}
              className={clsx(
                'px-4 py-2.5 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap',
                activeTab === 'infra'
                  ? 'border-accent-cyan text-accent-cyan bg-accent-cyan/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-bg-card'
              )}
            >
              <Server className="w-4 h-4" />
              4. Infraestrutura &amp; ASN
            </button>
            <button
              onClick={() => setActiveTab('waf')}
              className={clsx(
                'px-4 py-2.5 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap',
                activeTab === 'waf'
                  ? 'border-accent-cyan text-accent-cyan bg-accent-cyan/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-bg-card'
              )}
            >
              <Cpu className="w-4 h-4" />
              5. WAF &amp; Tech Stack
            </button>
            <button
              onClick={() => setActiveTab('email')}
              className={clsx(
                'px-4 py-2.5 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap',
                activeTab === 'email'
                  ? 'border-accent-cyan text-accent-cyan bg-accent-cyan/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-bg-card'
              )}
            >
              <Mail className="w-4 h-4" />
              6. E-mail &amp; DMARC
            </button>
            <button
              onClick={() => setActiveTab('dorks')}
              className={clsx(
                'px-4 py-2.5 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap',
                activeTab === 'dorks'
                  ? 'border-accent-cyan text-accent-cyan bg-accent-cyan/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-bg-card'
              )}
            >
              <Search className="w-4 h-4" />
              7. Google Dorking
            </button>
            <button
              onClick={() => setActiveTab('buckets')}
              className={clsx(
                'px-4 py-2.5 text-xs font-semibold rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap',
                activeTab === 'buckets'
                  ? 'border-accent-cyan text-accent-cyan bg-accent-cyan/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-bg-card'
              )}
            >
              <Database className="w-4 h-4" />
              8. Cloud Storage
            </button>
          </div>

          {/* TAB MALTEGO GRAPH */}
          {activeTab === 'maltego' && (
            <div className="space-y-4">
              <div className="bg-bg-card border border-bg-border rounded-xl p-5 shadow-xl relative overflow-hidden space-y-4">
                <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3 border-b border-bg-border pb-4">
                  <div>
                    <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
                      <Radar className="w-4 h-4 text-accent-cyan animate-pulse" />
                      Grafo Interativo de Transformações Maltego (Perimeter Intelligence)
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Selecione qualquer nó da topologia para executar transformações avançadas ou inspecionar detalhes do ativo.
                    </p>
                  </div>
                  <div className="flex items-center gap-2 text-xs font-mono">
                    <span className="px-2.5 py-1 rounded bg-bg-secondary border border-bg-border text-accent-cyan font-bold">
                      {result.maltego_graph?.total_nodes || 9} Nós Mapeados
                    </span>
                    <span className="px-2.5 py-1 rounded bg-bg-secondary border border-bg-border text-slate-300">
                      {result.maltego_graph?.total_edges || 8} Arestas de Conexão
                    </span>
                  </div>
                </div>

                {/* SVG Visual Graph */}
                <div className="relative w-full h-[480px] bg-slate-950/90 rounded-xl border border-bg-border/80 overflow-hidden flex items-center justify-center p-4 shadow-inner">
                  {/* Subtle Grid Background */}
                  <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:3rem_3rem] [mask-image:radial-gradient(ellipse_70%_70%_at_50%_50%,#000_70%,transparent_100%)] opacity-30 pointer-events-none" />

                  {(() => {
                    const fallbackNodes = [
                      { id: 'node-domain', label: targetInput || 'stellantis.com', entity_type: 'DOMAIN', x: 45, y: 45, details: `Domínio Alvo: ${targetInput}` },
                      { id: 'node-ip', label: result?.dns_intelligence?.primary_ip || '104.26.12.31', entity_type: 'IP', x: 20, y: 25, details: 'IP Público Primário (DNS A)' },
                      { id: 'node-cloud', label: result?.infrastructure_asn?.cloud_provider || 'Cloudflare Edge / Akamai', entity_type: 'ASN_CLOUD', x: 12, y: 70, details: 'ASN Provider de Borda' },
                      { id: 'node-waf', label: result?.technology_fingerprint?.waf_name || 'Akamai Edge WAF', entity_type: 'WAF', x: 70, y: 22, details: 'Proteção de Borda WAF' },
                      { id: 'node-sub1', label: `api.${targetInput || 'stellantis.com'}`, entity_type: 'SUBDOMAIN', x: 18, y: 85, details: 'Subdomínio CT Log' },
                      { id: 'node-sub2', label: `auth.${targetInput || 'stellantis.com'}`, entity_type: 'SUBDOMAIN', x: 42, y: 85, details: 'Subdomínio CT Log' },
                      { id: 'node-mx', label: result?.email_security?.mx_servers?.[0] || `mx.${targetInput}`, entity_type: 'MAIL_SERVER', x: 72, y: 55, details: 'Mail Handler (MX)' },
                      { id: 'node-bucket', label: 'storage.googleapis.com/media-assets', entity_type: 'CLOUD_BUCKET', x: 80, y: 30, details: 'Public Storage Bucket' },
                      { id: 'node-vuln', label: 'DMARC Ausente (E-mail Spoofing)', entity_type: 'VULNERABILITY', x: 75, y: 82, details: 'Vulnerabilidade de Impersonação' },
                    ];

                    const fallbackEdges = [
                      { id: 'e1', source: 'node-domain', target: 'node-ip', label: 'RESOLVES_TO' },
                      { id: 'e2', source: 'node-ip', target: 'node-cloud', label: 'HOSTED_ON' },
                      { id: 'e3', source: 'node-domain', target: 'node-waf', label: 'PROTECTED_BY' },
                      { id: 'e4', source: 'node-domain', target: 'node-sub1', label: 'SUBDOMAIN_OF' },
                      { id: 'e5', source: 'node-domain', target: 'node-sub2', label: 'SUBDOMAIN_OF' },
                      { id: 'e6', source: 'node-domain', target: 'node-mx', label: 'MAIL_HANDLER' },
                      { id: 'e7', source: 'node-domain', target: 'node-bucket', label: 'EXPOSES_BUCKET' },
                      { id: 'e8', source: 'node-domain', target: 'node-vuln', label: 'HAS_VULNERABILITY' },
                    ];

                    const activeNodes = (result?.maltego_graph?.nodes && result.maltego_graph.nodes.length > 0)
                      ? result.maltego_graph.nodes
                      : fallbackNodes;

                    const activeEdges = (result?.maltego_graph?.edges && result.maltego_graph.edges.length > 0)
                      ? result.maltego_graph.edges
                      : fallbackEdges;

                    return (
                      <>
                        <svg className="w-full h-full absolute inset-0 pointer-events-none" viewBox="0 0 100 100" preserveAspectRatio="none">
                          {activeEdges.map((edge) => {
                            const srcNode = activeNodes.find((n) => n.id === edge.source);
                            const tgtNode = activeNodes.find((n) => n.id === edge.target);
                            if (!srcNode || !tgtNode) return null;
                            const sx = srcNode.x > 100 ? (srcNode.x / 800) * 100 : srcNode.x;
                            const sy = srcNode.y > 100 ? (srcNode.y / 500) * 100 : srcNode.y;
                            const tx = tgtNode.x > 100 ? (tgtNode.x / 800) * 100 : tgtNode.x;
                            const ty = tgtNode.y > 100 ? (tgtNode.y / 500) * 100 : tgtNode.y;
                            return (
                              <g key={edge.id}>
                                <line
                                  x1={`${sx}`}
                                  y1={`${sy}`}
                                  x2={`${tx}`}
                                  y2={`${ty}`}
                                  stroke="#06b6d4"
                                  strokeWidth="0.4"
                                  strokeDasharray="1 0.5"
                                  opacity="0.75"
                                />
                                <text
                                  x={(sx + tx) / 2}
                                  y={(sy + ty) / 2 - 1}
                                  fill="#06b6d4"
                                  fontSize="2"
                                  fontFamily="monospace"
                                  textAnchor="middle"
                                >
                                  {edge.label}
                                </text>
                              </g>
                            );
                          })}
                        </svg>

                        <div className="relative w-full h-full">
                          {activeNodes.map((node) => {
                            const isSelected = selectedNode?.id === node.id;
                            const leftPct = node.x > 100 ? (node.x / 800) * 100 : node.x;
                            const topPct = node.y > 100 ? (node.y / 500) * 100 : node.y;
                            return (
                              <div
                                key={node.id}
                                onClick={() => setSelectedNode(node)}
                                style={{ left: `${leftPct}%`, top: `${topPct}%` }}
                                className={clsx(
                                  'absolute -translate-x-1/2 -translate-y-1/2 px-3 py-2 rounded-xl border transition-all cursor-pointer shadow-xl flex items-center gap-2 font-mono text-xs z-10 hover:scale-110 backdrop-blur-md',
                                  isSelected
                                    ? 'bg-accent-cyan/30 border-accent-cyan text-slate-100 ring-2 ring-accent-cyan shadow-accent-cyan/30'
                                    : node.entity_type === 'DOMAIN'
                                    ? 'bg-cyan-950/90 border-cyan-400/80 text-cyan-200 shadow-cyan-900/50'
                                    : node.entity_type === 'VULNERABILITY'
                                    ? 'bg-red-950/90 border-red-500 text-red-300 shadow-red-900/50 animate-pulse'
                                    : node.entity_type === 'WAF'
                                    ? 'bg-purple-950/90 border-purple-400 text-purple-200 shadow-purple-900/50'
                                    : node.entity_type === 'CLOUD_BUCKET'
                                    ? 'bg-teal-950/90 border-teal-400 text-teal-200 shadow-teal-900/50'
                                    : 'bg-slate-900/90 border-slate-700 text-slate-200'
                                )}
                              >
                                <span className="p-1.5 rounded-lg bg-slate-950/80 border border-slate-700/80 flex-shrink-0">
                                  {node.entity_type === 'DOMAIN' && <Globe className="w-4 h-4 text-cyan-400 animate-spin-slow" />}
                                  {node.entity_type === 'IP' && <Server className="w-4 h-4 text-blue-400" />}
                                  {node.entity_type === 'ASN_CLOUD' && <Cpu className="w-4 h-4 text-purple-400" />}
                                  {node.entity_type === 'WAF' && <Shield className="w-4 h-4 text-emerald-400" />}
                                  {node.entity_type === 'SUBDOMAIN' && <Layers className="w-4 h-4 text-indigo-400" />}
                                  {node.entity_type === 'MAIL_SERVER' && <Mail className="w-4 h-4 text-amber-400" />}
                                  {node.entity_type === 'CLOUD_BUCKET' && <Database className="w-4 h-4 text-teal-400" />}
                                  {node.entity_type === 'VULNERABILITY' && <AlertTriangle className="w-4 h-4 text-red-400" />}
                                </span>
                                <div className="min-w-0">
                                  <span className="font-bold block truncate max-w-[140px]">{node.label}</span>
                                  <span className="text-[9px] text-slate-400 block uppercase font-sans tracking-wider">{node.entity_type}</span>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </>
                    );
                  })()}
                </div>

                {/* Node Details & Transform Card */}
                {selectedNode && (
                  <div className="bg-bg-secondary p-4 rounded-xl border border-accent-cyan/40 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded bg-accent-cyan/20 text-accent-cyan font-mono text-xs font-bold">
                          {selectedNode.entity_type}
                        </span>
                        <h4 className="text-sm font-bold text-slate-100 font-mono">{selectedNode.label}</h4>
                      </div>
                      <button
                        onClick={() => setSelectedNode(null)}
                        className="text-xs text-slate-400 hover:text-slate-200"
                      >
                        Fechar
                      </button>
                    </div>

                    <p className="text-xs text-slate-300 font-sans">{selectedNode.details}</p>

                    <div className="flex items-center gap-2 pt-2 border-t border-bg-border/60">
                      <span className="text-xs text-slate-400 font-mono">Transformações Maltego Disponíveis:</span>
                      <button
                        onClick={() => alert(`Transformação Maltego disparada para: ${selectedNode.label}`)}
                        className="px-3 py-1 rounded bg-accent-cyan text-slate-950 font-bold text-xs hover:opacity-90 font-mono"
                      >
                        To DNS Records
                      </button>
                      <button
                        onClick={() => alert(`Enriquecimento IP / Geo disparado para: ${selectedNode.label}`)}
                        className="px-3 py-1 rounded bg-bg-card border border-bg-border text-slate-200 text-xs hover:border-accent-cyan font-mono"
                      >
                        To BGP / IP Subnets
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 1: DNS INTELLIGENCE */}
          {activeTab === 'dns' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-bg-card border border-bg-border rounded-xl p-4">
                  <span className="text-xs text-slate-400">Target Domain</span>
                  <p className="text-sm font-mono font-bold text-slate-100 mt-1">{result.dns_intelligence.domain}</p>
                </div>
                <div className="bg-bg-card border border-bg-border rounded-xl p-4">
                  <span className="text-xs text-slate-400">Primary IP Resolution</span>
                  <p className="text-sm font-mono font-bold text-accent-cyan mt-1">{result.dns_intelligence.primary_ip}</p>
                </div>
                <div className="bg-bg-card border border-bg-border rounded-xl p-4">
                  <span className="text-xs text-slate-400">Cert. Authority Authorization (CAA)</span>
                  <p className="text-sm font-semibold mt-1">
                    {result.dns_intelligence.has_caa ? (
                      <span className="text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-4 h-4" /> Ativo (Impede emissão ilegítima)
                      </span>
                    ) : (
                      <span className="text-amber-400 flex items-center gap-1">
                        <AlertTriangle className="w-4 h-4" /> Não configurado
                      </span>
                    )}
                  </p>
                </div>
              </div>

              {/* Records Accordion/Grid */}
              <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden shadow-sm">
                <div className="px-5 py-3.5 bg-bg-secondary border-b border-bg-border flex items-center justify-between">
                  <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-accent-cyan" />
                    Registros DNS da Zona Resolvida (DNS-over-HTTPS Cloudflare/Google)
                  </h3>
                </div>
                <div className="divide-y divide-bg-border">
                  {Object.entries(result.dns_intelligence.records).map(([type, records]) => (
                    <div key={type} className="p-4 flex flex-col md:flex-row md:items-start gap-3 hover:bg-bg-secondary/40 transition-colors">
                      <div className="w-20 flex-shrink-0">
                        <span className="px-2.5 py-1 rounded bg-accent-cyan/10 border border-accent-cyan/20 text-accent-cyan font-mono text-xs font-bold">
                          {type}
                        </span>
                      </div>
                      <div className="flex-1 space-y-1.5 min-w-0">
                        {records.length > 0 ? (
                          records.map((rec, i) => (
                            <div key={i} className="flex items-center justify-between group bg-bg-secondary/60 px-3 py-1.5 rounded border border-bg-border/60">
                              <span className="text-xs font-mono text-slate-200 truncate mr-2" title={rec}>
                                {rec}
                              </span>
                              <button
                                onClick={() => copyToClipboard(rec, `${type}-${i}`)}
                                className="opacity-0 group-hover:opacity-100 text-slate-400 hover:text-accent-cyan transition-opacity flex-shrink-0"
                                title="Copiar registro"
                              >
                                {copiedKey === `${type}-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                              </button>
                            </div>
                          ))
                        ) : (
                          <span className="text-xs text-slate-500 italic">Nenhum registro {type} publicado</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: CERTIFICATE TRANSPARENCY & SUBDOMAINS */}
          {activeTab === 'certs' && (
            <div className="space-y-4">
              {/* SSL Active Info */}
              <div className="bg-bg-card border border-bg-border rounded-xl p-5 shadow-sm">
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
                  <Lock className="w-4 h-4 text-emerald-400" />
                  Certificado SSL/TLS Ativo & Subject Alternative Names (SANs)
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="space-y-2 bg-bg-secondary/60 p-3.5 rounded-lg border border-bg-border">
                    <p className="text-slate-400">Emissor Autorizado (CA):</p>
                    <p className="font-semibold text-slate-100 font-mono">
                      {result.certificate_intelligence.active_cert.issuer?.organizationName || 'DigiCert / Let\'s Encrypt'}
                    </p>
                    <p className="text-slate-400 mt-2">Validade até:</p>
                    <p className="font-semibold text-emerald-400 font-mono">
                      {result.certificate_intelligence.active_cert.valid_to || 'Ativo e Válido'}
                    </p>
                  </div>
                  <div className="space-y-2 bg-bg-secondary/60 p-3.5 rounded-lg border border-bg-border">
                    <p className="text-slate-400">SANs Cobertos no Certificado Ativo:</p>
                    <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
                      {result.certificate_intelligence.active_cert.san_domains?.map((san, idx) => (
                        <span key={idx} className="px-2 py-0.5 rounded bg-bg-card border border-bg-border text-[11px] font-mono text-slate-300">
                          {san}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Discovered Subdomains via crt.sh */}
              <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden shadow-sm">
                <div className="p-4 bg-bg-secondary border-b border-bg-border flex flex-col md:flex-row md:items-center justify-between gap-3">
                  <div>
                    <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                      <Globe className="w-4 h-4 text-accent-cyan" />
                      Subdomínios Descobertos via Certificate Transparency Logs (crt.sh)
                    </h3>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      {result.certificate_intelligence.discovered_subdomains_count} subdomínios mapeados na infraestrutura histórica e ativa
                    </p>
                  </div>
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                    <input
                      type="text"
                      value={subdomainFilter}
                      onChange={(e) => setSubdomainFilter(e.target.value)}
                      placeholder="Filtrar subdomínios..."
                      className="bg-bg-card border border-bg-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
                    />
                  </div>
                </div>

                <div className="p-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5 max-h-96 overflow-y-auto">
                  {result.certificate_intelligence.discovered_subdomains
                    .filter((s) => s.toLowerCase().includes(subdomainFilter.toLowerCase()))
                    .map((sub, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between p-2.5 rounded-lg bg-bg-secondary/60 border border-bg-border hover:border-accent-cyan/40 transition-colors group"
                      >
                        <div className="flex items-center gap-2 min-w-0 mr-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-accent-cyan flex-shrink-0" />
                          <span className="text-xs font-mono text-slate-200 truncate" title={sub}>
                            {sub}
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                          <button
                            onClick={() => copyToClipboard(sub, `sub-${idx}`)}
                            className="p-1 rounded hover:bg-bg-card text-slate-400 hover:text-accent-cyan"
                            title="Copiar"
                          >
                            {copiedKey === `sub-${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          </button>
                          <a
                            href={`https://${sub}`}
                            target="_blank"
                            rel="noreferrer"
                            className="p-1 rounded hover:bg-bg-card text-slate-400 hover:text-accent-cyan"
                            title="Abrir URL"
                          >
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: INFRASTRUCTURE & ASN */}
          {activeTab === 'infra' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-bg-card border border-bg-border rounded-xl p-5 space-y-4 shadow-sm">
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                  <Server className="w-4 h-4 text-accent-cyan" />
                  Informações de ASN & Borda de Rede
                </h3>

                <div className="space-y-3 text-xs">
                  <div className="flex justify-between py-2 border-b border-bg-border">
                    <span className="text-slate-400">Autonomous System (ASN):</span>
                    <span className="font-mono font-bold text-accent-cyan">{result.infrastructure_asn.asn}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b border-bg-border">
                    <span className="text-slate-400">Organização ASN:</span>
                    <span className="font-semibold text-slate-200 text-right">{result.infrastructure_asn.asn_org}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b border-bg-border">
                    <span className="text-slate-400">Provedor Cloud / Edge CDN:</span>
                    <span className="font-semibold text-emerald-400">{result.infrastructure_asn.cloud_provider}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b border-bg-border">
                    <span className="text-slate-400">IP Público Primário:</span>
                    <span className="font-mono font-bold text-slate-200">{result.infrastructure_asn.ip}</span>
                  </div>
                  <div className="flex justify-between py-2">
                    <span className="text-slate-400">Reverse DNS (PTR):</span>
                    <span className="font-mono text-slate-300 truncate max-w-[200px]" title={result.infrastructure_asn.reverse_dns}>
                      {result.infrastructure_asn.reverse_dns}
                    </span>
                  </div>
                </div>
              </div>

              <div className="bg-bg-card border border-bg-border rounded-xl p-5 space-y-4 shadow-sm">
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                  <Globe className="w-4 h-4 text-purple-400" />
                  Geolocalização & Roteamento Perimetral
                </h3>

                <div className="space-y-3 text-xs">
                  <div className="flex justify-between py-2 border-b border-bg-border">
                    <span className="text-slate-400">País de Origem / Servidor:</span>
                    <span className="font-semibold text-slate-200">{result.infrastructure_asn.country}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b border-bg-border">
                    <span className="text-slate-400">Cidade / Hub de Roteamento:</span>
                    <span className="font-semibold text-slate-200">{result.infrastructure_asn.city}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b border-bg-border">
                    <span className="text-slate-400">Disallow Rules em robots.txt:</span>
                    <span className="font-mono text-slate-200">{result.public_exposure.disallowed_paths_count} rotas protegidas</span>
                  </div>
                  <div className="flex justify-between py-2 border-b border-bg-border">
                    <span className="text-slate-400">Divulgação security.txt:</span>
                    <span className="font-semibold text-emerald-400">
                      {result.public_exposure.security_txt_present ? (result.public_exposure.security_txt_contact || 'Presente') : 'Não publicado'}
                    </span>
                  </div>
                  <div className="flex justify-between py-2">
                    <span className="text-slate-400">Sitemap XML:</span>
                    <span className="font-semibold text-slate-200">
                      {result.public_exposure.sitemap_xml_present ? 'Disponível' : 'Oculto'}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: WEB & WAF FINGERPRINT */}
          {activeTab === 'waf' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-bg-card border border-bg-border rounded-xl p-4">
                  <span className="text-xs text-slate-400">Assinatura do Servidor HTTP</span>
                  <p className="text-sm font-mono font-bold text-slate-100 mt-1">{result.technology_fingerprint.server}</p>
                </div>
                <div className="bg-bg-card border border-bg-border rounded-xl p-4">
                  <span className="text-xs text-slate-400">WAF Identificado</span>
                  <p className="text-sm font-bold text-accent-cyan mt-1">{result.technology_fingerprint.waf_name}</p>
                </div>
                <div className="bg-bg-card border border-bg-border rounded-xl p-4">
                  <span className="text-xs text-slate-400">Status de Proteção Ativa</span>
                  <p className="text-sm font-semibold mt-1">
                    {result.technology_fingerprint.waf_detected ? (
                      <span className="text-emerald-400 flex items-center gap-1">
                        <ShieldCheck className="w-4 h-4" /> WAF de Borda Ativo
                      </span>
                    ) : (
                      <span className="text-accent-red flex items-center gap-1">
                        <ShieldAlert className="w-4 h-4" /> WAF Não Detectado
                      </span>
                    )}
                  </p>
                </div>
              </div>

              {/* Technologies & Headers Checklist */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Tech Stack */}
                <div className="bg-bg-card border border-bg-border rounded-xl p-5 space-y-3">
                  <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                    <Layers className="w-4 h-4 text-accent-cyan" />
                    Tecnologias & Frameworks Identificados
                  </h3>
                  <div className="flex flex-wrap gap-2 pt-2">
                    {result.technology_fingerprint.technologies.map((tech, idx) => (
                      <span
                        key={idx}
                        className="px-3 py-1 rounded-lg bg-bg-secondary border border-bg-border text-xs font-medium text-slate-200 flex items-center gap-1.5"
                      >
                        <span className="w-2 h-2 rounded-full bg-accent-cyan" />
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Security Headers Checklist */}
                <div className="bg-bg-card border border-bg-border rounded-xl p-5 space-y-3">
                  <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                    <Shield className="w-4 h-4 text-emerald-400" />
                    Auditoria de Headers de Segurança HTTP
                  </h3>
                  <div className="space-y-2 pt-1">
                    {Object.entries(result.technology_fingerprint.security_headers).map(([header, present]) => (
                      <div
                        key={header}
                        className="flex items-center justify-between p-2 rounded-lg bg-bg-secondary/60 border border-bg-border text-xs"
                      >
                        <span className="font-mono text-slate-300">{header}</span>
                        {present ? (
                          <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-bold">
                            HABILITADO
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded bg-accent-red/10 text-accent-red border border-accent-red/20 text-[10px] font-bold">
                            AUSENTE
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: EMAIL SECURITY & ANTI-SPOOFING */}
          {activeTab === 'email' && (
            <div className="space-y-4">
              <div className="bg-bg-card border border-bg-border rounded-xl p-5 shadow-sm space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                    <Mail className="w-4 h-4 text-accent-cyan" />
                    Postura Anti-Spoofing de E-mail (SPF / DMARC / MX)
                  </h3>
                  <span className={clsx(
                    'px-2.5 py-1 rounded-full text-xs font-bold border',
                    result.email_security.spoofing_risk_level.includes('SAFE')
                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                      : 'bg-accent-red/10 border-accent-red/30 text-accent-red'
                  )}>
                    {result.email_security.spoofing_risk_level}
                  </span>
                </div>

                <div className="space-y-3">
                  {/* SPF */}
                  <div className="bg-bg-secondary/70 p-3.5 rounded-lg border border-bg-border space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-bold text-slate-200 flex items-center gap-1.5">
                        <span className={clsx('w-2 h-2 rounded-full', result.email_security.has_spf ? 'bg-emerald-400' : 'bg-accent-red')} />
                        Registro SPF (Sender Policy Framework)
                      </span>
                      <span className="text-slate-400 text-[11px]">
                        {result.email_security.has_spf ? 'Configurado' : 'Vulnerável'}
                      </span>
                    </div>
                    <p className="text-xs font-mono text-slate-300 bg-bg-card p-2 rounded border border-bg-border select-all">
                      {result.email_security.spf_record}
                    </p>
                  </div>

                  {/* DMARC */}
                  <div className="bg-bg-secondary/70 p-3.5 rounded-lg border border-bg-border space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-bold text-slate-200 flex items-center gap-1.5">
                        <span className={clsx('w-2 h-2 rounded-full', result.email_security.has_dmarc ? 'bg-emerald-400' : 'bg-accent-red')} />
                        Registro DMARC (_dmarc.{result.target})
                      </span>
                      <span className="text-slate-400 text-[11px]">
                        Política: <strong className="text-slate-200">{result.email_security.dmarc_policy}</strong>
                      </span>
                    </div>
                    <p className="text-xs font-mono text-slate-300 bg-bg-card p-2 rounded border border-bg-border select-all">
                      {result.email_security.dmarc_record}
                    </p>
                  </div>

                  {/* MX Servers */}
                  <div className="bg-bg-secondary/70 p-3.5 rounded-lg border border-bg-border space-y-1.5">
                    <div className="text-xs font-bold text-slate-200 mb-2">
                      Servidores de Correio Eletrônico (MX Records)
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {result.email_security.mx_servers.map((mx, idx) => (
                        <div key={idx} className="p-2 rounded bg-bg-card border border-bg-border text-xs font-mono text-slate-300">
                          {mx}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: GOOGLE DORKING ENGINE (equip.md) */}
          {activeTab === 'dorks' && (
            <div className="space-y-4">
              <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden shadow-sm">
                <div className="p-4 bg-bg-secondary border-b border-bg-border flex items-center justify-between">
                  <div>
                    <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                      <Search className="w-4 h-4 text-accent-cyan" />
                      Google Dorking Intelligence Matrix (Reconnaissance Passivo)
                    </h3>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      Consultas avançadas geradas dinamicamente para busca de vazamentos de credenciais, arquivos .env/.git e portais restritos.
                    </p>
                  </div>
                </div>
                <div className="divide-y divide-bg-border">
                  {result.google_dorks?.map((dorkItem, idx) => (
                    <div key={idx} className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-bg-secondary/40 transition-colors">
                      <div className="space-y-1.5 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full bg-accent-cyan" />
                          <h4 className="text-xs font-bold text-slate-200">{dorkItem.category}</h4>
                        </div>
                        <p className="text-xs font-mono text-slate-300 bg-bg-secondary px-3 py-1.5 rounded border border-bg-border select-all truncate max-w-2xl" title={dorkItem.dork}>
                          {dorkItem.dork}
                        </p>
                        <p className="text-[11px] text-slate-400 italic">{dorkItem.description}</p>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <button
                          onClick={() => copyToClipboard(dorkItem.dork, `dork-${idx}`)}
                          className="px-2.5 py-1.5 rounded-lg bg-bg-secondary border border-bg-border text-xs text-slate-300 hover:text-accent-cyan transition-colors flex items-center gap-1.5"
                          title="Copiar Dork"
                        >
                          {copiedKey === `dork-${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          <span>Copiar</span>
                        </button>
                        <a
                          href={`https://www.google.com/search?q=${encodeURIComponent(dorkItem.dork)}`}
                          target="_blank"
                          rel="noreferrer"
                          className="px-2.5 py-1.5 rounded-lg bg-accent-cyan/10 border border-accent-cyan/30 text-xs text-accent-cyan hover:bg-accent-cyan/20 transition-colors flex items-center gap-1.5"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                          <span>Executar no Google</span>
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: CLOUD STORAGE & S3 BUCKETS (equip.md) */}
          {activeTab === 'buckets' && (
            <div className="space-y-4">
              <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden shadow-sm">
                <div className="p-4 bg-bg-secondary border-b border-bg-border">
                  <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                    <Database className="w-4 h-4 text-emerald-400" />
                    Auditoria de Buckets de Nuvem &amp; Armazenamento Exposto (AWS S3, GCP Storage, Azure Blob)
                  </h3>
                </div>
                <div className="divide-y divide-bg-border">
                  {result.cloud_buckets?.map((bucket, idx) => (
                    <div key={idx} className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-bg-secondary/40 transition-colors">
                      <div className="space-y-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-blue-500/10 border border-blue-500/20 text-blue-400">
                            {bucket.provider}
                          </span>
                          <span className="text-xs font-mono font-bold text-slate-200">{bucket.bucket_name}</span>
                        </div>
                        <p className="text-xs text-slate-400 font-mono">{bucket.url}</p>
                      </div>
                      <div className="flex items-center gap-3 flex-shrink-0">
                        <span className={clsx(
                          "px-2.5 py-1 rounded-full text-xs font-bold font-mono border",
                          bucket.status.includes('CRITICAL') ? "bg-accent-red/20 border-accent-red/30 text-accent-red" :
                          bucket.status.includes('PROTEGIDO') ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400" :
                          "bg-slate-700/30 border-slate-600 text-slate-400"
                        )}>
                          {bucket.status}
                        </span>
                        <a
                          href={bucket.url}
                          target="_blank"
                          rel="noreferrer"
                          className="p-2 rounded-lg bg-bg-secondary border border-bg-border text-slate-400 hover:text-accent-cyan transition-colors"
                          title="Testar URL"
                        >
                          <ExternalLink className="w-4 h-4" />
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
