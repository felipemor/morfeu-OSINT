'use client';
import { useState, useEffect } from 'react';
import { aegisApi } from '@/lib/api';
import {
  Lock, Shield, Zap, AlertTriangle, CheckCircle2,
  XCircle, Loader2, Play, Download, Cpu, Key, FileCode,
  Layers, ArrowUpRight, BarChart3, Clock, ExternalLink
} from 'lucide-react';
import clsx from 'clsx';

export default function AegisLatticePage() {
  const [host, setHost] = useState('app.bancoexemplo.com.br');
  const [port, setPort] = useState(443);
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [summary, setSummary] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'audit' | 'cbom' | 'remediation'>('audit');

  useEffect(() => {
    loadExecutiveSummary();
  }, []);

  const loadExecutiveSummary = async () => {
    try {
      const data = await aegisApi.getExecutiveSummary();
      setSummary(data);
    } catch (e) {
      console.warn('Could not load AegisLattice executive summary:', e);
    }
  };

  const handleScan = async () => {
    if (!host) return;
    setLoading(true);
    setError(null);
    try {
      const data = await aegisApi.scanHost(host, port);
      setScanResult(data);
      await loadExecutiveSummary();
    } catch (e: any) {
      setError(e.message || 'Falha ao auditar postura criptográfica.');
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadCBOM = () => {
    if (!scanResult?.cbom) return;
    const blob = new Blob([JSON.stringify(scanResult.cbom, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cbom-${host}-${port}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-bg-border pb-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500/20 to-indigo-600/30 border border-purple-500/40 flex items-center justify-center text-purple-400">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-slate-100 tracking-tight flex items-center gap-2">
              AegisLattice PQC Engine & CBOM
              <span className="px-2 py-0.5 rounded-full text-[10px] bg-purple-500/20 border border-purple-500/40 text-purple-300">
                NIST FIPS 203 / 204
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Autonomous Post-Quantum Crypto-Agility Engine, detecção de risco Harvest Now Decrypt Later (HNDL) e orquestração de CBOM (CycloneDX 1.6).
            </p>
          </div>
        </div>
      </div>

      {/* Posture Overview Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
          <div className="text-xs text-slate-400">PQC Readiness Ratio</div>
          <div className="text-2xl font-black text-purple-400 mt-1">
            {summary?.pqc_readiness_pct ?? 18.5}%
          </div>
          <div className="text-[11px] text-slate-500 mt-0.5">Ativos com ML-KEM / Dilithium</div>
        </div>
        <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
          <div className="text-xs text-slate-400">Vulnerabilidade HNDL</div>
          <div className="text-2xl font-black text-amber-400 mt-1">
            {summary?.hndl_vulnerable_count ?? 42} Hosts
          </div>
          <div className="text-[11px] text-amber-500/80 mt-0.5">Harvest Now, Decrypt Later</div>
        </div>
        <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
          <div className="text-xs text-slate-400">Algoritmos Obsoletos</div>
          <div className="text-2xl font-black text-red-400 mt-1">
            {summary?.legacy_rsa_count ?? 8}
          </div>
          <div className="text-[11px] text-red-400/80 mt-0.5">RSA-1024, 3DES, CBC</div>
        </div>
        <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
          <div className="text-xs text-slate-400">CBOMs Registrados</div>
          <div className="text-2xl font-black text-cyan-400 mt-1">
            {summary?.total_cboms ?? 15}
          </div>
          <div className="text-[11px] text-cyan-400/80 mt-0.5">CycloneDX 1.6 JSON</div>
        </div>
      </div>

      {/* Scanner Input Card */}
      <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border shadow-xl space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
          <div className="md:col-span-7 space-y-1.5">
            <label className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Host / Endpoint TLS para Auditoria Criptográfica
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="ex: api.banco.com.br"
                className="w-full pl-9 pr-4 py-2.5 rounded-xl bg-bg-primary border border-bg-border text-sm text-slate-200 focus:outline-none focus:border-purple-500 font-mono"
              />
            </div>
          </div>

          <div className="md:col-span-2 space-y-1.5">
            <label className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Porta
            </label>
            <input
              type="number"
              value={port}
              onChange={(e) => setPort(parseInt(e.target.value) || 443)}
              className="w-full px-3 py-2.5 rounded-xl bg-bg-primary border border-bg-border text-sm text-slate-200 focus:outline-none focus:border-purple-500 font-mono"
            />
          </div>

          <div className="md:col-span-3">
            <button
              onClick={handleScan}
              disabled={loading || !host}
              className="w-full py-2.5 px-4 rounded-xl font-bold text-sm bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-400 hover:to-indigo-500 text-slate-100 flex items-center justify-center gap-2 shadow-lg shadow-purple-500/20 disabled:opacity-50 transition-all cursor-pointer"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Inspecionando TLS...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Auditar Postura PQC</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-sm flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Result Display */}
      {scanResult && (
        <div className="space-y-6">
          <div className="border-b border-bg-border flex items-center justify-between">
            <div className="flex items-center gap-2">
              {[
                { id: 'audit', label: 'Auditoria de Handshake', icon: Shield },
                { id: 'cbom', label: 'CycloneDX 1.6 CBOM', icon: FileCode },
                { id: 'remediation', label: 'Plano de Agilidade PQC', icon: Zap },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={clsx(
                    'px-4 py-3 text-xs font-bold flex items-center gap-2 border-b-2 transition-all cursor-pointer',
                    activeTab === tab.id
                      ? 'border-purple-400 text-purple-300 bg-purple-500/10'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  )}
                >
                  <tab.icon className="w-4 h-4" />
                  <span>{tab.label}</span>
                </button>
              ))}
            </div>

            {scanResult.cbom && (
              <button
                onClick={handleDownloadCBOM}
                className="px-3 py-1.5 rounded-lg bg-bg-secondary border border-bg-border text-xs text-purple-300 hover:bg-bg-primary flex items-center gap-1.5 transition-all"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Exportar CBOM (JSON)</span>
              </button>
            )}
          </div>

          {activeTab === 'audit' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border space-y-4">
                <h3 className="text-sm font-bold text-slate-200">Parâmetros Criptográficos Extraídos</h3>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between py-1.5 border-b border-bg-border">
                    <span className="text-slate-400">Host Auditado</span>
                    <span className="font-mono text-slate-200">{scanResult.host}:{scanResult.port}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-bg-border">
                    <span className="text-slate-400">Versão TLS</span>
                    <span className="font-mono text-cyan-300">{scanResult.tls_version || 'TLSv1.3'}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-bg-border">
                    <span className="text-slate-400">Cipher Suite</span>
                    <span className="font-mono text-purple-300">{scanResult.cipher_suite}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-bg-border">
                    <span className="text-slate-400">Key Encapsulation (KEM)</span>
                    <span className="font-mono text-amber-300">{scanResult.key_exchange || 'ECDHE (X25519 Clássico)'}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-bg-border">
                    <span className="text-slate-400">Suporte PQC Híbrido</span>
                    <span className={clsx('font-bold', scanResult.pqc_supported ? 'text-emerald-400' : 'text-red-400')}>
                      {scanResult.pqc_supported ? 'SIM (Resistente a Shor)' : 'NÃO (Vulnerável HNDL)'}
                    </span>
                  </div>
                </div>
              </div>

              <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border space-y-4">
                <h3 className="text-sm font-bold text-slate-200">Classificação de Risco Quântico</h3>
                <div className={clsx(
                  'p-4 rounded-xl border space-y-2',
                  scanResult.risk_level === 'QUANTUM_RESISTANT' ? 'bg-emerald-500/10 border-emerald-500/30' :
                  scanResult.risk_level === 'HARVEST_NOW_DECRYPT' ? 'bg-amber-500/10 border-amber-500/30' :
                  'bg-red-500/10 border-red-500/30'
                )}>
                  <div className="text-xs font-black uppercase tracking-wider text-slate-200">
                    Nível: {scanResult.risk_level}
                  </div>
                  <p className="text-xs text-slate-300">
                    {scanResult.risk_level === 'QUANTUM_RESISTANT'
                      ? 'O endpoint utiliza algoritmos padronizados pelo NIST (FIPS 203) para troca de chaves.'
                      : 'Tráfego criptografado pode ser interceptado e armazenado hoje para descriptografia futura por computadores quânticos usando o Algoritmo de Shor.'}
                  </p>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'cbom' && (
            <div className="p-4 rounded-2xl bg-bg-primary border border-bg-border">
              <pre className="text-xs font-mono text-slate-300 overflow-x-auto max-h-96">
                {JSON.stringify(scanResult.cbom || {}, null, 2)}
              </pre>
            </div>
          )}

          {activeTab === 'remediation' && (
            <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border space-y-4">
              <h3 className="text-sm font-bold text-slate-200">Roteiro de Transição e Crypto-Agilidade</h3>
              <div className="space-y-3 text-xs">
                <div className="p-3.5 rounded-xl bg-bg-primary border border-bg-border flex items-start gap-3">
                  <div className="w-6 h-6 rounded-full bg-purple-500/20 text-purple-400 flex items-center justify-center font-bold flex-shrink-0">1</div>
                  <div>
                    <h4 className="font-bold text-slate-200">Habilitar KEM Híbrido no TLS 1.3</h4>
                    <p className="text-slate-400 mt-0.5">Configurar cipher suite híbrida `X25519+MLKEM768` em conformidade com o rascunho IETF.</p>
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-bg-primary border border-bg-border flex items-start gap-3">
                  <div className="w-6 h-6 rounded-full bg-purple-500/20 text-purple-400 flex items-center justify-center font-bold flex-shrink-0">2</div>
                  <div>
                    <h4 className="font-bold text-slate-200">Substituir Assinaturas RSA por ML-DSA (FIPS 204)</h4>
                    <p className="text-slate-400 mt-0.5">Emitir novos certificados digitais com suporte a chaves duplas (Dual-Cert).</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
