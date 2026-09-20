'use client';
import { useState } from 'react';
import { systemApi } from '@/lib/api';
import {
  Sparkles, Play, Loader2, CheckCircle2, AlertTriangle,
  X, Globe, Radio, Bug, Shield, Lock, CreditCard, ChevronRight,
  ExternalLink, Layers
} from 'lucide-react';
import clsx from 'clsx';
import Link from 'next/link';

interface UnifiedScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  defaultDomain?: string;
}

export default function UnifiedScanModal({ isOpen, onClose, defaultDomain = 'empresa.com.br' }: UnifiedScanModalProps) {
  const [domain, setDomain] = useState(defaultDomain);
  const [url, setUrl] = useState(`https://${defaultDomain}`);
  const [binPrefix, setBinPrefix] = useState('4532');
  const [brandName, setBrandName] = useState('Empresa');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleDomainChange = (val: string) => {
    const clean = val.replace('https://', '').replace('http://', '').split('/')[0];
    setDomain(clean);
    setUrl(`https://${clean}`);
    const name = clean.split('.')[0];
    if (name) setBrandName(name.charAt(0).toUpperCase() + name.slice(1));
  };

  const handleRun = async () => {
    if (!domain) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await systemApi.runUnifiedAll(domain, url, brandName, binPrefix);
      setResult(res);
    } catch (e: any) {
      setError(e.message || 'Erro ao executar scan unificado.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-3xl max-h-[90vh] flex flex-col bg-[#0d1117] border border-cyan-500/40 rounded-2xl shadow-2xl shadow-cyan-500/10 overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-white/10 bg-gradient-to-r from-cyan-950/40 via-blue-950/30 to-purple-950/20 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 text-cyan-400">
              <Sparkles className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h2 className="text-lg font-black text-white flex items-center gap-2">
                Scan Unificado Autônomo 360°
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  7 Motores Simultâneos
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Dispara orquestração automática em Pentest Web, EASM Dark Web, Aegis PQC, Brand Radar, Defesa de BIN e Forense.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-5">
          {!result && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-1.5">
                    Domínio Corporativo Alvo
                  </label>
                  <div className="relative">
                    <Globe className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={domain}
                      onChange={e => handleDomainChange(e.target.value)}
                      placeholder="empresa.com.br"
                      className="w-full pl-9 pr-3 py-2 rounded-xl bg-white/5 border border-white/10 text-sm text-white font-mono focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-1.5">
                    URL Principal da Aplicação
                  </label>
                  <input
                    type="text"
                    value={url}
                    onChange={e => setUrl(e.target.value)}
                    placeholder="https://empresa.com.br"
                    className="w-full px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-sm text-white font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-1.5">
                    Nome da Marca / Brand
                  </label>
                  <input
                    type="text"
                    value={brandName}
                    onChange={e => setBrandName(e.target.value)}
                    placeholder="Nome da Marca"
                    className="w-full px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-sm text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-1.5">
                    Prefixo BIN do Cartão (Anti-Fraude)
                  </label>
                  <div className="relative">
                    <CreditCard className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={binPrefix}
                      onChange={e => setBinPrefix(e.target.value)}
                      placeholder="ex: 4532 ou 5412"
                      maxLength={8}
                      className="w-full pl-9 pr-3 py-2 rounded-xl bg-white/5 border border-white/10 text-sm text-white font-mono focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>
              </div>

              {/* Engine Grid Checklist */}
              <div className="p-4 rounded-xl bg-white/3 border border-white/5 space-y-2">
                <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Motores que serão orquestrados em paralelo:</span>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-2 text-xs">
                  <div className="flex items-center gap-2 text-slate-300">
                    <Radio className="w-3.5 h-3.5 text-cyan-400" />
                    <span>EASM & Dark Web Leaks</span>
                  </div>
                  <div className="flex items-center gap-2 text-slate-300">
                    <Lock className="w-3.5 h-3.5 text-purple-400" />
                    <span>Aegis Post-Quantum & CBOM</span>
                  </div>
                  <div className="flex items-center gap-2 text-slate-300">
                    <Shield className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Brand Protection & Takedown</span>
                  </div>
                  <div className="flex items-center gap-2 text-slate-300">
                    <CreditCard className="w-3.5 h-3.5 text-amber-400" />
                    <span>BIN Monitor (Tor Circuit SOCKS5)</span>
                  </div>
                  <div className="flex items-center gap-2 text-slate-300">
                    <Bug className="w-3.5 h-3.5 text-red-400" />
                    <span>Pentest OWASP Engine</span>
                  </div>
                  <div className="flex items-center gap-2 text-slate-300">
                    <Layers className="w-3.5 h-3.5 text-blue-400" />
                    <span>Fiscal Forensic AI Benchmark</span>
                  </div>
                </div>
              </div>
            </>
          )}

          {error && (
            <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 flex-shrink-0 text-red-400" />
              <span>{error}</span>
            </div>
          )}

          {result && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                  <div>
                    <h3 className="text-sm font-bold text-emerald-300">Orquestração Concluída com Sucesso!</h3>
                    <p className="text-xs text-slate-400">
                      Todos os 7 motores ofensivos e defensivos processaram o alvo <strong className="text-white">{result.target_domain}</strong>.
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setResult(null)}
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-white/10 hover:bg-white/20 text-white"
                >
                  Novo Scan
                </button>
              </div>

              {/* Execution Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {result.easm && (
                  <div className="p-3.5 rounded-xl bg-white/3 border border-white/8 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-cyan-400 flex items-center gap-1.5">
                        <Radio className="w-3.5 h-3.5" /> EASM & Dark Web
                      </span>
                      <Link href="/easm" onClick={onClose} className="text-[11px] text-cyan-400 hover:underline flex items-center gap-0.5">
                        Ver detalhes <ChevronRight className="w-3 h-3" />
                      </Link>
                    </div>
                    <p className="text-xs text-slate-300">
                      Subdomínios: <strong>{result.easm.summary?.total_assets || 0}</strong> | Vazamentos Dark Web: <strong className="text-amber-400">{result.easm.summary?.dark_web_exposures || 0}</strong>
                    </p>
                  </div>
                )}

                {result.bin_darkweb_tor && (
                  <div className="p-3.5 rounded-xl bg-white/3 border border-white/8 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-amber-400 flex items-center gap-1.5">
                        <CreditCard className="w-3.5 h-3.5" /> BIN Leak Tor Hunter
                      </span>
                      <Link href="/boleto-validator" onClick={onClose} className="text-[11px] text-amber-400 hover:underline flex items-center gap-0.5">
                        Ver evidências <ChevronRight className="w-3 h-3" />
                      </Link>
                    </div>
                    <p className="text-xs text-slate-300">
                      Circuito Tor: <strong>{result.bin_darkweb_tor.tor_circuit?.status || 'Ativo'}</strong> | Dumps interceptados: <strong className="text-red-400">{result.bin_darkweb_tor.total_leaks_found || 0}</strong>
                    </p>
                  </div>
                )}

                {result.aegis_pqc && (
                  <div className="p-3.5 rounded-xl bg-white/3 border border-white/8 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-purple-400 flex items-center gap-1.5">
                        <Lock className="w-3.5 h-3.5" /> Aegis Post-Quantum
                      </span>
                      <Link href="/aegislattice" onClick={onClose} className="text-[11px] text-purple-400 hover:underline flex items-center gap-0.5">
                        Ver CBOM <ChevronRight className="w-3 h-3" />
                      </Link>
                    </div>
                    <p className="text-xs text-slate-300">
                      PQC Readiness: <strong>{result.aegis_pqc.pqc_readiness_score || 0}%</strong> | Status: <strong>{result.aegis_pqc.quantum_risk_level || 'EVALUATED'}</strong>
                    </p>
                  </div>
                )}

                {result.brand_protection && (
                  <div className="p-3.5 rounded-xl bg-white/3 border border-white/8 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                        <Shield className="w-3.5 h-3.5" /> Brand Protection Radar
                      </span>
                      <Link href="/brand-protection" onClick={onClose} className="text-[11px] text-emerald-400 hover:underline flex items-center gap-0.5">
                        Ver Takedowns <ChevronRight className="w-3 h-3" />
                      </Link>
                    </div>
                    <p className="text-xs text-slate-300">
                      Domínios suspeitos detectados: <strong className="text-amber-400">{result.brand_protection.alerts?.length || 0}</strong>
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-white/10 bg-white/2 flex items-center justify-between">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-bold text-slate-400 hover:text-white rounded-xl hover:bg-white/5 transition-colors"
          >
            Fechar
          </button>

          {!result && (
            <button
              onClick={handleRun}
              disabled={loading || !domain}
              className="px-5 py-2.5 rounded-xl font-bold text-xs bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 flex items-center gap-2 shadow-lg shadow-cyan-500/20 disabled:opacity-50 transition-all cursor-pointer"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Executando todos os 7 motores...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Executar Scan Unificado para Tudo</span>
                </>
              )}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
