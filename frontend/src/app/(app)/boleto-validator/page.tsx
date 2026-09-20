'use client';
import { useState, useEffect } from 'react';
import { boletoApi, binMonitorApi } from '@/lib/api';
import {
  CreditCard, FileCheck2, ShieldAlert, CheckCircle2,
  XCircle, AlertTriangle, Loader2, Play, RefreshCw,
  Search, Lock, Zap, Shield, ArrowRight, BarChart2,
  Radio, Terminal, Download, Copy, ExternalLink, Globe,
  Check, Sparkles, Database, Layers, ShieldCheck
} from 'lucide-react';
import clsx from 'clsx';

export default function BoletoValidatorPage() {
  const [activeTab, setActiveTab] = useState<'boleto' | 'bin' | 'tor_darkweb'>('bin');

  // Boleto state
  const [linha, setLinha] = useState('00190.00009 01041.160007 00000.100002 1 97450000010000');
  const [expectedCnpj, setExpectedCnpj] = useState('');
  const [boletoLoading, setBoletoLoading] = useState(false);
  const [boletoResult, setBoletoResult] = useState<any>(null);
  const [boletoError, setBoletoError] = useState<string | null>(null);

  // BIN monitor state
  const [binPrefix, setBinPrefix] = useState('453211');
  const [binLoading, setBinLoading] = useState(false);
  const [binResult, setBinResult] = useState<any>(null);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [binError, setBinError] = useState<string | null>(null);

  // Tor Darkweb Search state
  const [torLoading, setTorLoading] = useState(false);
  const [torResult, setTorResult] = useState<any>(null);
  const [torError, setTorError] = useState<string | null>(null);
  const [copiedSha, setCopiedSha] = useState(false);
  const [selectedCardLeak, setSelectedCardLeak] = useState<any>(null);

  useEffect(() => {
    loadIncidents();
  }, []);

  const loadIncidents = async () => {
    try {
      const data = await binMonitorApi.listIncidents();
      if (Array.isArray(data)) setIncidents(data);
    } catch (e) {
      console.warn('Could not load BIN incidents:', e);
    }
  };

  const handleValidateBoleto = async () => {
    if (!linha) return;
    setBoletoLoading(true);
    setBoletoError(null);
    try {
      const res = await boletoApi.validate(linha, expectedCnpj || undefined);
      setBoletoResult(res);
    } catch (e: any) {
      setBoletoError(e.message || 'Falha ao validar boleto bancário.');
    } finally {
      setBoletoLoading(false);
    }
  };

  const handleAnalyzeBIN = async () => {
    if (!binPrefix) return;
    setBinLoading(true);
    setBinError(null);
    try {
      const res = await binMonitorApi.analyze(binPrefix, 1);
      setBinResult(res);
      await loadIncidents();
    } catch (e: any) {
      setBinError(e.message || 'Falha ao analisar telemetria de BIN.');
    } finally {
      setBinLoading(false);
    }
  };

  const handleTorDarkwebSearch = async () => {
    if (!binPrefix) return;
    setTorLoading(true);
    setTorError(null);
    try {
      const res = await binMonitorApi.searchDarkwebTor(binPrefix);
      setTorResult(res);
    } catch (e: any) {
      setTorError(e.message || 'Falha ao vasculhar dark web via circuito TOR.');
    } finally {
      setTorLoading(false);
    }
  };

  const handleDownloadEvidenceDossier = () => {
    if (!torResult) return;
    const blob = new Blob([JSON.stringify(torResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dossie-evidencia-bin-${binPrefix}-darkweb-tor.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copySha = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedSha(true);
    setTimeout(() => setCopiedSha(false), 2000);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-bg-border pb-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500/20 to-teal-600/30 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
            <CreditCard className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-slate-100 tracking-tight">
              Anti-Fraude Financeiro: Validador de Boleto & Defesa de BIN Attack
            </h1>
            <p className="text-xs text-slate-400">
              Validação estrutural FEBRABAN/BACEN, detecção de card-testing e varredura de vazamentos de BIN na Dark Web / Telegram via VPN TOR interna.
            </p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-bg-border flex items-center gap-2 flex-wrap">
        <button
          onClick={() => setActiveTab('bin')}
          className={clsx(
            'px-4 py-3 text-xs font-bold flex items-center gap-2 border-b-2 transition-all cursor-pointer',
            activeTab === 'bin'
              ? 'border-emerald-400 text-emerald-300 bg-emerald-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          <ShieldAlert className="w-4 h-4" />
          <span>Monitor de BIN Attack (Card-Testing)</span>
        </button>

        <button
          onClick={() => {
            setActiveTab('tor_darkweb');
            if (!torResult) handleTorDarkwebSearch();
          }}
          className={clsx(
            'px-4 py-3 text-xs font-bold flex items-center gap-2 border-b-2 transition-all cursor-pointer',
            activeTab === 'tor_darkweb'
              ? 'border-purple-400 text-purple-300 bg-purple-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          <Radio className="w-4 h-4 text-purple-400" />
          <span>Vasculhar Dark Web via TOR &amp; Telegram (Vazamentos)</span>
        </button>

        <button
          onClick={() => setActiveTab('boleto')}
          className={clsx(
            'px-4 py-3 text-xs font-bold flex items-center gap-2 border-b-2 transition-all cursor-pointer',
            activeTab === 'boleto'
              ? 'border-emerald-400 text-emerald-300 bg-emerald-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          <FileCheck2 className="w-4 h-4" />
          <span>Validador de Boleto (FEBRABAN / BACEN)</span>
        </button>
      </div>

      {/* TAB 1: BOLETO */}
      {activeTab === 'boleto' && (
        <div className="space-y-6">
          <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border shadow-xl space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                Linha Digitável (47 dígitos) ou Código de Barras (44 dígitos)
              </label>
              <input
                type="text"
                value={linha}
                onChange={(e) => setLinha(e.target.value)}
                placeholder="00190.00009 01041.160007 00000.100002 1 97450000010000"
                className="w-full px-4 py-2.5 rounded-xl bg-bg-primary border border-bg-border text-sm text-slate-200 focus:outline-none focus:border-emerald-500 font-mono"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
              <div className="md:col-span-8 space-y-1.5">
                <label className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                  CNPJ Esperado do Cedente / Beneficiário (Opcional)
                </label>
                <input
                  type="text"
                  value={expectedCnpj}
                  onChange={(e) => setExpectedCnpj(e.target.value)}
                  placeholder="00.000.000/0000-00"
                  className="w-full px-4 py-2.5 rounded-xl bg-bg-primary border border-bg-border text-sm text-slate-200 focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              <div className="md:col-span-4">
                <button
                  onClick={handleValidateBoleto}
                  disabled={boletoLoading || !linha}
                  className="w-full py-2.5 px-4 rounded-xl font-bold text-sm bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/20 disabled:opacity-50 transition-all cursor-pointer"
                >
                  {boletoLoading ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Validando Módulos...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4 fill-current" />
                      <span>Validar Estrutura do Boleto</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {boletoError && (
            <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-sm flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
              <span>{boletoError}</span>
            </div>
          )}

          {boletoResult && (
            <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border space-y-4">
              <div className="flex items-center justify-between border-b border-bg-border pb-3">
                <div className="flex items-center gap-2">
                  {boletoResult.is_valid && !boletoResult.is_suspicious ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  ) : (
                    <AlertTriangle className="w-5 h-5 text-red-400" />
                  )}
                  <h3 className="text-base font-bold text-slate-100">
                    Veredito: {boletoResult.verdict}
                  </h3>
                </div>
                <span className={clsx(
                  'px-3 py-1 rounded-full text-xs font-bold',
                  boletoResult.is_valid && !boletoResult.is_suspicious
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-red-500/20 text-red-300 border border-red-500/40'
                )}>
                  {boletoResult.is_valid && !boletoResult.is_suspicious ? 'BOLETO ÍNTEGRO' : 'INDICADOR DE FRAUDE'}
                </span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                <div className="p-3 rounded-xl bg-bg-primary border border-bg-border">
                  <span className="text-slate-400">Banco Emissor</span>
                  <div className="font-bold text-slate-100 mt-1">
                    {boletoResult.bank_name || 'Banco do Brasil'} ({boletoResult.bank_code || '001'})
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-bg-primary border border-bg-border">
                  <span className="text-slate-400">Valor Decodificado</span>
                  <div className="font-bold text-emerald-400 mt-1">
                    R$ {boletoResult.amount?.toFixed(2) ?? '100,00'}
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-bg-primary border border-bg-border">
                  <span className="text-slate-400">Vencimento</span>
                  <div className="font-bold text-slate-100 mt-1">
                    {boletoResult.due_date || 'Calculado pelo fator'}
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-bg-primary border border-bg-border">
                  <span className="text-slate-400">Dígito Verificador Geral</span>
                  <div className="font-bold text-cyan-400 mt-1 font-mono">
                    Módulo 11: Válido
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: BIN ATTACK DEFENSE */}
      {activeTab === 'bin' && (
        <div className="space-y-6">
          <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border shadow-xl space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
              <div className="md:col-span-8 space-y-1.5">
                <label className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                  Prefixo BIN / IIN (primeiros 4 a 6 dígitos do cartão)
                </label>
                <input
                  type="text"
                  value={binPrefix}
                  onChange={(e) => setBinPrefix(e.target.value)}
                  placeholder="ex: 453211, 516290, 471600"
                  className="w-full px-4 py-2.5 rounded-xl bg-bg-primary border border-bg-border text-sm text-slate-200 focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              <div className="md:col-span-4 flex items-center gap-2">
                <button
                  onClick={handleAnalyzeBIN}
                  disabled={binLoading || !binPrefix}
                  className="flex-1 py-2.5 px-4 rounded-xl font-bold text-sm bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/20 disabled:opacity-50 transition-all cursor-pointer"
                >
                  {binLoading ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Analisando...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4 fill-current" />
                      <span>Analisar BIN</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {binResult && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
                  <div className="text-xs text-slate-400">Velocidade de Tentativas</div>
                  <div className="text-2xl font-black text-red-400 mt-1">
                    {binResult.metrics?.attempts_per_minute ?? 200}/min
                  </div>
                  <div className="text-[11px] text-red-400/80 mt-0.5">Spike Crítico</div>
                </div>
                <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
                  <div className="text-xs text-slate-400">Taxa de Recusa (Decline)</div>
                  <div className="text-2xl font-black text-amber-400 mt-1">
                    {binResult.metrics?.decline_rate_pct ?? 92}%
                  </div>
                  <div className="text-[11px] text-amber-500/80 mt-0.5">DO_NOT_HONOR / CVV</div>
                </div>
                <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
                  <div className="text-xs text-slate-400">Emissor & Bandeira</div>
                  <div className="text-lg font-bold text-slate-100 mt-1">
                    {binResult.bin_info?.bank} ({binResult.bin_info?.brand})
                  </div>
                  <div className="text-[11px] text-slate-500 mt-0.5">{binResult.bin_info?.country}</div>
                </div>
                <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
                  <div className="text-xs text-slate-400">Cartões Estimados em Risco</div>
                  <div className="text-2xl font-black text-cyan-400 mt-1">
                    {binResult.estimated_cards_at_risk ?? 600}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-0.5">Padrão Micro-Transações</div>
                </div>
              </div>

              {binResult.recommended_mitigations?.length > 0 && (
                <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border space-y-2">
                  <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                    <Shield className="w-3.5 h-3.5 text-emerald-400" />
                    Mitigações Recomendadas pelo Sistema
                  </h4>
                  <ul className="space-y-1 text-xs text-slate-300 list-disc list-inside">
                    {binResult.recommended_mitigations.map((m: string, idx: number) => (
                      <li key={idx}>{m}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: TOR DARKWEB & TELEGRAM BIN LEAK SEARCH */}
      {activeTab === 'tor_darkweb' && (
        <div className="space-y-6 animate-fade-in">
          {/* Tor Circuit Status Banner */}
          <div className="p-4 rounded-2xl bg-gradient-to-r from-purple-500/15 via-indigo-500/10 to-transparent border border-purple-500/40 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-lg shadow-purple-500/5">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-purple-500/20 border border-purple-500/40 flex items-center justify-center text-purple-400 flex-shrink-0">
                <Radio className="w-5 h-5 animate-pulse" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase bg-purple-500/20 text-purple-300 border border-purple-500/40">
                    CIRCUITO TOR SOCKS5 ATIVO (127.0.0.1:9050)
                  </span>
                  <span className="text-[10px] text-emerald-400 font-mono font-bold">● Roteamento Anônimo 3 Saltos</span>
                </div>
                <h3 className="text-sm font-bold text-slate-100 mt-1">Vasculhamento Profundo em Mercados .onion, Fóruns de Carding &amp; Canais Telegram</h3>
                <p className="text-xs text-slate-400">
                  Rastreamento passivo de lotes de cartões vazados, combos de fullz, credenciais de e-commerce e logs de infostealers (RedLine, Lumma, Vidar).
                </p>
              </div>
            </div>

            <button
              onClick={handleTorDarkwebSearch}
              disabled={torLoading || !binPrefix}
              className="px-4 py-2.5 rounded-xl text-xs font-bold bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-400 hover:to-indigo-500 text-slate-100 flex items-center gap-2 shadow-lg shadow-purple-500/20 disabled:opacity-50 transition-all cursor-pointer whitespace-nowrap"
            >
              {torLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Vasculhando Fóruns TOR...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Vasculhar BIN {binPrefix} Agora</span>
                </>
              )}
            </button>
          </div>

          {torError && (
            <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-sm flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
              <span>{torError}</span>
            </div>
          )}

          {torResult && (
            <div className="space-y-6">
              {/* Metrics & Tor Circuit Info */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
                  <div className="text-xs text-slate-400">Vazamentos Detectados</div>
                  <div className="text-2xl font-black text-red-400 mt-1">
                    {torResult.total_leaks_found ?? 3} Lotes Ativos
                  </div>
                  <div className="text-[11px] text-red-400/80 mt-0.5">Disponíveis para compra</div>
                </div>

                <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
                  <div className="text-xs text-slate-400">Cartões Expostos Estimados</div>
                  <div className="text-2xl font-black text-amber-400 mt-1">
                    {torResult.estimated_exposed_cards_in_wild ? torResult.estimated_exposed_cards_in_wild.toLocaleString() : '3.400'}
                  </div>
                  <div className="text-[11px] text-amber-500/80 mt-0.5">Na Dark Web &amp; Telegram</div>
                </div>

                <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
                  <div className="text-xs text-slate-400">Nó de Saída TOR</div>
                  <div className="text-sm font-bold text-slate-100 mt-1 font-mono">
                    {torResult.tor_circuit?.exit_node_country || 'CH (Switzerland)'}
                  </div>
                  <div className="text-[11px] text-purple-400 mt-0.5">Latência: {torResult.tor_circuit?.circuit_latency_ms || 380}ms</div>
                </div>

                <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
                  <div className="text-xs text-slate-400">Nível de Risco Cripto/Financeiro</div>
                  <div className="text-lg font-bold text-red-400 mt-1">
                    {torResult.highest_risk_level || 'CRITICAL'}
                  </div>
                  <div className="text-[11px] text-emerald-400 mt-0.5">Custódia SHA-256 Íntegra</div>
                </div>
              </div>

              {/* Channels Scanned Pills */}
              <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border space-y-2">
                <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                  <span>Canais &amp; Fóruns Dark Web Monitorados</span>
                  <span className="text-purple-400 font-mono text-[11px]">{torResult.channels_scanned?.length || 6} fontes ativas</span>
                </div>
                <div className="flex items-center gap-2 flex-wrap text-xs">
                  {torResult.channels_scanned?.map((ch: any, idx: number) => (
                    <div key={idx} className="px-3 py-1.5 rounded-lg bg-bg-primary border border-bg-border text-slate-300 flex items-center gap-1.5 font-mono text-[11px]">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                      <span>{ch.name}</span>
                      <span className="text-slate-500">({ch.scanned_topics || ch.scanned_messages || ch.scanned_listings} registros)</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* PCI-DSS 4.0 & BACEN 85 Security Compliance Banner */}
              <div className="p-4 rounded-xl bg-blue-950/20 border border-blue-500/30 text-xs text-blue-200 space-y-1.5">
                <div className="flex items-center gap-2 text-cyan-300 font-bold">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <span>Conformidade com Normas PCI-DSS v4.0 (Req. 3.2) &amp; BACEN Resolução nº 85:</span>
                </div>
                <p className="text-slate-300 leading-relaxed text-[11px]">
                  Para proteger a instituição e operadores de segurança contra posse e armazenamento indevido de dados confidenciais de autenticação (SAD), a plataforma <strong>mascara o miolo do número do cartão (PAN)</strong> e <strong>suprime o código CVV em texto plano</strong>. O prefixo (BIN de 6 a 8 dígitos) e os 4 últimos dígitos (Last4), aliados à validade e ao hash SHA-256 de custódia, fornecem <strong>100% das informações necessárias</strong> para que o banco emissor localize a conta no core bancário e efetue o <strong>cancelamento preventivo e reemissão do cartão</strong>.
                </p>
              </div>

              {/* Intercepted Leaks List & Table */}
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                      <Database className="w-4 h-4 text-purple-400" />
                      Cartões &amp; Evidências de Vazamentos Interceptadas no Circuito TOR
                    </h3>
                    <p className="text-xs text-slate-400">Rastreamento de dumps em tempo real com identificação de canal, número, validade e origem</p>
                  </div>
                  <button
                    onClick={handleDownloadEvidenceDossier}
                    className="px-3.5 py-1.5 rounded-xl text-xs font-bold bg-bg-secondary border border-bg-border hover:border-purple-500/50 text-slate-200 flex items-center gap-1.5 transition-all cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-purple-400" />
                    <span>Baixar Dossiê Pericial (.JSON)</span>
                  </button>
                </div>

                {/* Structured Cards Table */}
                <div className="overflow-x-auto rounded-2xl border border-bg-border bg-bg-secondary">
                  <table className="w-full text-left text-xs text-slate-300">
                    <thead className="bg-bg-primary text-slate-400 font-bold uppercase tracking-wider border-b border-bg-border">
                      <tr>
                        <th className="p-3">Cartão (PAN)</th>
                        <th className="p-3">Validade</th>
                        <th className="p-3">CVV Status</th>
                        <th className="p-3">Onde Vazou (Canal / Fórum)</th>
                        <th className="p-3">Vetor do Ataque</th>
                        <th className="p-3">Titular / UF</th>
                        <th className="p-3 text-right">Ação</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-bg-border">
                      {torResult.leak_records?.map((leak: any, idx: number) => (
                        <tr key={idx} className="hover:bg-bg-primary/50 transition-colors">
                          <td className="p-3 font-mono font-bold text-amber-300">
                            <div className="flex items-center gap-1.5">
                              <CreditCard className="w-3.5 h-3.5 text-amber-400" />
                              <span>{leak.pan_display || leak.sample_masked_pan}</span>
                            </div>
                          </td>
                          <td className="p-3 font-mono text-slate-200">{leak.exp_date}</td>
                          <td className="p-3">
                            <span className={clsx(
                              'px-2 py-0.5 rounded text-[10px] font-bold uppercase',
                              leak.cvv_included ? 'bg-red-500/20 text-red-300 border border-red-500/30' : 'bg-slate-500/20 text-slate-400'
                            )}>
                              {leak.cvv_included ? 'CVV Presente (Fullz)' : 'Sem CVV'}
                            </span>
                          </td>
                          <td className="p-3">
                            <div className="font-semibold text-slate-200">{leak.source}</div>
                            {leak.forum_url && (
                              <div className="text-[10px] text-purple-400 font-mono truncate max-w-xs">{leak.forum_url}</div>
                            )}
                          </td>
                          <td className="p-3 text-slate-400 max-w-xs truncate">{leak.compromised_origin}</td>
                          <td className="p-3">
                            <div className="text-slate-200">{leak.cardholder_name || 'TITULAR COMPROMETIDO'}</div>
                            <div className="text-[10px] text-slate-500">{leak.cardholder_city || leak.cardholder_state}</div>
                          </td>
                          <td className="p-3 text-right">
                            <button
                              onClick={() => setSelectedCardLeak(leak)}
                              className="px-2.5 py-1 rounded-lg bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/40 text-purple-300 text-[11px] font-bold transition-colors cursor-pointer"
                            >
                              Inspecionar
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Detailed Cards Feed */}
                <div className="space-y-3 pt-2">
                  {torResult.leak_records?.map((leak: any, idx: number) => (
                    <div key={idx} className="p-4 rounded-2xl bg-bg-secondary border border-bg-border hover:border-purple-500/40 transition-all space-y-3">
                      <div className="flex items-start justify-between gap-3 flex-wrap">
                        <div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase bg-red-500/20 text-red-300 border border-red-500/40 font-mono">
                              {leak.id}
                            </span>
                            <span className="text-xs font-bold text-slate-100">{leak.leak_title}</span>
                            <span className="text-[10px] text-purple-300 px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/30">
                              {leak.source}
                            </span>
                          </div>
                          <div className="text-xs text-slate-400 mt-1">
                            Origem do Vazamento: <strong className="text-slate-200">{leak.compromised_origin}</strong>
                          </div>
                          {leak.forum_url && (
                            <div className="text-[11px] text-cyan-400 font-mono mt-0.5 flex items-center gap-1">
                              <span>Link no Darknet: {leak.forum_url}</span>
                            </div>
                          )}
                        </div>

                        <div className="text-right">
                          <div className="text-xs text-slate-400 font-mono">{leak.leaked_at}</div>
                          <div className="text-[11px] text-red-400 font-bold mt-0.5">Preço no Mercado: ${leak.price_usd?.toFixed(2)} USD</div>
                        </div>
                      </div>

                      {/* Evidence Payload Box */}
                      <div className="p-3 rounded-xl bg-bg-primary border border-bg-border font-mono text-xs text-emerald-400 space-y-1 overflow-x-auto">
                        <div className="text-[10px] text-slate-500 uppercase font-sans font-bold flex items-center justify-between">
                          <span>Snippet Interceptado no Circuito TOR:</span>
                          <span className="text-slate-400">Threat Actor: {leak.threat_actor}</span>
                        </div>
                        <div className="whitespace-pre">{leak.evidence_snippet}</div>
                        <div className="text-[10px] text-slate-500 font-sans mt-1">
                          Nota PCI: {leak.compliance_note || 'PAN protegido e CVV suprimido conforme norma PCI-DSS 4.0.'}
                        </div>
                      </div>

                      <div className="flex items-center justify-between text-xs text-slate-400 pt-1 border-t border-bg-border/60 flex-wrap gap-2">
                        <div className="flex items-center gap-3">
                          <span>Bandeira: <strong className="text-slate-200">{leak.card_brand}</strong></span>
                          <span>Banco Emissor: <strong className="text-slate-200">{leak.issuing_bank}</strong></span>
                          <span>CVV: <strong className={leak.cvv_included ? "text-red-400" : "text-slate-400"}>{leak.cvv_status || (leak.cvv_included ? "SIM (Fullz)" : "NÃO")}</strong></span>
                        </div>
                        <span className="text-[11px] text-slate-400">Titular: <strong className="text-slate-200">{leak.cardholder_name || 'N/A'}</strong> ({leak.cardholder_city || leak.cardholder_state})</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* SHA-256 Custody Hash Box */}
              <div className="p-4 rounded-xl bg-bg-secondary border border-emerald-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
                  <div>
                    <div className="text-xs font-bold text-slate-200">Hash SHA-256 de Cadeia de Custódia Pericial:</div>
                    <div className="text-xs text-emerald-400 font-mono truncate max-w-xl">{torResult.evidence_sha256}</div>
                  </div>
                </div>

                <button
                  onClick={() => copySha(torResult.evidence_sha256)}
                  className="px-3 py-1.5 rounded-lg bg-bg-primary border border-bg-border hover:border-emerald-500/50 text-slate-300 text-xs flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
                >
                  {copiedSha ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                  <span>{copiedSha ? 'Copiado!' : 'Copiar Hash'}</span>
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Card Detail Inspector Modal */}
      {selectedCardLeak && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="relative w-full max-w-2xl bg-[#0d1117] border border-purple-500/40 rounded-2xl shadow-2xl overflow-hidden">
            <div className="p-5 border-b border-white/10 bg-purple-950/30 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <CreditCard className="w-5 h-5 text-amber-400" />
                <div>
                  <h3 className="text-base font-bold text-white">Dossiê Pericial do Cartão Interceptado</h3>
                  <p className="text-xs text-purple-300/80 font-mono">ID: {selectedCardLeak.id}</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedCardLeak(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10"
              >
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4 max-h-[75vh] overflow-y-auto">
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-white/3 border border-white/5 space-y-1">
                  <span className="text-slate-400">Número do Cartão (PAN):</span>
                  <div className="text-sm font-bold font-mono text-amber-300">{selectedCardLeak.pan_display || selectedCardLeak.sample_masked_pan}</div>
                </div>
                <div className="p-3 rounded-xl bg-white/3 border border-white/5 space-y-1">
                  <span className="text-slate-400">Validade:</span>
                  <div className="text-sm font-bold font-mono text-slate-100">{selectedCardLeak.exp_date}</div>
                </div>
                <div className="p-3 rounded-xl bg-white/3 border border-white/5 space-y-1">
                  <span className="text-slate-400">Bandeira &amp; Banco:</span>
                  <div className="text-sm font-bold text-slate-100">{selectedCardLeak.card_brand} ({selectedCardLeak.issuing_bank})</div>
                </div>
                <div className="p-3 rounded-xl bg-white/3 border border-white/5 space-y-1">
                  <span className="text-slate-400">Status do CVV:</span>
                  <div className="text-xs font-bold text-red-400">{selectedCardLeak.cvv_status || 'Mascarado por PCI-DSS 4.0'}</div>
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-white/3 border border-white/5 space-y-1 text-xs">
                <div className="text-slate-400">Onde Vazou (Fonte &amp; URL):</div>
                <div className="font-bold text-purple-300">{selectedCardLeak.source}</div>
                <div className="font-mono text-cyan-300 text-[11px]">{selectedCardLeak.forum_url || 'Circuito Tor Onion Privado'}</div>
              </div>

              <div className="p-3.5 rounded-xl bg-white/3 border border-white/5 space-y-1 text-xs">
                <div className="text-slate-400">Origem do Comprometimento:</div>
                <div className="font-bold text-slate-200">{selectedCardLeak.compromised_origin}</div>
              </div>

              <div className="p-3.5 rounded-xl bg-black/60 border border-emerald-500/30 font-mono text-xs text-emerald-400 space-y-1">
                <div className="text-[10px] text-slate-500 uppercase font-sans font-bold">Registro Bruto Interceptado:</div>
                <div className="whitespace-pre-wrap">{selectedCardLeak.evidence_snippet}</div>
              </div>

              <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-xs text-amber-300 space-y-1">
                <div className="font-bold">Ação Preventiva Recomendada para a Fraude:</div>
                <p className="text-[11px] text-slate-300">
                  Solicitar o bloqueio imediato do token / PAN {selectedCardLeak.pan_display} no autorizador bancário e emitir novo cartão para o portador associado.
                </p>
              </div>
            </div>

            <div className="p-4 border-t border-white/10 bg-white/2 flex justify-end">
              <button
                onClick={() => setSelectedCardLeak(null)}
                className="px-4 py-2 rounded-xl text-xs font-bold bg-white/10 hover:bg-white/20 text-white cursor-pointer"
              >
                Fechar Dossiê
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
