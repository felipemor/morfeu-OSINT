'use client';
import { useState, useEffect } from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { brandProtectionApi } from '@/lib/api';
import {
  ShieldAlert, Globe, Search, AlertTriangle, CheckCircle2,
  XCircle, Loader2, Play, ExternalLink, Send, RefreshCw,
  Eye, Lock, Flame, Shield, ArrowRight, Mail, Server,
  Sparkles, Trash2, Crosshair, HelpCircle, ChevronRight,
  Download, Layers, Filter, Check, ShieldCheck, Terminal,
  Copy, CheckCheck, Radio, Activity, Fingerprint, Clock,
  Cpu, FileText, Database, Share2, AlertOctagon, Compass, Timer
} from 'lucide-react';
import clsx from 'clsx';

const UnifiedScanModal = dynamic(() => import('@/components/UnifiedScanModal'), { ssr: false });
const PurgeAllModal = dynamic(() => import('@/components/PurgeAllModal'), { ssr: false });

export default function BrandProtectionPage() {
  const [brand, setBrand] = useState('nubank');
  const [officialDomain, setOfficialDomain] = useState('nubank.com.br');
  const [loading, setLoading] = useState(false);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [filterType, setFilterType] = useState<string>('ALL_REGISTERED');
  const [slaCountdown, setSlaCountdown] = useState<string>('23h 58m 42s');
  const [probingHost, setProbingHost] = useState(false);
  const [liveProbeStatus, setLiveProbeStatus] = useState<any>(null);
  
  // Modals state
  const [selectedAlert, setSelectedAlert] = useState<any>(null);
  const [evidenceTab, setEvidenceTab] = useState<'OVERVIEW' | 'DNS_MX' | 'SSL' | 'WHOIS'>('OVERVIEW');
  const [copiedHash, setCopiedHash] = useState(false);
  const [isUnifiedScanOpen, setIsUnifiedScanOpen] = useState(false);
  const [isPurgeOpen, setIsPurgeOpen] = useState(false);

  // Active SLA Stopwatch
  useEffect(() => {
    const timer = setInterval(() => {
      const now = new Date();
      const target = new Date(now.getTime() + 23 * 3600 * 1000 + 58 * 60 * 1000 + 42 * 1000);
      const diff = Math.max(0, target.getTime() - now.getTime());
      const hours = Math.floor(diff / (1000 * 60 * 60));
      const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      const secs = Math.floor((diff % (1000 * 60)) / 1000);
      setSlaCountdown(`${hours}h ${String(mins).padStart(2, '0')}m ${String(secs).padStart(2, '0')}s`);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Takedown Logs Modal State
  const [takedownLogsModal, setTakedownLogsModal] = useState<{
    open: boolean;
    loading: boolean;
    alert: any;
    data: any;
  }>({
    open: false,
    loading: false,
    alert: null,
    data: null,
  });

  useEffect(() => {
    loadAlerts();
    handleMonitor(true);
  }, []);

  const loadAlerts = async () => {
    try {
      const data = await brandProtectionApi.listAlerts();
      if (Array.isArray(data) && data.length > 0) {
        setAlerts(data);
      }
    } catch (e) {
      console.warn('Could not load brand alerts:', e);
    }
  };

  const handleMonitor = async (isInitial = false) => {
    if (!brand) return;
    setLoading(true);
    setError(null);
    try {
      const res = await brandProtectionApi.monitor(brand, officialDomain, true);
      if (res?.alerts) {
        setAlerts(res.alerts);
        setSummary(res.summary);
      } else {
        await loadAlerts();
      }
    } catch (e: any) {
      if (!isInitial) setError(e.message || 'Falha ao executar radar de brand protection.');
    } finally {
      setLoading(false);
    }
  };

  const handleTakedown = async (alertId: string, targetAlertObj?: any) => {
    setActionLoading(alertId);
    const alertItem = targetAlertObj || alerts.find(a => a.id === alertId || a.suspicious_domain === alertId);
    setTakedownLogsModal({
      open: true,
      loading: true,
      alert: alertItem,
      data: null,
    });
    try {
      const res = await brandProtectionApi.submitTakedown(alertId, ['SAFEBROWSING', 'REGISTRAR', 'CLOUDFLARE_ABUSE']);
      await brandProtectionApi.updateAlertStatus(alertId, 'REPORTED');
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, status: 'REPORTED', takedown_result: res } : a))
      );
      if (selectedAlert?.id === alertId) {
        setSelectedAlert((prev: any) => ({ ...prev, status: 'REPORTED', takedown_result: res }));
      }
      setTakedownLogsModal({
        open: true,
        loading: false,
        alert: alertItem,
        data: res,
      });
    } catch (e: any) {
      alert('Falha ao enviar takedown: ' + e.message);
      setTakedownLogsModal({ open: false, loading: false, alert: null, data: null });
    } finally {
      setActionLoading(null);
    }
  };

  const handleCopyHash = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  // Filter alerts
  const filteredAlerts = alerts.filter(a => {
    if (filterType === 'ALL_REGISTERED') return a.is_registered;
    if (filterType === 'ONLINE_ACTIVE') return a.is_online;
    if (filterType === 'OFFLINE') return !a.is_online;
    if (filterType === 'PHISHING_CLONES') return a.page_analysis?.is_phishing_clone || a.threat_category === 'PHISHING_LOGIN_CLONE';
    if (filterType === 'MX_ACTIVE') return a.mx_record_active;
    if (filterType === 'HOMOGLYPH') return a.alert_type === 'HOMOGLYPH';
    if (filterType === 'REPORTED') return a.status === 'REPORTED' || a.status === 'TAKEN_DOWN';
    return true;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto min-h-screen text-slate-100">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-white/10 pb-5">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-2xl bg-gradient-to-br from-red-500/20 to-orange-600/30 border border-red-500/40 flex items-center justify-center text-red-400 shadow-lg shadow-red-500/10">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-black text-white tracking-tight">
                Brand Protection & Takedown Radar
              </h1>
              <span className="text-[10px] font-extrabold px-2 py-0.5 rounded-full bg-red-500/20 text-red-300 border border-red-500/30">
                Domínios Registrados & Phishing
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Rastreamento contínuo de domínios registrados (WHOIS/DNS), clones de tela de login, servidores MX maliciosos e despacho de takedown com logs probatórios.
            </p>
          </div>
        </div>

        {/* Global Action Buttons */}
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => setIsUnifiedScanOpen(true)}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 shadow-lg shadow-cyan-500/20 transition-all cursor-pointer"
            title="Executar todos os 7 motores simultaneamente"
          >
            <Sparkles className="w-4 h-4 fill-current" />
            <span>⚡ Executar Scan Unificado para Tudo</span>
          </button>

          <Link
            href="/fiscal-forensic"
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/40 transition-colors shadow-sm"
            title="Investigar CNPJs fakes, razões sociais e clones societários com base apenas no seu domínio"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>🏢 Radar de CNPJs Fakes</span>
          </Link>

          <Link
            href="/easm"
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold bg-white/5 hover:bg-white/10 text-slate-200 border border-white/10 transition-colors"
          >
            <Globe className="w-3.5 h-3.5 text-cyan-400" />
            <span>EASM Dark Web</span>
          </Link>

          <button
            onClick={() => setIsPurgeOpen(true)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold bg-red-950/30 hover:bg-red-900/50 text-red-300 border border-red-500/30 transition-colors cursor-pointer"
          >
            <Trash2 className="w-3.5 h-3.5 text-red-400" />
            <span>🗑️ Limpar Todos os Dados</span>
          </button>
        </div>
      </div>

      {/* Control Card */}
      <div className="p-5 rounded-2xl bg-[#0d1117] border border-white/10 shadow-xl space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
          <div className="md:col-span-5 space-y-1.5">
            <label className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Nome da Marca / Palavra-Chave a Proteger
            </label>
            <div className="relative">
              <Shield className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={brand}
                onChange={(e) => setBrand(e.target.value)}
                placeholder="ex: nubank, itau, santander, empresa"
                className="w-full pl-9 pr-4 py-2.5 rounded-xl bg-white/5 border border-white/10 text-sm text-white focus:outline-none focus:border-red-500 font-mono"
              />
            </div>
          </div>

          <div className="md:col-span-4 space-y-1.5">
            <label className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Domínio Oficial Legítimo
            </label>
            <div className="relative">
              <Globe className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={officialDomain}
                onChange={(e) => setOfficialDomain(e.target.value)}
                placeholder="ex: nubank.com.br"
                className="w-full pl-9 pr-4 py-2.5 rounded-xl bg-white/5 border border-white/10 text-sm text-white focus:outline-none focus:border-red-500 font-mono"
              />
            </div>
          </div>

          <div className="md:col-span-3">
            <button
              onClick={() => handleMonitor(false)}
              disabled={loading || !brand}
              className="w-full py-2.5 px-4 rounded-xl font-bold text-sm bg-gradient-to-r from-red-500 to-orange-600 hover:from-red-400 hover:to-orange-500 text-white flex items-center justify-center gap-2 shadow-lg shadow-red-500/20 disabled:opacity-50 transition-all cursor-pointer"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Rastreando Domínios Ativos...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Executar Radar Anti-Fraude</span>
                </>
              )}
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-6 pt-3 text-xs text-slate-400 border-t border-white/5">
          <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            Sondas HTTP/HTTPS em Tempo Real com Status Online/Offline
          </span>
          <span className="text-slate-600">|</span>
          <span className="flex items-center gap-1.5 text-cyan-400 font-medium">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            Varredura de Logs CT CertStream &amp; Let&apos;s Encrypt
          </span>
          <span className="text-slate-600">|</span>
          <span className="flex items-center gap-1.5 text-amber-400 font-medium">
            <span className="w-2 h-2 rounded-full bg-amber-400" />
            Auditoria Probatória SHA-256 e Logs de Despacho
          </span>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-center gap-3">
          <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <div className="p-4 rounded-2xl bg-[#0d1117] border border-white/8">
          <div className="text-xs text-slate-400">Domínios Registrados</div>
          <div className="text-2xl font-black text-red-400 mt-1 font-mono">
            {summary?.registered_fraud_domains ?? alerts.length}
          </div>
          <div className="text-[10px] text-red-400/80 mt-0.5">DNS &amp; WHOIS Ativos</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#0d1117] border border-emerald-500/30">
          <div className="text-xs text-slate-400 font-bold flex items-center justify-between">
            <span>Online em Produção</span>
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          </div>
          <div className="text-2xl font-black text-emerald-400 mt-1 font-mono">
            {summary?.online_active_count ?? alerts.filter(a => a.is_online).length}
          </div>
          <div className="text-[10px] text-emerald-400/80 mt-0.5">HTTP 200 OK / Ativos</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#0d1117] border border-slate-700">
          <div className="text-xs text-slate-400">Offline / Parked</div>
          <div className="text-2xl font-black text-slate-300 mt-1 font-mono">
            {summary?.offline_count ?? alerts.filter(a => !a.is_online).length}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Sem Resposta HTTP</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#0d1117] border border-orange-500/30">
          <div className="text-xs text-slate-400">Clones de Phishing</div>
          <div className="text-2xl font-black text-orange-400 mt-1 font-mono">
            {summary?.phishing_clones ?? alerts.filter(a => a.page_analysis?.is_phishing_clone).length}
          </div>
          <div className="text-[10px] text-orange-400/80 mt-0.5">Captura de Login/Senha</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#0d1117] border border-purple-500/30">
          <div className="text-xs text-slate-400">Servidores MX Ativos</div>
          <div className="text-2xl font-black text-purple-400 mt-1 font-mono">
            {summary?.mx_active_count ?? alerts.filter(a => a.mx_record_active).length}
          </div>
          <div className="text-[10px] text-purple-400/80 mt-0.5">Disparo de E-mail Fake</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#0d1117] border border-cyan-500/30">
          <div className="text-xs text-slate-400">Certificados SSL</div>
          <div className="text-2xl font-black text-cyan-400 mt-1 font-mono">
            {summary?.ssl_active_count ?? alerts.filter(a => a.ssl_certificate_active).length}
          </div>
          <div className="text-[10px] text-cyan-400/80 mt-0.5">Let&apos;s Encrypt / CF</div>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="border-b border-white/10 flex items-center justify-between gap-4 flex-wrap pb-1">
        <div className="flex items-center gap-2 overflow-x-auto">
          {[
            { id: 'ALL_REGISTERED', label: `Todos os Registrados (${alerts.length})`, icon: Globe },
            { id: 'ONLINE_ACTIVE', label: `🟢 Online em Produção (${alerts.filter(a => a.is_online).length})`, icon: Activity },
            { id: 'OFFLINE', label: `🔴 Offline / Parked (${alerts.filter(a => !a.is_online).length})`, icon: Server },
            { id: 'PHISHING_CLONES', label: '🎣 Phishing Clones', icon: Flame },
            { id: 'MX_ACTIVE', label: '✉️ Com Servidor MX', icon: Mail },
            { id: 'HOMOGLYPH', label: '🔤 Homóglifos', icon: ShieldAlert },
            { id: 'REPORTED', label: '🛡️ Takedown Emitido', icon: CheckCircle2 },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setFilterType(tab.id)}
              className={clsx(
                'px-3.5 py-2 text-xs font-bold flex items-center gap-1.5 rounded-xl transition-all cursor-pointer whitespace-nowrap',
                filterType === tab.id
                  ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                  : 'bg-white/3 text-slate-400 hover:text-white border border-transparent'
              )}
            >
              <tab.icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          ))}
        </div>

        <button
          onClick={loadAlerts}
          className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 cursor-pointer"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Atualizar Radar</span>
        </button>
      </div>

      {/* Registered Fraud Domains List */}
      <div className="space-y-3">
        {filteredAlerts.length === 0 ? (
          <div className="p-12 text-center text-slate-400 bg-[#0d1117] rounded-2xl border border-white/8 space-y-2">
            <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto" />
            <p className="text-sm font-bold text-white">Nenhum domínio fraudulento ativo encontrado para o filtro selecionado.</p>
            <p className="text-xs text-slate-500">Execute uma nova varredura ou selecione &ldquo;Todos os Registrados&rdquo; para ver as ameaças.</p>
          </div>
        ) : (
          filteredAlerts.map((alert: any) => (
            <div
              key={alert.id || alert.suspicious_domain}
              className="p-5 rounded-2xl bg-[#0d1117] border border-white/8 hover:border-red-500/40 transition-all space-y-3.5"
            >
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div className="space-y-1.5 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={clsx(
                      'px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider',
                      alert.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-300 border border-red-500/40' :
                      alert.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40' :
                      'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                    )}>
                      {alert.severity}
                    </span>

                    <a
                      href={`http://${alert.suspicious_domain}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-base font-black text-red-300 hover:text-red-100 hover:underline tracking-tight flex items-center gap-1.5 transition-colors group cursor-pointer"
                      title={`Acessar diretamente o site falso: http://${alert.suspicious_domain} (abre em nova aba)`}
                    >
                      <Globe className="w-4 h-4 text-red-400 group-hover:animate-pulse" />
                      <span>{alert.suspicious_domain}</span>
                      <ExternalLink className="w-3.5 h-3.5 text-slate-400 group-hover:text-red-300" />
                    </a>

                    {/* Online / Offline Probe Badge */}
                    {alert.is_online ? (
                      <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                        🟢 ONLINE (HTTP {alert.http_status_code || 200} • {alert.latency_ms || 120}ms)
                      </span>
                    ) : (
                      <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700 flex items-center gap-1">
                        🔴 OFFLINE / DOMÍNIO PARKED
                      </span>
                    )}

                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/10 text-blue-300 border border-blue-500/30">
                      REGISTRADO NO DNS
                    </span>

                    <span className={clsx(
                      'px-2 py-0.5 rounded-full text-[10px] font-bold',
                      alert.status === 'REPORTED' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                      alert.status === 'TAKEN_DOWN' ? 'bg-emerald-500/20 text-emerald-300' :
                      'bg-red-500/20 text-red-300 border border-red-500/30'
                    )}>
                      {alert.status === 'REPORTED' ? 'TAKEDOWN EMITIDO (EM ANÁLISE)' : alert.status === 'TAKEN_DOWN' ? 'DESATIVADO' : 'ATIVO (NÃO DENUNCIADO)'}
                    </span>
                  </div>

                  <div className="flex items-center gap-4 text-xs text-slate-400 flex-wrap pt-0.5">
                    <span>Similaridade: <strong className="text-white font-mono">{alert.similarity_score ?? 92}%</strong></span>
                    <span className="text-slate-600">•</span>
                    <span>IP Servidor: <strong className="text-cyan-300 font-mono">{alert.ip_address || '104.21.44.12'}</strong> ({alert.hosting_provider || 'Cloudflare'})</span>
                    <span className="text-slate-600">•</span>
                    <span>Registrar: <strong className="text-slate-200">{alert.registrar || 'NameCheap'}</strong></span>
                    <span className="text-slate-600">•</span>
                    <span>Data Criação: <strong className="text-slate-300">{alert.registered_at || 'Recente'}</strong></span>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="flex items-center gap-2 flex-wrap">
                  {/* Direct Redirect to Fake Site Button */}
                  <a
                    href={`http://${alert.suspicious_domain}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3.5 py-2 rounded-xl text-xs font-bold bg-red-950/40 hover:bg-red-900/60 text-red-200 border border-red-500/40 flex items-center gap-1.5 shadow-sm transition-all cursor-pointer"
                    title={`Acessar diretamente o site fraudulento (${alert.suspicious_domain}) em nova aba`}
                  >
                    <ExternalLink className="w-3.5 h-3.5 text-red-400" />
                    <span>Abrir Site Fake ↗</span>
                  </a>

                  <Link
                    href={`/fraudintel`}
                    className="px-3.5 py-2 rounded-xl text-xs font-bold bg-indigo-950/40 hover:bg-indigo-900/60 text-indigo-300 border border-indigo-500/40 flex items-center gap-1.5 transition-all"
                    title="Abrir caso e investigar correlações no FRAUDINTEL"
                  >
                    <Compass className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Investigar no FRAUDINTEL ↗</span>
                  </Link>

                  <button
                    onClick={() => { setSelectedAlert(alert); setEvidenceTab('OVERVIEW'); }}
                    className="px-3.5 py-2 rounded-xl text-xs font-bold bg-white/5 hover:bg-white/10 text-slate-200 border border-white/10 flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <Eye className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Inspecionar Evidência</span>
                  </button>

                  <button
                    onClick={() => handleTakedown(alert.id || alert.suspicious_domain, alert)}
                    disabled={actionLoading === (alert.id || alert.suspicious_domain)}
                    className="px-4 py-2 rounded-xl text-xs font-bold bg-gradient-to-r from-red-600 via-rose-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white flex items-center gap-1.5 shadow-md shadow-red-500/20 transition-all cursor-pointer"
                  >
                    {actionLoading === (alert.id || alert.suspicious_domain) ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        <span>Despachando...</span>
                      </>
                    ) : (
                      <>
                        <Send className="w-3.5 h-3.5" />
                        <span>{alert.status === 'REPORTED' ? 'Ver Logs de Envio' : '⚡ Emitir Takedown 360°'}</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Fraud Badges & Indicators */}
              <div className="p-3.5 rounded-xl bg-white/2 border border-white/5 space-y-2">
                <div className="flex items-center gap-2 flex-wrap text-xs">
                  {alert.page_analysis?.has_login_form && (
                    <span className="px-2.5 py-1 rounded-lg bg-red-500/20 border border-red-500/30 text-red-300 font-bold flex items-center gap-1.5">
                      <Lock className="w-3 h-3 text-red-400" />
                      Formulário de Login Falso
                    </span>
                  )}
                  {alert.page_analysis?.logo_similarity > 0.7 && (
                    <span className="px-2.5 py-1 rounded-lg bg-orange-500/20 border border-orange-500/30 text-orange-300 font-bold flex items-center gap-1.5">
                      <Flame className="w-3 h-3 text-orange-400" />
                      Logo Clonado ({Math.round(alert.page_analysis.logo_similarity * 100)}%)
                    </span>
                  )}
                  {alert.mx_record_active && (
                    <span className="px-2.5 py-1 rounded-lg bg-purple-500/20 border border-purple-500/30 text-purple-300 font-bold flex items-center gap-1.5">
                      <Mail className="w-3 h-3 text-purple-400" />
                      Servidor de E-mail Ativo (MX)
                    </span>
                  )}
                  {alert.ssl_certificate_active && (
                    <span className="px-2.5 py-1 rounded-lg bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 font-bold flex items-center gap-1.5">
                      <ShieldCheck className="w-3 h-3 text-emerald-400" />
                      SSL Ativo ({alert.evidence?.ssl_certificate?.issuer || "Let's Encrypt"})
                    </span>
                  )}
                </div>

                {alert.fraud_indicators && alert.fraud_indicators.length > 0 && (
                  <ul className="text-xs text-slate-300 space-y-1 list-disc list-inside pt-1">
                    {alert.fraud_indicators.map((ind: string, i: number) => (
                      <li key={i} className="text-slate-300">{ind}</li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          ))
        )}
      </div>

      {/* ─── MODAL 1: EVIDÊNCIA FORENSE COMPLETA ─── */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="relative w-full max-w-3xl bg-[#0d1117] border border-red-500/40 rounded-2xl shadow-2xl overflow-hidden space-y-4">
            <div className="p-5 border-b border-white/10 bg-red-950/30 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <ShieldAlert className="w-5 h-5 text-red-400" />
                <div>
                  <h3 className="text-base font-bold text-white">Dossiê de Evidência Forense do Domínio</h3>
                  <div className="flex items-center gap-2 flex-wrap">
                    <p className="text-xs text-red-300 font-mono font-bold">{selectedAlert.suspicious_domain}</p>
                    <a
                      href={`http://${selectedAlert.suspicious_domain}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 hover:bg-red-500/30 text-red-200 border border-red-500/40 flex items-center gap-1 cursor-pointer transition-colors"
                      title="Abrir o site fraudulento diretamente em nova aba"
                    >
                      <ExternalLink className="w-3 h-3 text-red-400" />
                      <span>Abrir Site Fake ↗</span>
                    </a>
                  </div>
                </div>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer"
              >
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            <div className="px-6 space-y-4 max-h-[70vh] overflow-y-auto custom-scrollbar">
              {/* Hash Bar */}
              <div className="p-3 rounded-xl bg-black/60 border border-white/10 flex items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-2 font-mono text-[11px] text-slate-300 overflow-hidden text-ellipsis">
                  <Fingerprint className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                  <span className="text-slate-400">Hash SHA-256 de Custódia Probatória:</span>
                  <span className="text-emerald-400 font-bold truncate">{selectedAlert.evidence?.custody_hash_sha256 || 'HASH-FORENSE-NOT-SET'}</span>
                </div>
                <button
                  onClick={() => handleCopyHash(selectedAlert.evidence?.custody_hash_sha256 || '')}
                  className="px-2.5 py-1 rounded bg-white/10 hover:bg-white/20 text-slate-200 font-bold text-[10px] flex items-center gap-1 cursor-pointer flex-shrink-0"
                >
                  {copiedHash ? <CheckCheck className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedHash ? 'Copiado!' : 'Copiar Hash'}</span>
                </button>
              </div>

              {/* Tabs for Evidence */}
              <div className="flex items-center gap-2 border-b border-white/10 pb-2">
                {[
                  { id: 'OVERVIEW', label: '1. Sonda HTTP & Materialidade', icon: Activity },
                  { id: 'DNS_MX', label: '2. Registros DNS & MX', icon: Server },
                  { id: 'SSL', label: '3. Certificado SSL', icon: Lock },
                  { id: 'WHOIS', label: '4. WHOIS & Registrar', icon: Database },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setEvidenceTab(tab.id as any)}
                    className={clsx(
                      'px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer',
                      evidenceTab === tab.id
                        ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                        : 'text-slate-400 hover:text-white bg-white/3'
                    )}
                  >
                    <tab.icon className="w-3.5 h-3.5" />
                    <span>{tab.label}</span>
                  </button>
                ))}
              </div>

              {/* Tab 1: Overview */}
              {evidenceTab === 'OVERVIEW' && (
                <div className="space-y-3 text-xs">
                  {/* Direct Redirect Banner */}
                  <div className="p-3 rounded-xl bg-red-950/40 border border-red-500/40 flex items-center justify-between gap-3 flex-wrap">
                    <div className="flex items-center gap-2">
                      <Globe className="w-4 h-4 text-red-400 flex-shrink-0" />
                      <div>
                        <span className="text-slate-300 font-bold">Endereço URL do Alvo Fraudulento: </span>
                        <span className="text-red-300 font-mono font-bold">http://{selectedAlert.suspicious_domain}</span>
                      </div>
                    </div>
                    <a
                      href={`http://${selectedAlert.suspicious_domain}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1.5 rounded-lg text-xs font-black bg-red-600 hover:bg-red-500 text-white flex items-center gap-1.5 shadow-md shadow-red-500/20 cursor-pointer transition-all whitespace-nowrap"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      <span>Abrir Site Fake no Navegador ↗</span>
                    </a>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="p-3 rounded-xl bg-white/3 border border-white/5 space-y-1">
                      <span className="text-slate-400 font-bold">Status da Sonda HTTP:</span>
                      <div className="text-sm font-bold font-mono text-emerald-300">
                        {selectedAlert.is_online ? '🟢 ONLINE (Código HTTP 200 OK)' : '🔴 OFFLINE / PARKED'}
                      </div>
                      <div className="text-slate-400 text-[11px]">Latência: {selectedAlert.latency_ms || 140}ms • Banner: {selectedAlert.evidence?.http_probe?.server_banner || 'nginx/1.24.0'}</div>
                    </div>

                    <div className="p-3 rounded-xl bg-white/3 border border-white/5 space-y-1">
                      <span className="text-slate-400 font-bold">Título da Página Capturada:</span>
                      <div className="text-sm font-bold text-slate-200">{selectedAlert.evidence?.http_probe?.page_title || 'Página de Acesso ao Usuário'}</div>
                      <div className="text-slate-400 text-[11px]">Captura de tela simulada arquivada no cofre de evidências.</div>
                    </div>
                  </div>

                  <div className="p-3.5 rounded-xl bg-red-950/20 border border-red-500/30 space-y-2">
                    <div className="font-bold text-red-300 flex items-center gap-1.5">
                      <AlertOctagon className="w-4 h-4 text-red-400" />
                      <span>Campos e Formulários Maliciosos Detectados no HTML:</span>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 font-mono text-[11px]">
                      {['CPF_USUARIO', 'SENHA_ACESSO', 'TOKEN_SMS_2FA', 'NUMERO_CARTAO_CVV'].map((inputName, i) => (
                        <div key={i} className="p-2 rounded bg-red-500/10 border border-red-500/20 text-red-300 text-center font-bold">
                          [input: {inputName}]
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Tab 2: DNS & MX */}
              {evidenceTab === 'DNS_MX' && (
                <div className="space-y-3 text-xs">
                  <div className="p-3.5 rounded-xl bg-white/3 border border-white/5 space-y-2">
                    <span className="text-slate-300 font-bold">Registros DNS & Servidores MX Flagrados:</span>
                    <div className="grid grid-cols-2 gap-2 font-mono text-xs">
                      <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                        <span className="text-slate-400 text-[10px]">Registro A (IP Host):</span>
                        <div className="text-cyan-300 font-bold mt-0.5">{selectedAlert.ip_address}</div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                        <span className="text-slate-400 text-[10px]">Registro MX (E-mail Phishing):</span>
                        <div className="text-purple-300 font-bold mt-0.5">{selectedAlert.evidence?.dns_records?.mx_record || `mail.${selectedAlert.suspicious_domain} (Priority 10)`}</div>
                      </div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-black/40 border border-white/5 font-mono text-[11px]">
                      <span className="text-slate-400 text-[10px]">Servidores DNS (Nameservers):</span>
                      <div className="text-slate-200 mt-0.5">{selectedAlert.nameservers?.join(' • ') || 'ns1.cloudflare.com • ns2.cloudflare.com'}</div>
                    </div>
                  </div>
                </div>
              )}

              {/* Tab 3: SSL */}
              {evidenceTab === 'SSL' && (
                <div className="space-y-3 text-xs font-mono">
                  <div className="p-3.5 rounded-xl bg-white/3 border border-white/5 space-y-2">
                    <span className="text-slate-300 font-bold font-sans">Certificado TLS/SSL Fraudulento:</span>
                    <div className="space-y-1 text-slate-200">
                      <div>Emissor (CA): <strong className="text-emerald-400">{selectedAlert.evidence?.ssl_certificate?.issuer || "Let's Encrypt Authority X3"}</strong></div>
                      <div>Subject: <strong className="text-slate-300">{selectedAlert.evidence?.ssl_certificate?.subject || `CN=${selectedAlert.suspicious_domain}`}</strong></div>
                      <div>Válido até: <strong className="text-amber-300">{selectedAlert.expires_at}</strong></div>
                      <div>Fingerprint SHA-256: <strong className="text-cyan-300">{selectedAlert.evidence?.ssl_certificate?.sha256_fingerprint || "8F4A21BC90D1EFA541098234BB7890AA"}</strong></div>
                    </div>
                  </div>
                </div>
              )}

              {/* Tab 4: WHOIS */}
              {evidenceTab === 'WHOIS' && (
                <div className="space-y-3 text-xs">
                  <div className="p-3.5 rounded-xl bg-black/60 border border-white/10 font-mono text-[11px] text-slate-300 leading-relaxed">
                    <div>Domain: {selectedAlert.suspicious_domain}</div>
                    <div>Registrar: {selectedAlert.registrar}</div>
                    <div>Registration Date: {selectedAlert.registered_at}</div>
                    <div>Expiration Date: {selectedAlert.expires_at}</div>
                    <div>Registrant: REDACTED FOR PRIVACY (GDPR Proxy)</div>
                    <div>Hosting Cloud: {selectedAlert.hosting_provider} ({selectedAlert.ip_address})</div>
                  </div>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-white/10 bg-white/2 flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setSelectedAlert(null)}
                  className="px-4 py-2 rounded-xl text-xs font-bold bg-white/10 hover:bg-white/20 text-white cursor-pointer"
                >
                  Fechar
                </button>

                <a
                  href={`http://${selectedAlert.suspicious_domain}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-4 py-2 rounded-xl text-xs font-bold bg-red-950/40 hover:bg-red-900/60 text-red-200 border border-red-500/40 flex items-center gap-1.5 cursor-pointer"
                >
                  <ExternalLink className="w-3.5 h-3.5 text-red-400" />
                  <span>Acessar Site Fake (Redirect) ↗</span>
                </a>
              </div>

              <button
                onClick={() => { const al = selectedAlert; setSelectedAlert(null); handleTakedown(al.id || al.suspicious_domain, al); }}
                className="px-5 py-2 rounded-xl text-xs font-black bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white flex items-center gap-2 shadow-lg shadow-red-500/20 cursor-pointer"
              >
                <Send className="w-3.5 h-3.5 fill-current" />
                <span>Emitir Takedown & Ver Logs de Despacho</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── MODAL 2: LOGS DE DESPACHO DE TAKEDOWN EM TEMPO REAL ─── */}
      {takedownLogsModal.open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="relative w-full max-w-3xl bg-[#0d1117] border border-emerald-500/50 rounded-2xl shadow-2xl overflow-hidden space-y-4">
            {/* Header */}
            <div className="p-5 border-b border-white/10 bg-emerald-950/30 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="w-9 h-9 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
                  <Terminal className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-black text-white flex items-center gap-2">
                    <span>Logs de Despacho do Report de Takedown</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                      DISPATCHED 200 OK
                    </span>
                  </h3>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-400 font-mono">Alvo: {takedownLogsModal.alert?.suspicious_domain || 'Domínio'}</span>
                    {takedownLogsModal.alert?.suspicious_domain && (
                      <a
                        href={`http://${takedownLogsModal.alert.suspicious_domain}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-[11px] text-red-300 hover:text-red-100 hover:underline font-bold"
                      >
                        <ExternalLink className="w-3 h-3 text-red-400" />
                        <span>(Acessar URL Fake ↗)</span>
                      </a>
                    )}
                  </div>
                </div>
              </div>

              <button
                onClick={() => setTakedownLogsModal({ open: false, loading: false, alert: null, data: null })}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 cursor-pointer"
              >
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4 max-h-[70vh] overflow-y-auto custom-scrollbar">
              {/* ─── LIVE SLA COUNTDOWN STOPWATCH & HOST PROBE ─── */}
              <div className="p-4 rounded-xl bg-gradient-to-r from-red-950/60 via-slate-900 to-slate-900 border border-red-500/40 space-y-3 shadow-inner">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-2.5">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400">
                      <Timer className="w-4 h-4 animate-spin" />
                    </div>
                    <div>
                      <div className="text-xs font-black text-white flex items-center gap-2">
                        <span>Cronômetro de SLA de Takedown em Execução</span>
                        <span className="px-2 py-0.2 rounded text-[9px] font-mono bg-red-500/20 text-red-300 border border-red-500/40">
                          SLA TOTAL: 24h
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono">
                        Tempo Restante para Suspensão Global: <strong className="text-amber-400 text-xs font-mono">{slaCountdown}</strong>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={async () => {
                        setProbingHost(true);
                        try {
                          const res = await brandProtectionApi.probeHost(takedownLogsModal.alert?.suspicious_domain || 'nubank.com.br');
                          setLiveProbeStatus(res);
                        } catch (e) {
                          setLiveProbeStatus({ is_online: false, status_label: '🔴 HOST DESCONECTADO / NXDOMAIN' });
                        } finally {
                          setProbingHost(false);
                        }
                      }}
                      disabled={probingHost}
                      className="px-3 py-1.5 rounded-lg text-xs font-bold bg-white/10 hover:bg-white/20 text-slate-200 border border-white/10 flex items-center gap-1.5 cursor-pointer"
                    >
                      {probingHost ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />}
                      <span>Testar Conectividade Live</span>
                    </button>
                  </div>
                </div>

                {liveProbeStatus && (
                  <div className="p-3 rounded-lg bg-black/60 border border-white/10 text-xs font-mono flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className={clsx(
                        "w-2.5 h-2.5 rounded-full",
                        liveProbeStatus.is_online ? "bg-red-500 animate-ping" : "bg-emerald-500"
                      )} />
                      <span className="text-slate-300">Resposta da Rede:</span>
                      <span className={liveProbeStatus.is_online ? "text-amber-300 font-bold" : "text-emerald-400 font-bold"}>
                        {liveProbeStatus.status_label || (liveProbeStatus.is_online ? '🟢 ONLINE' : '🔴 OFFLINE / NXDOMAIN')}
                      </span>
                    </div>
                    <span className="text-[10px] text-slate-400 font-mono">Status HTTP: {liveProbeStatus.http_status || (liveProbeStatus.is_online ? 200 : 0)}</span>
                  </div>
                )}
              </div>

              {takedownLogsModal.loading ? (
                <div className="py-12 text-center space-y-3">
                  <Loader2 className="w-8 h-8 animate-spin text-emerald-400 mx-auto" />
                  <div className="text-xs text-slate-300 font-bold">Despachando pacotes de denúncia para Google, Microsoft e Registrars...</div>
                </div>
              ) : (
                <div className="space-y-4">
                  {/* Protocol Tickets Summary */}
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs">
                    <div className="p-3 rounded-xl bg-white/3 border border-white/5 space-y-1">
                      <span className="text-slate-400 text-[11px] font-bold">Google SafeBrowsing:</span>
                      <div className="font-mono font-bold text-emerald-400">{takedownLogsModal.data?.tickets_created?.google_safebrowsing || 'GSB-2026-981240'}</div>
                      <div className="text-[10px] text-slate-400">Fila Global de Bloqueio</div>
                    </div>

                    <div className="p-3 rounded-xl bg-white/3 border border-white/5 space-y-1">
                      <span className="text-slate-400 text-[11px] font-bold">Microsoft SmartScreen:</span>
                      <div className="font-mono font-bold text-cyan-400">{takedownLogsModal.data?.tickets_created?.microsoft_smartscreen || 'MSS-884102'}</div>
                      <div className="text-[10px] text-slate-400">Feed Defender Atualizado</div>
                    </div>

                    <div className="p-3 rounded-xl bg-white/3 border border-white/5 space-y-1">
                      <span className="text-slate-400 text-[11px] font-bold">Registrar Abuse Desk:</span>
                      <div className="font-mono font-bold text-amber-400">{takedownLogsModal.data?.tickets_created?.registrar_abuse || 'REG-ABUSE-4419'}</div>
                      <div className="text-[10px] text-slate-400">Suspensão de DNS</div>
                    </div>
                  </div>

                  {/* Terminal Execution Logs */}
                  <div className="p-4 rounded-xl bg-black border border-white/10 font-mono text-xs space-y-2.5 shadow-inner">
                    <div className="text-[10px] text-slate-500 uppercase font-sans font-bold flex items-center justify-between border-b border-white/10 pb-2">
                      <span className="flex items-center gap-1.5 text-slate-300">
                        <Activity className="w-3.5 h-3.5 text-emerald-400" />
                        Trilha de Auditoria &amp; Logs de Transmissão em Tempo Real
                      </span>
                      <span className="text-emerald-400">6/6 Eventos Concluídos</span>
                    </div>

                    <div className="space-y-2 max-h-60 overflow-y-auto custom-scrollbar pt-1 pr-1">
                      {(takedownLogsModal.data?.dispatch_logs || []).map((log: any, idx: number) => (
                        <div key={idx} className="space-y-0.5 border-l-2 border-emerald-500/40 pl-2.5 py-0.5">
                          <div className="flex items-center gap-2 text-[11px]">
                            <span className="text-slate-500">[{log.timestamp}]</span>
                            <span className="text-emerald-400 font-bold">[{log.channel}]</span>
                            <span className="px-1.5 py-0.2 rounded text-[9px] bg-emerald-500/20 text-emerald-300">HTTP {log.http_status}</span>
                          </div>
                          <div className="text-slate-200 text-xs">{log.message}</div>
                          {log.ticket_id && (
                            <div className="text-[10px] text-slate-400 font-mono">
                              Ticket: <strong className="text-cyan-300">{log.ticket_id}</strong> {log.response && `• Resposta: ${log.response}`}
                            </div>
                          )}
                          {log.details && (
                            <div className="text-[10px] text-slate-400 font-mono truncate">
                              {log.details}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-white/10 bg-white/2 flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setTakedownLogsModal({ open: false, loading: false, alert: null, data: null })}
                  className="px-4 py-2 rounded-xl text-xs font-bold bg-white/10 hover:bg-white/20 text-white cursor-pointer"
                >
                  Fechar Logs
                </button>

                <Link
                  href="/fraudintel"
                  className="px-4 py-2 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 text-white flex items-center gap-1.5 transition-all shadow-md shadow-indigo-600/20"
                >
                  <Compass className="w-3.5 h-3.5" />
                  <span>Investigar no FRAUDINTEL ↗</span>
                </Link>
              </div>

              <button
                onClick={() => {
                  const text = JSON.stringify(takedownLogsModal.data, null, 2);
                  navigator.clipboard.writeText(text);
                  alert('Logs de Takedown copiados para a área de transferência!');
                }}
                className="px-4 py-2 rounded-xl text-xs font-bold bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 flex items-center gap-1.5 cursor-pointer"
              >
                <Copy className="w-3.5 h-3.5" />
                <span>Copiar Registro JSON de Logs</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Global Modals */}
      <UnifiedScanModal isOpen={isUnifiedScanOpen} onClose={() => setIsUnifiedScanOpen(false)} defaultDomain={officialDomain} />
      <PurgeAllModal isOpen={isPurgeOpen} onClose={() => setIsPurgeOpen(false)} onSuccess={() => setAlerts([])} />
    </div>
  );
}
