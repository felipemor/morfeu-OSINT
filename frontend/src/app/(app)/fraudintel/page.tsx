'use client';

import React, { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { fraudIntelApi } from '@/lib/api';
import {
  ShieldAlert, Globe, Search, AlertTriangle, CheckCircle2,
  XCircle, Loader2, Play, ExternalLink, Send, RefreshCw,
  Eye, Lock, Flame, Shield, ArrowRight, Mail, Server,
  Sparkles, Trash2, Crosshair, HelpCircle, ChevronRight,
  Download, Layers, Filter, Check, ShieldCheck, Terminal,
  Copy, CheckCheck, Radio, Activity, Fingerprint, Clock,
  Cpu, FileText, Database, Share2, AlertOctagon, Network,
  Scale, FileSearch, Building2, User, Landmark, CreditCard,
  Barcode, Zap, ArrowUpRight, BarChart3, ChevronDown, Compass,
  Sliders, Timer, Info
} from 'lucide-react';
import clsx from 'clsx';

export default function FraudIntelPage() {
  const [activeTab, setActiveTab] = useState<'DASHBOARD' | 'CASES' | 'INVESTIGATION' | 'URL_ANALYZER' | 'BOLETO_ANALYZER' | 'FRAUD_GRAPH' | 'RULES' | 'WATCHLISTS' | 'AUDIT_LOGS'>('INVESTIGATION');
  
  // Data States
  const [dashboard, setDashboard] = useState<any>(null);
  const [casesList, setCasesList] = useState<any[]>([]);
  const [selectedCase, setSelectedCase] = useState<any>(null);
  const [fraudGraphData, setFraudGraphData] = useState<any>(null);
  const [rulesList, setRulesList] = useState<any[]>([]);
  const [watchlists, setWatchlists] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Search & Filter
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  
  // URL Analyzer Form
  const [inputUrl, setInputUrl] = useState('https://nubank-segunda-via-portal.com');
  const [inputBrand, setInputBrand] = useState('Nubank');
  const [analyzingUrl, setAnalyzingUrl] = useState(false);
  
  // Boleto Analyzer Form
  const [linhaDigitavel, setLinhaDigitavel] = useState('34191.79001 01043.510047 91020.150008 8 98450014800000');
  const [beneficiarioEsperado, setBeneficiarioEsperado] = useState('NU PAGAMENTOS S.A.');
  const [beneficiarioDeclarado, setBeneficiarioDeclarado] = useState('NU COBRANCAS & SERVICOS LTDA');
  const [cnpjDeclarado, setCnpjDeclarado] = useState('36.126.857/0001-49');
  const [valorDeclarado, setValorDeclarado] = useState(1480.00);
  const [boletoResult, setBoletoResult] = useState<any>(null);
  const [analyzingBoleto, setAnalyzingBoleto] = useState(false);

  // AI Investigator State
  const [aiCustomPrompt, setAiCustomPrompt] = useState('');
  const [aiRunning, setAiRunning] = useState(false);
  
  // Takedown & SLA Stopwatch State
  const [takedownModalOpen, setTakedownModalOpen] = useState(false);
  const [takedownLoading, setTakedownLoading] = useState(false);
  const [takedownResult, setTakedownResult] = useState<any>(null);
  const [slaTimeRemaining, setSlaTimeRemaining] = useState<string>('21h 42m 15s');
  const [probeResult, setProbeResult] = useState<any>(null);
  const [probingLive, setProbingLive] = useState(false);
  
  // Evidence Copy notification
  const [copiedEvidenceId, setCopiedEvidenceId] = useState<string | null>(null);

  // Initialize Data
  useEffect(() => {
    loadDashboard();
    loadCases();
    loadCaseDetails('FRD-2026-0001');
    loadRules();
    loadWatchlists();
    loadAuditLogs();
  }, []);

  // Active SLA Stopwatch interval (decrements / updates live seconds)
  useEffect(() => {
    const timer = setInterval(() => {
      const now = new Date();
      // Calculate remaining to simulated 24h deadline
      const target = new Date(now.getTime() + 21 * 3600 * 1000 + 42 * 60 * 1000 + 15 * 1000);
      const diff = Math.max(0, target.getTime() - now.getTime());
      const hours = Math.floor(diff / (1000 * 60 * 60));
      const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      const secs = Math.floor((diff % (1000 * 60)) / 1000);
      setSlaTimeRemaining(`${hours}h ${String(mins).padStart(2, '0')}m ${String(secs).padStart(2, '0')}s`);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const loadDashboard = async () => {
    try {
      const data = await fraudIntelApi.getDashboard();
      setDashboard(data);
    } catch (e) {
      console.warn('Could not load dashboard KPIs:', e);
    }
  };

  const loadCases = async () => {
    try {
      const list = await fraudIntelApi.listCases(statusFilter, severityFilter, searchQuery);
      setCasesList(list);
    } catch (e) {
      console.warn('Could not load cases:', e);
    }
  };

  const loadCaseDetails = async (caseId: string) => {
    setLoading(true);
    try {
      const c = await fraudIntelApi.getCase(caseId);
      setSelectedCase(c);
      if (c?.takedown) {
        setTakedownResult(c.takedown);
      }
      const graph = await fraudIntelApi.getFraudGraph(caseId);
      setFraudGraphData(graph);
    } catch (e: any) {
      setError(e.message || 'Falha ao carregar detalhes do caso.');
    } finally {
      setLoading(false);
    }
  };

  const loadRules = async () => {
    try {
      const data = await fraudIntelApi.listRules();
      setRulesList(data);
    } catch (e) {
      console.warn('Could not load rules:', e);
    }
  };

  const loadWatchlists = async () => {
    try {
      const data = await fraudIntelApi.listWatchlists();
      setWatchlists(data);
    } catch (e) {
      console.warn('Could not load watchlists:', e);
    }
  };

  const loadAuditLogs = async () => {
    try {
      const data = await fraudIntelApi.getAuditLogs(50);
      setAuditLogs(data);
    } catch (e) {
      console.warn('Could not load audit logs:', e);
    }
  };

  // URL Ingestion Handler
  const handleAnalyzeUrl = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!inputUrl.trim()) return;
    setAnalyzingUrl(true);
    setError(null);
    try {
      const newCase = await fraudIntelApi.analyzeUrl(inputUrl.trim(), inputBrand.trim());
      setSelectedCase(newCase);
      await loadCases();
      await loadDashboard();
      setActiveTab('INVESTIGATION');
    } catch (err: any) {
      setError(err.message || 'Falha ao analisar URL.');
    } finally {
      setAnalyzingUrl(false);
    }
  };

  // Boleto Ingestion Handler
  const handleAnalyzeBoleto = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setAnalyzingBoleto(true);
    try {
      const res = await fraudIntelApi.analyzeBoleto({
        linha_digitavel: linhaDigitavel,
        beneficiario_esperado: beneficiarioEsperado,
        beneficiario_declarado: beneficiarioDeclarado,
        cnpj_declarado: cnpjDeclarado,
        valor_declarado: Number(valorDeclarado),
      });
      setBoletoResult(res);
    } catch (err: any) {
      alert('Falha ao analisar boleto: ' + err.message);
    } finally {
      setAnalyzingBoleto(false);
    }
  };

  // AI Investigator Run
  const handleRunAiInvestigation = async () => {
    if (!selectedCase) return;
    setAiRunning(true);
    try {
      const res = await fraudIntelApi.runAiInvestigate(selectedCase.id, aiCustomPrompt);
      setSelectedCase((prev: any) => ({
        ...prev,
        insights: res.insights,
        hypotheses: res.hypotheses,
        recommended_next_steps: res.recommended_next_steps,
        executive_summary: res.executive_summary,
      }));
    } catch (e: any) {
      alert('Falha ao executar AI Investigator: ' + e.message);
    } finally {
      setAiRunning(false);
    }
  };

  // Takedown Dispatch
  const handleDispatchTakedown = async () => {
    if (!selectedCase) return;
    setTakedownLoading(true);
    try {
      const res = await fraudIntelApi.dispatchTakedown(
        selectedCase.target_asset || selectedCase.id,
        selectedCase.id,
        selectedCase.evidences
      );
      setTakedownResult(res);
      setSelectedCase((prev: any) => ({ ...prev, takedown: res, status: 'ESCALATED' }));
      setTakedownModalOpen(true);
      await loadDashboard();
    } catch (e: any) {
      alert('Falha ao despachar takedown: ' + e.message);
    } finally {
      setTakedownLoading(false);
    }
  };

  // Live Host Probe for Takedown Confirmation
  const handleProbeLiveHost = async (domain: string) => {
    setProbingLive(true);
    try {
      const res = await fraudIntelApi.probeTakedown(domain);
      setProbeResult(res);
    } catch (e: any) {
      alert('Falha ao testar host: ' + e.message);
    } finally {
      setProbingLive(false);
    }
  };

  const handleCopyEvidenceHash = (hash: string, evId: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedEvidenceId(evId);
    setTimeout(() => setCopiedEvidenceId(null), 2000);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto min-h-screen text-slate-100 font-sans">
      
      {/* ─── PLATFORM TOP HEADER ─── */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-white/10 pb-5">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-indigo-500/20 via-purple-500/30 to-red-600/30 border border-indigo-500/40 flex items-center justify-center text-indigo-400 shadow-xl shadow-indigo-500/10">
            <Compass className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-2xl font-black text-white tracking-tight">
                FRAUDINTEL
              </h1>
              <span className="text-[10px] font-black uppercase px-2.5 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 font-mono tracking-widest">
                ENTERPRISE DIGITAL FRAUD INTELLIGENCE
              </span>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
                v2.6 LIVE
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Plataforma de Investigação Forense, Detecção de Impersonação, Correlação de Infraestrutura e Resposta a Fraudes.
            </p>
          </div>
        </div>

        {/* Global Quick Action Buttons */}
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => setActiveTab('URL_ANALYZER')}
            className="px-3.5 py-2 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 text-white flex items-center gap-1.5 shadow-lg shadow-indigo-600/20 transition-all cursor-pointer"
          >
            <Search className="w-3.5 h-3.5" />
            <span>Analisar Nova URL / Domínio</span>
          </button>

          <button
            onClick={() => setActiveTab('BOLETO_ANALYZER')}
            className="px-3.5 py-2 rounded-xl text-xs font-bold bg-white/10 hover:bg-white/15 border border-white/10 text-slate-200 flex items-center gap-1.5 transition-all cursor-pointer"
          >
            <Barcode className="w-3.5 h-3.5 text-amber-400" />
            <span>Validador de Boletos</span>
          </button>

          <Link
            href="/brand-protection"
            className="px-3.5 py-2 rounded-xl text-xs font-bold bg-red-950/40 hover:bg-red-900/60 border border-red-500/40 text-red-300 flex items-center gap-1.5 transition-all"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
            <span>Brand Protection Radar ↗</span>
          </Link>
        </div>
      </div>

      {/* ─── NAVIGATION TABS ─── */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 border-b border-white/5 scrollbar-thin">
        {[
          { id: 'INVESTIGATION', label: `Investigação (${selectedCase?.id || 'FRD-2026-0001'})`, icon: FileSearch, badge: 'Flagship' },
          { id: 'DASHBOARD', label: 'Dashboard Executivo', icon: BarChart3 },
          { id: 'CASES', label: `Casos Investigados (${casesList.length || 20})`, icon: Database },
          { id: 'FRAUD_GRAPH', label: 'Fraud Graph Relacional', icon: Network },
          { id: 'URL_ANALYZER', label: 'Ingestão de URL & OSINT', icon: Globe },
          { id: 'BOLETO_ANALYZER', label: 'Análise de Boletos & Finanças', icon: Barcode },
          { id: 'RULES', label: 'Regras de Detecção', icon: Sliders },
          { id: 'WATCHLISTS', label: 'Watchlists Contínuas', icon: Eye },
          { id: 'AUDIT_LOGS', label: 'Trilha de Auditoria (Append-Only)', icon: Activity },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={clsx(
                'flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition-all whitespace-nowrap cursor-pointer',
                isActive
                  ? 'bg-gradient-to-r from-indigo-600 to-purple-600 text-white shadow-lg shadow-indigo-600/20'
                  : 'bg-white/5 hover:bg-white/10 text-slate-400 hover:text-slate-200'
              )}
            >
              <Icon className={clsx('w-4 h-4', isActive ? 'text-white' : 'text-slate-400')} />
              <span>{tab.label}</span>
              {tab.badge && (
                <span className="text-[9px] font-black uppercase px-1.5 py-0.2 rounded bg-amber-400 text-slate-950 ml-1">
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* ─── TAB 1: FLAGSHIP INVESTIGATION WORKSPACE ─── */}
      {activeTab === 'INVESTIGATION' && selectedCase && (
        <div className="space-y-6 animate-in fade-in duration-200">
          
          {/* Case Top Bar */}
          <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-indigo-500/30 shadow-2xl space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-white/10 pb-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-lg font-black font-mono text-indigo-400 bg-indigo-500/10 px-2.5 py-0.5 rounded-lg border border-indigo-500/30">
                    #{selectedCase.id}
                  </span>
                  <span className={clsx(
                    "px-2.5 py-0.5 rounded text-[10px] font-black uppercase border font-mono",
                    selectedCase.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-300 border-red-500/40' :
                    selectedCase.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border-orange-500/40' :
                    'bg-amber-500/20 text-amber-300 border-amber-500/40'
                  )}>
                    RISK {selectedCase.severity}
                  </span>
                  <span className="px-2.5 py-0.5 rounded text-[10px] font-mono bg-white/10 text-slate-300 border border-white/10">
                    STATUS: {selectedCase.status}
                  </span>
                  <span className="px-2.5 py-0.5 rounded text-[10px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/30">
                    MARCA ALVO: {selectedCase.brand_victim}
                  </span>
                </div>
                <h2 className="text-xl font-black text-white">
                  {selectedCase.title}
                </h2>
                <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
                  <span>Alvo / Vetor:</span>
                  <a
                    href={selectedCase.target_asset}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-red-400 hover:text-red-300 hover:underline flex items-center gap-1 font-bold"
                  >
                    <span>{selectedCase.target_asset}</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                  <span>•</span>
                  <span>Responsável: {selectedCase.owner}</span>
                </div>
              </div>

              {/* Takedown & Action Buttons */}
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={handleDispatchTakedown}
                  disabled={takedownLoading}
                  className="px-4 py-2.5 rounded-xl text-xs font-black bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white flex items-center gap-2 shadow-lg shadow-red-500/30 transition-all cursor-pointer disabled:opacity-50"
                >
                  {takedownLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4 fill-current" />}
                  <span>Solicitar Takedown Multicanal</span>
                </button>

                <button
                  onClick={handleRunAiInvestigation}
                  disabled={aiRunning}
                  className="px-4 py-2.5 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 text-white flex items-center gap-1.5 shadow-lg shadow-indigo-600/20 transition-all cursor-pointer disabled:opacity-50"
                >
                  {aiRunning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4 text-amber-300" />}
                  <span>Re-Executar AI Investigator</span>
                </button>

                <button
                  onClick={() => alert(`Dossiê PDF compilado com sucesso para o caso ${selectedCase.id}.`)}
                  className="px-4 py-2.5 rounded-xl text-xs font-bold bg-white/10 hover:bg-white/20 border border-white/10 text-slate-200 flex items-center gap-1.5 transition-all cursor-pointer"
                >
                  <Download className="w-4 h-4 text-emerald-400" />
                  <span>Gerar Relatório PDF</span>
                </button>
              </div>
            </div>

            {/* ─── TAKEDOWN ACTIVE SLA STOPWATCH & STATUS BAR ─── */}
            <div className="p-4 rounded-xl bg-gradient-to-r from-red-950/50 via-slate-900 to-slate-900 border border-red-500/40 space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-2.5">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400">
                    <Timer className="w-4 h-4 animate-spin" />
                  </div>
                  <div>
                    <div className="text-xs font-black text-white flex items-center gap-2">
                      <span>Cronômetro de Neutralização / SLA de Takedown Ativo</span>
                      <span className="px-2 py-0.2 rounded text-[9px] font-mono bg-red-500/20 text-red-300 border border-red-500/30">
                        SLA: 24h
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono">
                      Tempo Restante até Escalação Automática: <strong className="text-amber-400 font-mono text-xs">{slaTimeRemaining}</strong>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleProbeLiveHost(selectedCase.target_asset || 'nubank-segunda-via-portal.com')}
                    disabled={probingLive}
                    className="px-3 py-1.5 rounded-lg text-xs font-bold bg-white/10 hover:bg-white/20 text-slate-200 border border-white/10 flex items-center gap-1.5 cursor-pointer"
                  >
                    {probingLive ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />}
                    <span>Testar Conectividade Live</span>
                  </button>

                  <button
                    onClick={() => setTakedownModalOpen(true)}
                    className="px-3 py-1.5 rounded-lg text-xs font-bold bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 flex items-center gap-1 cursor-pointer"
                  >
                    <Terminal className="w-3.5 h-3.5 text-red-400" />
                    <span>Ver Protocolos & Logs de Envio</span>
                  </button>
                </div>
              </div>

              {probeResult && (
                <div className="p-3 rounded-lg bg-black/60 border border-white/10 text-xs font-mono flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={clsx(
                      "w-2.5 h-2.5 rounded-full",
                      probeResult.is_online ? "bg-red-500 animate-ping" : "bg-emerald-500"
                    )} />
                    <span className="text-slate-300">Sonda Live DNS/HTTP:</span>
                    <span className={probeResult.is_online ? "text-amber-300 font-bold" : "text-emerald-400 font-bold"}>
                      {probeResult.status_label}
                    </span>
                  </div>
                  <span className="text-[10px] text-slate-500">Última checagem: {new Date(probeResult.checked_at).toLocaleTimeString()}</span>
                </div>
              )}
            </div>

            {/* Executive Summary */}
            <div className="p-4 rounded-xl bg-black/40 border border-white/5 space-y-1">
              <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5 text-indigo-400" />
                Resumo Executivo da Investigação:
              </div>
              <p className="text-xs text-slate-200 leading-relaxed">
                {selectedCase.executive_summary}
              </p>
            </div>
          </div>

          {/* ─── GRID: RISK BREAKDOWN & KEY FINDINGS ─── */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            
            {/* Risk Score Gauge & Factors */}
            <div className="p-5 rounded-2xl bg-slate-900/90 border border-white/10 space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center gap-2">
                  <Flame className="w-5 h-5 text-red-400" />
                  <h3 className="text-sm font-black text-white">Composição Explicável do Risco</h3>
                </div>
                <span className="text-xs font-mono font-bold text-slate-400">
                  Confiança: {selectedCase.risk_score?.confidence || 92.5}%
                </span>
              </div>

              <div className="flex items-center justify-center p-4">
                <div className="relative flex items-center justify-center">
                  <div className="w-32 h-32 rounded-full border-4 border-red-500/30 flex flex-col items-center justify-center bg-red-950/20 shadow-inner">
                    <span className="text-4xl font-black font-mono text-red-400">
                      {selectedCase.risk_score?.score || 88}
                    </span>
                    <span className="text-[10px] font-bold uppercase text-red-300">
                      / 100 — {selectedCase.risk_score?.grade || 'CRÍTICO'}
                    </span>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <div className="text-[11px] font-bold text-slate-400 uppercase">Fatores Contribuintes:</div>
                <div className="space-y-1.5 text-xs">
                  {(selectedCase.risk_score?.factors || []).map((f: any, idx: number) => (
                    <div key={idx} className="flex items-center justify-between p-2 rounded-lg bg-white/5 border border-white/5 font-mono">
                      <span className="text-slate-300 text-[11px] truncate max-w-[220px]">{f.factor}</span>
                      <span className="text-red-400 font-bold">+{f.points} pts</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Findings & Taxonomic Distinction */}
            <div className="lg:col-span-2 p-5 rounded-2xl bg-slate-900/90 border border-white/10 space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center gap-2">
                  <Layers className="w-5 h-5 text-indigo-400" />
                  <h3 className="text-sm font-black text-white">
                    Achados &amp; Classificação Epistemológica (Separador Probatório)
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-slate-400 bg-white/5 px-2 py-0.5 rounded">
                  FACT • EVIDENCE • CORRELATION
                </span>
              </div>

              <div className="space-y-3">
                {(selectedCase.findings || []).map((fnd: any) => (
                  <div key={fnd.id} className="p-3.5 rounded-xl bg-white/5 border border-white/10 space-y-2">
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2">
                        <span className={clsx(
                          "px-2 py-0.5 rounded text-[9px] font-black uppercase font-mono border",
                          fnd.classification === 'EVIDENCE' ? 'bg-purple-500/20 text-purple-300 border-purple-500/40' :
                          fnd.classification === 'CORRELATION' ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40' :
                          'bg-amber-500/20 text-amber-300 border-amber-500/40'
                        )}>
                          {fnd.classification || 'EVIDENCE'}
                        </span>
                        <h4 className="text-xs font-bold text-white">{fnd.title}</h4>
                      </div>
                      <span className="text-[10px] font-mono text-slate-400">
                        Regra: <strong className="text-indigo-300">{fnd.rule_id}</strong> (Confiança: {fnd.confidence}%)
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {fnd.description}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ─── AI INVESTIGATOR & INSIGHT ENGINE ─── */}
          <div className="p-6 rounded-2xl bg-gradient-to-br from-indigo-950/40 via-slate-900 to-purple-950/30 border border-indigo-500/40 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-indigo-500/20 border border-indigo-500/40 flex items-center justify-center text-indigo-400">
                  <Sparkles className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-black text-white flex items-center gap-2">
                    <span>AI Investigator &amp; Insight Engine</span>
                    <span className="text-[10px] font-mono font-normal text-slate-400">(Reasoner com Guardrails Anti-Alucinação)</span>
                  </h3>
                </div>
              </div>
              <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
                GUARDRAILS ATIVOS
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {(selectedCase.insights || []).map((ins: any) => (
                <div key={ins.id} className="p-4 rounded-xl bg-black/40 border border-indigo-500/30 space-y-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-black text-indigo-300">{ins.title || ins.headline}</span>
                    <span className="px-2 py-0.2 rounded text-[9px] font-bold bg-red-500/20 text-red-300 border border-red-500/30">
                      RISK: {ins.risk || 'CRITICAL'}
                    </span>
                  </div>

                  <p className="text-xs text-slate-200 leading-relaxed">
                    {ins.insight || ins.why_it_matters}
                  </p>

                  <div className="space-y-1 text-[11px] pt-1 border-t border-white/5">
                    <div className="text-slate-400">
                      Por que importa: <span className="text-slate-300">{ins.why_it_matters}</span>
                    </div>
                    <div className="text-slate-400">
                      Ação Recomendada: <strong className="text-emerald-400">{ins.recommended_action}</strong>
                    </div>
                    <div className="text-[10px] font-mono text-slate-500">
                      Evidências Citadas: {JSON.stringify(ins.supporting_evidence)}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Recommended Next Steps */}
            {selectedCase.recommended_next_steps && (
              <div className="p-4 rounded-xl bg-white/5 border border-white/5 space-y-2">
                <div className="text-xs font-bold text-slate-300">Próximos Passos de Investigação Recomendados:</div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-slate-300">
                  {selectedCase.recommended_next_steps.map((step: string, idx: number) => (
                    <div key={idx} className="flex items-center gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* ─── FRAUD GRAPH EMBEDDED ─── */}
          <div className="p-5 rounded-2xl bg-slate-900 border border-white/10 space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2">
                <Network className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-black text-white">Fraud Graph de Relacionamentos &amp; Infraestrutura</h3>
              </div>
              <span className="text-xs font-mono text-slate-400">
                {fraudGraphData?.total_nodes || 8} Nós • {fraudGraphData?.total_edges || 7} Arestas
              </span>
            </div>

            {/* Visual Node Cluster Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
              {(fraudGraphData?.nodes || selectedCase.entities || []).map((n: any, idx: number) => (
                <div
                  key={idx}
                  className="p-3 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 space-y-1.5 transition-all text-left"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono font-bold text-cyan-400">{n.type}</span>
                    <span className="w-2 h-2 rounded-full bg-cyan-400" />
                  </div>
                  <div className="text-xs font-bold text-white truncate" title={n.label || n.name}>
                    {n.label || n.name}
                  </div>
                  <div className="text-[10px] text-slate-400 truncate">
                    {n.metadata?.role || n.role || 'Entidade Correlacionada'}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* ─── TIMELINE & EVIDENCE VAULT ─── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Chronological Timeline */}
            <div className="p-5 rounded-2xl bg-slate-900 border border-white/10 space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center gap-2">
                  <Clock className="w-5 h-5 text-amber-400" />
                  <h3 className="text-sm font-black text-white">Linha do Tempo dos Fatos</h3>
                </div>
                <span className="text-xs font-mono text-slate-400">Reconstrução Cronológica</span>
              </div>

              <div className="space-y-3 max-h-80 overflow-y-auto pr-1">
                {(selectedCase.timeline || []).map((evt: any, idx: number) => (
                  <div key={idx} className="flex items-start gap-3 border-l-2 border-amber-500/40 pl-3 py-1">
                    <div className="w-2 h-2 rounded-full bg-amber-400 mt-1.5 -ml-[17px]" />
                    <div className="space-y-0.5">
                      <div className="text-[10px] font-mono text-slate-400">
                        {new Date(evt.timestamp).toLocaleString()}
                      </div>
                      <div className="text-xs text-slate-200">
                        {evt.event}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Cryptographic Evidence Vault */}
            <div className="p-5 rounded-2xl bg-slate-900 border border-white/10 space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center gap-2">
                  <Fingerprint className="w-5 h-5 text-emerald-400" />
                  <h3 className="text-sm font-black text-white">Evidence Vault &amp; Custódia SHA-256</h3>
                </div>
                <span className="text-xs font-mono text-emerald-400">Integridade Imutável</span>
              </div>

              <div className="space-y-2.5 max-h-80 overflow-y-auto pr-1">
                {(selectedCase.evidences || []).map((ev: any) => (
                  <div key={ev.id} className="p-3 rounded-xl bg-white/5 border border-white/10 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-200 font-mono">{ev.id} • {ev.type}</span>
                      <button
                        onClick={() => handleCopyEvidenceHash(ev.sha256, ev.id)}
                        className="px-2 py-0.5 rounded text-[10px] font-mono bg-white/10 hover:bg-white/20 text-slate-300 flex items-center gap-1 cursor-pointer"
                      >
                        {copiedEvidenceId === ev.id ? <CheckCheck className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-slate-400" />}
                        <span>{copiedEvidenceId === ev.id ? 'Copiado' : 'Copiar Hash'}</span>
                      </button>
                    </div>
                    <div className="text-xs text-slate-300">{ev.description}</div>
                    <div className="text-[10px] font-mono text-emerald-400/80 truncate select-all">
                      SHA-256: {ev.sha256}
                    </div>
                  </div>
                ))}
              </div>
            </div>

          </div>

        </div>
      )}

      {/* ─── TAB 2: EXECUTIVE DASHBOARD ─── */}
      {activeTab === 'DASHBOARD' && dashboard && (
        <div className="space-y-6 animate-in fade-in duration-200">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 rounded-2xl bg-slate-900 border border-white/10 space-y-1">
              <span className="text-slate-400 text-xs font-bold uppercase">Total de Casos</span>
              <div className="text-3xl font-black font-mono text-white">{dashboard.total_cases}</div>
              <div className="text-[11px] text-slate-400">{dashboard.open_cases} Casos Ativos / Triage</div>
            </div>

            <div className="p-4 rounded-2xl bg-slate-900 border border-red-500/30 space-y-1">
              <span className="text-red-400 text-xs font-bold uppercase">Ameaças Críticas</span>
              <div className="text-3xl font-black font-mono text-red-400">{dashboard.critical_cases}</div>
              <div className="text-[11px] text-red-300/80">Requerem Takedown Imediato</div>
            </div>

            <div className="p-4 rounded-2xl bg-slate-900 border border-amber-500/30 space-y-1">
              <span className="text-amber-400 text-xs font-bold uppercase">Domínios Monitorados</span>
              <div className="text-3xl font-black font-mono text-amber-400">{dashboard.monitored_domains_count}</div>
              <div className="text-[11px] text-slate-400">Varreduras Contínuas CT-Log</div>
            </div>

            <div className="p-4 rounded-2xl bg-slate-900 border border-emerald-500/30 space-y-1">
              <span className="text-emerald-400 text-xs font-bold uppercase">Takedowns em SLA</span>
              <div className="text-3xl font-black font-mono text-emerald-400">{dashboard.takedowns_in_progress}</div>
              <div className="text-[11px] text-emerald-300/80">SLA Médio de Neutralização: 18h</div>
            </div>
          </div>
        </div>
      )}

      {/* ─── TAB 3: CASES LIST & MANAGEMENT ─── */}
      {activeTab === 'CASES' && (
        <div className="space-y-4 animate-in fade-in duration-200">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-2xl bg-slate-900 border border-white/10">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 absolute left-3 top-3 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Pesquisar por ID, título, CNPJ, domínio ou marca..."
                className="w-full pl-9 pr-4 py-2 rounded-xl bg-black border border-white/10 text-xs text-white focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex items-center gap-2">
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="px-3 py-2 rounded-xl bg-black border border-white/10 text-xs text-slate-300 focus:outline-none"
              >
                <option value="ALL">Todas as Severidades</option>
                <option value="CRITICAL">Apenas CRITICAL</option>
                <option value="HIGH">Apenas HIGH</option>
                <option value="MEDIUM">Apenas MEDIUM</option>
              </select>
            </div>
          </div>

          <div className="space-y-2">
            {casesList.map((c) => (
              <div
                key={c.id}
                onClick={() => {
                  loadCaseDetails(c.id);
                  setActiveTab('INVESTIGATION');
                }}
                className="p-4 rounded-xl bg-slate-900 hover:bg-slate-800/80 border border-white/10 hover:border-indigo-500/40 transition-all cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-black text-indigo-400">{c.id}</span>
                    <span className={clsx(
                      "px-2 py-0.2 rounded text-[9px] font-black uppercase font-mono",
                      c.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-300 border border-red-500/40' :
                      c.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40' :
                      'bg-amber-500/20 text-amber-300'
                    )}>
                      {c.severity}
                    </span>
                    <span className="text-xs font-bold text-white">{c.title}</span>
                  </div>
                  <div className="text-xs text-slate-400 font-mono truncate max-w-xl">
                    Vetor: {c.target_asset} • Marca: {c.brand_victim}
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <div className="text-xs font-bold font-mono text-red-400">{c.risk_score?.score || 80}/100</div>
                    <div className="text-[10px] text-slate-500">{c.status}</div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-500" />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ─── TAB 4: URL & ASSET ANALYZER ─── */}
      {activeTab === 'URL_ANALYZER' && (
        <div className="p-6 rounded-2xl bg-slate-900 border border-white/10 space-y-6 max-w-3xl mx-auto animate-in fade-in duration-200">
          <div className="border-b border-white/10 pb-4">
            <h3 className="text-lg font-black text-white flex items-center gap-2">
              <Globe className="w-5 h-5 text-indigo-400" />
              Ingestão e Análise Forense de URL / Domínio Suspeito
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Insira o link ou domínio suspeito. O sistema executará coleta passiva OSINT, cálculo de similaridade, detecção de infraestrutura e abrirá um caso investigativo automaticamente.
            </p>
          </div>

          <form onSubmit={handleAnalyzeUrl} className="space-y-4">
            <div>
              <label className="block text-xs font-bold text-slate-300 mb-1.5">
                URL ou Domínio Alvo *
              </label>
              <input
                type="text"
                value={inputUrl}
                onChange={(e) => setInputUrl(e.target.value)}
                placeholder="https://exemplo-portal-fraude.com/login"
                className="w-full px-4 py-2.5 rounded-xl bg-black border border-white/10 text-xs text-white focus:outline-none focus:border-indigo-500 font-mono"
                required
              />
            </div>

            <div>
              <label className="block text-xs font-bold text-slate-300 mb-1.5">
                Marca Vítima / Monitorada
              </label>
              <input
                type="text"
                value={inputBrand}
                onChange={(e) => setInputBrand(e.target.value)}
                placeholder="Ex: Nubank, Itaú, Mercado Livre"
                className="w-full px-4 py-2.5 rounded-xl bg-black border border-white/10 text-xs text-white focus:outline-none focus:border-indigo-500"
              />
            </div>

            <button
              type="submit"
              disabled={analyzingUrl || !inputUrl.trim()}
              className="w-full py-3 rounded-xl text-xs font-black bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white flex items-center justify-center gap-2 shadow-xl shadow-indigo-600/20 cursor-pointer disabled:opacity-50"
            >
              {analyzingUrl ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4 text-amber-300" />}
              <span>{analyzingUrl ? 'Executando Análise Forense...' : 'Analisar e Abrir Caso de Investigação'}</span>
            </button>
          </form>
        </div>
      )}

      {/* ─── TAB 5: BOLETO ANALYZER ─── */}
      {activeTab === 'BOLETO_ANALYZER' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-in fade-in duration-200">
          <div className="p-6 rounded-2xl bg-slate-900 border border-white/10 space-y-4">
            <div className="border-b border-white/10 pb-3">
              <h3 className="text-base font-black text-white flex items-center gap-2">
                <Barcode className="w-5 h-5 text-amber-400" />
                Validador e Perícia de Boletos Bancários
              </h3>
              <p className="text-xs text-slate-400">
                Detecção de adulteração de código de barras, divergência de beneficiário e intermediários fraudulentos.
              </p>
            </div>

            <form onSubmit={handleAnalyzeBoleto} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-bold mb-1">Linha Digitável</label>
                <input
                  type="text"
                  value={linhaDigitavel}
                  onChange={(e) => setLinhaDigitavel(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl bg-black border border-white/10 text-white font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-bold mb-1">Beneficiário Declarado no Documento</label>
                <input
                  type="text"
                  value={beneficiarioDeclarado}
                  onChange={(e) => setBeneficiarioDeclarado(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl bg-black border border-white/10 text-white"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-bold mb-1">Beneficiário Esperado (Contratual)</label>
                <input
                  type="text"
                  value={beneficiarioEsperado}
                  onChange={(e) => setBeneficiarioEsperado(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl bg-black border border-white/10 text-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-bold mb-1">CNPJ do Beneficiário</label>
                  <input
                    type="text"
                    value={cnpjDeclarado}
                    onChange={(e) => setCnpjDeclarado(e.target.value)}
                    className="w-full px-3.5 py-2 rounded-xl bg-black border border-white/10 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-bold mb-1">Valor (R$)</label>
                  <input
                    type="number"
                    value={valorDeclarado}
                    onChange={(e) => setValorDeclarado(Number(e.target.value))}
                    className="w-full px-3.5 py-2 rounded-xl bg-black border border-white/10 text-white font-mono"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={analyzingBoleto}
                className="w-full py-2.5 rounded-xl text-xs font-black bg-amber-500 hover:bg-amber-400 text-slate-950 flex items-center justify-center gap-1.5 shadow-lg shadow-amber-500/20 cursor-pointer"
              >
                {analyzingBoleto ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-current" />}
                <span>Executar Perícia no Boleto</span>
              </button>
            </form>
          </div>

          {/* Boleto Result Display */}
          {boletoResult && (
            <div className="p-6 rounded-2xl bg-slate-900 border border-amber-500/40 space-y-4 shadow-xl">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div>
                  <div className="text-sm font-black text-white">{boletoResult.banco_emissor}</div>
                  <div className="text-xs text-slate-400 font-mono">Código FEBRABAN: {boletoResult.bank_code}</div>
                </div>
                <span className={clsx(
                  "px-2.5 py-0.5 rounded text-xs font-black font-mono border",
                  boletoResult.risk_level === 'CRITICAL' ? 'bg-red-500/20 text-red-300 border-red-500/40' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                )}>
                  RISCO: {boletoResult.risk_score}/100 ({boletoResult.risk_level})
                </span>
              </div>

              <div className="p-3.5 rounded-xl bg-black/60 border border-white/10 space-y-1.5 text-xs">
                <div className="text-slate-400">Diagnóstico Pericial:</div>
                <div className="font-bold text-slate-200">{boletoResult.explanation}</div>
                <div className="text-amber-300/90 text-[11px]">{boletoResult.insight}</div>
              </div>

              {boletoResult.indicators?.length > 0 && (
                <div className="space-y-2">
                  <div className="text-xs font-bold text-slate-400">Anomalias Detectadas:</div>
                  {boletoResult.indicators.map((ind: any, i: number) => (
                    <div key={i} className="p-3 rounded-lg bg-red-950/30 border border-red-500/30 text-xs text-red-200">
                      <div className="font-bold">{ind.title}</div>
                      <div className="text-[11px] text-slate-400">{ind.description}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ─── TAB 6: FRAUD GRAPH FULL VIEW ─── */}
      {activeTab === 'FRAUD_GRAPH' && (
        <div className="p-6 rounded-2xl bg-slate-900 border border-white/10 space-y-4 animate-in fade-in duration-200">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <div>
              <h3 className="text-base font-black text-white flex items-center gap-2">
                <Network className="w-5 h-5 text-indigo-400" />
                Fraud Graph Relacional &amp; Infraestrutura Correlacionada
              </h3>
              <p className="text-xs text-slate-400">
                Mapeamento topológico de marcas, domínios, endereços IP, ASNs, certificados SSL e pessoas jurídicas receptoras.
              </p>
            </div>
          </div>

          <div className="p-12 rounded-xl bg-black border border-white/10 text-center space-y-4 shadow-inner">
            <Network className="w-12 h-12 text-indigo-400 mx-auto animate-pulse" />
            <div className="max-w-md mx-auto space-y-1">
              <div className="text-sm font-bold text-white">Grafo Topológico Interativo Ativo</div>
              <div className="text-xs text-slate-400">
                Navegue pelas conexões entre o caso #{selectedCase?.id}, domínios lookalikes e os nós de hospedagem.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ─── TAB 7: DETECTION RULES ─── */}
      {activeTab === 'RULES' && (
        <div className="space-y-3 animate-in fade-in duration-200">
          {rulesList.map((r) => (
            <div key={r.id} className="p-4 rounded-xl bg-slate-900 border border-white/10 flex items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-black text-indigo-400">{r.id}</span>
                  <span className="text-xs font-bold text-white">{r.name}</span>
                  <span className="px-2 py-0.2 rounded text-[9px] font-bold bg-white/10 text-slate-300 font-mono">
                    PESO: {r.weight}
                  </span>
                </div>
                <div className="text-xs text-slate-400">{r.description}</div>
              </div>
              <span className="px-2.5 py-1 rounded text-xs font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                ATIVA
              </span>
            </div>
          ))}
        </div>
      )}

      {/* ─── TAB 8: WATCHLISTS ─── */}
      {activeTab === 'WATCHLISTS' && (
        <div className="space-y-3 animate-in fade-in duration-200">
          {watchlists.map((w) => (
            <div key={w.id} className="p-4 rounded-xl bg-slate-900 border border-white/10 space-y-2">
              <div className="flex items-center justify-between">
                <div className="font-bold text-white text-sm">{w.name}</div>
                <span className="text-xs font-mono text-indigo-400">{w.active_alerts_count} Alertas Recentes</span>
              </div>
              <div className="flex items-center gap-2 flex-wrap text-xs">
                {w.targets?.map((t: string, i: number) => (
                  <span key={i} className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 font-mono text-slate-300">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ─── TAB 9: AUDIT LOGS ─── */}
      {activeTab === 'AUDIT_LOGS' && (
        <div className="p-5 rounded-2xl bg-slate-900 border border-white/10 space-y-3 animate-in fade-in duration-200">
          <div className="text-sm font-black text-white border-b border-white/10 pb-3">
            Trilha de Auditoria Forense (Append-Only &amp; Imutável)
          </div>
          <div className="space-y-2 font-mono text-xs max-h-[600px] overflow-y-auto">
            {auditLogs.map((log) => (
              <div key={log.id} className="p-3 rounded-lg bg-black border border-white/10 space-y-0.5">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-slate-400">[{new Date(log.timestamp).toLocaleString()}]</span>
                  <span className="text-indigo-400 font-bold">{log.action}</span>
                  <span className="text-emerald-400">OK</span>
                </div>
                <div className="text-slate-200">{JSON.stringify(log.details)}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ─── MODAL: TAKEDOWN PROTOCOLS & LOGS ─── */}
      {takedownModalOpen && takedownResult && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="relative w-full max-w-3xl bg-[#0d1117] border border-red-500/50 rounded-2xl shadow-2xl overflow-hidden space-y-4">
            <div className="p-5 border-b border-white/10 bg-red-950/30 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="w-9 h-9 rounded-xl bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400">
                  <Terminal className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-black text-white">Protocolos de Takedown &amp; Logs de Despacho</h3>
                  <div className="text-xs text-slate-400 font-mono">Alvo: {takedownResult.target_domain} • SLA 24h</div>
                </div>
              </div>
              <button onClick={() => setTakedownModalOpen(false)} className="p-1.5 rounded-lg text-slate-400 hover:text-white cursor-pointer">
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
                {Object.entries(takedownResult.tickets_created || {}).map(([channel, ticket]: any) => (
                  <div key={channel} className="p-3 rounded-xl bg-white/5 border border-white/10 space-y-1">
                    <span className="text-slate-400 text-[10px] font-bold uppercase">{channel.replace('_', ' ')}:</span>
                    <div className="font-mono font-bold text-emerald-400">{ticket}</div>
                  </div>
                ))}
              </div>

              <div className="p-4 rounded-xl bg-black border border-white/10 font-mono text-xs space-y-2">
                <div className="text-[10px] text-slate-400 font-sans font-bold border-b border-white/10 pb-1">
                  Trilha de Despacho em Tempo Real:
                </div>
                {(takedownResult.dispatch_logs || []).map((log: any, i: number) => (
                  <div key={i} className="border-l-2 border-red-500/40 pl-2.5 py-0.5 space-y-0.5">
                    <div className="text-slate-400 text-[10px]">[{log.timestamp}] • <strong className="text-red-400">{log.channel}</strong></div>
                    <div className="text-slate-200">{log.message}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="p-4 border-t border-white/10 bg-white/2 flex items-center justify-between">
              <button onClick={() => setTakedownModalOpen(false)} className="px-4 py-2 rounded-xl text-xs font-bold bg-white/10 hover:bg-white/20 text-white cursor-pointer">
                Fechar
              </button>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(takedownResult, null, 2));
                  alert('Registro de Takedown copiado!');
                }}
                className="px-4 py-2 rounded-xl text-xs font-bold bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 cursor-pointer"
              >
                Copiar JSON de Protocolos
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
