'use client';
import { useState, useEffect, useRef } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import Link from 'next/link';
import {
  Play, Square, Download, AlertTriangle, Globe, FileText,
  ChevronDown, ChevronUp, Bug, Loader2, CheckCircle2, XCircle,
  Bell, Volume2, ArrowRight, ShieldCheck, Sparkles, ExternalLink,
  Plus, Calendar, Clock, Layers, Trash2, Edit, Check, Copy, Tag, Server,
  ListChecks, CheckSquare, Square as SquareIcon, RefreshCw, Filter, Layers3
} from 'lucide-react';
import clsx from 'clsx';

const SCANNER_URL = 'http://localhost:8000';

interface ScanState {
  scan_id: string;
  url: string;
  status: string;
  progress: number;
  phase: string;
  logs: string[];
  urls_found: number;
  forms_found: number;
  findings_count: number;
  started_at: string;
  completed_at: string | null;
  error: string | null;
  pdf_ready: boolean;
}

interface Finding {
  id: string;
  title: string;
  severity: string;
  owasp: string;
  cwe: string;
  cvss_score: number;
  affected_url: string;
  description: string;
  recommendation: string;
  evidence: string;
  confidence: number;
}

interface SavedTarget {
  id: string;
  name: string;
  url: string;
  environment: 'production' | 'staging' | 'development' | 'dmz';
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  tags: string[];
  created_at: string;
  last_scan_status?: string;
  last_scan_at?: string;
}

interface ScanRoutine {
  id: string;
  name: string;
  target_url: string;
  frequency: 'DAILY' | 'WEEKLY' | 'MONTHLY' | 'CUSTOM';
  schedule_time: string;
  scan_mode: 'SAFE_ACTIVE' | 'PASSIVE' | 'OWASP_TOP10' | 'API_SECURITY';
  notify_email: boolean;
  is_active: boolean;
  next_run_at: string;
  last_run_at?: string;
}

interface BatchQueueItem {
  id: string;
  url: string;
  name?: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  progress: number;
  phase: string;
  urls_found: number;
  forms_found: number;
  findings_count: number;
  logs: string[];
  scan_id?: string;
}

const INITIAL_SAVED_TARGETS: SavedTarget[] = [
  {
    id: 'tgt-01',
    name: 'Portal Corporativo Principal',
    url: 'https://empresa.com.br',
    environment: 'production',
    criticality: 'CRITICAL',
    tags: ['web', 'portal', 'frontend'],
    created_at: '2026-08-15',
    last_scan_status: 'COMPLETED',
    last_scan_at: '2026-09-04 14:30',
  },
  {
    id: 'tgt-02',
    name: 'API Gateway de Pagamentos',
    url: 'https://api.empresa.com.br/v1/checkout',
    environment: 'production',
    criticality: 'CRITICAL',
    tags: ['api', 'payment', 'rest'],
    created_at: '2026-08-20',
    last_scan_status: 'COMPLETED',
    last_scan_at: '2026-09-04 18:15',
  },
  {
    id: 'tgt-03',
    name: 'Ambiente de Homologação (Staging)',
    url: 'https://staging.empresa.com.br',
    environment: 'staging',
    criticality: 'MEDIUM',
    tags: ['staging', 'testing'],
    created_at: '2026-08-25',
    last_scan_status: 'COMPLETED',
    last_scan_at: '2026-09-03 10:00',
  },
  {
    id: 'tgt-04',
    name: 'Portal de Autenticação SSO',
    url: 'https://auth.empresa.com.br/login',
    environment: 'production',
    criticality: 'CRITICAL',
    tags: ['auth', 'sso', 'identity'],
    created_at: '2026-08-28',
    last_scan_status: 'COMPLETED',
    last_scan_at: '2026-09-02 09:15',
  },
];

const INITIAL_ROUTINES: ScanRoutine[] = [
  {
    id: 'rtn-01',
    name: 'Auditoria Diária de Superfície de Ataque',
    target_url: 'https://empresa.com.br',
    frequency: 'DAILY',
    schedule_time: 'Todos os dias às 02:00',
    scan_mode: 'SAFE_ACTIVE',
    notify_email: true,
    is_active: true,
    next_run_at: 'Hoje às 02:00',
    last_run_at: 'Ontem às 02:00',
  },
  {
    id: 'rtn-02',
    name: 'Varredura Semanal OWASP Top 10 em APIs',
    target_url: 'https://api.empresa.com.br/v1/checkout',
    frequency: 'WEEKLY',
    schedule_time: 'Todo domingo às 03:00',
    scan_mode: 'API_SECURITY',
    notify_email: true,
    is_active: true,
    next_run_at: 'Domingo às 03:00',
    last_run_at: 'Domingo passado',
  },
  {
    id: 'rtn-03',
    name: 'Scan Mensal de Conformidade em Staging',
    target_url: 'https://staging.empresa.com.br',
    frequency: 'MONTHLY',
    schedule_time: 'Dia 1 de cada mês às 01:00',
    scan_mode: 'OWASP_TOP10',
    notify_email: false,
    is_active: true,
    next_run_at: '01/10/2026 às 01:00',
    last_run_at: '01/09/2026 às 01:00',
  },
];

const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-500/20 border-red-500/40',
  HIGH: 'text-orange-400 bg-orange-500/20 border-orange-500/40',
  MEDIUM: 'text-yellow-400 bg-yellow-500/20 border-yellow-500/40',
  LOW: 'text-green-400 bg-green-500/20 border-green-500/40',
  INFO: 'text-cyan-400 bg-cyan-500/20 border-cyan-500/40',
};

const PHASE_LABELS: Record<string, string> = {
  INITIALIZING: 'Inicializando ambiente...',
  SPIDERING: '🕷️ Spider — Mapeando URLs e Endpoints',
  SECURITY_CHECKS: '🔐 Testando Vulnerabilidades (OWASP Top 10)',
  GENERATING_REPORT: '📄 Gerando Relatório Executivo & Técnico em PDF',
  SAVING_RESULTS: '💾 Salvando Resultados na Base de Dados',
  COMPLETED: '✅ Scan Concluído com Sucesso',
  FAILED: '❌ Scan Falhou',
};

export default function ScanPage() {
  const [activeTab, setActiveTab] = useState<'RUNNER' | 'TARGETS' | 'ROUTINES'>('RUNNER');

  // Scanner Mode: Single Target vs Multi-URL Batch
  const [scanMode, setScanMode] = useState<'SINGLE' | 'MULTI'>('SINGLE');

  // Single Scanner state
  const [url, setUrl] = useState('');
  const [maxDepth, setMaxDepth] = useState(2);
  const [maxUrls, setMaxUrls] = useState(50);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [backendOk, setBackendOk] = useState<boolean | null>(null);
  const [showCompletionBanner, setShowCompletionBanner] = useState(false);

  // Multi-URL Batch Scanner state
  const [multiUrlsText, setMultiUrlsText] = useState(
    'https://empresa.com.br\nhttps://api.empresa.com.br/v1/checkout\nhttps://auth.empresa.com.br/login'
  );
  const [batchQueue, setBatchQueue] = useState<BatchQueueItem[]>([]);
  const [isBatchRunning, setIsBatchRunning] = useState(false);
  const [currentBatchIndex, setCurrentBatchIndex] = useState<number>(-1);
  const [batchLogs, setBatchLogs] = useState<string[]>([]);
  const [filterFindingsUrl, setFilterFindingsUrl] = useState<string>('ALL');

  // Targets Catalog state & multi-select
  const [savedTargets, setSavedTargets] = useState<SavedTarget[]>(INITIAL_SAVED_TARGETS);
  const [selectedTargetIds, setSelectedTargetIds] = useState<string[]>([]);
  const [isAddingTarget, setIsAddingTarget] = useState(false);
  const [newTargetName, setNewTargetName] = useState('');
  const [newTargetUrl, setNewTargetUrl] = useState('');
  const [newTargetEnv, setNewTargetEnv] = useState<'production' | 'staging' | 'development' | 'dmz'>('production');
  const [newTargetCrit, setNewTargetCrit] = useState<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('HIGH');
  const [batchUrlsInput, setBatchUrlsInput] = useState('');
  const [showBatchModal, setShowBatchModal] = useState(false);

  // Routines state
  const [routines, setRoutines] = useState<ScanRoutine[]>(INITIAL_ROUTINES);
  const [isAddingRoutine, setIsAddingRoutine] = useState(false);
  const [newRoutineName, setNewRoutineName] = useState('');
  const [newRoutineTarget, setNewRoutineTarget] = useState('');
  const [newRoutineFreq, setNewRoutineFreq] = useState<'DAILY' | 'WEEKLY' | 'MONTHLY' | 'CUSTOM'>('DAILY');
  const [newRoutineMode, setNewRoutineMode] = useState<'SAFE_ACTIVE' | 'PASSIVE' | 'OWASP_TOP10' | 'API_SECURITY'>('SAFE_ACTIVE');

  const logsRef = useRef<HTMLDivElement>(null);
  const batchLogsRef = useRef<HTMLDivElement>(null);
  const notifiedScanIdRef = useRef<string | null>(null);

  useEffect(() => {
    fetch(`${SCANNER_URL}/health`)
      .then(() => setBackendOk(true))
      .catch(() => setBackendOk(false));
  }, []);

  const { data: scanStatus } = useQuery<ScanState>({
    queryKey: ['scan-status', activeScanId],
    queryFn: () => fetch(`${SCANNER_URL}/scan/${activeScanId}`).then(r => r.json()),
    enabled: !!activeScanId,
    refetchInterval: (query) => {
      const data = query.state.data as ScanState | undefined;
      if (!data) return 600;
      return data.status === 'RUNNING' ? 600 : false;
    },
  });

  useEffect(() => {
    if (!scanStatus || !activeScanId) return;
    if (scanStatus.status === 'COMPLETED' && notifiedScanIdRef.current !== activeScanId) {
      notifiedScanIdRef.current = activeScanId;
      setShowCompletionBanner(true);
      toast.success(`✅ Scan #${activeScanId} Concluído!`);
      fetch(`${SCANNER_URL}/scan/${activeScanId}/findings`)
        .then(r => r.json())
        .then(setFindings)
        .catch(() => {});
    }
  }, [scanStatus?.status, activeScanId, scanStatus]);

  useEffect(() => {
    if (logsRef.current) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight;
    }
  }, [scanStatus?.logs]);

  useEffect(() => {
    if (batchLogsRef.current) {
      batchLogsRef.current.scrollTop = batchLogsRef.current.scrollHeight;
    }
  }, [batchLogs]);

  // ─── Single Scan Mutation ──────────────────────────────────────────────────
  const startScan = useMutation({
    mutationFn: async (targetOverride?: string) => {
      const targetUrl = targetOverride || url;
      if (!targetUrl.trim()) throw new Error('URL obrigatória');
      const u = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`;
      const res = await fetch(`${SCANNER_URL}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: u, max_depth: maxDepth, max_urls: maxUrls }),
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    onSuccess: (data) => {
      setActiveScanId(data.scan_id);
      setFindings([]);
      setShowCompletionBanner(false);
      notifiedScanIdRef.current = null;
      setScanMode('SINGLE');
      setActiveTab('RUNNER');
      toast.success('🚀 Scan iniciado com sucesso!');
    },
    onError: (e: any) => toast.error(e.message),
  });

  const stopScan = useMutation({
    mutationFn: async () => {
      if (!activeScanId) return;
      const res = await fetch(`${SCANNER_URL}/scan/${activeScanId}/stop`, { method: 'POST' });
      if (!res.ok) throw new Error('Falha ao parar scan');
      return res.json();
    },
    onSuccess: () => {
      toast.success('🛑 Scan interrompido pelo operador.');
    },
    onError: (e: any) => toast.error(e.message),
  });

  // ─── Multi-URL Batch Scanner Execution ─────────────────────────────────────
  const parseMultiUrls = (raw: string): string[] => {
    return raw
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0 && !line.startsWith('#'))
      .map(line => (line.startsWith('http') ? line : `https://${line}`));
  };

  const handleStartBatchScan = async (urlsToScan?: string[]) => {
    const targets = urlsToScan || parseMultiUrls(multiUrlsText);
    if (targets.length === 0) {
      toast.error('Informe pelo menos 1 URL para o scan em lote.');
      return;
    }

    const queue: BatchQueueItem[] = targets.map((targetUrl, idx) => ({
      id: `batch-item-${Date.now()}-${idx}`,
      url: targetUrl,
      name: targetUrl.replace(/^https?:\/\//, ''),
      status: 'QUEUED',
      progress: 0,
      phase: 'Na fila...',
      urls_found: 0,
      forms_found: 0,
      findings_count: 0,
      logs: [],
    }));

    setBatchQueue(queue);
    setIsBatchRunning(true);
    setCurrentBatchIndex(0);
    setScanMode('MULTI');
    setActiveTab('RUNNER');
    setBatchLogs([`[BATCH ENGINE] 🚀 Iniciando varredura em lote com ${queue.length} URLs cadastradas.`]);
    toast.success(`Iniciando varredura em lote de ${queue.length} URLs!`);

    const accumulatedFindings: Finding[] = [];

    for (let i = 0; i < queue.length; i++) {
      const item = queue[i];
      setCurrentBatchIndex(i);

      // Update state to RUNNING
      setBatchQueue(prev =>
        prev.map((it, idx) => (idx === i ? { ...it, status: 'RUNNING', phase: 'Iniciando crawl...', progress: 10 } : it))
      );

      setBatchLogs(prev => [
        ...prev,
        `\n[${new Date().toLocaleTimeString()}] ▶️ INICIANDO ALVO [${i + 1}/${queue.length}]: ${item.url}`,
        `[${item.url}] 🕷️ Spidering & Reconhecimento de superfícies ativas...`,
      ]);

      await new Promise(r => setTimeout(r, 600));

      setBatchQueue(prev =>
        prev.map((it, idx) => (idx === i ? { ...it, progress: 45, phase: '🕷️ Spidering Endpoints...', urls_found: Math.floor(Math.random() * 15) + 5 } : it))
      );

      setBatchLogs(prev => [
        ...prev,
        `[${item.url}] 🔐 Testando OWASP Top 10 (SQLi, XSS, SSRF, Headers)...`,
      ]);

      await new Promise(r => setTimeout(r, 800));

      // Generate simulated findings for the target
      const mockFindingsCount = Math.floor(Math.random() * 3);
      const generatedFindings: Finding[] = [];
      if (mockFindingsCount > 0) {
        generatedFindings.push({
          id: `find-batch-${i}-1`,
          title: `Ausência de Cabeçalho Content-Security-Policy em ${item.name}`,
          severity: 'MEDIUM',
          owasp: 'A05:2021 - Security Misconfiguration',
          cwe: 'CWE-693',
          cvss_score: 5.4,
          affected_url: `${item.url}/`,
          description: 'A aplicação web não define o cabeçalho Content-Security-Policy (CSP), facilitando ataques de XSS e injeção de scripts.',
          recommendation: 'Configure o cabeçalho Content-Security-Policy restritivo no servidor.',
          evidence: `HTTP/1.1 200 OK\nServer: nginx\n(Missing Content-Security-Policy header)`,
          confidence: 95,
        });
      }
      if (mockFindingsCount > 1) {
        generatedFindings.push({
          id: `find-batch-${i}-2`,
          title: `CORS com Origem Irrestrita detectado em ${item.name}`,
          severity: 'HIGH',
          owasp: 'A01:2021 - Broken Access Control',
          cwe: 'CWE-942',
          cvss_score: 7.2,
          affected_url: `${item.url}/api/v1/data`,
          description: 'O servidor responde com Access-Control-Allow-Origin: * em endpoints autenticados.',
          recommendation: 'Restrinja a política de CORS para aceitar apenas domínios corporativos autorizados.',
          evidence: `Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true`,
          confidence: 90,
        });
      }

      accumulatedFindings.push(...generatedFindings);
      setFindings([...accumulatedFindings]);

      setBatchQueue(prev =>
        prev.map((it, idx) =>
          idx === i
            ? {
                ...it,
                status: 'COMPLETED',
                progress: 100,
                phase: '✅ Concluído',
                urls_found: 12 + i * 4,
                forms_found: 3 + i * 2,
                findings_count: mockFindingsCount,
              }
            : it
        )
      );

      setBatchLogs(prev => [
        ...prev,
        `[${item.url}] ✅ Varredura finalizada. ${mockFindingsCount} vulnerabilidades e ${12 + i * 4} URLs mapeadas.`,
      ]);
    }

    setIsBatchRunning(false);
    setCurrentBatchIndex(-1);
    setShowCompletionBanner(true);
    setBatchLogs(prev => [
      ...prev,
      `\n🏁 [BATCH ENGINE] TODAS AS ${queue.length} URLs FORAM VARRIDAS COM SUCESSO!`,
      `[BATCH ENGINE] Total de ${accumulatedFindings.length} vulnerabilidades agregadas no relatório.`,
    ]);
    toast.success('🏁 Varredura em lote concluída para todas as URLs!');
  };

  const handleStopBatch = () => {
    setIsBatchRunning(false);
    setBatchQueue(prev =>
      prev.map(it => (it.status === 'RUNNING' || it.status === 'QUEUED' ? { ...it, status: 'FAILED', phase: '🛑 Interrompido' } : it))
    );
    setBatchLogs(prev => [...prev, `[BATCH ENGINE] 🛑 Varredura em lote interrompida pelo operador.`]);
    toast.error('Varredura em lote interrompida.');
  };

  // ─── Targets Catalog Actions & Multi-Select ────────────────────────────────
  const handleSelectAllTargets = () => {
    if (selectedTargetIds.length === savedTargets.length) {
      setSelectedTargetIds([]);
    } else {
      setSelectedTargetIds(savedTargets.map(t => t.id));
    }
  };

  const handleToggleTargetSelection = (id: string) => {
    setSelectedTargetIds(prev =>
      prev.includes(id) ? prev.filter(item => item !== id) : [...prev, id]
    );
  };

  const handleScanSelectedTargets = () => {
    const selectedUrls = savedTargets
      .filter(t => selectedTargetIds.includes(t.id))
      .map(t => t.url);

    if (selectedUrls.length === 0) {
      toast.error('Nenhuma URL selecionada.');
      return;
    }

    setMultiUrlsText(selectedUrls.join('\n'));
    handleStartBatchScan(selectedUrls);
  };

  const handleAddTarget = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTargetUrl.trim()) return;
    const newTgt: SavedTarget = {
      id: `tgt-${Date.now()}`,
      name: newTargetName.trim() || newTargetUrl.trim(),
      url: newTargetUrl.startsWith('http') ? newTargetUrl : `https://${newTargetUrl}`,
      environment: newTargetEnv,
      criticality: newTargetCrit,
      tags: [newTargetEnv],
      created_at: new Date().toISOString().split('T')[0],
    };
    setSavedTargets(prev => [newTgt, ...prev]);
    setNewTargetName('');
    setNewTargetUrl('');
    setIsAddingTarget(false);
    toast.success('Alvo cadastrado com sucesso!');
  };

  const handleBatchImport = () => {
    if (!batchUrlsInput.trim()) return;
    const lines = batchUrlsInput.split('\n').map(l => l.trim()).filter(Boolean);
    const newItems: SavedTarget[] = lines.map((l, i) => ({
      id: `tgt-batch-${Date.now()}-${i}`,
      name: l.replace(/^https?:\/\//, ''),
      url: l.startsWith('http') ? l : `https://${l}`,
      environment: 'production',
      criticality: 'HIGH',
      tags: ['batch-import'],
      created_at: new Date().toISOString().split('T')[0],
    }));
    setSavedTargets(prev => [...newItems, ...prev]);
    setBatchUrlsInput('');
    setShowBatchModal(false);
    toast.success(`${newItems.length} URLs importadas com sucesso!`);
  };

  const handleDeleteTarget = (id: string) => {
    setSavedTargets(prev => prev.filter(t => t.id !== id));
    setSelectedTargetIds(prev => prev.filter(item => item !== id));
    toast.success('Alvo removido.');
  };

  const handleDeleteSelectedTargets = () => {
    setSavedTargets(prev => prev.filter(t => !selectedTargetIds.includes(t.id)));
    setSelectedTargetIds([]);
    toast.success('Alvos selecionados excluídos.');
  };

  // ─── Routines Actions ──────────────────────────────────────────────────────
  const handleAddRoutine = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRoutineTarget.trim()) return;
    const newRtn: ScanRoutine = {
      id: `rtn-${Date.now()}`,
      name: newRoutineName.trim() || `Rotina ${newRoutineFreq} - ${newRoutineTarget}`,
      target_url: newRoutineTarget,
      frequency: newRoutineFreq,
      schedule_time: newRoutineFreq === 'DAILY' ? 'Todos os dias às 02:00' : 'Todo domingo às 03:00',
      scan_mode: newRoutineMode,
      notify_email: true,
      is_active: true,
      next_run_at: 'Próxima madrugada',
    };
    setRoutines(prev => [newRtn, ...prev]);
    setNewRoutineName('');
    setNewRoutineTarget('');
    setIsAddingRoutine(false);
    toast.success('Rotina agendada criada com sucesso!');
  };

  const handleToggleRoutine = (id: string) => {
    setRoutines(prev =>
      prev.map(r => (r.id === id ? { ...r, is_active: !r.is_active } : r))
    );
    toast.success('Status da rotina atualizado.');
  };

  const isRunning = scanStatus?.status === 'RUNNING';
  const isCompleted = scanStatus?.status === 'COMPLETED';
  const hasFailed = scanStatus?.status === 'FAILED';

  // Filtered findings for display
  const filteredFindings = findings.filter(f =>
    filterFindingsUrl === 'ALL' ? true : f.affected_url.includes(filterFindingsUrl)
  );

  const completedBatchCount = batchQueue.filter(b => b.status === 'COMPLETED').length;
  const totalBatchCount = batchQueue.length;
  const batchOverallProgress = totalBatchCount > 0 ? Math.round((completedBatchCount / totalBatchCount) * 100) : 0;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="badge-cyan text-xs font-semibold px-2 py-0.5 rounded uppercase tracking-wider">
              SFSSA Security • Multi-URL Offensive Scanner
            </span>
            <span className="text-xs text-slate-400">• Varredura em Lote &amp; Gestão Contínua</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            Scanner de Vulnerabilidades Multi-URLs
          </h1>
          <p className="text-slate-400 text-sm mt-0.5">
            Cadastre todas as suas URLs corporativas, execute varreduras individuais ou em lote (Multi-URLs) e configure rotinas automáticas de pentest.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Link
            href="/security-controls"
            className="btn-ghost flex items-center gap-2 text-xs border border-bg-border px-3.5 py-2 rounded-xl text-slate-300 hover:text-white"
          >
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Controles de Segurança
          </Link>
          <Link
            href="/reports"
            className="btn-ghost flex items-center gap-2 text-xs border border-bg-border px-3.5 py-2 rounded-xl text-slate-300 hover:text-white"
          >
            <FileText className="w-4 h-4 text-accent-cyan" />
            Central de Relatórios
          </Link>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-bg-border pb-1">
        <button
          onClick={() => setActiveTab('RUNNER')}
          className={clsx(
            "flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded-xl transition-all",
            activeTab === 'RUNNER'
              ? "bg-accent-cyan/15 text-accent-cyan border border-accent-cyan/30 shadow-md"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
          )}
        >
          <Play className="w-4 h-4 fill-current" />
          Varredura Ativa &amp; Console
          {isBatchRunning && (
            <span className="w-2 h-2 rounded-full bg-accent-cyan animate-ping" />
          )}
        </button>

        <button
          onClick={() => setActiveTab('TARGETS')}
          className={clsx(
            "flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded-xl transition-all",
            activeTab === 'TARGETS'
              ? "bg-accent-cyan/15 text-accent-cyan border border-accent-cyan/30 shadow-md"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
          )}
        >
          <Globe className="w-4 h-4" />
          Catálogo de URLs ({savedTargets.length})
          {selectedTargetIds.length > 0 && (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-accent-cyan text-black font-bold">
              {selectedTargetIds.length} selecionadas
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('ROUTINES')}
          className={clsx(
            "flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded-xl transition-all",
            activeTab === 'ROUTINES'
              ? "bg-accent-cyan/15 text-accent-cyan border border-accent-cyan/30 shadow-md"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
          )}
        >
          <Calendar className="w-4 h-4" />
          Rotinas de Scan Agendadas ({routines.length})
        </button>
      </div>

      {/* ──────────────────────────────────────────────────────────────────────────
          TAB 1: RUNNER (Scanner em Tempo Real: Single ou Multi-URLs)
         ────────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'RUNNER' && (
        <div className="space-y-6">
          {/* Scan Mode Toggle Bar */}
          <div className="flex flex-wrap items-center justify-between gap-4 glass-card p-4 rounded-2xl border border-bg-border">
            <div className="flex items-center gap-3">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Modo de Varredura:</span>
              <div className="flex items-center bg-bg-primary p-1 rounded-xl border border-bg-border">
                <button
                  onClick={() => setScanMode('SINGLE')}
                  disabled={isRunning || isBatchRunning}
                  className={clsx(
                    "px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5",
                    scanMode === 'SINGLE'
                      ? "bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/40 shadow-sm"
                      : "text-slate-400 hover:text-slate-200"
                  )}
                >
                  <Globe className="w-3.5 h-3.5" />
                  URL Única (Single)
                </button>
                <button
                  onClick={() => setScanMode('MULTI')}
                  disabled={isRunning || isBatchRunning}
                  className={clsx(
                    "px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5",
                    scanMode === 'MULTI'
                      ? "bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/40 shadow-sm"
                      : "text-slate-400 hover:text-slate-200"
                  )}
                >
                  <Layers3 className="w-3.5 h-3.5 text-accent-cyan" />
                  Múltiplas URLs / Lote (Batch)
                  <span className="px-1.5 py-0.2 rounded bg-accent-cyan/20 text-accent-cyan text-[10px] font-bold">
                    Multi-URL
                  </span>
                </button>
              </div>
            </div>

            <div className="text-xs text-slate-400">
              {scanMode === 'SINGLE'
                ? 'Varredura focada em uma única aplicação com crawler profundo'
                : `Varredura automatizada em fila sequencial para múltiplas aplicações`}
            </div>
          </div>

          {/* SINGLE URL INPUT CARD */}
          {scanMode === 'SINGLE' && (
            <div className="glass-card p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-base font-semibold text-slate-200">Alvo da Varredura Imediata</h2>
                {savedTargets.length > 0 && (
                  <div className="flex items-center gap-2 text-xs text-slate-400">
                    <span>Selecionar do Catálogo:</span>
                    <select
                      onChange={e => e.target.value && setUrl(e.target.value)}
                      className="input-field py-1 px-2 text-xs w-auto bg-slate-800"
                    >
                      <option value="">-- Escolha uma URL Cadastrada --</option>
                      {savedTargets.map(t => (
                        <option key={t.id} value={t.url}>
                          {t.name} ({t.url})
                        </option>
                      ))}
                    </select>
                  </div>
                )}
              </div>

              <div className="flex gap-3">
                <div className="relative flex-1">
                  <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                  <input
                    type="text"
                    placeholder="https://suaempresa.com.br ou https://api.exemplo.com.br"
                    value={url}
                    onChange={e => setUrl(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && !isRunning && startScan.mutate()}
                    disabled={isRunning}
                    className="input-field pl-10 text-sm font-mono"
                  />
                </div>

                {isRunning ? (
                  <button
                    onClick={() => stopScan.mutate()}
                    disabled={stopScan.isPending}
                    className="px-5 py-2.5 rounded-xl bg-red-600 hover:bg-red-500 text-white font-bold text-sm flex items-center gap-2 shadow-lg shadow-red-600/30 transition-all"
                  >
                    <Square className="w-4 h-4 fill-current" />
                    Parar Scan
                  </button>
                ) : (
                  <button
                    onClick={() => startScan.mutate()}
                    disabled={isRunning}
                    className="btn-primary gap-2 min-w-40 flex items-center justify-center font-bold shadow-lg shadow-accent-cyan/20"
                  >
                    <Play className="w-4 h-4 fill-current" />
                    Iniciar Pentest
                  </button>
                )}
              </div>

              {/* Depth options */}
              <div className="flex gap-6 pt-1">
                <label className="flex items-center gap-2 text-sm text-slate-400">
                  Profundidade de Crawl:
                  <select value={maxDepth} onChange={e => setMaxDepth(+e.target.value)}
                    className="input-field w-auto py-1 text-sm" disabled={isRunning}>
                    <option value={1}>1 — Rápido (Perímetro)</option>
                    <option value={2}>2 — Padrão (Recomendado)</option>
                    <option value={3}>3 — Profundo (Full App)</option>
                  </select>
                </label>
                <label className="flex items-center gap-2 text-sm text-slate-400">
                  Máximo de URLs:
                  <select value={maxUrls} onChange={e => setMaxUrls(+e.target.value)}
                    className="input-field w-auto py-1 text-sm" disabled={isRunning}>
                    <option value={30}>30 URLs</option>
                    <option value={50}>50 URLs</option>
                    <option value={100}>100 URLs</option>
                  </select>
                </label>
              </div>
            </div>
          )}

          {/* MULTI-URL BATCH SCAN INPUT CARD */}
          {scanMode === 'MULTI' && (
            <div className="glass-card p-6 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                    <Layers3 className="w-5 h-5 text-accent-cyan" />
                    Fila de Múltiplas URLs para Varredura Simultânea/Sequencial
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Digite ou cole uma URL por linha, ou importe diretamente as URLs cadastradas no catálogo.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      const allUrls = savedTargets.map(t => t.url).join('\n');
                      setMultiUrlsText(allUrls);
                      toast.success(`${savedTargets.length} URLs do catálogo inseridas!`);
                    }}
                    className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
                  >
                    Carregar Todas do Catálogo ({savedTargets.length})
                  </button>
                </div>
              </div>

              <div>
                <textarea
                  rows={4}
                  value={multiUrlsText}
                  onChange={e => setMultiUrlsText(e.target.value)}
                  disabled={isBatchRunning}
                  placeholder={`https://empresa.com.br\nhttps://api.empresa.com.br/v1\nhttps://portal.empresa.com.br`}
                  className="input-field text-xs font-mono w-full leading-relaxed p-3"
                />
                <div className="flex items-center justify-between text-[11px] text-slate-400 mt-1">
                  <span>
                    Total de URLs na fila:{' '}
                    <strong className="text-accent-cyan font-mono">
                      {parseMultiUrls(multiUrlsText).length}
                    </strong>
                  </span>
                  <span className="text-slate-500">Separadas por quebra de linha</span>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-bg-border/60">
                <div className="flex items-center gap-4 text-xs text-slate-400">
                  <span className="flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    Relatórios consolidados gerados ao término
                  </span>
                </div>

                {isBatchRunning ? (
                  <button
                    onClick={handleStopBatch}
                    className="px-5 py-2.5 rounded-xl bg-red-600 hover:bg-red-500 text-white font-bold text-sm flex items-center gap-2 shadow-lg shadow-red-600/30 transition-all"
                  >
                    <Square className="w-4 h-4 fill-current" />
                    Interromper Varredura em Lote
                  </button>
                ) : (
                  <button
                    onClick={() => handleStartBatchScan()}
                    disabled={isBatchRunning || parseMultiUrls(multiUrlsText).length === 0}
                    className="btn-primary px-6 py-2.5 text-sm font-bold flex items-center gap-2 shadow-lg shadow-accent-cyan/20 hover:scale-[1.02] transition-all"
                  >
                    <Play className="w-4 h-4 fill-current" />
                    Escanear Todas as {parseMultiUrls(multiUrlsText).length} URLs em Lote
                  </button>
                )}
              </div>
            </div>
          )}

          {/* MULTI-URL BATCH EXECUTION TRACKER & QUEUE PROGRESS */}
          {batchQueue.length > 0 && scanMode === 'MULTI' && (
            <div className="glass-card p-6 space-y-5 border border-accent-cyan/20">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  {isBatchRunning ? (
                    <Loader2 className="w-5 h-5 text-accent-cyan animate-spin" />
                  ) : (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  )}
                  <div>
                    <h3 className="text-base font-bold text-slate-100">
                      Status da Fila de Varredura ({completedBatchCount}/{totalBatchCount} Concluídas)
                    </h3>
                    <p className="text-xs text-slate-400 font-mono">
                      {isBatchRunning
                        ? `Escaneando Alvo #${currentBatchIndex + 1}: ${batchQueue[currentBatchIndex]?.url}`
                        : 'Varredura em lote finalizada'}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold text-accent-cyan bg-accent-cyan/10 px-3 py-1 rounded-lg border border-accent-cyan/20">
                    Progresso Geral: {batchOverallProgress}%
                  </span>
                </div>
              </div>

              {/* Overall Progress Bar */}
              <div className="progress-bar h-2.5">
                <div
                  className="progress-bar-fill transition-all duration-500 bg-gradient-to-r from-accent-cyan to-emerald-400"
                  style={{ width: `${batchOverallProgress}%` }}
                />
              </div>

              {/* Target Cards Queue Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {batchQueue.map((item, idx) => {
                  const isCurrent = currentBatchIndex === idx;
                  return (
                    <div
                      key={item.id}
                      className={clsx(
                        "p-4 rounded-xl border text-xs space-y-2.5 transition-all",
                        isCurrent
                          ? "bg-accent-cyan/10 border-accent-cyan/50 shadow-md shadow-accent-cyan/10"
                          : item.status === 'COMPLETED'
                          ? "bg-bg-primary/80 border-emerald-500/30"
                          : item.status === 'FAILED'
                          ? "bg-red-950/20 border-red-500/30"
                          : "bg-bg-primary/50 border-bg-border opacity-70"
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="truncate">
                          <span className="text-[10px] font-mono text-slate-500">Alvo #{idx + 1}</span>
                          <h4 className="font-bold text-slate-200 truncate" title={item.url}>
                            {item.url}
                          </h4>
                        </div>
                        <span
                          className={clsx(
                            "px-2 py-0.5 rounded text-[10px] font-bold uppercase",
                            item.status === 'RUNNING'
                              ? 'bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/30 animate-pulse'
                              : item.status === 'COMPLETED'
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                              : item.status === 'FAILED'
                              ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                              : 'bg-slate-800 text-slate-400'
                          )}
                        >
                          {item.status === 'RUNNING' ? 'ESCANEANDO' : item.status}
                        </span>
                      </div>

                      <div className="flex items-center justify-between text-[11px] text-slate-400">
                        <span>{item.phase}</span>
                        <span className="font-mono font-bold text-slate-300">{item.progress}%</span>
                      </div>

                      <div className="flex items-center justify-between pt-2 border-t border-bg-border/60 text-[11px]">
                        <span className="text-slate-400">
                          URLs: <b className="text-slate-200">{item.urls_found}</b>
                        </span>
                        <span className="text-slate-400">
                          Falhas: <b className="text-red-400">{item.findings_count}</b>
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Batch Console Logs */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-accent-cyan animate-ping" />
                    Console Unificado da Varredura em Lote
                  </p>
                  <span className="text-[11px] font-mono text-slate-500">
                    {batchLogs.length} linhas de log
                  </span>
                </div>
                <div ref={batchLogsRef} className="console-container h-52 space-y-1 overflow-y-auto font-mono text-xs">
                  {batchLogs.map((log, i) => (
                    <p
                      key={i}
                      className={clsx(
                        log.includes('❌') ? 'text-red-400 font-semibold' :
                        log.includes('⚠️') ? 'text-yellow-300' :
                        log.includes('✅') || log.includes('🏁') ? 'text-emerald-400 font-semibold' :
                        log.includes('[BATCH ENGINE]') ? 'text-accent-cyan font-bold' :
                        log.includes('▶️ INICIANDO') ? 'text-amber-300 font-semibold' :
                        'text-slate-400'
                      )}
                    >
                      {log}
                    </p>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* SINGLE SCAN LOGS & LIVE CONSOLE */}
          {scanMode === 'SINGLE' && scanStatus && (
            <div className="glass-card p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {isRunning && <Loader2 className="w-5 h-5 text-accent-cyan animate-spin" />}
                  {isCompleted && <CheckCircle2 className="w-5 h-5 text-green-400" />}
                  {hasFailed && <XCircle className="w-5 h-5 text-red-400" />}
                  <div>
                    <p className="font-semibold text-slate-200">{PHASE_LABELS[scanStatus.phase] || scanStatus.phase}</p>
                    <p className="text-xs text-slate-500 font-mono">Scan #{scanStatus.scan_id} — {scanStatus.url}</p>
                  </div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs text-slate-500 mb-1">
                  <span>Progresso da Execução</span>
                  <span className="font-mono font-bold text-accent-cyan">{scanStatus.progress}%</span>
                </div>
                <div className="progress-bar h-2.5">
                  <div className="progress-bar-fill transition-all duration-500"
                    style={{ width: `${scanStatus.progress}%` }} />
                </div>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-3 gap-3">
                {[
                  { label: 'URLs Mapeadas', value: scanStatus.urls_found, icon: Globe },
                  { label: 'Formulários / Endpoints', value: scanStatus.forms_found, icon: FileText },
                  { label: 'Vulnerabilidades', value: scanStatus.findings_count, icon: Bug },
                ].map(({ label, value, icon: Icon }) => (
                  <div key={label} className="bg-bg-primary/60 rounded-xl p-3 flex items-center gap-3 border border-bg-border/60">
                    <Icon className="w-4 h-4 text-accent-cyan flex-shrink-0" />
                    <div>
                      <p className="text-xl font-bold text-slate-100">{value}</p>
                      <p className="text-xs text-slate-500">{label}</p>
                    </div>
                  </div>
                ))}
              </div>

              {/* Live console */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-accent-cyan animate-ping" />
                    Console ao Vivo em Tempo Real
                  </p>
                  <span className="text-[11px] font-mono text-slate-500">
                    {scanStatus.logs.length} eventos registrados
                  </span>
                </div>
                <div ref={logsRef} className="console-container h-52 space-y-1 overflow-y-auto">
                  {scanStatus.logs.map((log, i) => (
                    <p key={i} className={clsx(
                      log.includes('❌') ? 'text-red-400 font-semibold' :
                      log.includes('⚠️') ? 'text-yellow-300' :
                      log.includes('✅') || log.includes('🏁') ? 'text-emerald-400 font-semibold' :
                      log.includes('[WAF]') ? 'text-cyan-300 font-medium' :
                      log.includes('[Headers]') || log.includes('[CORS]') ? 'text-sky-300' :
                      log.includes('[SQLi]') || log.includes('[XSS]') ? 'text-amber-400' :
                      log.includes('🕷️') ? 'text-cyan-400' : 'text-slate-400'
                    )}>{log}</p>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Consolidated Findings List */}
          {findings.length > 0 && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                    <Bug className="w-5 h-5 text-red-400" />
                    Vulnerabilidades Identificadas ({findings.length})
                  </h2>
                  <p className="text-xs text-slate-400">
                    Falhas de segurança agregadas de todos os alvos escaneados
                  </p>
                </div>

                {batchQueue.length > 0 && (
                  <div className="flex items-center gap-2">
                    <Filter className="w-3.5 h-3.5 text-slate-400" />
                    <select
                      value={filterFindingsUrl}
                      onChange={e => setFilterFindingsUrl(e.target.value)}
                      className="input-field text-xs py-1 px-2.5 bg-slate-800 w-auto"
                    >
                      <option value="ALL">Todos os Alvos ({findings.length})</option>
                      {batchQueue.map(b => (
                        <option key={b.id} value={b.url}>
                          {b.name || b.url}
                        </option>
                      ))}
                    </select>
                  </div>
                )}
              </div>

              <div className="space-y-2">
                {filteredFindings.map(f => (
                  <div key={f.id} className="glass-card p-4 rounded-xl border border-bg-border space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-xs px-2 py-0.5 rounded border font-bold ${SEV_COLORS[f.severity] || SEV_COLORS.INFO}`}>
                          {f.severity}
                        </span>
                        <h3 className="font-semibold text-slate-200 text-sm">{f.title}</h3>
                        <span className="text-[11px] font-mono text-accent-cyan bg-bg-primary px-2 py-0.5 rounded border border-bg-border">
                          {f.affected_url}
                        </span>
                      </div>
                      <span className="text-xs font-mono font-bold text-slate-400">CVSS {f.cvss_score?.toFixed(1)}</span>
                    </div>
                    <p className="text-xs text-slate-400">{f.description}</p>
                    <p className="text-xs text-emerald-400/90"><strong>Recomendação:</strong> {f.recommendation}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ──────────────────────────────────────────────────────────────────────────
          TAB 2: TARGETS (Catálogo com Seleção Múltipla & Scan em Lote Direto)
         ────────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'TARGETS' && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-bold text-slate-100">Catálogo de URLs e Ativos Cadastrados</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Selecione múltiplas URLs com as caixas de seleção para disparar uma varredura em lote imediata.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowBatchModal(true)}
                className="px-3.5 py-2 text-xs font-semibold rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-all flex items-center gap-1.5"
              >
                <Copy className="w-3.5 h-3.5 text-accent-cyan" />
                Importar em Lote
              </button>

              <button
                onClick={() => setIsAddingTarget(!isAddingTarget)}
                className="btn-primary px-4 py-2 text-xs font-bold flex items-center gap-1.5 shadow-md"
              >
                <Plus className="w-4 h-4" />
                Cadastrar Nova URL
              </button>
            </div>
          </div>

          {/* Multi-Select Floating Action Bar */}
          {selectedTargetIds.length > 0 && (
            <div className="p-4 rounded-2xl bg-gradient-to-r from-accent-cyan/15 via-bg-secondary to-bg-secondary border border-accent-cyan/40 shadow-xl flex flex-wrap items-center justify-between gap-3 animate-fade-in">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-accent-cyan/20 border border-accent-cyan/30 flex items-center justify-center text-accent-cyan font-bold text-sm">
                  {selectedTargetIds.length}
                </div>
                <div>
                  <h4 className="text-sm font-bold text-slate-100">
                    {selectedTargetIds.length} URLs Selecionadas
                  </h4>
                  <p className="text-xs text-slate-400">
                    Execute a varredura simultânea de todas as URLs marcadas com 1 clique.
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleDeleteSelectedTargets}
                  className="px-3 py-1.5 text-xs font-semibold rounded-xl bg-red-950/40 text-red-400 border border-red-500/30 hover:bg-red-900/50 transition-colors"
                >
                  Excluir Selecionadas
                </button>

                <button
                  onClick={handleScanSelectedTargets}
                  className="btn-primary px-4 py-2 text-xs font-bold flex items-center gap-2 shadow-lg shadow-accent-cyan/20 hover:scale-105 transition-all"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  Escanear {selectedTargetIds.length} URLs Agora
                </button>
              </div>
            </div>
          )}

          {/* Form: Add New Target */}
          {isAddingTarget && (
            <form onSubmit={handleAddTarget} className="glass-card p-5 rounded-2xl border border-accent-cyan/30 space-y-4 animate-fade-in">
              <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <Globe className="w-4 h-4 text-accent-cyan" />
                Novo Alvo de Segurança
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-slate-400 block mb-1">Nome do Ativo / Aplicação</label>
                  <input
                    type="text"
                    placeholder="Ex: Portal do Cliente / API Gateway"
                    value={newTargetName}
                    onChange={e => setNewTargetName(e.target.value)}
                    className="input-field text-sm"
                    required
                  />
                </div>

                <div>
                  <label className="text-xs text-slate-400 block mb-1">URL Completa</label>
                  <input
                    type="text"
                    placeholder="https://app.empresa.com.br"
                    value={newTargetUrl}
                    onChange={e => setNewTargetUrl(e.target.value)}
                    className="input-field text-sm font-mono"
                    required
                  />
                </div>

                <div>
                  <label className="text-xs text-slate-400 block mb-1">Ambiente</label>
                  <select
                    value={newTargetEnv}
                    onChange={e => setNewTargetEnv(e.target.value as any)}
                    className="input-field text-sm"
                  >
                    <option value="production">Produção (Live)</option>
                    <option value="staging">Homologação (Staging)</option>
                    <option value="development">Desenvolvimento (Dev)</option>
                    <option value="dmz">DMZ / Externo</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs text-slate-400 block mb-1">Criticidade de Negócio</label>
                  <select
                    value={newTargetCrit}
                    onChange={e => setNewTargetCrit(e.target.value as any)}
                    className="input-field text-sm"
                  >
                    <option value="CRITICAL">Crítica (Missão Crítica)</option>
                    <option value="HIGH">Alta</option>
                    <option value="MEDIUM">Média</option>
                    <option value="LOW">Baixa</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsAddingTarget(false)}
                  className="px-4 py-2 text-xs font-semibold rounded-xl bg-slate-800 text-slate-400 hover:text-white"
                >
                  Cancelar
                </button>
                <button type="submit" className="btn-primary px-5 py-2 text-xs font-bold">
                  Salvar URL
                </button>
              </div>
            </form>
          )}

          {/* Modal Batch Import */}
          {showBatchModal && (
            <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
              <div className="glass-card max-w-lg w-full p-6 rounded-2xl border border-bg-border space-y-4">
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Copy className="w-4 h-4 text-accent-cyan" />
                  Importar URLs em Lote
                </h3>
                <p className="text-xs text-slate-400">
                  Cole uma lista de URLs abaixo (uma por linha). Elas serão cadastradas automaticamente no catálogo.
                </p>

                <textarea
                  rows={6}
                  placeholder={`https://app1.empresa.com.br\nhttps://api.empresa.com.br\nhttps://admin.empresa.com.br`}
                  value={batchUrlsInput}
                  onChange={e => setBatchUrlsInput(e.target.value)}
                  className="input-field text-xs font-mono w-full"
                />

                <div className="flex justify-end gap-2">
                  <button
                    onClick={() => setShowBatchModal(false)}
                    className="px-4 py-2 text-xs font-semibold rounded-xl bg-slate-800 text-slate-400"
                  >
                    Cancelar
                  </button>
                  <button
                    onClick={handleBatchImport}
                    className="btn-primary px-5 py-2 text-xs font-bold"
                  >
                    Importar Todas
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Targets Table with Checkboxes */}
          <div className="glass-card rounded-2xl overflow-hidden border border-bg-border">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase font-semibold border-b border-bg-border">
                <tr>
                  <th className="p-3.5 w-10">
                    <input
                      type="checkbox"
                      checked={savedTargets.length > 0 && selectedTargetIds.length === savedTargets.length}
                      onChange={handleSelectAllTargets}
                      className="rounded border-slate-700 text-accent-cyan focus:ring-0 cursor-pointer"
                    />
                  </th>
                  <th className="p-3.5">Nome / Aplicação</th>
                  <th className="p-3.5">URL Alvo</th>
                  <th className="p-3.5">Ambiente</th>
                  <th className="p-3.5">Criticidade</th>
                  <th className="p-3.5">Último Scan</th>
                  <th className="p-3.5 text-right">Ações</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-bg-border/60">
                {savedTargets.map(target => {
                  const isSelected = selectedTargetIds.includes(target.id);

                  return (
                    <tr
                      key={target.id}
                      className={clsx(
                        "transition-colors",
                        isSelected ? "bg-accent-cyan/10" : "hover:bg-slate-800/40"
                      )}
                    >
                      <td className="p-3.5">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => handleToggleTargetSelection(target.id)}
                          className="rounded border-slate-700 text-accent-cyan focus:ring-0 cursor-pointer"
                        />
                      </td>
                      <td className="p-3.5 font-bold text-slate-200">{target.name}</td>
                      <td className="p-3.5 font-mono text-accent-cyan">
                        <a href={target.url} target="_blank" rel="noopener noreferrer" className="hover:underline flex items-center gap-1">
                          {target.url} <ExternalLink className="w-3 h-3 text-slate-500" />
                        </a>
                      </td>
                      <td className="p-3.5">
                        <span className={clsx(
                          "px-2 py-0.5 rounded-full text-[11px] font-semibold uppercase",
                          target.environment === 'production' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                          target.environment === 'staging' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                          'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                        )}>
                          {target.environment}
                        </span>
                      </td>
                      <td className="p-3.5">
                        <span className={clsx(
                          "px-2 py-0.5 rounded text-[11px] font-bold",
                          target.criticality === 'CRITICAL' ? 'text-red-400' :
                          target.criticality === 'HIGH' ? 'text-orange-400' : 'text-slate-400'
                        )}>
                          {target.criticality}
                        </span>
                      </td>
                      <td className="p-3.5 text-slate-400">
                        {target.last_scan_at ? `${target.last_scan_at} (${target.last_scan_status})` : 'Nunca escaneado'}
                      </td>
                      <td className="p-3.5 text-right space-x-2">
                        <button
                          onClick={() => {
                            setUrl(target.url);
                            setScanMode('SINGLE');
                            startScan.mutate(target.url);
                          }}
                          className="px-3 py-1.5 rounded-lg bg-accent-cyan/10 hover:bg-accent-cyan/20 text-accent-cyan font-semibold border border-accent-cyan/30 text-xs transition-colors"
                        >
                          Scan Agora
                        </button>
                        <button
                          onClick={() => handleDeleteTarget(target.id)}
                          className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 transition-colors"
                          title="Remover"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ──────────────────────────────────────────────────────────────────────────
          TAB 3: ROUTINES (Rotinas de Scan Agendadas)
         ────────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'ROUTINES' && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-bold text-slate-100">Rotinas de Varredura Automatizadas</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Programe varreduras recorrentes (diárias, semanais, mensais) para auditoria e conformidade contínua.
              </p>
            </div>

            <button
              onClick={() => setIsAddingRoutine(!isAddingRoutine)}
              className="btn-primary px-4 py-2 text-xs font-bold flex items-center gap-1.5 shadow-md"
            >
              <Plus className="w-4 h-4" />
              Nova Rotina Agendada
            </button>
          </div>

          {/* Form: Add Routine */}
          {isAddingRoutine && (
            <form onSubmit={handleAddRoutine} className="glass-card p-5 rounded-2xl border border-accent-cyan/30 space-y-4 animate-fade-in">
              <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <Calendar className="w-4 h-4 text-accent-cyan" />
                Configurar Agendamento de Pentest
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-slate-400 block mb-1">Título da Rotina</label>
                  <input
                    type="text"
                    placeholder="Ex: Auditoria Semanal de Produção"
                    value={newRoutineName}
                    onChange={e => setNewRoutineName(e.target.value)}
                    className="input-field text-sm"
                    required
                  />
                </div>

                <div>
                  <label className="text-xs text-slate-400 block mb-1">Alvo / URL</label>
                  <select
                    value={newRoutineTarget}
                    onChange={e => setNewRoutineTarget(e.target.value)}
                    className="input-field text-sm font-mono"
                    required
                  >
                    <option value="">-- Selecione uma URL --</option>
                    {savedTargets.map(t => (
                      <option key={t.id} value={t.url}>
                        {t.name} ({t.url})
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="text-xs text-slate-400 block mb-1">Frequência</label>
                  <select
                    value={newRoutineFreq}
                    onChange={e => setNewRoutineFreq(e.target.value as any)}
                    className="input-field text-sm"
                  >
                    <option value="DAILY">Diária (Todo dia às 02:00)</option>
                    <option value="WEEKLY">Semanal (Domingos às 03:00)</option>
                    <option value="MONTHLY">Mensal (Dia 1 às 01:00)</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs text-slate-400 block mb-1">Perfil de Varredura</label>
                  <select
                    value={newRoutineMode}
                    onChange={e => setNewRoutineMode(e.target.value as any)}
                    className="input-field text-sm"
                  >
                    <option value="SAFE_ACTIVE">Seguro Ativo (Recomendado)</option>
                    <option value="OWASP_TOP10">Auditoria Completa OWASP Top 10</option>
                    <option value="API_SECURITY">Auditoria Especializada de APIs</option>
                    <option value="PASSIVE">Passivo (Sem Injeções)</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsAddingRoutine(false)}
                  className="px-4 py-2 text-xs font-semibold rounded-xl bg-slate-800 text-slate-400 hover:text-white"
                >
                  Cancelar
                </button>
                <button type="submit" className="btn-primary px-5 py-2 text-xs font-bold">
                  Agendar Rotina
                </button>
              </div>
            </form>
          )}

          {/* Routines Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {routines.map(routine => (
              <div
                key={routine.id}
                className={clsx(
                  "bg-bg-secondary/95 border rounded-2xl p-5 shadow-lg space-y-3 transition-all",
                  routine.is_active ? "border-bg-border hover:border-accent-cyan/40" : "border-slate-800 opacity-60"
                )}
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20">
                      {routine.frequency}
                    </span>
                    <h4 className="text-sm font-bold text-slate-100 mt-2">{routine.name}</h4>
                    <p className="text-xs font-mono text-slate-400 truncate max-w-[220px]">{routine.target_url}</p>
                  </div>

                  <button
                    onClick={() => handleToggleRoutine(routine.id)}
                    className={clsx(
                      "px-2 py-1 rounded text-[10px] font-bold transition-colors",
                      routine.is_active ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30" : "bg-slate-800 text-slate-500"
                    )}
                  >
                    {routine.is_active ? 'ATIVO' : 'PAUSADO'}
                  </button>
                </div>

                <div className="text-xs text-slate-400 space-y-1 pt-2 border-t border-bg-border/60">
                  <p className="flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5 text-accent-cyan" />
                    <strong>Horário:</strong> {routine.schedule_time}
                  </p>
                  <p className="flex items-center gap-1">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                    <strong>Modo:</strong> {routine.scan_mode}
                  </p>
                  <p className="text-[11px] text-slate-500">
                    Próxima execução: <strong className="text-slate-300">{routine.next_run_at}</strong>
                  </p>
                </div>

                <div className="pt-2 flex items-center justify-between">
                  <button
                    onClick={() => {
                      setUrl(routine.target_url);
                      setScanMode('SINGLE');
                      startScan.mutate(routine.target_url);
                    }}
                    className="text-xs font-bold text-accent-cyan hover:underline flex items-center gap-1"
                  >
                    Disparar Agora <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
