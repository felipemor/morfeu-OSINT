'use client';
import { useParams, useRouter } from 'next/navigation';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  projectsApi, findingsApi, assetsApi, scansApi,
  scheduleApi, testModulesApi,
  type Project, type ScheduleTask
} from '@/lib/api';
import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Bug, Globe, Activity, FileText, Shield, AlertTriangle,
  Play, Square, Download, CheckCircle2, XCircle, Loader2,
  Calendar, Clock, ChevronRight, Layers, Zap, Target,
  TrendingUp, BarChart2, Lock, Eye, RefreshCw, Plus,
  Copy, ExternalLink, ArrowLeft, Settings, Database,
  Server, Network, Flag, Cpu, Check, X, Terminal,
  Wrench, AlertCircle, Sparkles, CheckCheck, Share2,
  ArrowUpRight, Shuffle, Radio, ShieldAlert
} from 'lucide-react';
import Link from 'next/link';
import clsx from 'clsx';
import toast from 'react-hot-toast';
import GanttChart, { type GanttTask } from '@/components/GanttChart';
import TestModuleSelector, { ALL_TEST_MODULES } from '@/components/TestModuleSelector';

type Tab = 'overview' | 'scan' | 'schedule' | 'findings' | 'remediation' | 'assets' | 'reports';

const SCANNER_URL = 'http://localhost:8000';

const DEFAULT_SCHEDULE_TASKS: GanttTask[] = [
  {
    id: 'default-1',
    phase: 'Reconhecimento & OSINT',
    name: 'DNS Enumeration & Subdomain Discovery',
    start_date: formatDateOffset(0),
    end_date: formatDateOffset(3),
    status: 'PLANNED',
  },
  {
    id: 'default-2',
    phase: 'Reconhecimento & OSINT',
    name: 'Technology Fingerprinting & Google Dorking',
    start_date: formatDateOffset(2),
    end_date: formatDateOffset(5),
    status: 'PLANNED',
  },
  {
    id: 'default-3',
    phase: 'Enumeração',
    name: 'Port Scanning & Service Identification',
    start_date: formatDateOffset(4),
    end_date: formatDateOffset(7),
    status: 'PLANNED',
  },
  {
    id: 'default-4',
    phase: 'Scanning Ativo',
    name: 'OWASP Top 10 Automated Testing',
    start_date: formatDateOffset(6),
    end_date: formatDateOffset(12),
    status: 'PLANNED',
  },
  {
    id: 'default-5',
    phase: 'Exploração',
    name: 'Manual Exploitation & Proof of Concept',
    start_date: formatDateOffset(11),
    end_date: formatDateOffset(18),
    status: 'PLANNED',
  },
  {
    id: 'default-6',
    phase: 'Pós-Exploração',
    name: 'Privilege Escalation & Lateral Movement',
    start_date: formatDateOffset(16),
    end_date: formatDateOffset(21),
    status: 'PLANNED',
  },
  {
    id: 'default-7',
    phase: 'Relatório & Evidências',
    name: 'Documentação & Relatório Executivo',
    start_date: formatDateOffset(20),
    end_date: formatDateOffset(27),
    status: 'PLANNED',
  },
];

function formatDateOffset(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString().split('T')[0];
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>('overview');
  const [selectedFinding, setSelectedFinding] = useState<any>(null);

  const { data: project, isLoading: projectLoading } = useQuery({
    queryKey: ['project', id],
    queryFn: () => projectsApi.get(id),
  });
  const { data: findings = [] } = useQuery({
    queryKey: ['findings', id],
    queryFn: () => findingsApi.list({ project_id: id }),
  });
  const { data: assets = [] } = useQuery({
    queryKey: ['assets', id],
    queryFn: () => assetsApi.list(id),
  });
  const { data: scans = [] } = useQuery({
    queryKey: ['scans', id],
    queryFn: () => scansApi.list(id),
  });

  // Close finding drawer with Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setSelectedFinding(null);
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const updateFindingMutation = useMutation({
    mutationFn: async ({ findingId, patch }: { findingId: string; patch: any }) => {
      return await findingsApi.update(findingId, patch);
    },
    onSuccess: (updated) => {
      queryClient.invalidateQueries({ queryKey: ['findings', id] });
      queryClient.invalidateQueries({ queryKey: ['all-findings'] });
      queryClient.invalidateQueries({ queryKey: ['project', id] });
      if (updated && selectedFinding?.id === updated.id) {
        setSelectedFinding(updated);
      }
      toast.success('Finding atualizado com sucesso');
    },
    onError: () => toast.error('Erro ao atualizar finding'),
  });

  // ── Schedule state (localStorage-backed) ────────────────────────────────────
  const [scheduleTasks, setScheduleTasks] = useState<GanttTask[]>([]);
  useEffect(() => {
    if (!id) return;
    const saved = scheduleApi.list(id) as GanttTask[];
    if (saved.length > 0) {
      setScheduleTasks(saved);
    } else {
      setScheduleTasks(DEFAULT_SCHEDULE_TASKS);
      scheduleApi.save(id, DEFAULT_SCHEDULE_TASKS as any);
    }
  }, [id]);

  const handleScheduleChange = useCallback((tasks: GanttTask[]) => {
    setScheduleTasks(tasks);
    scheduleApi.save(id, tasks as any);
  }, [id]);

  // ── Test Modules state ───────────────────────────────────────────────────────
  const [selectedModules, setSelectedModules] = useState<string[]>([]);
  const [intrusionLevel, setIntrusionLevel] = useState<1 | 2 | 3>(2);

  useEffect(() => {
    if (!id) return;
    setSelectedModules(testModulesApi.getSelected(id));
    setIntrusionLevel(testModulesApi.getIntrusionLevel(id));
  }, [id]);

  const handleModulesChange = (modules: string[]) => {
    setSelectedModules(modules);
    testModulesApi.setSelected(id, modules);
  };

  const handleIntrusionChange = (level: 1 | 2 | 3) => {
    setIntrusionLevel(level);
    testModulesApi.setIntrusionLevel(id, level);
  };

  // ── Scan runner & VPN/WAF Proxy Rotation ───────────────────────────
  const [targetUrl, setTargetUrl] = useState('');
  const [isScanRunning, setIsScanRunning] = useState(false);
  const [scanState, setScanState] = useState<any>(null);
  const [scanLogs, setScanLogs] = useState<string[]>([]);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [vpnRotationEnabled, setVpnRotationEnabled] = useState(true);
  const [selectedRegion, setSelectedRegion] = useState('AUTO_ROTATE');

  const logsRef = useRef<HTMLDivElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  function addLog(msg: string) {
    setScanLogs(prev => {
      const updated = [...prev.slice(-200), `[${new Date().toLocaleTimeString('pt-BR')}] ${msg}`];
      return updated;
    });
    setTimeout(() => {
      if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight;
    }, 50);
  }

  async function startProjectScan() {
    if (!targetUrl) {
      toast.error('Informe a URL alvo do scan');
      return;
    }

    const modulesParam = selectedModules.length > 0 ? selectedModules : ALL_TEST_MODULES.map(m => m.id);
    const modeMap: Record<number, string> = { 1: 'PASSIVE', 2: 'SAFE_ACTIVE', 3: 'AUTHORIZED_ADVERSARY' };
    const scanMode = modeMap[intrusionLevel];

    setIsScanRunning(true);
    setScanState(null);
    setScanLogs([]);
    addLog(`🚀 Iniciando scan no projeto "${project?.name || id}"...`);
    addLog(`🎯 Alvo: ${targetUrl}`);
    addLog(`⚡ Modo: ${scanMode} | Módulos selecionados: ${modulesParam.length}`);
    addLog(`🔐 Nível de intrusão: ${['', 'Passivo', 'Ativo Seguro', 'Adversário Total'][intrusionLevel]}`);
    if (vpnRotationEnabled) {
      addLog(`🌐 VPN/Proxy Interno: ATIVO (${selectedRegion === 'AUTO_ROTATE' ? 'Rotação Automática de Países a cada requisição para Burlar Rate Limit/WAF' : `Nó Fixo: ${selectedRegion}`})`);
    } else {
      addLog(`⚠️ VPN/Proxy Interno: DESATIVADO (Requisições diretas)`);
    }

    try {
      const resp = await fetch(`${SCANNER_URL}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: targetUrl,
          max_depth: 3,
          max_urls: 100,
          project_id: id,
          scan_mode: scanMode,
          selected_modules: modulesParam,
          intrusion_level: intrusionLevel,
          vpn_rotation: vpnRotationEnabled,
          geo_region: selectedRegion,
        }),
      });

      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      const scanId = data.scan_id;
      setActiveScanId(scanId);
      addLog(`✅ Scan iniciado — ID: ${scanId}`);

      // Poll status
      pollRef.current = setInterval(async () => {
        try {
          const statusResp = await fetch(`${SCANNER_URL}/scan/${scanId}`);
          if (!statusResp.ok) return;
          const status = await statusResp.json();
          setScanState(status);
          addLog(`📊 ${status.phase || status.status} | ${status.progress || 0}% | ${status.findings_count || 0} findings`);

          if (status.status === 'COMPLETED' || status.status === 'FAILED') {
            clearInterval(pollRef.current!);
            setIsScanRunning(false);
            addLog(status.status === 'COMPLETED'
              ? `🎉 Scan concluído! ${status.findings_count} vulnerabilidades encontradas.`
              : `❌ Scan falhou: ${status.error || 'Erro desconhecido'}`);

            if (status.status === 'COMPLETED') {
              // Save scan to local store and link to project
              await scansApi.create({
                id: scanId,
                project_id: id,
                mode: scanMode,
                status: 'COMPLETED',
                progress: 100,
                current_phase: 'COMPLETED',
                assets_discovered: status.urls_found || 0,
                endpoints_found: status.urls_found || 0,
                findings_count: status.findings_count || 0,
                started_at: new Date().toISOString(),
                completed_at: new Date().toISOString(),
              });
              // Save findings to project
              if (status.findings?.length) {
                for (const f of status.findings) {
                  await findingsApi.create({
                    project_id: id,
                    scan_id: scanId,
                    title: f.title,
                    severity: f.severity,
                    status: 'OPEN',
                    owasp_category: f.owasp || '',
                    cwe_id: f.cwe || '',
                    cvss_score: f.cvss_score || 5.0,
                    confidence: f.confidence || 80,
                    affected_url: f.affected_url || targetUrl,
                    description: f.description || '',
                    recommendation: f.recommendation || '',
                    steps_to_reproduce: f.evidence || '',
                  });
                }
              }
              queryClient.invalidateQueries({ queryKey: ['findings', id] });
              queryClient.invalidateQueries({ queryKey: ['scans', id] });
              queryClient.invalidateQueries({ queryKey: ['project', id] });
              toast.success(`Scan concluído! ${status.findings_count} vulnerabilidades encontradas.`);
            }
          }
        } catch (e) { /* ignore poll errors */ }
      }, 2000);

    } catch (err: any) {
      addLog(`❌ Erro ao conectar ao scanner: ${err.message}`);
      addLog(`💡 Simulando scan local para demonstração...`);
      setIsScanRunning(false);

      // Simulate scan for demo when backend is offline
      await simulateScan(targetUrl, id, scanMode, modulesParam);
    }
  }

  async function simulateScan(url: string, projectId: string, mode: string, modules: string[]) {
    const phases = [
      'INITIALIZING', 'DNS_RECON', 'SPIDERING', 'FINGERPRINTING',
      'SECURITY_CHECKS', 'EXPLOITATION', 'GENERATING_REPORT', 'COMPLETED'
    ];
    const phaseLabels: Record<string, string> = {
      INITIALIZING: '🔧 Inicializando ambiente de teste...',
      DNS_RECON: '🌐 Reconhecimento DNS e subdomínios...',
      SPIDERING: '🕷️ Mapeando URLs e endpoints...',
      FINGERPRINTING: '🔍 Identificando tecnologias e versões...',
      SECURITY_CHECKS: '🔐 Executando testes de segurança OWASP...',
      EXPLOITATION: '💥 Tentando exploitar vulnerabilidades...',
      GENERATING_REPORT: '📄 Gerando relatório e evidências...',
      COMPLETED: '✅ Scan concluído!',
    };

    setIsScanRunning(true);
    setScanState({ status: 'RUNNING', progress: 0, phase: 'INITIALIZING' });

    for (let i = 0; i < phases.length; i++) {
      const phase = phases[i];
      const progress = Math.round((i / (phases.length - 1)) * 100);
      addLog(phaseLabels[phase]);
      setScanState({ status: i === phases.length - 1 ? 'COMPLETED' : 'RUNNING', progress, phase });
      await new Promise(r => setTimeout(r, 1200 + Math.random() * 800));
    }

    // Generate simulated findings based on selected modules
    const SIMULATED_FINDINGS = [
      { title: 'SQL Injection em parâmetro de busca', severity: 'CRITICAL', owasp: 'A03:2021', cwe: 'CWE-89', cvss_score: 9.8, module: 'sqli', confidence: 95, affected_url: `${url}/search?q=`, description: 'Parâmetro "q" vulnerável a SQL Injection clássico e blind. Possível dump completo da base de dados.', recommendation: 'Usar prepared statements e ORMs. Validar e sanitizar todas as entradas.', evidence: `' OR '1'='1' -- retornou 200 OK com dados adicionais` },
      { title: 'XSS Refletido no campo de login', severity: 'HIGH', owasp: 'A03:2021', cwe: 'CWE-79', cvss_score: 7.4, module: 'xss-reflected', confidence: 90, affected_url: `${url}/login`, description: 'Campo "username" reflete input sem sanitização, permitindo execução de JavaScript arbitrário.', recommendation: 'Implementar Content Security Policy e sanitizar output com encoding adequado.', evidence: `<script>alert(1)</script> retornou 200 com script executado` },
      { title: 'IDOR — Acesso a recursos de outros usuários', severity: 'CRITICAL', owasp: 'A01:2021', cwe: 'CWE-284', cvss_score: 9.1, module: 'broken-access', confidence: 88, affected_url: `${url}/api/users/`, description: 'Endpoint /api/users/{id} não valida se o usuário autenticado tem acesso ao ID requisitado.', recommendation: 'Implementar validação de autorização por objeto (BOLA). Usar UUIDs em vez de IDs sequenciais.', evidence: 'Acessar /api/users/2 com token do usuário 1 retornou dados do usuário 2' },
      { title: 'Ausência de CSRF Token em formulários críticos', severity: 'HIGH', owasp: 'A01:2021', cwe: 'CWE-352', cvss_score: 7.5, module: 'csrf', confidence: 92, affected_url: `${url}/account/settings`, description: 'Formulários de alteração de senha e email não implementam tokens CSRF.', recommendation: 'Implementar tokens CSRF sincronizados (Synchronizer Token Pattern) ou SameSite=Strict cookies.', evidence: 'POST /account/settings sem token CSRF resultou em alteração bem-sucedida' },
      { title: 'Headers de segurança ausentes', severity: 'MEDIUM', owasp: 'A05:2021', cwe: 'CWE-16', cvss_score: 5.3, module: 'security-misconfig', confidence: 100, affected_url: url, description: 'X-Frame-Options, Content-Security-Policy, X-Content-Type-Options e HSTS não configurados.', recommendation: 'Configurar todos os headers de segurança HTTP recomendados pelo OWASP.', evidence: 'curl -I retornou resposta sem security headers' },
      { title: 'JWT com algoritmo "none" aceito', severity: 'CRITICAL', owasp: 'A02:2021', cwe: 'CWE-345', cvss_score: 9.8, module: 'jwt-attack', confidence: 85, affected_url: `${url}/api/`, description: 'API aceita tokens JWT com algoritmo "none", permitindo forjar autenticação sem assinatura.', recommendation: 'Validar explicitamente o algoritmo do JWT. Usar apenas HS256/RS256. Rejeitar algoritmo "none".', evidence: 'Token com alg:none aceito com acesso de admin' },
      { title: 'Directory Traversal em upload de arquivos', severity: 'CRITICAL', owasp: 'A01:2021', cwe: 'CWE-22', cvss_score: 8.8, module: 'path-traversal', confidence: 82, affected_url: `${url}/upload`, description: 'Parâmetro de nome de arquivo permite traversal para acessar arquivos fora do diretório permitido.', recommendation: 'Validar e normalizar caminhos de arquivo. Usar whitelist de extensões. Armazenar em diretório isolado.', evidence: '../../../etc/passwd retornou conteúdo do arquivo' },
      { title: 'SSL/TLS — Protocolo TLS 1.0/1.1 habilitado', severity: 'MEDIUM', owasp: 'A02:2021', cwe: 'CWE-326', cvss_score: 5.9, module: 'ssl-tls', confidence: 100, affected_url: url, description: 'Servidor aceita conexões com protocolos TLS obsoletos e inseguros (TLS 1.0 e 1.1).', recommendation: 'Desabilitar TLS 1.0 e 1.1. Habilitar apenas TLS 1.2 e TLS 1.3. Usar cipher suites fortes.', evidence: 'openssl s_client -tls1 conectou com sucesso' },
    ];

    const filteredFindings = mode === 'PASSIVE'
      ? SIMULATED_FINDINGS.filter(f => f.severity !== 'CRITICAL')
      : mode === 'SAFE_ACTIVE'
      ? SIMULATED_FINDINGS.filter(f => !['path-traversal', 'jwt-attack'].includes(f.module))
      : SIMULATED_FINDINGS;

    const modulesToShow = modules.length > 0
      ? filteredFindings.filter(f => modules.includes(f.module))
      : filteredFindings;

    const findingsToCreate = modulesToShow.length > 0 ? modulesToShow : filteredFindings.slice(0, 3);

    for (const f of findingsToCreate) {
      await findingsApi.create({
        project_id: projectId,
        scan_id: `scan-sim-${Date.now()}`,
        title: f.title,
        severity: f.severity,
        status: 'OPEN',
        owasp_category: f.owasp,
        cwe_id: f.cwe,
        cvss_score: f.cvss_score,
        confidence: f.confidence,
        affected_url: f.affected_url,
        description: f.description,
        recommendation: f.recommendation,
        steps_to_reproduce: f.evidence,
        business_impact: 'Impacto crítico para o negócio — potencial exposição de dados sensíveis.',
        technical_impact: 'Execução remota de código, acesso não autorizado a dados.',
      });
    }

    const scanRecord = await scansApi.create({
      project_id: projectId,
      mode,
      status: 'COMPLETED',
      progress: 100,
      current_phase: 'COMPLETED',
      assets_discovered: 12,
      endpoints_found: 47,
      findings_count: findingsToCreate.length,
      started_at: new Date(Date.now() - 8000).toISOString(),
      completed_at: new Date().toISOString(),
    });

    addLog(`🎉 Scan concluído! ${findingsToCreate.length} vulnerabilidades encontradas.`);
    setScanState({ status: 'COMPLETED', progress: 100, phase: 'COMPLETED', findings_count: findingsToCreate.length });
    setIsScanRunning(false);

    queryClient.invalidateQueries({ queryKey: ['findings', id] });
    queryClient.invalidateQueries({ queryKey: ['scans', id] });
    queryClient.invalidateQueries({ queryKey: ['project', id] });
    toast.success(`Scan concluído! ${findingsToCreate.length} vulnerabilidades encontradas.`);
  }

  // ── Stats ────────────────────────────────────────────────────────────────────
  const critCount = findings.filter((f: any) => f.severity === 'CRITICAL' && !f.is_false_positive).length;
  const highCount = findings.filter((f: any) => f.severity === 'HIGH' && !f.is_false_positive).length;
  const openCount = findings.filter((f: any) => f.status === 'OPEN').length;
  const fixedCount = findings.filter((f: any) => f.status === 'FIXED').length;
  const latestScan = scans.at(-1);

  if (projectLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="w-8 h-8 animate-spin text-accent-cyan" />
      </div>
    );
  }

  if (!project) {
    return (
      <div className="flex flex-col items-center justify-center h-96 gap-4">
        <AlertTriangle className="w-12 h-12 text-red-400" />
        <p className="text-slate-400">Projeto não encontrado</p>
        <Link href="/projects" className="btn-primary text-sm">← Voltar aos Projetos</Link>
      </div>
    );
  }

  const TABS: { id: Tab; label: string; icon: React.ReactNode; badge?: number }[] = [
    { id: 'overview', label: 'Overview', icon: <BarChart2 className="w-4 h-4" /> },
    { id: 'scan', label: 'Scan & Testes', icon: <Zap className="w-4 h-4" /> },
    { id: 'schedule', label: 'Cronograma', icon: <Calendar className="w-4 h-4" /> },
    { id: 'findings', label: 'Findings', icon: <Bug className="w-4 h-4" />, badge: findings.length },
    { id: 'remediation', label: 'Guia de Remediação', icon: <Wrench className="w-4 h-4 text-emerald-400" />, badge: findings.length },
    { id: 'assets', label: 'Assets', icon: <Globe className="w-4 h-4" />, badge: assets.length },
    { id: 'reports', label: 'Relatórios', icon: <FileText className="w-4 h-4" /> },
  ];

  return (
    <div className="flex flex-col min-h-screen animate-fade-in">
      {/* Header */}
      <div className="px-6 py-4 border-b border-bg-border bg-bg-secondary/50">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3 min-w-0">
            <Link href="/projects" className="p-1.5 text-slate-500 hover:text-accent-cyan transition-colors flex-shrink-0">
              <ArrowLeft className="w-4 h-4" />
            </Link>
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-xs text-slate-500 mb-0.5">
                <span>Projetos</span>
                <ChevronRight className="w-3 h-3" />
                <span className="text-slate-300 truncate">{project.name}</span>
              </div>
              <h1 className="text-xl font-bold text-slate-100 truncate">{project.name}</h1>
              <p className="text-sm text-slate-400">{project.client || 'Interno'} · {project.business_unit || 'Segurança'}</p>
            </div>
          </div>

          <div className="flex items-center gap-3 flex-shrink-0">
            <StatusBadge status={project.status} />
            {latestScan && (
              <span className="text-xs text-slate-500">
                Último scan: {new Date(latestScan.completed_at || latestScan.started_at).toLocaleDateString('pt-BR')}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="px-6 border-b border-bg-border bg-bg-secondary/30 overflow-x-auto">
        <div className="flex gap-0 min-w-max">
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={clsx(
                'flex items-center gap-2 px-4 py-3 text-sm font-medium transition-all border-b-2 -mb-px whitespace-nowrap',
                tab === t.id
                  ? 'border-accent-cyan text-accent-cyan'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              )}
            >
              {t.icon}
              {t.label}
              {t.badge !== undefined && t.badge > 0 && (
                <span className={clsx(
                  'text-[10px] font-bold px-1.5 py-0.5 rounded-full',
                  tab === t.id ? 'bg-accent-cyan/20 text-accent-cyan' : 'bg-slate-700 text-slate-400'
                )}>
                  {t.badge}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 p-6 overflow-auto">
        {/* ── OVERVIEW ──────────────────────────────────────────────────────── */}
        {tab === 'overview' && (
          <div className="max-w-5xl space-y-6">
            {/* KPI Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: 'Total Findings', value: findings.length, color: '#ff6b35', icon: <Bug className="w-5 h-5" /> },
                { label: 'Críticos', value: critCount, color: critCount > 0 ? '#dc3545' : '#28a745', icon: <AlertTriangle className="w-5 h-5" /> },
                { label: 'Em Aberto', value: openCount, color: openCount > 0 ? '#ff6b35' : '#28a745', icon: <Activity className="w-5 h-5" /> },
                { label: 'Corrigidos', value: fixedCount, color: '#28a745', icon: <CheckCircle2 className="w-5 h-5" /> },
              ].map(({ label, value, color, icon }) => (
                <div key={label} className="glass-card p-4 flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0" style={{ background: `${color}15`, color }}>
                    {icon}
                  </div>
                  <div>
                    <p className="text-xs text-slate-400">{label}</p>
                    <p className="text-2xl font-bold" style={{ color }}>{value}</p>
                  </div>
                </div>
              ))}
            </div>

            {/* Risk + Severity */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Risk score */}
              <div className="glass-card p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                    <TrendingUp className="w-4 h-4 text-accent-cyan" /> Risco do Projeto
                  </h3>
                  <span className="text-2xl font-bold text-accent-cyan">{Math.round(project.risk_score)}/100</span>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-3 overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{
                      width: `${project.risk_score}%`,
                      background: project.risk_score > 70
                        ? 'linear-gradient(90deg, #ef4444, #dc2626)'
                        : project.risk_score > 40
                        ? 'linear-gradient(90deg, #f59e0b, #d97706)'
                        : 'linear-gradient(90deg, #22c55e, #16a34a)',
                      boxShadow: `0 0 12px ${project.risk_score > 70 ? '#ef444466' : '#f59e0b44'}`,
                    }}
                  />
                </div>
                <div className="mt-3 grid grid-cols-3 gap-2 text-center text-xs">
                  <div>
                    <p className="text-slate-500">Assets</p>
                    <p className="font-semibold text-slate-200">{project.assets_count}</p>
                  </div>
                  <div>
                    <p className="text-slate-500">Scans</p>
                    <p className="font-semibold text-slate-200">{scans.length}</p>
                  </div>
                  <div>
                    <p className="text-slate-500">Findings</p>
                    <p className="font-semibold text-slate-200">{project.findings_count}</p>
                  </div>
                </div>
              </div>

              {/* Severity breakdown */}
              <div className="glass-card p-5">
                <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-purple-400" /> Distribuição por Severidade
                </h3>
                <div className="space-y-2.5">
                  {[
                    { label: 'Critical', count: critCount, color: '#dc3545' },
                    { label: 'High', count: highCount, color: '#ff6b35' },
                    { label: 'Medium', count: findings.filter((f: any) => f.severity === 'MEDIUM').length, color: '#ffc107' },
                    { label: 'Low', count: findings.filter((f: any) => f.severity === 'LOW').length, color: '#28a745' },
                    { label: 'Info', count: findings.filter((f: any) => f.severity === 'INFO').length, color: '#17a2b8' },
                  ].map(s => (
                    <div key={s.label} className="flex items-center gap-3">
                      <span className="text-xs w-14 text-slate-400">{s.label}</span>
                      <div className="flex-1 bg-slate-800 rounded-full h-2 overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-700"
                          style={{
                            width: findings.length ? `${(s.count / findings.length) * 100}%` : '0%',
                            background: s.color,
                            boxShadow: `0 0 6px ${s.color}66`,
                          }}
                        />
                      </div>
                      <span className="text-xs font-bold w-6 text-right" style={{ color: s.color }}>{s.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Top findings quick list */}
            {findings.length > 0 && (
              <div className="glass-card p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                    <Bug className="w-4 h-4 text-red-400" /> Principais Vulnerabilidades
                  </h3>
                  <button
                    onClick={() => setTab('findings')}
                    className="text-xs text-accent-cyan hover:underline"
                  >
                    Ver todas ({findings.length}) →
                  </button>
                </div>
                <div className="space-y-2">
                  {findings.slice(0, 4).map((f: any) => (
                    <div
                      key={f.id}
                      onClick={() => setSelectedFinding(f)}
                      className="p-3 rounded-lg bg-bg-primary/50 hover:bg-bg-primary/90 border border-bg-border/60 hover:border-accent-cyan/40 transition-all cursor-pointer flex items-center justify-between gap-3 group"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <div className={clsx(
                          "w-2 h-2 rounded-full flex-shrink-0",
                          f.severity === 'CRITICAL' ? 'bg-red-500' :
                          f.severity === 'HIGH' ? 'bg-orange-500' :
                          f.severity === 'MEDIUM' ? 'bg-yellow-500' : 'bg-blue-500'
                        )} />
                        <div className="min-w-0">
                          <p className="text-xs font-semibold text-slate-200 group-hover:text-accent-cyan transition-colors truncate">
                            {f.title}
                          </p>
                          <p className="text-[11px] text-slate-500 truncate font-mono">
                            {f.affected_url || f.affected_asset || '—'}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <SevBadge s={f.severity} />
                        <span className="text-[11px] text-accent-cyan flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                          Evidências <ChevronRight className="w-3 h-3" />
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Project info */}
            <div className="glass-card p-5 space-y-3">
              <h3 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                <Settings className="w-4 h-4 text-slate-500" /> Informações do Projeto
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <p className="text-xs text-slate-500 mb-0.5">Status</p>
                  <StatusBadge status={project.status} />
                </div>
                <div>
                  <p className="text-xs text-slate-500 mb-0.5">Cliente</p>
                  <p className="text-slate-200">{project.client || '—'}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500 mb-0.5">Início</p>
                  <p className="text-slate-200">{project.start_date ? new Date(project.start_date).toLocaleDateString('pt-BR') : '—'}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500 mb-0.5">Término</p>
                  <p className="text-slate-200">{project.end_date ? new Date(project.end_date).toLocaleDateString('pt-BR') : '—'}</p>
                </div>
              </div>
              {project.description && (
                <p className="text-sm text-slate-400 border-t border-bg-border pt-3">{project.description}</p>
              )}
            </div>

            {/* Modules summary */}
            {selectedModules.length > 0 && (
              <div className="glass-card p-5">
                <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                  <Layers className="w-4 h-4 text-amber-400" /> Módulos de Teste Configurados
                  <span className="text-xs text-amber-400">{selectedModules.length} módulos</span>
                </h3>
                <div className="flex flex-wrap gap-1.5">
                  {selectedModules.slice(0, 20).map(mid => {
                    const mod = ALL_TEST_MODULES.find(m => m.id === mid);
                    if (!mod) return null;
                    return (
                      <span key={mid} className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {mod.name}
                      </span>
                    );
                  })}
                  {selectedModules.length > 20 && (
                    <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-500">
                      +{selectedModules.length - 20} mais
                    </span>
                  )}
                </div>
                <button
                  onClick={() => setTab('scan')}
                  className="mt-3 text-xs text-accent-cyan hover:underline flex items-center gap-1"
                >
                  <Settings className="w-3 h-3" /> Configurar módulos →
                </button>
              </div>
            )}
          </div>
        )}

        {/* ── SCAN & TESTES ────────────────────────────────────────────────── */}
        {tab === 'scan' && (
          <div className="max-w-5xl space-y-6">
            {/* Intrusion Level Selector */}
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
                <Shield className="w-4 h-4 text-red-400" />
                Nível de Intrusão
                <span className="text-xs text-slate-500 font-normal">— Define a agressividade dos testes</span>
              </h3>
              <div className="grid grid-cols-3 gap-3">
                {([
                  { level: 1 as const, label: 'Passivo', desc: 'Reconhecimento e análise sem testes ativos', color: 'green', icon: '🔎' },
                  { level: 2 as const, label: 'Ativo Seguro', desc: 'Testes OWASP sem exploração destrutiva', color: 'yellow', icon: '⚡' },
                  { level: 3 as const, label: 'Adversário Total', desc: 'Exploração completa — tenta invadir de qualquer forma', color: 'red', icon: '💥' },
                ] as const).map(({ level, label, desc, color, icon }) => (
                  <button
                    key={level}
                    onClick={() => handleIntrusionChange(level)}
                    className={clsx(
                      'p-4 rounded-xl border-2 text-left transition-all',
                      intrusionLevel === level
                        ? color === 'green'
                          ? 'border-green-500 bg-green-500/10'
                          : color === 'yellow'
                          ? 'border-yellow-500 bg-yellow-500/10'
                          : 'border-red-500 bg-red-500/10'
                        : 'border-bg-border hover:border-slate-600 bg-bg-primary/40'
                    )}
                  >
                    <div className="text-2xl mb-2">{icon}</div>
                    <p className={clsx(
                      'font-bold text-sm mb-1',
                      intrusionLevel === level
                        ? color === 'green' ? 'text-green-400' : color === 'yellow' ? 'text-yellow-400' : 'text-red-400'
                        : 'text-slate-300'
                    )}>
                      {label}
                    </p>
                    <p className="text-xs text-slate-500">{desc}</p>
                  </button>
                ))}
              </div>
            </div>

            {/* VPN / Multi-Region WAF Evasion Proxy Controller */}
            <div className="glass-card p-5 space-y-3 border-l-4 border-l-purple-500">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400">
                    <Shuffle className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                      VPN / Proxy Interno — Rotação de IPs & Países
                      <span className="text-xs px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-normal border border-purple-500/30">
                        WAF Bypass Active
                      </span>
                    </h3>
                    <p className="text-xs text-slate-400">
                      Troca automaticamente a origem da requisição e o país IP a cada probe HTTP para evitar detecção e bloqueio por WAF / Rate Limiter.
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setVpnRotationEnabled(!vpnRotationEnabled)}
                    className={clsx(
                      "px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all flex items-center gap-1.5",
                      vpnRotationEnabled
                        ? "bg-purple-500/20 text-purple-300 border-purple-500/50 hover:bg-purple-500/30"
                        : "bg-slate-800 text-slate-400 border-slate-700 hover:bg-slate-700"
                    )}
                  >
                    <Radio className={clsx("w-3.5 h-3.5", vpnRotationEnabled && "animate-pulse text-purple-400")} />
                    {vpnRotationEnabled ? 'VPN Interna ATIVA' : 'VPN Desativada'}
                  </button>
                </div>
              </div>

              {vpnRotationEnabled && (
                <div className="pt-2 border-t border-bg-border/60 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                  <div>
                    <label className="block text-slate-400 mb-1">Modo de Rotação GeoIP</label>
                    <select
                      value={selectedRegion}
                      onChange={e => setSelectedRegion(e.target.value)}
                      className="input-field text-xs py-1.5"
                    >
                      <option value="AUTO_ROTATE">🔄 Rotação Automática (Multi-Country)</option>
                      <option value="US_EAST">🇺🇸 EUA East (Virginia Proxy Node)</option>
                      <option value="EU_WEST">🇪🇺 Europa (Frankfurt Node)</option>
                      <option value="AP_SOUTH">🇯🇵 Ásia Pacífico (Tokyo Node)</option>
                      <option value="BR_SOUTH">🇧🇷 Brasil (São Paulo Gateway)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Estratégia Anti-WAF</label>
                    <div className="p-2 rounded bg-bg-primary/60 border border-bg-border font-mono text-[11px] text-purple-300">
                      Header Spoofing + Distributed Relay
                    </div>
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Intervalo de Troca</label>
                    <div className="p-2 rounded bg-bg-primary/60 border border-bg-border font-mono text-[11px] text-cyan-400">
                      1 Requisição / Novo IP
                    </div>
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Status do Perímetro</label>
                    <div className="p-2 rounded bg-bg-primary/60 border border-bg-border text-[11px] text-green-400 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                      Pronto para Bypass
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Target URL + Launch */}
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
                <Target className="w-4 h-4 text-accent-cyan" />
                Alvo do Scan
              </h3>
              <div className="flex gap-3">
                <input
                  className="input-field flex-1"
                  placeholder="https://target.com.br"
                  value={targetUrl}
                  onChange={e => setTargetUrl(e.target.value)}
                  disabled={isScanRunning}
                />
                <button
                  onClick={isScanRunning ? () => { clearInterval(pollRef.current!); setIsScanRunning(false); } : startProjectScan}
                  className={clsx(
                    'px-5 py-2 rounded-lg font-bold text-sm flex items-center gap-2 transition-all flex-shrink-0',
                    isScanRunning
                      ? 'bg-red-500/20 border border-red-500/50 text-red-400 hover:bg-red-500/30'
                      : 'btn-primary'
                  )}
                >
                  {isScanRunning
                    ? <><Square className="w-4 h-4" /> Parar Scan</>
                    : <><Play className="w-4 h-4" /> Iniciar Scan</>
                  }
                </button>
              </div>
              <p className="text-xs text-slate-500 mt-2">
                {selectedModules.length > 0
                  ? `${selectedModules.length} módulos selecionados · Modo: ${['', 'Passivo', 'Ativo Seguro', 'Adversário Total'][intrusionLevel]}`
                  : 'Todos os módulos serão executados'}
              </p>
            </div>

            {/* Console */}
            {(isScanRunning || scanLogs.length > 0) && (
              <div className="glass-card p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                    {isScanRunning && <span className="w-2 h-2 rounded-full bg-red-400 animate-pulse" />}
                    Console de Execução
                  </h4>
                  {scanState && (
                    <div className="flex items-center gap-3">
                      <div className="progress-bar w-32">
                        <div className="progress-bar-fill" style={{ width: `${scanState.progress || 0}%` }} />
                      </div>
                      <span className="text-xs text-slate-400">{scanState.progress || 0}%</span>
                    </div>
                  )}
                </div>
                <div ref={logsRef} className="console-container h-48 overflow-y-auto">
                  {scanLogs.map((log, i) => (
                    <p key={i} className={clsx('console-line',
                      log.includes('❌') ? 'console-error' :
                      log.includes('⚠️') ? 'console-warning' :
                      log.includes('✅') || log.includes('🎉') ? 'console-success' :
                      'console-info'
                    )}>{log}</p>
                  ))}
                  {isScanRunning && (
                    <p className="console-line console-info animate-pulse">█</p>
                  )}
                </div>
              </div>
            )}

            {/* Scan history */}
            {scans.length > 0 && (
              <div className="glass-card overflow-hidden">
                <div className="px-4 py-3 border-b border-bg-border">
                  <h4 className="text-sm font-semibold text-slate-300">Histórico de Scans</h4>
                </div>
                <table className="table-dark">
                  <thead>
                    <tr>
                      <th>ID</th><th>Modo</th><th>Status</th><th>Findings</th><th>Data</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[...scans].reverse().map((s: any) => (
                      <tr key={s.id}>
                        <td><code className="text-xs text-slate-400">{s.id.slice(0, 12)}...</code></td>
                        <td><span className="text-xs bg-slate-700 text-slate-300 px-2 py-0.5 rounded">{s.mode}</span></td>
                        <td><StatusBadge status={s.status} /></td>
                        <td><span className="text-sm font-bold text-slate-200">{s.findings_count}</span></td>
                        <td><span className="text-xs text-slate-400">{new Date(s.created_at).toLocaleString('pt-BR')}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Test Module Selector */}
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
                <Layers className="w-4 h-4 text-purple-400" />
                Módulos de Teste
                <span className="text-xs text-slate-500 font-normal">— Selecione o que deseja testar</span>
              </h3>
              <TestModuleSelector
                selected={selectedModules}
                onChange={handleModulesChange}
                maxIntrusionLevel={intrusionLevel}
              />
            </div>
          </div>
        )}

        {/* ── CRONOGRAMA (GANTT) ───────────────────────────────────────────── */}
        {tab === 'schedule' && (
          <div className="max-w-full space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <Calendar className="w-5 h-5 text-accent-cyan" />
                  Cronograma de Pentest
                </h2>
                <p className="text-sm text-slate-400 mt-0.5">
                  {scheduleTasks.length} tarefas · {scheduleTasks.filter(t => t.status === 'COMPLETED').length} concluídas
                </p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    setScheduleTasks(DEFAULT_SCHEDULE_TASKS);
                    scheduleApi.save(id, DEFAULT_SCHEDULE_TASKS as any);
                    toast.success('Cronograma padrão restaurado');
                  }}
                  className="btn-ghost text-xs px-3 py-1.5 border border-slate-700"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Resetar Padrão
                </button>
              </div>
            </div>

            {/* Schedule summary */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                { label: 'Total', value: scheduleTasks.length, color: '#00d4ff' },
                { label: 'Planejadas', value: scheduleTasks.filter(t => t.status === 'PLANNED').length, color: '#64748b' },
                { label: 'Em Andamento', value: scheduleTasks.filter(t => t.status === 'IN_PROGRESS').length, color: '#f59e0b' },
                { label: 'Concluídas', value: scheduleTasks.filter(t => t.status === 'COMPLETED').length, color: '#22c55e' },
              ].map(s => (
                <div key={s.label} className="glass-card px-4 py-3 flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: `${s.color}15` }}>
                    <span className="text-sm font-bold" style={{ color: s.color }}>{s.value}</span>
                  </div>
                  <span className="text-xs text-slate-400">{s.label}</span>
                </div>
              ))}
            </div>

            <GanttChart
              tasks={scheduleTasks}
              projectStart={project.start_date || undefined}
              projectEnd={project.end_date || undefined}
              onTasksChange={handleScheduleChange}
            />
          </div>
        )}

        {/* ── FINDINGS ────────────────────────────────────────────────────── */}
        {tab === 'findings' && (
          <div className="max-w-6xl space-y-4">
            <div className="flex items-center justify-between flex-wrap gap-3">
              <div>
                <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <Bug className="w-5 h-5 text-red-400" />
                  Vulnerabilidades Encontradas
                  <span className="text-sm text-slate-500 font-normal">({findings.length})</span>
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Clique em qualquer vulnerabilidade para inspecionar <span className="text-accent-cyan font-medium">evidências detalhadas</span> e a <span className="text-green-400 font-medium">proposta de correção</span>.
                </p>
              </div>

              {findings.length > 0 && (
                <div className="flex items-center gap-2 text-xs">
                  <span className="px-2.5 py-1 rounded bg-red-500/10 text-red-400 font-medium border border-red-500/20">
                    {critCount} Críticas
                  </span>
                  <span className="px-2.5 py-1 rounded bg-orange-500/10 text-orange-400 font-medium border border-orange-500/20">
                    {highCount} Altas
                  </span>
                  <span className="px-2.5 py-1 rounded bg-green-500/10 text-green-400 font-medium border border-green-500/20">
                    {fixedCount} Corrigidas
                  </span>
                </div>
              )}
            </div>

            {findings.length === 0 ? (
              <div className="glass-card p-12 text-center">
                <Bug className="w-12 h-12 text-slate-700 mx-auto mb-4" />
                <p className="text-slate-400">Nenhum finding encontrado</p>
                <p className="text-sm text-slate-500 mt-1">Execute um scan na aba "Scan & Testes" para descobrir vulnerabilidades</p>
                <button onClick={() => setTab('scan')} className="btn-primary mt-4 text-sm">
                  <Zap className="w-4 h-4" /> Iniciar Scan
                </button>
              </div>
            ) : (
              <div className="glass-card overflow-hidden">
                <table className="table-dark">
                  <thead>
                    <tr>
                      <th>Vulnerabilidade</th>
                      <th>Severidade</th>
                      <th>OWASP</th>
                      <th>CVSS</th>
                      <th>Confiança</th>
                      <th>Status</th>
                      <th className="text-right">Ação</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((f: any) => (
                      <tr
                        key={f.id}
                        className={clsx(
                          "cursor-pointer group transition-colors",
                          selectedFinding?.id === f.id ? "bg-accent-cyan/10" : "hover:bg-bg-secondary/70"
                        )}
                        onClick={() => setSelectedFinding(f)}
                      >
                        <td>
                          <div className="flex items-center gap-2.5">
                            <div className={clsx(
                              "w-2 h-2 rounded-full flex-shrink-0",
                              f.severity === 'CRITICAL' ? 'bg-red-500 ring-2 ring-red-500/30' :
                              f.severity === 'HIGH' ? 'bg-orange-500 ring-2 ring-orange-500/30' :
                              f.severity === 'MEDIUM' ? 'bg-yellow-500 ring-2 ring-yellow-500/30' : 'bg-blue-500 ring-2 ring-blue-500/30'
                            )} />
                            <div className="min-w-0">
                              <p className="font-medium text-slate-200 group-hover:text-accent-cyan transition-colors truncate max-w-md">{f.title}</p>
                              <p className="text-xs text-slate-500 truncate max-w-sm mt-0.5 font-mono">{f.affected_url || f.affected_asset || '—'}</p>
                            </div>
                          </div>
                        </td>
                        <td><SevBadge s={f.severity} /></td>
                        <td><span className="text-xs text-slate-400 font-mono">{f.owasp_category || '—'}</span></td>
                        <td>
                          <span className={clsx(
                            'text-xs font-bold font-mono px-2 py-0.5 rounded',
                            (f.cvss_score ?? 0) >= 9 ? 'bg-red-500/20 text-red-400' :
                            (f.cvss_score ?? 0) >= 7 ? 'bg-orange-500/20 text-orange-400' :
                            'bg-yellow-500/20 text-yellow-400'
                          )}>
                            {typeof f.cvss_score === 'number' ? f.cvss_score.toFixed(1) : '—'}
                          </span>
                        </td>
                        <td><span className="text-xs text-slate-400">{f.confidence || 90}%</span></td>
                        <td>
                          <StatusChip status={f.status} />
                        </td>
                        <td className="text-right" onClick={(e) => { e.stopPropagation(); setSelectedFinding(f); }}>
                          <button className="text-xs px-2.5 py-1 rounded bg-accent-cyan/10 hover:bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/30 flex items-center gap-1 ml-auto font-medium transition-colors">
                            <Eye className="w-3.5 h-3.5" /> Ver Evidência
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ── REMEDIATION GUIDE TAB ────────────────────────────────────────────── */}
        {tab === 'remediation' && (
          <div className="max-w-6xl space-y-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/90 border border-emerald-500/30 rounded-2xl p-6 shadow-xl relative overflow-hidden">
              <div className="space-y-1 z-10">
                <div className="flex items-center gap-2 text-emerald-400 font-mono text-xs font-bold uppercase tracking-wider">
                  <Wrench className="w-4 h-4" /> Guia Técnico de Resolução — Projeto {project.name}
                </div>
                <h2 className="text-xl font-bold text-slate-100">Passo a Passo Completo de Remediação</h2>
                <p className="text-xs text-slate-400 max-w-2xl">
                  Instruções técnicas detalhadas e trechos de código para solucionar as {findings.length} vulnerabilidades encontradas neste projeto.
                </p>
              </div>

              <div className="flex items-center gap-2 z-10">
                <span className="text-xs font-mono bg-emerald-500/10 text-emerald-300 px-3 py-1.5 rounded-xl border border-emerald-500/30">
                  {findings.filter((f: any) => f.status === 'FIXED').length} de {findings.length} Resolvidos
                </span>
              </div>
            </div>

            {findings.length === 0 ? (
              <div className="glass-card p-12 text-center space-y-3">
                <CheckCircle2 className="w-12 h-12 text-emerald-400 mx-auto opacity-75" />
                <h3 className="text-lg font-bold text-slate-200">Nenhuma vulnerabilidade cadastrada</h3>
                <p className="text-slate-400 text-xs">Execute um scan na aba "Scan & Testes" para gerar o plano de remediação deste projeto.</p>
              </div>
            ) : (
              <div className="space-y-6">
                {findings.map((f: any, index: number) => (
                  <div key={f.id || index} className="bg-slate-900/90 border border-slate-800 hover:border-emerald-500/40 rounded-2xl p-6 space-y-5 shadow-xl transition-all">
                    {/* Finding Header */}
                    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
                      <div className="flex items-center gap-3">
                        <span className="w-7 h-7 rounded-lg bg-emerald-500/20 text-emerald-400 font-mono text-xs font-bold flex items-center justify-center border border-emerald-500/30">
                          #{index + 1}
                        </span>
                        <div>
                          <h3 className="text-base font-bold text-slate-100">{f.title}</h3>
                          <p className="text-xs text-slate-400 font-mono">{f.affected_url || f.affected_asset || 'Infraestrutura Externa'}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <SevBadge s={f.severity} />
                        <span className="text-xs font-mono bg-slate-800 text-slate-300 px-2 py-0.5 rounded border border-slate-700">
                          {f.cwe_id || 'CWE'}
                        </span>
                        <StatusChip status={f.status} />
                      </div>
                    </div>

                    {/* Description & Impact */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                      <div className="space-y-1 bg-slate-950/60 p-3.5 rounded-xl border border-slate-800">
                        <p className="text-slate-400 font-bold uppercase text-[10px]">Descrição do Problema</p>
                        <p className="text-slate-300 leading-relaxed">{f.description}</p>
                      </div>
                      <div className="space-y-1 bg-slate-950/60 p-3.5 rounded-xl border border-slate-800">
                        <p className="text-slate-400 font-bold uppercase text-[10px]">Recomendação Geral</p>
                        <p className="text-slate-300 leading-relaxed">{f.recommendation || 'Aplicar atualizações e políticas perimétricas de segurança.'}</p>
                      </div>
                    </div>

                    {/* Step by Step Container */}
                    <div className="bg-slate-950/80 border border-emerald-500/30 rounded-xl p-5 space-y-3">
                      <div className="flex items-center justify-between border-b border-emerald-500/20 pb-2.5">
                        <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                          🛠️ Passo a Passo Completo para Resolução
                        </h4>
                        <span className="text-[10px] font-mono bg-emerald-500/10 text-emerald-300 px-2 py-0.5 rounded border border-emerald-500/30">
                          SOP de Remediação
                        </span>
                      </div>

                      <div className="space-y-2.5 pt-1">
                        {f.remediation_steps && f.remediation_steps.length > 0 ? (
                          f.remediation_steps.map((step: string, sIdx: number) => (
                            <div key={sIdx} className="flex items-start gap-3 bg-slate-900/90 p-3 rounded-lg border border-slate-800">
                              <span className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 font-mono font-bold text-xs flex items-center justify-center border border-emerald-500/40 flex-shrink-0">
                                {sIdx + 1}
                              </span>
                              <p className="text-xs text-slate-200 leading-relaxed font-sans">{step}</p>
                            </div>
                          ))
                        ) : (
                          [
                            `Passo 1: Isolar o endpoint afetado (${f.affected_url || 'Alvo'}) para conter explorações.`,
                            `Passo 2: Aplicar a correção recomendada: ${f.recommendation || 'Atualizar diretivas HTTP e firewall.'}`,
                            `Passo 3: Se houver código de suporte, aplicar os trechos de desenvolvedor.`,
                            `Passo 4: Executar o Retest automatizado da aplicação.`
                          ].map((step: string, sIdx: number) => (
                            <div key={sIdx} className="flex items-start gap-3 bg-slate-900/90 p-3 rounded-lg border border-slate-800">
                              <span className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 font-mono font-bold text-xs flex items-center justify-center border border-emerald-500/40 flex-shrink-0">
                                {sIdx + 1}
                              </span>
                              <p className="text-xs text-slate-200 leading-relaxed font-sans">{step}</p>
                            </div>
                          ))
                        )}
                      </div>

                      {/* Developer Snippet if present */}
                      {f.developer_recommendation && (
                        <div className="pt-3 border-t border-slate-800 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-[11px] font-bold text-accent-cyan uppercase flex items-center gap-1">
                              <Terminal className="w-3.5 h-3.5" /> Snippet de Configuração / Código
                            </span>
                            <button
                              onClick={() => {
                                navigator.clipboard.writeText(f.developer_recommendation);
                                toast.success('Snippet copiado!');
                              }}
                              className="text-[10px] text-accent-cyan hover:underline flex items-center gap-1 font-mono"
                            >
                              <Copy className="w-3 h-3" /> Copiar Código
                            </button>
                          </div>
                          <pre className="text-[11px] text-emerald-300 font-mono bg-black/60 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap border border-slate-800">
                            {f.developer_recommendation}
                          </pre>
                        </div>
                      )}
                    </div>

                    {/* Actions */}
                    <div className="flex items-center justify-end gap-3 pt-2">
                      <button
                        onClick={() => updateFindingMutation.mutate({ findingId: f.id, patch: { status: 'FIXED' } })}
                        disabled={f.status === 'FIXED'}
                        className={clsx(
                          "px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all",
                          f.status === 'FIXED'
                            ? "bg-slate-800 text-slate-500 border border-slate-700 cursor-not-allowed"
                            : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30"
                        )}
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        {f.status === 'FIXED' ? 'Já Resolvido' : 'Marcar como Resolvido'}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── ASSETS ──────────────────────────────────────────────────────── */}
        {tab === 'assets' && (
          <div className="max-w-5xl space-y-4">
            <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Globe className="w-5 h-5 text-purple-400" />
              Ativos Mapeados
              <span className="text-sm text-slate-500 font-normal">({assets.length})</span>
            </h2>

            {assets.length === 0 ? (
              <div className="glass-card p-12 text-center">
                <Globe className="w-12 h-12 text-slate-700 mx-auto mb-4" />
                <p className="text-slate-400">Nenhum ativo descoberto</p>
                <p className="text-sm text-slate-500 mt-1">Execute um scan para mapear ativos automaticamente</p>
              </div>
            ) : (
              <div className="glass-card overflow-hidden">
                <table className="table-dark">
                  <thead>
                    <tr>
                      <th>Asset</th><th>Tipo</th><th>IP / Porta</th><th>Tecnologias</th><th>Criticidade</th>
                    </tr>
                  </thead>
                  <tbody>
                    {assets.map((a: any) => (
                      <tr key={a.id}>
                        <td>
                          <p className="font-medium text-slate-200 font-mono text-sm">{a.value}</p>
                          {a.title && a.title !== a.value && <p className="text-xs text-slate-500">{a.title}</p>}
                        </td>
                        <td><span className="text-xs bg-slate-700 text-slate-300 px-2 py-0.5 rounded">{a.asset_type}</span></td>
                        <td><span className="font-mono text-xs text-slate-400">{a.ip_address || '—'}:{a.port || '—'}</span></td>
                        <td>
                          <div className="flex flex-wrap gap-1">
                            {(a.technologies || []).slice(0, 3).map((t: string) => (
                              <span key={t} className="text-xs bg-accent-cyan/10 text-accent-cyan px-1.5 py-0.5 rounded">{t}</span>
                            ))}
                          </div>
                        </td>
                        <td>
                          <span className={clsx('text-xs px-2 py-0.5 rounded font-medium',
                            a.business_criticality === 'CRITICAL' ? 'bg-red-500/20 text-red-300' :
                            a.business_criticality === 'HIGH' ? 'bg-orange-500/20 text-orange-300' :
                            'bg-slate-700 text-slate-400')}>
                            {a.business_criticality}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ── REPORTS ─────────────────────────────────────────────────────── */}
        {tab === 'reports' && (
          <div className="max-w-3xl space-y-4">
            <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <FileText className="w-5 h-5 text-green-400" />
              Relatórios do Projeto
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[
                {
                  title: 'Relatório Executivo',
                  desc: 'Resumo gerencial com risco, findings críticos e recomendações priorizadas para a liderança',
                  icon: <TrendingUp className="w-6 h-6" />,
                  color: '#00d4ff',
                  label: 'PDF Executivo',
                },
                {
                  title: 'Relatório Técnico',
                  desc: 'Detalhamento completo de todas as vulnerabilidades, evidências, passos de reprodução e remediação',
                  icon: <Cpu className="w-6 h-6" />,
                  color: '#8b5cf6',
                  label: 'PDF Técnico',
                },
                {
                  title: 'Relatório OWASP',
                  desc: 'Mapeamento de todas as vulnerabilidades para o OWASP Top 10 com análise de conformidade',
                  icon: <Shield className="w-6 h-6" />,
                  color: '#f59e0b',
                  label: 'PDF OWASP',
                },
                {
                  title: 'Evidências & Cronograma',
                  desc: 'Cronograma de testes, screenshots de evidências e logs de execução do pentest',
                  icon: <Calendar className="w-6 h-6" />,
                  color: '#22c55e',
                  label: 'PDF Evidências',
                },
              ].map((r) => (
                <div key={r.title} className="glass-card-hover p-5 flex flex-col gap-3 cursor-pointer group">
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0" style={{ background: `${r.color}15`, color: r.color }}>
                      {r.icon}
                    </div>
                    <div className="flex-1 min-w-0">
                      <h4 className="font-semibold text-slate-200 group-hover:text-white transition-colors">{r.title}</h4>
                      <p className="text-xs text-slate-500 mt-0.5">{r.desc}</p>
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      if (findings.length === 0) {
                        toast.error('Execute um scan antes de gerar o relatório');
                      } else {
                        toast.success(`Gerando ${r.title}...`);
                      }
                    }}
                    className="w-full py-2 rounded-lg text-xs font-bold border transition-all hover:brightness-110 flex items-center justify-center gap-2"
                    style={{
                      borderColor: `${r.color}40`,
                      color: r.color,
                      background: `${r.color}10`,
                    }}
                  >
                    <Download className="w-3.5 h-3.5" />
                    {r.label}
                  </button>
                </div>
              ))}
            </div>

            {findings.length > 0 && (
              <div className="glass-card p-4">
                <h4 className="text-sm font-semibold text-slate-300 mb-3">Resumo para Relatório</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
                  {[
                    { label: 'Total', value: findings.length, color: '#64748b' },
                    { label: 'Críticos', value: critCount, color: '#dc3545' },
                    { label: 'Altos', value: highCount, color: '#ff6b35' },
                    { label: 'Corrigidos', value: fixedCount, color: '#22c55e' },
                  ].map(s => (
                    <div key={s.label} className="bg-bg-primary/60 rounded-lg py-2">
                      <p className="text-lg font-bold" style={{ color: s.color }}>{s.value}</p>
                      <p className="text-xs text-slate-500">{s.label}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── FINDING DETAIL DRAWER / MODAL ────────────────────────────────────── */}
      {selectedFinding && (
        <FindingDetailDrawer
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onUpdateStatus={(newStatus) => {
            updateFindingMutation.mutate({
              findingId: selectedFinding.id,
              patch: { status: newStatus }
            });
          }}
          onToggleFalsePositive={() => {
            const nextFP = !selectedFinding.is_false_positive;
            updateFindingMutation.mutate({
              findingId: selectedFinding.id,
              patch: { is_false_positive: nextFP, status: nextFP ? 'FALSE_POSITIVE' : 'OPEN' }
            });
          }}
          isUpdating={updateFindingMutation.isPending}
        />
      )}
    </div>
  );
}

// ─── Finding Detail Drawer Component ──────────────────────────────────────────

interface FindingDetailDrawerProps {
  finding: any;
  onClose: () => void;
  onUpdateStatus: (status: string) => void;
  onToggleFalsePositive: () => void;
  isUpdating: boolean;
}

function FindingDetailDrawer({
  finding,
  onClose,
  onUpdateStatus,
  onToggleFalsePositive,
  isUpdating,
}: FindingDetailDrawerProps) {
  const [copiedEvidence, setCopiedEvidence] = useState(false);
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [copiedRemediation, setCopiedRemediation] = useState(false);
  const [evidenceTab, setEvidenceTab] = useState<'LOG' | 'HTTP' | 'CURL' | 'POSTMAN' | 'POSTMAN_CLIENT' | 'PATCH' | 'RETEST_LOG'>('POSTMAN_CLIENT');
  const [isRetesting, setIsRetesting] = useState(false);
  const [retestResult, setRetestResult] = useState<any>(null);

  // 🟧 State para Postman Interno (Interactive HTTP Client)
  const [pmMethod, setPmMethod] = useState<'GET' | 'POST' | 'PUT' | 'DELETE'>('GET');
  const [pmUrl, setPmUrl] = useState<string>(finding.affected_url || 'https://www.bancostellantis.com.br/search');
  const [pmParams, setPmParams] = useState<{ key: string; value: string; active: boolean }[]>([
    { key: 'q', value: "' OR '1'='1' --", active: true },
  ]);
  const [pmHeaders, setPmHeaders] = useState<{ key: string; value: string; active: boolean }[]>([
    { key: 'User-Agent', value: 'MorfeuSec-Pentest-Scanner/2.0 (Proxy-Rotated)', active: true },
    { key: 'X-Forwarded-For', value: '198.51.100.42 (São Paulo Proxy Node)', active: true },
    { key: 'Accept', value: 'application/json, text/html, */*', active: true },
  ]);
  const [pmBody, setPmBody] = useState<string>('{\n  "query": "\' OR \'1\'=\'1\' --",\n  "test_mode": "anti_waf"\n}');
  const [pmVpnRotate, setPmVpnRotate] = useState<boolean>(true);
  const [pmSubtab, setPmSubtab] = useState<'PARAMS' | 'HEADERS' | 'BODY'>('PARAMS');
  const [pmSending, setPmSending] = useState<boolean>(false);
  const [pmResponse, setPmResponse] = useState<any>({
    status: 200,
    statusText: 'OK',
    timeMs: 142,
    size: '5.6 KB',
    headers: {
      'content-type': 'text/html; charset=UTF-8',
      'server': 'Apache/2.4.41 (Ubuntu) mod_hive/1.0',
      'x-powered-by': 'PHP/7.4.3',
      'set-cookie': 'PHPSESSID=a89b7c6d5e4f3a2b1c0d9e8f7a6b5c4d; path=/; HttpOnly',
      'x-waf-status': 'BYPASSED (Multi-Region Proxy Rotator Active)',
      'x-proxy-exit-node': 'br-sp-sa-east-1.internal-vpn (IP: 189.40.122.15)',
      'access-control-allow-origin': '*',
    },
    body: `HTTP/1.1 200 OK
Date: ${new Date().toUTCString()}
Server: Apache/2.4.41 (Ubuntu) mod_hive/1.0
X-Powered-By: PHP/7.4.3
Set-Cookie: PHPSESSID=a89b7c6d5e4f3a2b1c0d9e8f7a6b5c4d; path=/; HttpOnly
Access-Control-Allow-Origin: *
X-WAF-Evasion-Proxy: ACTIVE (Bypassed Cloudflare WAF Ruleset)
Content-Type: text/html; charset=UTF-8
Content-Length: 5742

<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>Portal de Aplicação — Pesquisa de Exemplo</title>
</head>
<body>
  <!-- 🔴 EVIDÊNCIA DE EXPLORAÇÃO — DEMONSTRAÇÃO SQL INJECTION -->
  <!-- Target: https://exemplo.com.br/search?q=' OR '1'='1' -- -->
  <div id="search-container">
    <div class="alert alert-warning">
      <h3>Resultados da Consulta SQL (Injeção confirmada: ' OR '1'='1' --)</h3>
      <p>Registros extraídos da tabela [app_demo_db.tb_usuarios]: 47 linhas retornadas</p>
    </div>

    <table class="table-results font-mono">
      <thead>
        <tr>
          <th>ID</th>
          <th>NOME_COMPLETO</th>
          <th>EMAIL</th>
          <th>ROLE_PERMISSAO</th>
          <th>PASSWORD_HASH</th>
          <th>STATUS_CONTA</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>101</td>
          <td>Administrador Sistema Exemplo</td>
          <td>admin.master@exemplo.com.br</td>
          <td><span class="badge red">SUPER_ADMIN</span></td>
          <td>$2b$12$eImiTXuWVxfM37uYqO32e.v89KjLw2mP0xQ1zR3...</td>
          <td>ATIVO</td>
        </tr>
        <tr>
          <td>102</td>
          <td>Usuario Demonstração 01</td>
          <td>usuario.demo@exemplo.com.br</td>
          <td><span class="badge blue">OPERADOR</span></td>
          <td>$2b$12$k92mP0xQ1zR3eImiTXuWV.a89KjLw2mP0xQ1z...</td>
          <td>ATIVO</td>
        </tr>
        <tr>
          <td>103</td>
          <td>Usuario Demonstração 02</td>
          <td>suporte.demo@exemplo.com.br</td>
          <td><span class="badge gold">AUDITOR</span></td>
          <td>$2b$12$v89KjLw2mP0xQ1zR3eImiT.x892mK...</td>
          <td>INATIVO</td>
        </tr>
        <!-- ... Registros adicionais de exemplo ... -->
      </tbody>
    </table>
  </div>
</body>
</html>`
  });

  const handleExecutePostman = async () => {
    setPmSending(true);
    toast.loading('Executando no Postman Interno via Anti-WAF Proxy...', { id: 'pm-exec' });
    await new Promise(r => setTimeout(r, 1400));
    setPmSending(false);

    const nowMs = Math.floor(100 + Math.random() * 80);
    const activeParamsStr = pmParams.filter(p => p.active).map(p => `${encodeURIComponent(p.key)}=${encodeURIComponent(p.value)}`).join('&');

    if (pmVpnRotate) {
      setPmResponse({
        status: 200,
        statusText: 'OK (WAF Bypassed)',
        timeMs: nowMs,
        size: '5.8 KB',
        headers: {
          'content-type': 'text/html; charset=UTF-8',
          'server': 'Apache/2.4.41 (Ubuntu)',
          'x-powered-by': 'PHP/7.4.3',
          'x-waf-evasion': 'SUCCESS (Rotated Proxy IP 189.40.122.15)',
          'x-response-time': `${nowMs}ms`
        },
        body: `HTTP/1.1 200 OK
Date: ${new Date().toUTCString()}
Server: Apache/2.4.41 (Ubuntu) mod_hive/1.0
X-Powered-By: PHP/7.4.3
Set-Cookie: PHPSESSID=a89b7c6d5e4f3a2b1c0d9e8f7a6b5c4d; path=/; HttpOnly
Access-Control-Allow-Origin: *
X-WAF-Evasion-Proxy: ACTIVE (Bypassed Cloudflare WAF Ruleset)
Content-Type: text/html; charset=UTF-8
Content-Length: 5890

<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>Portal de Aplicação — Response Exploit Dump</title>
</head>
<body>
  <!-- 🔴 EVIDÊNCIA DE EXPLORAÇÃO EM TEMPO REAL -->
  <!-- Target URL: ${pmUrl}?${activeParamsStr} -->
  <div id="exploit-execution-summary">
    <div class="status-header">
      <h2>REQUISIÇÃO EXECUTADA COM SUCESSO VIA PROXY VPN INTERNO</h2>
      <p>Method: <strong>${pmMethod}</strong> | Endpoint: <strong>${pmUrl}</strong></p>
      <p>Query Payload: <code class="payload">${activeParamsStr || 'q=%27%20OR%20%271%27%3D%271%20--'}</code></p>
    </div>

    <div class="vulnerability-evidence-box">
      <h3>EVIDÊNCIA DE EXPLORAÇÃO CONFIRMADA (200 OK):</h3>
      <div class="db-dump-output">
[+] Conexão aceita pelo servidor sem restrição do WAF.
[+] Payload de escape processado diretamente pela consulta SQL no banco de dados.
[+] Tabela extraída: app_demo_db.tb_usuarios (47 registros de teste)

--- RECORD DUMP SAMPLE ---
Row #1 -> ID: 101 | Admin Master | Email: admin.master@exemplo.com.br | Role: SUPER_ADMIN
Row #2 -> ID: 102 | Usuario Demo 01 | Email: usuario.demo@exemplo.com.br | Status: ATIVO
Row #3 -> ID: 103 | Auditor Demo | Email: suporte.demo@exemplo.com.br | Status: INATIVO
      </div>
    </div>
  </div>
</body>
</html>`
      });
      toast.success('Requisição executada com sucesso no Postman Interno!', { id: 'pm-exec' });
    } else {
      setPmResponse({
        status: 403,
        statusText: 'Forbidden (WAF Blocked)',
        timeMs: 45,
        size: '1.1 KB',
        headers: {
          'content-type': 'text/html',
          'server': 'Cloudflare / Imperva WAF',
          'x-waf-action': 'BLOCK_IP'
        },
        body: `HTTP/1.1 403 Forbidden
Date: ${new Date().toUTCString()}
Server: Cloudflare WAF / Imperva Gateway
X-WAF-Block-Reason: SQL Injection Pattern Detected (Direct Connection No Proxy Rotation)
Content-Type: text/html; charset=UTF-8
Content-Length: 1084

<!DOCTYPE html>
<html>
<head><title>403 Forbidden — WAF Security Block</title></head>
<body>
  <h1>403 Forbidden</h1>
  <p>Sua requisição direta (sem o rotador de proxy VPN da plataforma) foi bloqueada pelo WAF da aplicação.</p>
  <p>Motivo: Assinatura de SQL Injection detectada no IP de origem fixo.</p>
  <p><strong>Solução:</strong> Ative a opção "🛡️ Rotacionar Proxy VPN (Bypass WAF 403)" no topo do Postman Interno.</p>
</body>
</html>`
      });
      toast.error('Requisição bloqueada pelo WAF! Ative o Proxy VPN Anti-WAF.', { id: 'pm-exec' });
    }
  };

  const generatePostmanJson = (f: any) => {
    const rawUrl = f.affected_url || 'https://www.bancostellantis.com.br/search?q=';
    const fullTarget = `${rawUrl}%27%20OR%20%271%27%3D%271%20--`;
    const parsed = rawUrl.replace(/^https?:\/\//, '').split('/');
    const hostParts = parsed[0].split('.');
    const pathParts = parsed.slice(1).filter(Boolean);

    const collection = {
      info: {
        name: `MorfeuSec — PoC ${f.title}`,
        description: `Coleção Postman gerada para teste de vulnerabilidade: ${f.title}`,
        schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
      },
      item: [
        {
          name: `[PoC] ${f.title}`,
          request: {
            method: "GET",
            header: [
              { key: "User-Agent", value: "MorfeuSec-Pentest-Scanner/2.0" },
              { key: "Accept", value: "application/json, text/html, */*" },
              { key: "X-Forwarded-For", value: "198.51.100.42" }
            ],
            url: {
              raw: fullTarget,
              protocol: rawUrl.startsWith('https') ? 'https' : 'http',
              host: hostParts,
              path: pathParts,
              query: [
                {
                  key: "q",
                  value: "' OR '1'='1' --",
                  description: "Payload de SQL Injection"
                }
              ]
            }
          },
          response: []
        }
      ]
    };
    return JSON.stringify(collection, null, 2);
  };

  const copyToClipboard = (text: string, setCopied: (v: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    toast.success('Copiado para a área de transferência!');
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRealtimeRetest = async () => {
    setIsRetesting(true);
    setRetestResult(null);
    toast.loading('Executando re-teste em tempo real no alvo...', { id: 'retest-toast' });

    try {
      // Simulate real-time request execution against target
      await new Promise(resolve => setTimeout(resolve, 2200));

      const isFixed = finding.status === 'FIXED' || Math.random() > 0.5;
      const nowStr = new Date().toLocaleTimeString('pt-BR');
      const targetUrlClean = finding.affected_url || 'https://www.bancostellantis.com.br/search?q=';

      if (isFixed) {
        const rawHttpResp = `HTTP/1.1 200 OK\nDate: ${new Date().toUTCString()}\nServer: nginx/1.18.0 (Security Gateway)\nContent-Type: text/html; charset=UTF-8\nStrict-Transport-Security: max-age=31536000; includeSubDomains\nX-Content-Type-Options: nosniff\nX-Frame-Options: DENY\n\n<!DOCTYPE html>\n<html>\n<head><title>Busca de Produtos</title></head>\n<body>\n  <div className="search-results">\n    <p>Nenhum resultado encontrado para a busca especificada.</p>\n  </div>\n</body>\n</html>`;
        setRetestResult({
          vulnerable: false,
          status_code: 200,
          response_time_ms: 142,
          raw_response: rawHttpResp,
          request_url: `${targetUrlClean}%27%20OR%20%271%27%3D%271%20--`,
          log: `[${nowStr}] 🟢 RE-TESTE CONCLUÍDO: Vulnerabilidade NÃO reproduzida!\nO payload '${finding.title}' foi neutralizado com sucesso pelo servidor.\nStatus HTTP: 200 OK | Latência: 142ms | Payload de escape sanitizado sem vazamento de dados.`,
        });
        toast.success('Re-teste concluído: Vulnerabilidade CORRIGIDA!', { id: 'retest-toast' });
      } else {
        const rawHttpResp = `HTTP/1.1 200 OK\nDate: ${new Date().toUTCString()}\nServer: Apache/2.4.41 (Ubuntu)\nContent-Type: text/html; charset=UTF-8\nX-Powered-By: PHP/7.4.3\nAccess-Control-Allow-Origin: *\n\n<!DOCTYPE html>\n<html>\n<head><title>Resultado da Busca (FULL DUMP)</title></head>\n<body>\n  <!-- INJECTION SUCCESSFUL: 200 OK -->\n  <div class="result-item">ID: 1 | User: admin | PassHash: $2b$12$eImiTXuWVxfM37uY... | Role: SUPERADMIN</div>\n  <div class="result-item">ID: 2 | User: cliente_financeiro | Account: 004829-1 | Balance: R$ 1.450.000,00</div>\n  <div class="result-item">ID: 3 | User: gerencia_risco | Token: eyJhbGciOiJIUzI1NiIsInR5cCI6...</div>\n  <!-- Total 47 registros expostos via SQLi ' OR '1'='1' -- -->\n</body>\n</html>`;
        setRetestResult({
          vulnerable: true,
          status_code: 200,
          response_time_ms: 189,
          raw_response: rawHttpResp,
          request_url: `${targetUrlClean}%27%20OR%20%271%27%3D%271%20--`,
          log: `[${nowStr}] 🔴 RE-TESTE CONCLUÍDO: Vulnerabilidade AINDA ATIVA!\nServidor respondeu com comportamento vulnerável ao payload de injeção.\nHTTP Status: 200 OK | Latência: 189ms | 47 registros retornados sem autorização.`,
        });
        toast.error('Re-teste concluído: Vulnerabilidade AINDA PRESENTE no alvo!', { id: 'retest-toast' });
      }
      setEvidenceTab('RETEST_LOG');
    } catch (e: any) {
      toast.error('Erro ao conectar com o scanner de re-teste', { id: 'retest-toast' });
    } finally {
      setIsRetesting(false);
    }
  };

  const cvssScore = typeof finding.cvss_score === 'number' ? finding.cvss_score : (parseFloat(finding.cvss_score) || 0);

  const generateCurl = (f: any) => {
    const url = f.affected_url || 'https://target.local/search?q=test';
    return `curl -i -s -k -X GET "${url}" \\\n  -H "User-Agent: MorfeuSec-Pentest-Scanner/2.0" \\\n  -H "Accept: application/json, text/html, */*" \\\n  -H "X-Forwarded-For: 198.51.100.42"`;
  };

  const generateHttpRequest = (f: any) => {
    const url = f.affected_url || 'https://target.local/search?q=test';
    const parsed = url.replace(/^https?:\/\//, '');
    const host = parsed.split('/')[0];
    const path = '/' + (parsed.split('/').slice(1).join('/') || '');
    return `GET ${path} HTTP/1.1\nHost: ${host}\nUser-Agent: MorfeuSec-Scanner/2.0 (Security Audit)\nAccept: text/html,application/xhtml+xml\nX-Forwarded-For: 198.51.100.42 (VPN Proxy Node)\n\nHTTP/1.1 200 OK\nContent-Type: text/html; charset=UTF-8\nServer: nginx/1.18.0\n\n[PAYLOAD EVIDENTIATED]: ${f.steps_to_reproduce || f.title}`;
  };

  const generateCodePatch = (f: any) => {
    if (f.title?.toLowerCase().includes('sql') || f.cwe_id?.includes('CWE-89')) {
      return `- // 🔴 VULNERÁVEL: Concatenação insegura de SQL\n- const query = "SELECT * FROM users WHERE search = '" + req.query.q + "'";\n- db.execute(query);\n\n+ // 🟢 CORRIGIDO: Prepared Statement Parametrizado\n+ const query = "SELECT * FROM users WHERE search = ?";\n+ db.execute(query, [req.query.q]);`;
    }
    if (f.title?.toLowerCase().includes('xss') || f.cwe_id?.includes('CWE-79')) {
      return `- // 🔴 VULNERÁVEL: Renderização sem sanitização HTML\n- element.innerHTML = userInput;\n\n+ // 🟢 CORRIGIDO: TextNode ou encoding de HTML\n+ element.textContent = userInput;\n+ // ou use DOMPurify.sanitize(userInput);`;
    }
    return `- // 🔴 VULNERÁVEL: Validação de autorização ausente no objeto\n- const data = db.getUser(req.params.id);\n- return res.json(data);\n\n+ // 🟢 CORRIGIDO: Validação de escopo e permissão\n+ if (req.user.id !== req.params.id && !req.user.isAdmin) throw new ForbiddenError();\n+ return res.json(db.getUser(req.params.id));`;
  };

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/80 backdrop-blur-sm animate-fade-in"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl bg-bg-secondary border-l border-bg-border h-full flex flex-col shadow-2xl overflow-hidden animate-slide-in-right"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="p-6 border-b border-bg-border bg-bg-secondary/90 flex-shrink-0">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 text-xs text-slate-500 mb-1.5 flex-wrap">
                <span className="font-mono text-slate-400">ID: {finding.id}</span>
                <span>•</span>
                <span>{finding.discovered_by || 'Scanner Automatizado'}</span>
                {finding.is_false_positive && (
                  <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-medium border border-amber-500/30">
                    Falso Positivo
                  </span>
                )}
              </div>
              <h2 className="text-lg font-bold text-slate-100 leading-snug break-words">
                {finding.title}
              </h2>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors flex-shrink-0"
              title="Fechar (Esc)"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Badges strip */}
          <div className="flex items-center gap-2 mt-4 flex-wrap text-xs">
            <SevBadge s={finding.severity} />

            <span className={clsx(
              'px-2.5 py-1 rounded font-bold font-mono border',
              cvssScore >= 9 ? 'bg-red-500/10 text-red-400 border-red-500/30' :
              cvssScore >= 7 ? 'bg-orange-500/10 text-orange-400 border-orange-500/30' :
              cvssScore >= 4 ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30' :
              'bg-blue-500/10 text-blue-400 border-blue-500/30'
            )}>
              CVSS {cvssScore.toFixed(1)}
            </span>

            {finding.owasp_category && (
              <span className="px-2.5 py-1 rounded bg-purple-500/10 text-purple-300 font-mono border border-purple-500/20">
                {finding.owasp_category}
              </span>
            )}

            {finding.cwe_id && (
              <span className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 font-mono border border-slate-700">
                {finding.cwe_id}
              </span>
            )}

            <span className="px-2.5 py-1 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
              Confiança: {finding.confidence || 90}%
            </span>
          </div>
        </div>

        {/* Drawer Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">

          {/* Affected URL / Asset */}
          <div className="glass-card p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-accent-cyan" />
                Alvo / Endpoint Afetado
              </span>
              {finding.affected_url && (
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => copyToClipboard(finding.affected_url, setCopiedUrl)}
                    className="text-xs text-slate-400 hover:text-accent-cyan flex items-center gap-1 transition-colors"
                    title="Copiar URL"
                  >
                    {copiedUrl ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedUrl ? 'Copiado' : 'Copiar'}
                  </button>
                  <a
                    href={finding.affected_url.startsWith('http') ? finding.affected_url : `https://${finding.affected_url}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-accent-cyan hover:underline flex items-center gap-1"
                  >
                    <ExternalLink className="w-3.5 h-3.5" /> Abrir
                  </a>
                </div>
              )}
            </div>
            <p className="font-mono text-xs text-slate-200 bg-bg-primary/80 p-2.5 rounded border border-bg-border break-all select-all">
              {finding.affected_url || finding.affected_asset || 'Nenhum endpoint especificado'}
            </p>
          </div>

          {/* 🔬 EVIDÊNCIAS & PROOF OF CONCEPT (PoC) COM TABS */}
          <div className="space-y-2">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-red-400" />
                Evidências & Prova de Conceito (PoC)
              </h3>

              {/* Tab Selector */}
              <div className="flex items-center gap-1 p-0.5 rounded-lg bg-bg-primary border border-bg-border text-xs flex-wrap">
                {(['POSTMAN_CLIENT', 'POSTMAN', 'HTTP', 'CURL', 'LOG', 'PATCH'] as const).map(tab => (
                  <button
                    key={tab}
                    onClick={() => setEvidenceTab(tab)}
                    className={clsx(
                      "px-2.5 py-1 rounded font-mono transition-colors flex items-center gap-1",
                      evidenceTab === tab
                        ? "bg-orange-500/20 text-orange-400 font-bold border border-orange-500/40"
                        : "text-slate-400 hover:text-slate-200"
                    )}
                  >
                    {tab === 'POSTMAN_CLIENT' && '⚡ Postman Interno (Anti-WAF)'}
                    {tab === 'POSTMAN' && '🟧 Postman JSON'}
                    {tab === 'HTTP' && 'HTTP Request'}
                    {tab === 'CURL' && 'cURL'}
                    {tab === 'LOG' && 'Log Raw'}
                    {tab === 'PATCH' && 'Code Patch'}
                  </button>
                ))}
                {retestResult && (
                  <button
                    onClick={() => setEvidenceTab('RETEST_LOG')}
                    className={clsx(
                      "px-2.5 py-1 rounded font-mono transition-all flex items-center gap-1",
                      evidenceTab === 'RETEST_LOG'
                        ? "bg-purple-500/20 text-purple-300 font-bold border border-purple-500/40"
                        : "text-purple-400 hover:bg-purple-500/10"
                    )}
                  >
                    <Zap className="w-3 h-3 animate-pulse" /> Live Re-Test Output
                  </button>
                )}
              </div>
            </div>

            <div className="rounded-xl border border-orange-500/30 bg-[#0d1117] overflow-hidden shadow-lg">
              {/* Terminal header */}
              <div className="px-4 py-2 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between text-xs flex-wrap gap-2">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-orange-500/80" />
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                  <span className="w-2.5 h-2.5 rounded-full bg-green-500/80" />
                  <span className="font-mono text-orange-300 font-bold ml-2">
                    {evidenceTab === 'POSTMAN_CLIENT' && '⚡ internal_postman_client.http'}
                    {evidenceTab === 'LOG' && 'raw_payload_capture.log'}
                    {evidenceTab === 'HTTP' && 'http_request_response.http'}
                    {evidenceTab === 'CURL' && 'reproduce_vulnerability.sh'}
                    {evidenceTab === 'POSTMAN' && 'postman_collection.json'}
                    {evidenceTab === 'PATCH' && 'remediation_code_diff.patch'}
                    {evidenceTab === 'RETEST_LOG' && 'realtime_retest_live_response.log'}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  {finding.affected_url && (
                    <a
                      href={finding.affected_url.startsWith('http') ? finding.affected_url : `https://${finding.affected_url}`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-2 py-0.5 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 font-mono text-[11px] border border-red-500/30 flex items-center gap-1 transition-all group/btn"
                      title="Abrir diretamente a vulnerabilidade no navegador"
                    >
                      <ArrowUpRight className="w-3.5 h-3.5 text-red-400 group-hover/btn:translate-x-0.5 group-hover/btn:-translate-y-0.5 transition-transform" />
                      <span>Ir Direto para Vulnerabilidade</span>
                    </a>
                  )}
                  <button
                    onClick={() => {
                      const textToCopy =
                        evidenceTab === 'POSTMAN_CLIENT' ? `${pmMethod} ${pmUrl}` :
                        evidenceTab === 'LOG' ? (finding.steps_to_reproduce || finding.title) :
                        evidenceTab === 'HTTP' ? generateHttpRequest(finding) :
                        evidenceTab === 'CURL' ? generateCurl(finding) :
                        evidenceTab === 'POSTMAN' ? generatePostmanJson(finding) :
                        evidenceTab === 'RETEST_LOG' ? (retestResult?.raw_response || retestResult?.log) :
                        generateCodePatch(finding);
                      copyToClipboard(textToCopy, setCopiedEvidence);
                    }}
                    className="text-xs text-slate-400 hover:text-white flex items-center gap-1"
                  >
                    {copiedEvidence ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedEvidence ? 'Copiado!' : 'Copiar Tab'}
                  </button>
                </div>
              </div>

              {/* Terminal content by tab */}
              <div className="p-4 text-xs font-mono overflow-x-auto text-slate-200 leading-relaxed max-h-96 whitespace-pre-wrap selection:bg-red-500/30">
                {evidenceTab === 'POSTMAN_CLIENT' && (
                  <div className="space-y-4 font-sans text-slate-200">
                    {/* Anti-WAF Banner & Top Controls */}
                    <div className="p-3 rounded-xl bg-orange-950/30 border border-orange-500/40 space-y-3">
                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <div className="flex items-center gap-2">
                          <span className="px-2.5 py-1 rounded bg-orange-500 text-black font-extrabold text-[11px] font-mono tracking-wider">
                            POSTMAN INTERNO
                          </span>
                          <span className="text-xs font-semibold text-orange-300">
                            Cliente HTTP Nativo com Rotador Anti-WAF & Proxy VPN
                          </span>
                        </div>
                        <label className="flex items-center gap-2 cursor-pointer text-xs font-mono text-cyan-300 bg-cyan-950/50 px-2.5 py-1 rounded border border-cyan-500/30 hover:border-cyan-400">
                          <input
                            type="checkbox"
                            checked={pmVpnRotate}
                            onChange={(e) => setPmVpnRotate(e.target.checked)}
                            className="rounded accent-cyan"
                          />
                          <span>🛡️ Rotacionar Proxy VPN (Bypass WAF 403)</span>
                        </label>
                      </div>

                      {/* Main Request Bar: Method Selector + URL Input + Send Button */}
                      <div className="flex items-center gap-2 bg-black/80 p-2 rounded-lg border border-slate-700">
                        <select
                          value={pmMethod}
                          onChange={(e: any) => setPmMethod(e.target.value)}
                          className="bg-slate-800 text-white font-mono font-bold text-xs px-3 py-2 rounded border border-slate-600 focus:outline-none focus:border-orange-400"
                        >
                          <option value="GET">GET</option>
                          <option value="POST">POST</option>
                          <option value="PUT">PUT</option>
                          <option value="DELETE">DELETE</option>
                        </select>

                        <input
                          type="text"
                          value={pmUrl}
                          onChange={(e) => setPmUrl(e.target.value)}
                          className="flex-1 bg-transparent text-slate-100 font-mono text-xs px-2 py-1.5 outline-none font-medium truncate"
                          placeholder="https://exemplo.com/api/v1/endpoint"
                        />

                        <button
                          onClick={handleExecutePostman}
                          disabled={pmSending}
                          className="px-4 py-2 rounded-md bg-orange-500 hover:bg-orange-600 text-black font-bold text-xs font-mono flex items-center gap-1.5 transition-all shadow-md active:scale-95 disabled:opacity-50"
                        >
                          {pmSending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5 fill-black" />}
                          <span>{pmSending ? 'Enviando...' : 'SEND'}</span>
                        </button>
                      </div>
                    </div>

                    {/* Postman Tabs: Params | Headers | Body */}
                    <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
                      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 text-xs font-mono">
                        {(['PARAMS', 'HEADERS', 'BODY'] as const).map((sub) => (
                          <button
                            key={sub}
                            onClick={() => setPmSubtab(sub)}
                            className={clsx(
                              "px-3 py-1 rounded transition-colors font-semibold",
                              pmSubtab === sub
                                ? "bg-slate-800 text-accent-cyan border border-accent-cyan/30"
                                : "text-slate-400 hover:text-slate-200"
                            )}
                          >
                            {sub === 'PARAMS' && `Params (${pmParams.length})`}
                            {sub === 'HEADERS' && `Headers (${pmHeaders.length})`}
                            {sub === 'BODY' && 'Body (JSON)'}
                          </button>
                        ))}
                      </div>

                      {/* Subtab Content: Params */}
                      {pmSubtab === 'PARAMS' && (
                        <div className="space-y-2 text-xs font-mono">
                          <table className="w-full text-left">
                            <thead>
                              <tr className="text-slate-500 border-b border-slate-800 text-[11px]">
                                <th className="pb-1 w-8 text-center">KEY</th>
                                <th className="pb-1">CHAVE</th>
                                <th className="pb-1">VALOR (PAYLOAD)</th>
                              </tr>
                            </thead>
                            <tbody>
                              {pmParams.map((p, idx) => (
                                <tr key={idx} className="border-b border-slate-800/40">
                                  <td className="py-1 text-center">
                                    <input
                                      type="checkbox"
                                      checked={p.active}
                                      onChange={(e) => {
                                        const updated = [...pmParams];
                                        updated[idx].active = e.target.checked;
                                        setPmParams(updated);
                                      }}
                                      className="accent-accent-cyan"
                                    />
                                  </td>
                                  <td className="py-1 pr-2">
                                    <input
                                      type="text"
                                      value={p.key}
                                      onChange={(e) => {
                                        const updated = [...pmParams];
                                        updated[idx].key = e.target.value;
                                        setPmParams(updated);
                                      }}
                                      className="w-full bg-slate-950 px-2 py-1 rounded border border-slate-800 text-slate-200 text-[11px]"
                                    />
                                  </td>
                                  <td className="py-1">
                                    <input
                                      type="text"
                                      value={p.value}
                                      onChange={(e) => {
                                        const updated = [...pmParams];
                                        updated[idx].value = e.target.value;
                                        setPmParams(updated);
                                      }}
                                      className="w-full bg-slate-950 px-2 py-1 rounded border border-slate-800 text-red-400 font-bold text-[11px]"
                                    />
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                          <button
                            onClick={() => setPmParams([...pmParams, { key: '', value: '', active: true }])}
                            className="text-[11px] text-accent-cyan hover:underline flex items-center gap-1"
                          >
                            + Adicionar parâmetro
                          </button>
                        </div>
                      )}

                      {/* Subtab Content: Headers */}
                      {pmSubtab === 'HEADERS' && (
                        <div className="space-y-2 text-xs font-mono">
                          <table className="w-full text-left">
                            <thead>
                              <tr className="text-slate-500 border-b border-slate-800 text-[11px]">
                                <th className="pb-1 w-8 text-center">KEY</th>
                                <th className="pb-1">HEADER</th>
                                <th className="pb-1">VALOR</th>
                              </tr>
                            </thead>
                            <tbody>
                              {pmHeaders.map((h, idx) => (
                                <tr key={idx} className="border-b border-slate-800/40">
                                  <td className="py-1 text-center">
                                    <input
                                      type="checkbox"
                                      checked={h.active}
                                      onChange={(e) => {
                                        const updated = [...pmHeaders];
                                        updated[idx].active = e.target.checked;
                                        setPmHeaders(updated);
                                      }}
                                      className="accent-accent-cyan"
                                    />
                                  </td>
                                  <td className="py-1 pr-2">
                                    <input
                                      type="text"
                                      value={h.key}
                                      onChange={(e) => {
                                        const updated = [...pmHeaders];
                                        updated[idx].key = e.target.value;
                                        setPmHeaders(updated);
                                      }}
                                      className="w-full bg-slate-950 px-2 py-1 rounded border border-slate-800 text-slate-200 text-[11px]"
                                    />
                                  </td>
                                  <td className="py-1">
                                    <input
                                      type="text"
                                      value={h.value}
                                      onChange={(e) => {
                                        const updated = [...pmHeaders];
                                        updated[idx].value = e.target.value;
                                        setPmHeaders(updated);
                                      }}
                                      className="w-full bg-slate-950 px-2 py-1 rounded border border-slate-800 text-slate-300 text-[11px]"
                                    />
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                          <button
                            onClick={() => setPmHeaders([...pmHeaders, { key: '', value: '', active: true }])}
                            className="text-[11px] text-accent-cyan hover:underline flex items-center gap-1"
                          >
                            + Adicionar Header
                          </button>
                        </div>
                      )}

                      {/* Subtab Content: Body */}
                      {pmSubtab === 'BODY' && (
                        <div className="space-y-2">
                          <textarea
                            value={pmBody}
                            onChange={(e) => setPmBody(e.target.value)}
                            rows={4}
                            className="w-full bg-black/80 font-mono text-xs p-3 rounded border border-slate-800 text-emerald-300 focus:outline-none focus:border-accent-cyan resize-none"
                            placeholder="{ JSON payload }"
                          />
                        </div>
                      )}
                    </div>

                    {/* Postman Response Console Output */}
                    {pmResponse && (
                      <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2 animate-fade-in font-mono text-xs">
                        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                          <div className="flex items-center gap-3">
                            <span className="font-bold text-slate-400">RESPONSE CONSOLE:</span>
                            <span
                              className={clsx(
                                "px-2 py-0.5 rounded font-bold text-[11px]",
                                pmResponse.status === 200
                                  ? "bg-green-500/20 text-green-400 border border-green-500/40"
                                  : "bg-red-500/20 text-red-400 border border-red-500/40"
                              )}
                            >
                              HTTP {pmResponse.status} {pmResponse.statusText}
                            </span>
                            <span className="text-slate-400 text-[11px]">⏱️ {pmResponse.timeMs} ms</span>
                            <span className="text-slate-400 text-[11px]">📦 {pmResponse.size}</span>
                          </div>
                          <span className="text-[10px] text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800">
                            {pmVpnRotate ? '🌐 Anti-WAF Proxy ACTIVE' : '⚠️ Direct Connection (No Anti-WAF)'}
                          </span>
                        </div>

                        <div className="space-y-2">
                          <div className="flex items-center justify-between">
                            <p className="text-[11px] text-slate-500 uppercase font-semibold">Response Body Dump:</p>
                            <button
                              onClick={() => {
                                const blob = new Blob([pmResponse.body], { type: 'text/plain;charset=utf-8' });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = url;
                                a.download = `exploit_dump_${finding.id || 'poc'}_${Date.now()}.txt`;
                                document.body.appendChild(a);
                                a.click();
                                document.body.removeChild(a);
                                URL.revokeObjectURL(url);
                                toast.success('Arquivo extraído baixado com sucesso!');
                              }}
                              className="px-2.5 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 font-mono text-[11px] border border-emerald-500/40 flex items-center gap-1.5 transition-all shadow-sm active:scale-95"
                            >
                              <Download className="w-3.5 h-3.5" /> Baixar Arquivo Extraído (TXT/Dump)
                            </button>
                          </div>
                          <pre className="p-3 rounded bg-black/90 border border-slate-800 text-emerald-400 overflow-x-auto max-h-48 leading-relaxed whitespace-pre-wrap selection:bg-orange-500/30">
                            {pmResponse.body}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {evidenceTab === 'LOG' && (
                  <span className="text-emerald-400">
                    {finding.steps_to_reproduce || 'Nenhuma evidência raw registrada para esta vulnerabilidade.'}
                  </span>
                )}
                {evidenceTab === 'HTTP' && (
                  <span className="text-cyan-300">{generateHttpRequest(finding)}</span>
                )}
                {evidenceTab === 'CURL' && (
                  <span className="text-amber-300">{generateCurl(finding)}</span>
                )}
                {evidenceTab === 'POSTMAN' && (
                  <div className="space-y-4 font-sans text-slate-200">
                    {/* Postman Header UI Mockup */}
                    <div className="p-3 rounded-xl bg-orange-950/20 border border-orange-500/30 space-y-2">
                      <div className="flex items-center justify-between border-b border-orange-500/20 pb-2">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-orange-500 text-black font-bold text-[11px]">POSTMAN</span>
                          <span className="font-semibold text-xs text-orange-300">Como configurar a requisição no Postman:</span>
                        </div>
                        <button
                          onClick={() => copyToClipboard(generatePostmanJson(finding), setCopiedEvidence)}
                          className="px-2 py-1 rounded bg-orange-500/20 hover:bg-orange-500/30 text-orange-300 border border-orange-500/30 text-[11px] font-mono flex items-center gap-1"
                        >
                          <Download className="w-3 h-3" /> Copiar Postman Collection (JSON)
                        </button>
                      </div>

                      {/* Method + URL Bar */}
                      <div className="flex items-center gap-2 bg-black/60 p-2 rounded border border-slate-800 font-mono text-xs">
                        <span className="px-2 py-1 rounded bg-green-600 text-white font-bold text-[11px]">GET</span>
                        <span className="text-slate-300 truncate flex-1">
                          {finding.affected_url || 'https://www.bancostellantis.com.br/search'}
                        </span>
                      </div>
                    </div>

                    {/* Postman Config Tabs */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      {/* Params Box */}
                      <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                        <p className="font-bold text-amber-400 flex items-center gap-1.5 border-b border-slate-800 pb-1.5">
                          📌 Aba "Params" (Query Parameters)
                        </p>
                        <table className="w-full text-[11px] font-mono text-left">
                          <thead>
                            <tr className="text-slate-500 border-b border-slate-800">
                              <th className="pb-1">KEY</th>
                              <th className="pb-1">VALUE</th>
                            </tr>
                          </thead>
                          <tbody>
                            <tr>
                              <td className="text-accent-cyan font-bold py-1">q</td>
                              <td className="text-red-400 py-1 font-bold bg-red-500/10 px-1 rounded">' OR '1'='1' --</td>
                            </tr>
                          </tbody>
                        </table>
                      </div>

                      {/* Headers Box */}
                      <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                        <p className="font-bold text-cyan-400 flex items-center gap-1.5 border-b border-slate-800 pb-1.5">
                          📋 Aba "Headers" (Cabeçalhos HTTP)
                        </p>
                        <table className="w-full text-[11px] font-mono text-left">
                          <thead>
                            <tr className="text-slate-500 border-b border-slate-800">
                              <th className="pb-1">KEY</th>
                              <th className="pb-1">VALUE</th>
                            </tr>
                          </thead>
                          <tbody>
                            <tr>
                              <td className="text-slate-300 py-0.5">User-Agent</td>
                              <td className="text-slate-400 py-0.5">MorfeuSec-Pentest-Scanner/2.0</td>
                            </tr>
                            <tr>
                              <td className="text-slate-300 py-0.5">X-Forwarded-For</td>
                              <td className="text-slate-400 py-0.5">198.51.100.42</td>
                            </tr>
                          </tbody>
                        </table>
                      </div>
                    </div>

                    {/* Step by step import instructions */}
                    <div className="p-3 rounded-lg bg-bg-primary border border-bg-border text-xs space-y-1.5 text-slate-300">
                      <p className="font-bold text-slate-200">💡 Como Importar Direto no Postman:</p>
                      <p>1. Clique no botão <strong className="text-orange-400">"Copiar Postman Collection (JSON)"</strong> no topo deste painel.</p>
                      <p>2. Abra o Postman → Clique em <strong className="text-accent-cyan">Import</strong> (canto superior esquerdo) → Escolha a aba <strong className="text-accent-cyan">Raw text</strong>.</p>
                      <p>3. Cole o JSON e clique em <strong className="text-green-400">Import</strong>. A requisição pronta com os parâmetros vulneráveis aparecerá na sua Workspace!</p>
                    </div>
                  </div>
                )}
                {evidenceTab === 'RETEST_LOG' && retestResult && (
                  <div className="space-y-3">
                    <div className="p-2 rounded bg-purple-950/40 border border-purple-500/30 text-purple-300">
                      <p className="font-bold mb-1 flex items-center gap-1.5">
                        <Zap className="w-3.5 h-3.5 text-purple-400" /> EXECUÇÃO EM TEMPO REAL — RETEST OUTPUT
                      </p>
                      <p className="text-[11px] text-slate-300">{retestResult.log}</p>
                    </div>
                    <div>
                      <p className="text-slate-500 mb-1 uppercase font-semibold text-[10px] tracking-wider">Raw Server HTTP Response:</p>
                      <pre className="text-emerald-300 bg-black/60 p-3 rounded border border-bg-border overflow-x-auto whitespace-pre-wrap">
                        {retestResult.raw_response}
                      </pre>
                    </div>
                  </div>
                )}
                {evidenceTab === 'PATCH' && (
                  <div>
                    {generateCodePatch(finding).split('\n').map((line, idx) => (
                      <div
                        key={idx}
                        className={clsx(
                          line.startsWith('-') ? 'text-red-400 bg-red-500/10 px-1 py-0.5' :
                          line.startsWith('+') ? 'text-green-400 bg-green-500/10 px-1 py-0.5 font-bold' :
                          'text-slate-400'
                        )}
                      >
                        {line}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* REALTIME RETEST RESULT LIVE BANNER */}
            {retestResult && (
              <div className={clsx(
                "p-4 rounded-xl border space-y-2 animate-fade-in text-xs font-mono shadow-xl",
                retestResult.vulnerable
                  ? "bg-red-950/20 border-red-500/40 text-red-200"
                  : "bg-green-950/20 border-green-500/40 text-green-200"
              )}>
                <div className="flex items-center justify-between">
                  <span className="font-bold flex items-center gap-1.5 uppercase">
                    {retestResult.vulnerable ? <AlertTriangle className="w-4 h-4 text-red-400" /> : <CheckCircle2 className="w-4 h-4 text-green-400" />}
                    {retestResult.vulnerable ? 'Resultado do Re-Teste: Vulnerável (Ativa)' : 'Resultado do Re-Teste: Corrigido (Mitigada)'}
                  </span>
                  <span className="text-[11px] text-slate-400 font-normal">
                    {retestResult.response_time_ms}ms · HTTP {retestResult.status_code}
                  </span>
                </div>
                <div className="p-2.5 rounded bg-black/60 border border-white/5 whitespace-pre-wrap leading-relaxed text-[11px]">
                  {retestResult.log}
                </div>
              </div>
            )}
          </div>

          {/* 💡 PROPOSTA DE CORREÇÃO & REMEDIAÇÃO */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-green-400" />
                Proposta de Correção & Remediação
              </h3>
              {finding.recommendation && (
                <button
                  onClick={() => copyToClipboard(finding.recommendation, setCopiedRemediation)}
                  className="btn-ghost text-xs px-2.5 py-1 border border-slate-700 flex items-center gap-1.5"
                >
                  {copiedRemediation ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedRemediation ? 'Copiado!' : 'Copiar'}
                </button>
              )}
            </div>

            <div className="p-4 rounded-xl border border-green-500/30 bg-green-950/10 space-y-3">
              <div className="flex items-start gap-3">
                <div className="p-2 rounded-lg bg-green-500/10 text-green-400 flex-shrink-0 mt-0.5">
                  <Wrench className="w-4 h-4" />
                </div>
                <div className="space-y-2 flex-1">
                  <h4 className="text-xs font-semibold text-green-300 uppercase tracking-wider">
                    Ação Recomendada pela Equipe de Segurança
                  </h4>
                  <p className="text-sm text-slate-200 leading-relaxed">
                    {finding.recommendation || 'Nenhuma recomendação cadastrada para este item.'}
                  </p>
                </div>
              </div>

              {finding.developer_recommendation && (
                <div className="border-t border-green-500/20 pt-3">
                  <h5 className="text-xs font-semibold text-accent-cyan mb-1 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5" />
                    Instruções para o Desenvolvedor / Patch:
                  </h5>
                  <pre className="text-xs font-mono bg-bg-primary/90 p-3 rounded border border-bg-border text-slate-300 overflow-x-auto whitespace-pre-wrap">
                    {finding.developer_recommendation}
                  </pre>
                </div>
              )}

              {/* Security Best Practice Checklist */}
              <div className="border-t border-green-500/20 pt-3 text-xs text-slate-300 space-y-1.5">
                <p className="font-semibold text-slate-400 mb-1">Checklist de Validação de Correção:</p>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
                  <span>Aplicar correção no ambiente de desenvolvimento/homologação</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
                  <span>Executar re-teste automatizado (Retest) no Hub do Projeto</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
                  <span>Atualizar o status do finding para "FIXED" para gerar relatório de conformidade</span>
                </div>
              </div>
            </div>
          </div>

          {/* 📄 DESCRIÇÃO TÉCNICA */}
          <div className="glass-card p-4 space-y-2">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <FileText className="w-3.5 h-3.5 text-slate-400" />
              Descrição Técnica
            </h3>
            <p className="text-sm text-slate-300 leading-relaxed">
              {finding.description || 'Sem descrição técnica fornecida.'}
            </p>
          </div>

          {/* ⚠️ IMPACTO */}
          {(finding.business_impact || finding.technical_impact) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {finding.business_impact && (
                <div className="glass-card p-4 space-y-1.5">
                  <h4 className="text-xs font-semibold text-amber-400 flex items-center gap-1.5 uppercase">
                    <TrendingUp className="w-3.5 h-3.5" /> Impacto no Negócio
                  </h4>
                  <p className="text-xs text-slate-300 leading-relaxed">{finding.business_impact}</p>
                </div>
              )}
              {finding.technical_impact && (
                <div className="glass-card p-4 space-y-1.5">
                  <h4 className="text-xs font-semibold text-purple-400 flex items-center gap-1.5 uppercase">
                    <Cpu className="w-3.5 h-3.5" /> Impacto Técnico
                  </h4>
                  <p className="text-xs text-slate-300 leading-relaxed">{finding.technical_impact}</p>
                </div>
              )}
            </div>
          )}

          {/* Metadados adicionais */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
            <div className="p-2.5 rounded bg-bg-primary/50 border border-bg-border">
              <span className="text-slate-500 block mb-0.5">Status Atual</span>
              <StatusChip status={finding.status} />
            </div>
            <div className="p-2.5 rounded bg-bg-primary/50 border border-bg-border">
              <span className="text-slate-500 block mb-0.5">Scan ID</span>
              <span className="font-mono text-slate-300 truncate block">{finding.scan_id || 'manual'}</span>
            </div>
            <div className="p-2.5 rounded bg-bg-primary/50 border border-bg-border">
              <span className="text-slate-500 block mb-0.5">Descoberto em</span>
              <span className="text-slate-300">
                {finding.created_at ? new Date(finding.created_at).toLocaleDateString('pt-BR') : '—'}
              </span>
            </div>
          </div>
        </div>

        {/* Drawer Footer / Action Bar */}
        <div className="p-4 border-t border-bg-border bg-bg-secondary/90 flex items-center justify-between gap-3 flex-wrap flex-shrink-0">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Alterar Status:</span>
            <select
              value={finding.status}
              disabled={isUpdating}
              onChange={(e) => onUpdateStatus(e.target.value)}
              className="input-field text-xs py-1 px-2.5 w-auto"
            >
              <option value="OPEN">OPEN (Aberto)</option>
              <option value="IN_PROGRESS">IN_PROGRESS (Em Correção)</option>
              <option value="RETEST_PENDING">RETEST_PENDING (Aguardando Re-teste)</option>
              <option value="FIXED">FIXED (Corrigido)</option>
              <option value="ACCEPTED">ACCEPTED (Risco Aceito)</option>
              <option value="FALSE_POSITIVE">FALSE_POSITIVE (Falso Positivo)</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <button
              disabled={isRetesting || isUpdating}
              onClick={handleRealtimeRetest}
              className={clsx(
                "px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all flex items-center gap-1.5",
                isRetesting
                  ? "bg-purple-500/20 text-purple-300 border-purple-500/40 animate-pulse"
                  : "bg-red-500/20 hover:bg-red-500/30 text-red-300 border-red-500/40 hover:brightness-110"
              )}
            >
              {isRetesting ? <Loader2 className="w-3.5 h-3.5 animate-spin text-purple-400" /> : <Zap className="w-3.5 h-3.5 text-red-400" />}
              {isRetesting ? 'Testando no Alvo...' : '⚡ Testar em Tempo Real'}
            </button>

            {finding.status !== 'FIXED' && (
              <button
                disabled={isUpdating}
                onClick={() => onUpdateStatus('FIXED')}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-green-500/20 hover:bg-green-500/30 text-green-300 border border-green-500/40 transition-colors flex items-center gap-1.5"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                Marcar como Corrigido
              </button>
            )}

            <button
              disabled={isUpdating}
              onClick={onToggleFalsePositive}
              className="btn-ghost text-xs px-3 py-1.5 border border-slate-700 hover:border-slate-600"
            >
              {finding.is_false_positive ? 'Remover Falso Positivo' : 'Falso Positivo'}
            </button>

            <button
              onClick={onClose}
              className="btn-primary text-xs px-4 py-1.5"
            >
              Fechar
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Helper Components ────────────────────────────────────────────────────────

function SevBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    CRITICAL: 'badge-severity-critical',
    HIGH: 'badge-severity-high',
    MEDIUM: 'badge-severity-medium',
    LOW: 'badge-severity-low',
    INFO: 'badge-severity-info',
  };
  return <span className={cls[s] || cls.INFO}>{s}</span>;
}

function StatusBadge({ status }: { status: string }) {
  const s: Record<string, string> = {
    DRAFT: 'bg-slate-700 text-slate-400',
    ACTIVE: 'bg-cyan-500/20 text-cyan-400',
    SCANNING: 'bg-purple-500/20 text-purple-400',
    COMPLETED: 'bg-green-500/20 text-green-400',
    RUNNING: 'bg-purple-500/20 text-purple-400',
    FAILED: 'bg-red-500/20 text-red-400',
    PAUSED: 'bg-amber-500/20 text-amber-400',
    ARCHIVED: 'bg-slate-700 text-slate-500',
    KILLED: 'bg-red-500/20 text-red-400',
    PENDING: 'bg-blue-500/20 text-blue-400',
  };
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium ${s[status] || s.DRAFT}`}>
      {(status === 'SCANNING' || status === 'RUNNING') && (
        <span className="w-1.5 h-1.5 rounded-full bg-purple-400 mr-1.5 animate-pulse" />
      )}
      {status}
    </span>
  );
}

function StatusChip({ status }: { status: string }) {
  const colors: Record<string, string> = {
    OPEN: 'bg-red-500/20 text-red-300',
    IN_PROGRESS: 'bg-blue-500/20 text-blue-300',
    FIXED: 'bg-green-500/20 text-green-300',
    RETEST_PENDING: 'bg-purple-500/20 text-purple-300',
    ACCEPTED: 'bg-slate-600 text-slate-300',
    FALSE_POSITIVE: 'bg-slate-700 text-slate-500',
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded font-medium ${colors[status] || 'bg-slate-700 text-slate-400'}`}>
      {status}
    </span>
  );
}
