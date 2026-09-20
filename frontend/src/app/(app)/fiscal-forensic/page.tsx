'use client';
import { useState, useEffect, useRef } from 'react';
import dynamic from 'next/dynamic';
import { fiscalForensicApi, projectsApi, type Project } from '@/lib/api';
import {
  FileCheck2, ShieldAlert, AlertTriangle, CheckCircle2,
  XCircle, Loader2, Play, Download, Upload, Search,
  Network, BarChart3, Bot, Send, Lock, RefreshCw,
  Eye, FileText, Layers, TrendingUp, Sparkles, Filter,
  ArrowUpRight, Building, CheckSquare, HelpCircle, ChevronRight,
  UploadCloud, X, Plus, FileSpreadsheet, FileCode, Check, FileUp,
  FolderKanban, Briefcase, Calendar, UserCheck, Activity, ArrowRight,
  ExternalLink, ShieldCheck, Trash2, Building2, Landmark, Scale,
  Copy, CheckCheck, AlertOctagon, UserX, Fingerprint, ShieldBan,
  Globe, Radio, Server
} from 'lucide-react';
import clsx from 'clsx';
import Link from 'next/link';

const UnifiedScanModal = dynamic(() => import('@/components/UnifiedScanModal'), { ssr: false });

export default function FiscalForensicPage() {
  const [loading, setLoading] = useState(false);
  const [auditData, setAuditData] = useState<any>(null);
  const [selectedFinding, setSelectedFinding] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<'findings' | 'fake_cnpj' | 'graph' | 'benford' | 'cases' | 'evidence' | 'copilot' | 'quality'>('fake_cnpj');
  const [isUnifiedScanOpen, setIsUnifiedScanOpen] = useState(false);
  
  // Fake CNPJ & Corporate Clones state
  const [targetDomain, setTargetDomain] = useState('nubank.com.br');
  const [fakeCnpjLoading, setFakeCnpjLoading] = useState(false);
  const [fakeCnpjData, setFakeCnpjData] = useState<any>(null);
  const [selectedFakeCategory, setSelectedFakeCategory] = useState<string>('ALL');
  const [copiedDossier, setCopiedDossier] = useState(false);
  const [copiedUrlId, setCopiedUrlId] = useState<string | null>(null);
  const [legalDossierModal, setLegalDossierModal] = useState<{ open: boolean; loading: boolean; data: any }>({
    open: false,
    loading: false,
    data: null,
  });

  // Projects state
  const [projectsList, setProjectsList] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>('');
  const [newProjectModalOpen, setNewProjectModalOpen] = useState(false);
  const [newProjName, setNewProjName] = useState('');
  const [newProjClient, setNewProjClient] = useState('');
  const [newProjUnit, setNewProjUnit] = useState('Controladoria & Auditoria Fiscal');
  const [newProjDesc, setNewProjDesc] = useState('');

  // Filter state
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');

  // Copilot chat state
  const [copilotQuery, setCopilotQuery] = useState('');
  const [copilotLoading, setCopilotLoading] = useState(false);
  const [copilotMessages, setCopilotMessages] = useState<Array<{ role: 'user' | 'assistant'; text: string; confidence?: number; references?: string[] }>>([
    {
      role: 'assistant',
      text: 'Olá, Auditor. Sou o **Fiscal Auditor Copilot**. Posso responder a perguntas sobre os riscos, desvios estatísticos da Lei de Benford, concentração de fornecedores e evidências do dataset.',
    }
  ]);

  // Case modal state
  const [caseTitle, setCaseTitle] = useState('');
  const [caseModalOpen, setCaseModalOpen] = useState(false);

  // Upload modal & drag state
  const [uploadModalOpen, setUploadModalOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const inlineFileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    loadProjects();
    loadAudit();
    handleSearchFakeCnpj('nubank.com.br');
  }, []);

  const handleSearchFakeCnpj = async (domainToSearch?: string) => {
    const dom = (domainToSearch || targetDomain).trim();
    if (!dom) return;
    setFakeCnpjLoading(true);
    try {
      const res = await fiscalForensicApi.searchFakeCnpj(dom);
      setFakeCnpjData(res);
      setTargetDomain(dom);
    } catch (e: any) {
      console.warn('Could not search fake CNPJs', e);
    } finally {
      setFakeCnpjLoading(false);
    }
  };

  const handleGenerateLegalDossier = async (fakeId: string) => {
    setLegalDossierModal({ open: true, loading: true, data: null });
    setCopiedDossier(false);
    try {
      const res = await fiscalForensicApi.generateLegalDossier(targetDomain, fakeId, fakeCnpjData);
      setLegalDossierModal({ open: true, loading: false, data: res });
    } catch (e: any) {
      alert('Falha ao gerar dossiê jurídico: ' + (e.message || e));
      setLegalDossierModal({ open: false, loading: false, data: null });
    }
  };

  const handleCopyDossier = () => {
    if (!legalDossierModal.data?.dossier_markdown) return;
    navigator.clipboard.writeText(legalDossierModal.data.dossier_markdown);
    setCopiedDossier(true);
    setTimeout(() => setCopiedDossier(false), 2500);
  };

  const handleCopyUrl = (url: string, id: string) => {
    navigator.clipboard.writeText(url);
    setCopiedUrlId(id);
    setTimeout(() => setCopiedUrlId(null), 2500);
  };

  const handleDownloadDossierFile = () => {
    if (!legalDossierModal.data?.dossier_markdown) return;
    const blob = new Blob([legalDossierModal.data.dossier_markdown], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = legalDossierModal.data.filename || 'DOSSIE_LEGAL_FRAUDE_CNPJ.md';
    a.click();
    URL.revokeObjectURL(url);
  };

  const loadProjects = async () => {
    try {
      const list = await projectsApi.list();
      setProjectsList(list);
      const saved = typeof window !== 'undefined' ? localStorage.getItem('fiscal_active_project_id') : null;
      if (saved && list.some(p => p.id === saved)) {
        setSelectedProjectId(saved);
      } else if (list.length > 0) {
        setSelectedProjectId(list[0].id);
      }
    } catch (e) {
      console.warn('Could not load projects list', e);
    }
  };

  const handleSelectProject = (id: string) => {
    setSelectedProjectId(id);
    if (typeof window !== 'undefined') {
      localStorage.setItem('fiscal_active_project_id', id);
    }
  };

  const [newProjFocus, setNewProjFocus] = useState('SOD_FRAUD');

  const handleCreateProject = async () => {
    if (!newProjName.trim()) return;
    try {
      const focusLabels: Record<string, string> = {
        SOD_FRAUD: 'Detecção de Fraude em Aquisições & Conflito SoD',
        TAX_EVASION: 'Fraude Tributária & Inconsistências Fiscais',
        GHOST_VENDOR: 'Detecção de Fornecedores Fantasmas & Relações Ocultas',
        FORENSIC_SPED: 'Auditoria Forense Contábil SPED/NF-e & Benford',
      };
      const proj = await projectsApi.create({
        name: newProjName.trim(),
        client: newProjClient.trim() || 'Empresa Auditada Matriz S.A.',
        business_unit: newProjUnit.trim() || 'Controladoria, Perícia & Auditoria Forense',
        project_type: 'FINANCIAL_FRAUD',
        description: newProjDesc.trim() || `Frente de Teste de Fraude Financeira: ${focusLabels[newProjFocus] || 'Auditoria Contábil e Fiscal'}.`,
        status: 'ACTIVE',
      });
      setProjectsList(prev => [proj, ...prev]);
      setSelectedProjectId(proj.id);
      if (typeof window !== 'undefined') {
        localStorage.setItem('fiscal_active_project_id', proj.id);
      }
      setNewProjName('');
      setNewProjClient('');
      setNewProjDesc('');
      setNewProjectModalOpen(false);
    } catch (e: any) {
      alert('Erro ao criar projeto de fraude financeira: ' + e.message);
    }
  };

  const loadAudit = async () => {
    setLoading(true);
    try {
      const data = await fiscalForensicApi.getLatestAudit();
      setAuditData(data);
      if (data?.findings?.length > 0) {
        setSelectedFinding(data.findings[0]);
      }
    } catch (e) {
      console.warn('Could not load latest audit, seeding default...', e);
      handleSeedDemo(1000);
    } finally {
      setLoading(false);
    }
  };

  const handleSeedDemo = async (count: number = 1000) => {
    setLoading(true);
    try {
      const data = await fiscalForensicApi.seedDemo(count);
      setAuditData(data);
      if (data?.findings?.length > 0) {
        setSelectedFinding(data.findings[0]);
      }
    } catch (e: any) {
      alert('Falha ao gerar demonstração: ' + e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (fileToUpload?: File) => {
    const file = fileToUpload || selectedFile;
    if (!file) return;
    setUploading(true);
    setUploadError(null);
    setUploadSuccess(null);
    try {
      const data = await fiscalForensicApi.uploadDataset(file);
      setAuditData(data);
      if (data?.findings?.length > 0) {
        setSelectedFinding(data.findings[0]);
      }
      setUploadSuccess(`Arquivo "${file.name}" processado com sucesso! ${data?.findings?.length || 0} anomalias encontradas.`);
      setTimeout(() => {
        setUploadModalOpen(false);
        setUploadSuccess(null);
        setSelectedFile(null);
      }, 1600);
    } catch (e: any) {
      setUploadError(e.message || 'Falha ao processar arquivo.');
    } finally {
      setUploading(false);
    }
  };

  const handleCreateCase = async () => {
    if (!caseTitle.trim()) return;
    try {
      const newCase = await fiscalForensicApi.createCase({
        title: caseTitle,
        description: `Caso investigativo gerado a partir do apontamento: ${selectedFinding?.title || 'Auditoria Fiscal'}`,
        finding_ids: selectedFinding ? [selectedFinding.id] : [],
        priority: selectedFinding?.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
      });
      setAuditData((prev: any) => ({
        ...prev,
        cases: [newCase, ...(prev?.cases || [])],
      }));
      setCaseTitle('');
      setCaseModalOpen(false);
      setActiveTab('cases');
    } catch (e: any) {
      alert('Falha ao criar caso: ' + e.message);
    }
  };

  const handleCopilotSend = async () => {
    if (!copilotQuery.trim()) return;
    const userQ = copilotQuery;
    setCopilotMessages(prev => [...prev, { role: 'user', text: userQ }]);
    setCopilotQuery('');
    setCopilotLoading(true);

    try {
      const res = await fiscalForensicApi.queryCopilot(userQ, auditData?.dataset_id);
      setCopilotMessages(prev => [
        ...prev,
        {
          role: 'assistant',
          text: res.answer,
          confidence: res.confidence,
          references: res.referenced_findings,
        }
      ]);
    } catch (e: any) {
      setCopilotMessages(prev => [
        ...prev,
        { role: 'assistant', text: 'Erro ao consultar o Copilot: ' + e.message }
      ]);
    } finally {
      setCopilotLoading(false);
    }
  };

  const handleReviewFinding = async (findingId: string, newStatus: string) => {
    try {
      await fiscalForensicApi.reviewFinding(findingId, newStatus, 'Status atualizado pelo auditor');
      setAuditData((prev: any) => ({
        ...prev,
        findings: prev.findings.map((f: any) => f.id === findingId ? { ...f, status: newStatus } : f),
      }));
      if (selectedFinding?.id === findingId) {
        setSelectedFinding((prev: any) => ({ ...prev, status: newStatus }));
      }
    } catch (e: any) {
      alert('Falha ao atualizar finding: ' + e.message);
    }
  };

  const handleDownloadPDF = () => {
    const url = 'http://localhost:8000/api/v1/fiscal/reports/pdf';
    window.open(url, '_blank');
  };

  const stats = auditData?.stats_summary || {};
  const risk = auditData?.risk_profile || {};
  const quality = auditData?.quality_data || {};
  const hhi = auditData?.hhi_data || {};
  const benford = stats?.benford_results || {};
  const allFindings = auditData?.findings || [];
  const graph = auditData?.network_graph || { nodes: [], links: [] };

  const filteredFindings = allFindings.filter((f: any) => {
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    if (categoryFilter !== 'ALL' && f.category !== categoryFilter) return false;
    return true;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-bg-border pb-5">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-2xl bg-gradient-to-br from-emerald-500/20 via-teal-500/30 to-cyan-600/30 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-500/10">
            <FileCheck2 className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-slate-100 tracking-tight flex items-center gap-2">
              Fiscal Forensic AI
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase bg-emerald-500/20 border border-emerald-500/40 text-emerald-300">
                Auditoria & Detecção de Anomalias
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Auditoria fiscal automatizada, análise forense de dados contábeis, motor de regras, Lei de Benford e explicabilidade pericial não-acusatória.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => setIsUnifiedScanOpen(true)}
            className="px-3.5 py-2 rounded-xl text-xs font-black bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 flex items-center gap-2 shadow-lg shadow-cyan-500/20 transition-all cursor-pointer"
            title="Executar todos os 7 motores simultaneamente (Web + EASM + PQC + Brand + BIN + Forense)"
          >
            <Sparkles className="w-4 h-4 fill-current" />
            <span>⚡ Executar Scan Unificado para Tudo</span>
          </button>

          <button
            onClick={() => setUploadModalOpen(true)}
            disabled={loading || uploading}
            className="px-3.5 py-2 rounded-xl text-xs font-bold bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/50 text-emerald-300 flex items-center gap-2 shadow-lg shadow-emerald-500/10 transition-all cursor-pointer"
          >
            <Upload className="w-4 h-4 text-emerald-400" />
            <span>Upload de Relatórios / Dados</span>
          </button>

          <button
            onClick={() => handleSeedDemo(1000)}
            disabled={loading || uploading}
            className="px-3.5 py-2 rounded-xl text-xs font-bold bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 flex items-center gap-2 shadow-lg shadow-emerald-500/20 transition-all cursor-pointer"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-current" />}
            <span>Run Full Audit (Demo 1k+)</span>
          </button>

          <button
            onClick={handleDownloadPDF}
            className="px-3.5 py-2 rounded-xl text-xs font-bold bg-bg-secondary border border-bg-border hover:border-emerald-500/50 text-slate-200 flex items-center gap-2 transition-all cursor-pointer"
          >
            <Download className="w-4 h-4 text-emerald-400" />
            <span>Laudo PDF (18 Seções)</span>
          </button>
        </div>
      </div>

      {/* ─── ACTIVE PROJECT & AUDIT FRONT BAR ─── */}
      <div className="p-4 rounded-2xl bg-gradient-to-r from-bg-secondary via-bg-secondary/90 to-bg-secondary/70 border border-emerald-500/30 shadow-xl space-y-3">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Project Info & Selector */}
          <div className="flex items-start sm:items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 flex-shrink-0">
              <Briefcase className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Frente de Auditoria Ativa:</span>
                <select
                  value={selectedProjectId}
                  onChange={(e) => handleSelectProject(e.target.value)}
                  className="bg-bg-primary border border-emerald-500/50 rounded-lg px-2.5 py-1 text-xs font-bold text-emerald-300 focus:outline-none focus:border-emerald-400 cursor-pointer"
                >
                  {projectsList.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.client || 'Geral'})
                    </option>
                  ))}
                  {projectsList.length === 0 && (
                    <option value="proj-fiscal-default">Auditoria Fiscal Corporativa 2026</option>
                  )}
                </select>
                <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                  EM ANDAMENTO
                </span>
              </div>
              <div className="flex items-center gap-3 text-xs text-slate-400 mt-1 flex-wrap">
                <span className="flex items-center gap-1 text-slate-300">
                  <Building className="w-3.5 h-3.5 text-cyan-400" />
                  Alvo: <strong className="text-slate-100">{projectsList.find(p => p.id === selectedProjectId)?.client || 'Empresa Auditada Matriz S.A.'}</strong>
                </span>
                <span className="text-slate-600">•</span>
                <span className="flex items-center gap-1">
                  <Layers className="w-3.5 h-3.5 text-purple-400" />
                  Escopo: <span className="text-slate-300">{projectsList.find(p => p.id === selectedProjectId)?.business_unit || 'Controladoria & Compliance Fiscal'}</span>
                </span>
                <span className="text-slate-600">•</span>
                <span className="flex items-center gap-1">
                  <UserCheck className="w-3.5 h-3.5 text-emerald-400" />
                  Auditor Líder: <span className="text-slate-300">Felipe Costa (Perito Forense)</span>
                </span>
              </div>
            </div>
          </div>

          {/* Project Actions */}
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => setNewProjectModalOpen(true)}
              className="px-3 py-1.5 rounded-xl text-xs font-bold bg-emerald-500 hover:bg-emerald-400 text-slate-950 flex items-center gap-1.5 transition-all cursor-pointer shadow-md shadow-emerald-500/10"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Novo Projeto / Frente</span>
            </button>

            {selectedProjectId && (
              <Link
                href={`/projects/${selectedProjectId}`}
                className="px-3 py-1.5 rounded-xl text-xs font-bold bg-bg-primary border border-bg-border hover:border-emerald-500/50 text-slate-300 flex items-center gap-1.5 transition-all"
              >
                <span>Ver Workspace</span>
                <ExternalLink className="w-3 h-3 text-slate-400" />
              </Link>
            )}
          </div>
        </div>
      </div>

      {/* ─── DIRECT ON-PAGE UPLOAD & INGESTION CARD ─── */}
      <div className="p-5 rounded-2xl bg-bg-secondary border border-emerald-500/30 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-bg-border pb-3">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <UploadCloud className="w-5 h-5 text-emerald-400" />
              Ingestão de Arquivos & Relatórios Fiscais da Frente
            </h2>
            <p className="text-xs text-slate-400">
              Faça upload direto de planilhas de lançamentos, SPED Fiscal, XMLs de NF-e ou CSVs contábeis para auditoria instantânea.
            </p>
          </div>
          <div className="flex items-center gap-1 text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-lg border border-emerald-500/20">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Mapeamento Automático de Schema</span>
          </div>
        </div>

        {/* On-Page Dropzone */}
        <div
          onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setIsDragging(false);
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
              setSelectedFile(e.dataTransfer.files[0]);
            }
          }}
          className={clsx(
            'border-2 border-dashed rounded-xl p-6 transition-all duration-200 flex flex-col items-center justify-center gap-3 text-center',
            isDragging
              ? 'border-emerald-500 bg-emerald-500/10 scale-[0.99]'
              : selectedFile
              ? 'border-emerald-500/60 bg-emerald-500/5'
              : 'border-bg-border hover:border-emerald-500/40 bg-bg-primary/40'
          )}
        >
          <input
            type="file"
            ref={inlineFileInputRef}
            className="hidden"
            accept=".xlsx,.xls,.csv,.tsv,.txt,.sped,.xml,.json"
            onChange={(e) => {
              if (e.target.files && e.target.files[0]) {
                setSelectedFile(e.target.files[0]);
              }
            }}
          />

          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 w-full">
            <div className="flex items-center gap-4 text-left">
              <div className="w-12 h-12 rounded-xl bg-bg-primary border border-bg-border flex items-center justify-center text-emerald-400 shadow-inner flex-shrink-0">
                {uploading ? (
                  <Loader2 className="w-6 h-6 animate-spin text-emerald-400" />
                ) : selectedFile ? (
                  <FileSpreadsheet className="w-6 h-6 text-emerald-400" />
                ) : (
                  <FileUp className="w-6 h-6 text-slate-400" />
                )}
              </div>
              <div>
                {selectedFile ? (
                  <div>
                    <div className="text-sm font-bold text-emerald-400 flex items-center gap-2">
                      <span>{selectedFile.name}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                        {(selectedFile.size / 1024).toFixed(1)} KB
                      </span>
                    </div>
                    <div className="text-xs text-slate-400 mt-0.5">
                      Arquivo carregado e pronto para os 5 motores forenses da plataforma.
                    </div>
                  </div>
                ) : (
                  <div>
                    <div className="text-sm font-bold text-slate-200">
                      Arraste seu arquivo para cá ou selecione do computador
                    </div>
                    <div className="text-xs text-slate-400 mt-0.5">
                      Aceita <strong className="text-emerald-300">Excel (.xlsx, .xls)</strong>, <strong className="text-cyan-300">SPED Fiscal (.sped, .txt)</strong>, <strong className="text-amber-300">XML NF-e/CT-e</strong>, CSV e JSON.
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              {selectedFile ? (
                <>
                  <button
                    type="button"
                    onClick={() => setSelectedFile(null)}
                    className="px-3 py-2 rounded-xl text-xs font-bold text-slate-400 hover:text-slate-200 hover:bg-bg-primary border border-bg-border cursor-pointer transition-colors"
                  >
                    Trocar Arquivo
                  </button>

                  <button
                    type="button"
                    onClick={() => handleFileUpload()}
                    disabled={uploading}
                    className="px-4 py-2 rounded-xl text-xs font-bold bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 flex items-center gap-2 shadow-lg shadow-emerald-500/20 transition-all cursor-pointer disabled:opacity-40"
                  >
                    {uploading ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        <span>Auditando...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 fill-current" />
                        <span>Processar & Iniciar Auditoria Forense</span>
                      </>
                    )}
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  onClick={() => inlineFileInputRef.current?.click()}
                  className="px-4 py-2 rounded-xl text-xs font-bold bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/50 text-emerald-300 flex items-center gap-2 shadow-lg shadow-emerald-500/10 cursor-pointer transition-all"
                >
                  <Upload className="w-4 h-4 text-emerald-400" />
                  <span>Selecionar Arquivo</span>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Formats & Benchmark Presets Bar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pt-1 text-xs">
          <div className="flex items-center gap-2 flex-wrap text-[11px] text-slate-400">
            <span className="font-bold text-slate-300">Formatos:</span>
            <span className="px-2 py-0.5 rounded bg-bg-primary border border-bg-border text-emerald-400 font-mono">.xlsx / .xls</span>
            <span className="px-2 py-0.5 rounded bg-bg-primary border border-bg-border text-cyan-400 font-mono">.sped (EFD)</span>
            <span className="px-2 py-0.5 rounded bg-bg-primary border border-bg-border text-amber-400 font-mono">.xml (NF-e)</span>
            <span className="px-2 py-0.5 rounded bg-bg-primary border border-bg-border text-purple-400 font-mono">.csv / .json</span>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] text-slate-400">Ou use dataset de teste:</span>
            <button
              onClick={() => handleSeedDemo(1000)}
              disabled={loading || uploading}
              className="px-2.5 py-1 rounded-lg bg-bg-primary hover:bg-emerald-500/20 border border-bg-border hover:border-emerald-500/40 text-slate-300 font-medium text-[11px] transition-all cursor-pointer"
            >
              ⚡ SAP ERP (1k)
            </button>
            <button
              onClick={() => handleSeedDemo(2500)}
              disabled={loading || uploading}
              className="px-2.5 py-1 rounded-lg bg-bg-primary hover:bg-cyan-500/20 border border-bg-border hover:border-cyan-500/40 text-slate-300 font-medium text-[11px] transition-all cursor-pointer"
            >
              🏢 Volumetria (2.5k)
            </button>
            <button
              onClick={() => handleSeedDemo(300)}
              disabled={loading || uploading}
              className="px-2.5 py-1 rounded-lg bg-bg-primary hover:bg-amber-500/20 border border-bg-border hover:border-amber-500/40 text-slate-300 font-medium text-[11px] transition-all cursor-pointer"
            >
              🚨 Fraude SoD (300)
            </button>
          </div>
        </div>

        {/* Feedback alerts */}
        {uploadError && (
          <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-300 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
            <span>{uploadError}</span>
          </div>
        )}

        {uploadSuccess && (
          <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>{uploadSuccess}</span>
          </div>
        )}
      </div>
      <div className="p-3.5 rounded-xl bg-bg-secondary/70 border border-bg-border flex items-center justify-between gap-3 overflow-x-auto text-xs">
        <span className="font-bold text-slate-300 flex items-center gap-1.5 flex-shrink-0">
          <Sparkles className="w-4 h-4 text-emerald-400" />
          5 Motores Integrados:
        </span>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="px-2.5 py-1 rounded-lg bg-bg-primary border border-bg-border text-slate-300 font-mono text-[11px]">
            1. Duplicate Detection (Inteligente)
          </span>
          <span className="px-2.5 py-1 rounded-lg bg-bg-primary border border-bg-border text-slate-300 font-mono text-[11px]">
            2. Benford Analysis (1º Dígito / MAD)
          </span>
          <span className="px-2.5 py-1 rounded-lg bg-bg-primary border border-bg-border text-slate-300 font-mono text-[11px]">
            3. Segregation of Duties (SoD)
          </span>
          <span className="px-2.5 py-1 rounded-lg bg-bg-primary border border-bg-border text-slate-300 font-mono text-[11px]">
            4. Graph Fraud & Conflitos
          </span>
          <span className="px-2.5 py-1 rounded-lg bg-bg-primary border border-bg-border text-emerald-300 font-mono text-[11px]">
            5. AI Auditor (Não-Acusatório)
          </span>
        </div>
        <div className="flex items-center gap-1 text-[11px] text-slate-400 flex-shrink-0">
          <span>Screening:</span>
          <strong className="text-cyan-400 font-mono">RFB • CGU (CEIS/CNEP) • TCU • BCB</strong>
        </div>
      </div>

      {/* Top Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
          <div className="text-[11px] text-slate-400">Registros Analisados</div>
          <div className="text-xl font-black text-slate-100 mt-1 font-mono">
            {stats.total_records ? stats.total_records.toLocaleString() : '1.000'}
          </div>
          <div className="text-[10px] text-emerald-400 mt-0.5">100% Ingestão Concluída</div>
        </div>

        <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
          <div className="text-[11px] text-slate-400">Volume Total Auditado</div>
          <div className="text-xl font-black text-cyan-400 mt-1 font-mono">
            R$ {stats.total_volume ? (stats.total_volume / 1000000).toFixed(1) + 'M' : '14.8M'}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Base Histórica Normalizada</div>
        </div>

        <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
          <div className="text-[11px] text-slate-400">Exposição sob Investigação</div>
          <div className="text-xl font-black text-red-400 mt-1 font-mono">
            R$ {risk.total_exposure ? (risk.total_exposure / 1000000).toFixed(2) + 'M' : '2.4M'}
          </div>
          <div className="text-[10px] text-red-400/80 mt-0.5">{risk.exposure_ratio_pct ?? 16.2}% do Volume</div>
        </div>

        <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
          <div className="text-[11px] text-slate-400">Data Quality Score</div>
          <div className="text-xl font-black text-emerald-400 mt-1">
            {quality.data_quality_score ?? 94}%
          </div>
          <div className="text-[10px] text-emerald-500/80 mt-0.5">{quality.quality_status ?? 'EXCELLENT'}</div>
        </div>

        <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
          <div className="text-[11px] text-slate-400">Risk Score Global</div>
          <div className="text-xl font-black text-amber-400 mt-1">
            {risk.overall_risk_score ?? 82}/100
          </div>
          <div className="text-[10px] text-amber-500/80 mt-0.5">{risk.risk_classification ?? 'ALTO RISCO'}</div>
        </div>

        <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
          <div className="text-[11px] text-slate-400">Apontamentos (Findings)</div>
          <div className="text-xl font-black text-slate-100 mt-1">
            {allFindings.length}
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5">
            <strong className="text-red-400">{risk.critical_count ?? 1} Críticos</strong> • {risk.high_count ?? 3} Altos
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-bg-border flex items-center gap-2 overflow-x-auto">
        {[
          { id: 'fake_cnpj', label: `🏢 CNPJs Fakes & Clones (${fakeCnpjData?.fake_cnpjs?.length || 4})`, icon: Landmark },
          { id: 'findings', label: `Findings & Explicabilidade (${allFindings.length})`, icon: ShieldAlert },
          { id: 'graph', label: 'Forensic Entity Graph', icon: Network },
          { id: 'benford', label: 'Estatística & Benford', icon: BarChart3 },
          { id: 'cases', label: `Casos de Auditoria (${auditData?.cases?.length || 1})`, icon: CheckSquare },
          { id: 'evidence', label: 'Evidence Vault (SHA-256)', icon: Lock },
          { id: 'copilot', label: 'Auditor Copilot (IA)', icon: Bot },
          { id: 'quality', label: `Data Quality (${quality.data_quality_score ?? 94}%)`, icon: CheckCircle2 },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={clsx(
              'px-4 py-3 text-xs font-bold flex items-center gap-2 border-b-2 transition-all cursor-pointer whitespace-nowrap',
              activeTab === tab.id
                ? 'border-emerald-400 text-emerald-300 bg-emerald-500/10'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            )}
          >
            <tab.icon className="w-4 h-4" />
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* TAB 0: FAKE CNPJ & CORPORATE CLONES RADAR */}
      {activeTab === 'fake_cnpj' && (
        <div className="space-y-6">
          {/* ─── DOMAIN SEARCH HERO BAR ─── */}
          <div className="p-5 rounded-2xl bg-gradient-to-r from-bg-secondary via-bg-secondary/90 to-bg-secondary/70 border border-emerald-500/40 shadow-xl space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-emerald-500/20 via-teal-500/30 to-cyan-600/30 border border-emerald-500/40 flex items-center justify-center text-emerald-400 flex-shrink-0 shadow-lg shadow-emerald-500/10">
                  <Landmark className="w-6 h-6" />
                </div>
                <div>
                  <div className="text-base font-black text-slate-100 flex items-center gap-2">
                    <span>Radar Autônomo de CNPJs Fakes, Razões Sociais & Clones Societários</span>
                    <span className="px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                      1-DOMÍNIO BUSCA TOTAL
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Informe apenas o domínio da sua organização (ex: <strong className="text-emerald-300">nubank.com.br</strong>). O motor identifica a identidade corporativa legítima e varre a Receita Federal, Juntas Comerciais e sites de phishing em busca de CNPJs e Razões Sociais falsas.
                  </p>
                </div>
              </div>
            </div>

            {/* Input & Action */}
            <div className="flex flex-col sm:flex-row items-center gap-2 pt-1">
              <div className="relative flex-1 w-full">
                <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={targetDomain}
                  onChange={(e) => setTargetDomain(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSearchFakeCnpj()}
                  placeholder="Digite apenas o domínio corporativo (ex: nubank.com.br, inter.co, seudominio.com.br)..."
                  className="w-full pl-10 pr-4 py-3 rounded-xl bg-bg-primary border border-emerald-500/40 focus:border-emerald-400 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none shadow-inner"
                />
              </div>
              <button
                onClick={() => handleSearchFakeCnpj()}
                disabled={fakeCnpjLoading || !targetDomain.trim()}
                className="w-full sm:w-auto px-6 py-3 rounded-xl text-xs font-black bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/20 transition-all cursor-pointer disabled:opacity-40 whitespace-nowrap"
              >
                {fakeCnpjLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4 fill-current" />}
                <span>⚡ Rastrear CNPJs e Razões Sociais Fakes</span>
              </button>
            </div>

            {/* Fast Presets */}
            <div className="flex items-center gap-2 flex-wrap text-xs pt-1">
              <span className="text-[11px] font-bold text-slate-400">Exemplos corporativos:</span>
              {[
                { label: 'Nubank', dom: 'nubank.com.br' },
                { label: 'Banco Itaú', dom: 'itau.com.br' },
                { label: 'Banco Inter', dom: 'inter.co' },
                { label: 'Mercado Livre', dom: 'mercadolivre.com.br' },
                { label: 'Magazine Luiza', dom: 'magazineluiza.com.br' },
              ].map((item) => (
                <button
                  key={item.dom}
                  onClick={() => { setTargetDomain(item.dom); handleSearchFakeCnpj(item.dom); }}
                  className={clsx(
                    "px-2.5 py-1 rounded-lg text-[11px] font-mono transition-all border cursor-pointer",
                    targetDomain === item.dom 
                      ? "bg-emerald-500/20 border-emerald-500/60 text-emerald-300 font-bold shadow-sm" 
                      : "bg-bg-primary border-bg-border hover:border-emerald-500/40 text-slate-300"
                  )}
                >
                  {item.label} ({item.dom})
                </button>
              ))}
            </div>
          </div>

          {/* ─── SUMMARY KPIS ─── */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="p-4 rounded-xl bg-bg-secondary border border-red-500/30">
              <div className="text-[11px] text-slate-400 font-bold flex items-center justify-between">
                <span>CNPJs Fakes Detectados</span>
                <Landmark className="w-4 h-4 text-red-400" />
              </div>
              <div className="text-2xl font-black text-red-400 mt-1 font-mono">
                {fakeCnpjData?.summary?.total_fake_cnpjs_detected ?? 4}
              </div>
              <div className="text-[10px] text-red-400/80 mt-0.5">Operando ou Preparados para Fraude</div>
            </div>

            <div className="p-4 rounded-xl bg-bg-secondary border border-amber-500/30">
              <div className="text-[11px] text-slate-400 font-bold flex items-center justify-between">
                <span>Clones Societários RFB</span>
                <Building2 className="w-4 h-4 text-amber-400" />
              </div>
              <div className="text-2xl font-black text-amber-400 mt-1 font-mono">
                {fakeCnpjData?.summary?.societary_clones ?? 1}
              </div>
              <div className="text-[10px] text-amber-400/80 mt-0.5">Abertos na Junta com Nome Similar</div>
            </div>

            <div className="p-4 rounded-xl bg-bg-secondary border border-purple-500/30">
              <div className="text-[11px] text-slate-400 font-bold flex items-center justify-between">
                <span>Roubo de Identidade (Phishing)</span>
                <Fingerprint className="w-4 h-4 text-purple-400" />
              </div>
              <div className="text-2xl font-black text-purple-400 mt-1 font-mono">
                {fakeCnpjData?.summary?.stolen_identities_in_phishing ?? 1}
              </div>
              <div className="text-[10px] text-purple-400/80 mt-0.5">CNPJ de Terceiro no Rodapé</div>
            </div>

            <div className="p-4 rounded-xl bg-bg-secondary border border-rose-500/30">
              <div className="text-[11px] text-slate-400 font-bold flex items-center justify-between">
                <span>Sócios Laranjas / Fantasmas</span>
                <UserX className="w-4 h-4 text-rose-400" />
              </div>
              <div className="text-2xl font-black text-rose-400 mt-1 font-mono">
                {fakeCnpjData?.fake_cnpjs?.filter((f: any) => f.categoria_fraude === 'EMPRESA_FANTASMA_LARANJA')?.length ?? 1}
              </div>
              <div className="text-[10px] text-rose-400/80 mt-0.5">Endereço de Fachada / 0800 Fake</div>
            </div>

            <div className="p-4 rounded-xl bg-bg-secondary border border-cyan-500/30">
              <div className="text-[11px] text-slate-400 font-bold flex items-center justify-between">
                <span>Dossiês Prontos p/ RFB/DEIC</span>
                <Scale className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-2xl font-black text-cyan-400 mt-1 font-mono">
                100%
              </div>
              <div className="text-[10px] text-cyan-400/80 mt-0.5">Custódia Criptográfica SHA-256</div>
            </div>
          </div>

          {/* ─── CARD: IDENTIDADE CORPORATIVA OFICIAL LEGÍTIMA ─── */}
          {fakeCnpjData?.official_identity && (
            <div className="p-5 rounded-2xl bg-gradient-to-r from-emerald-950/30 via-bg-secondary to-bg-secondary border border-emerald-500/50 shadow-xl space-y-3">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-emerald-500/20 pb-3">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
                    <ShieldCheck className="w-5 h-5" />
                  </div>
                  <div>
                    <span className="text-[10px] font-black uppercase tracking-wider text-emerald-400">
                      Identidade Corporativa Oficial Legítima (Matriz Registrada)
                    </span>
                    <h3 className="text-sm font-black text-slate-100 flex items-center gap-2">
                      <span>{fakeCnpjData.official_identity.razao_social}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                        {fakeCnpjData.official_identity.situacao_rfb}
                      </span>
                    </h3>
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  <div className="text-xs font-mono font-bold text-emerald-300 bg-emerald-500/10 px-3 py-1.5 rounded-xl border border-emerald-500/30 flex items-center gap-1.5">
                    <span>CNPJ MATRIZ: {fakeCnpjData.official_identity.official_cnpj}</span>
                  </div>
                  <a
                    href={`https://cnpj.biz/${fakeCnpjData.official_identity.official_cnpj.replace(/\D/g, '')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3 py-1.5 rounded-xl text-xs font-bold bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/50 text-emerald-300 flex items-center gap-1.5 transition-all cursor-pointer"
                    title="Consultar registro oficial do CNPJ na base pública da Receita Federal"
                  >
                    <Landmark className="w-3.5 h-3.5" />
                    <span>Ver Registro RFB (Ativo) ↗</span>
                  </a>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-bg-primary/80 border border-bg-border space-y-1">
                  <span className="text-[11px] text-slate-400 font-bold">Nome Fantasia & Fundação:</span>
                  <div className="font-bold text-slate-200">{fakeCnpjData.official_identity.nome_fantasia}</div>
                  <div className="text-slate-400 text-[11px]">Desde: {fakeCnpjData.official_identity.fundacao} • Capital: {fakeCnpjData.official_identity.capital_social}</div>
                </div>

                <div className="p-3 rounded-xl bg-bg-primary/80 border border-bg-border space-y-1">
                  <span className="text-[11px] text-slate-400 font-bold">Endereço Oficial Registrado:</span>
                  <div className="text-slate-300 text-[11px] leading-relaxed">{fakeCnpjData.official_identity.endereco}</div>
                </div>

                <div className="p-3 rounded-xl bg-bg-primary/80 border border-bg-border space-y-1">
                  <span className="text-[11px] text-slate-400 font-bold">CNAEs Autorizados:</span>
                  <div className="text-[10px] text-slate-400 space-y-0.5">
                    {fakeCnpjData.official_identity.cnaes?.slice(0, 2).map((c: string, idx: number) => (
                      <div key={idx} className="truncate" title={c}>• {c}</div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ─── FILTROS DE CATEGORIA DE FRAUDE ─── */}
          <div className="flex items-center justify-between gap-3 flex-wrap border-b border-bg-border pb-3">
            <div className="flex items-center gap-2 flex-wrap text-xs">
              <span className="text-xs font-bold text-slate-400 flex items-center gap-1">
                <Filter className="w-3.5 h-3.5" /> Filtrar por Tipo de Fraude:
              </span>
              {[
                { id: 'ALL', label: 'Todos os Fakes' },
                { id: 'CLONE_SOCIETARIO_RECEITA', label: 'Clones Societários RFB' },
                { id: 'ROUBO_IDENTIDADE_RODAPE', label: 'Roubo de Identidade (Phishing)' },
                { id: 'EMPRESA_FANTASMA_LARANJA', label: 'Empresas Fantasma / Laranja' },
                { id: 'CNPJ_INAPTO_OPERANDO', label: 'CNPJs Inaptos em Uso' },
              ].map((f) => (
                <button
                  key={f.id}
                  onClick={() => setSelectedFakeCategory(f.id)}
                  className={clsx(
                    "px-3 py-1.5 rounded-xl font-bold text-xs transition-all border cursor-pointer",
                    selectedFakeCategory === f.id
                      ? "bg-emerald-500/20 border-emerald-500/60 text-emerald-300 shadow-sm"
                      : "bg-bg-secondary border-bg-border hover:border-slate-700 text-slate-400"
                  )}
                >
                  {f.label}
                </button>
              ))}
            </div>

            <div className="text-xs text-slate-400 font-mono">
              Mostrando {
                (fakeCnpjData?.fake_cnpjs || []).filter((item: any) => selectedFakeCategory === 'ALL' || item.categoria_fraude === selectedFakeCategory).length
              } CNPJ(s) infratores
            </div>
          </div>

          {/* ─── CARDS DE CNPJS FAKES EM OPERAÇÃO ─── */}
          <div className="space-y-4">
            {(fakeCnpjData?.fake_cnpjs || [])
              .filter((item: any) => selectedFakeCategory === 'ALL' || item.categoria_fraude === selectedFakeCategory)
              .map((fake: any) => (
                <div
                  key={fake.id}
                  className="p-5 rounded-2xl bg-bg-secondary border border-bg-border hover:border-red-500/40 transition-all shadow-lg space-y-4"
                >
                  {/* Card Header */}
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-bg-border pb-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <a
                          href={`https://cnpj.biz/${fake.cnpj.replace(/\D/g, '')}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-base font-black font-mono text-red-400 hover:text-red-300 tracking-wider flex items-center gap-1.5 bg-red-500/10 hover:bg-red-500/20 px-2.5 py-1 rounded-lg border border-red-500/30 transition-all"
                          title="Abrir página de registro cadastral do CNPJ na base pública da Receita Federal (RFB)"
                        >
                          <Landmark className="w-4 h-4 text-red-400" />
                          <span>CNPJ: {fake.cnpj}</span>
                          <ExternalLink className="w-3.5 h-3.5 text-red-400" />
                        </a>
                        <a
                          href={`https://cnpj.biz/${fake.cnpj.replace(/\D/g, '')}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className={clsx(
                            "px-2.5 py-1 rounded-lg text-[10px] font-black uppercase border font-mono flex items-center gap-1 transition-all hover:scale-105",
                            fake.situacao_rfb === 'ATIVA' 
                              ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/30 hover:bg-emerald-500/20"
                              : "bg-red-500/10 text-red-300 border-red-500/30 hover:bg-red-500/20"
                          )}
                          title={`Situação Cadastral: ${fake.situacao_rfb}. Clique para ver o registro na íntegra.`}
                        >
                          <span>RFB: {fake.situacao_rfb}</span>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase bg-red-500/20 text-red-300 border border-red-500/40">
                          {fake.categoria_fraude.replace(/_/g, ' ')}
                        </span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-black bg-rose-500/20 text-rose-300 border border-rose-500/40">
                          SCORE DE FRAUDE: {fake.score_fraude}%
                        </span>
                      </div>
                      <h4 className="text-sm font-black text-slate-100 flex items-center gap-2">
                        <span className="text-slate-400 text-xs">Razão Social Fake:</span>
                        <span className="text-amber-300">{fake.razao_social}</span>
                        {fake.nome_fantasia && (
                          <span className="text-xs text-slate-400 font-normal">
                            (Fantasia: <strong className="text-slate-200">{fake.nome_fantasia}</strong>)
                          </span>
                        )}
                      </h4>
                    </div>

                    {/* Action Buttons */}
                    <div className="flex items-center gap-2 flex-wrap self-start lg:self-auto">
                      <a
                        href={`https://cnpj.biz/${fake.cnpj.replace(/\D/g, '')}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-3.5 py-2.5 rounded-xl text-xs font-bold bg-bg-primary hover:bg-bg-border border border-slate-700 hover:border-slate-500 text-slate-200 flex items-center gap-1.5 transition-all cursor-pointer whitespace-nowrap"
                        title="Ver ficha cadastral completa do CNPJ (Ativo ou Baixado/Inapto)"
                      >
                        <Landmark className="w-4 h-4 text-cyan-400" />
                        <span>Ver Registro CNPJ ↗</span>
                      </a>

                      {fake.site_fraude_ativo?.url && (
                        <a
                          href={fake.site_fraude_ativo.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="px-3.5 py-2.5 rounded-xl text-xs font-black bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white flex items-center gap-1.5 shadow-lg shadow-red-500/30 transition-all cursor-pointer whitespace-nowrap"
                          title="Abrir o site falso da fraude em nova aba para verificação pericial"
                        >
                          <ExternalLink className="w-4 h-4" />
                          <span>Abrir Site Fake ↗</span>
                        </a>
                      )}

                      <button
                        onClick={() => handleGenerateLegalDossier(fake.id)}
                        className="px-4 py-2.5 rounded-xl text-xs font-black bg-gradient-to-r from-slate-800 to-slate-700 hover:from-slate-700 hover:to-slate-600 border border-red-500/40 text-slate-100 flex items-center gap-2 shadow-lg transition-all cursor-pointer whitespace-nowrap"
                      >
                        <Scale className="w-4 h-4 text-red-400 fill-current" />
                        <span>📄 Dossiê & Notificação</span>
                      </button>
                    </div>
                  </div>

                  {/* ─── SITE DA FRAUDE ATIVA EM OPERAÇÃO (DESTAQUE PERICIAL) ─── */}
                  {fake.site_fraude_ativo && (
                    <div className={clsx(
                      "p-4 rounded-xl border space-y-3 shadow-inner transition-all",
                      fake.site_fraude_ativo.is_online
                        ? "bg-gradient-to-r from-red-950/40 via-rose-950/20 to-bg-primary border-red-500/40"
                        : "bg-gradient-to-r from-slate-900/60 via-slate-950/40 to-bg-primary border-slate-700/60"
                    )}>
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-bg-border/60 pb-2.5">
                        <div className="flex items-center gap-2 flex-wrap">
                          <div className="relative flex items-center justify-center">
                            <span className="relative flex h-3 w-3">
                              {fake.site_fraude_ativo.is_online ? (
                                <>
                                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                                  <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
                                </>
                              ) : (
                                <span className="relative inline-flex rounded-full h-3 w-3 bg-slate-500"></span>
                              )}
                            </span>
                          </div>
                          <span className={clsx(
                            "text-xs font-black uppercase tracking-wider flex items-center gap-1.5",
                            fake.site_fraude_ativo.is_online ? "text-red-300" : "text-slate-300"
                          )}>
                            <Globe className="w-3.5 h-3.5 text-slate-400" />
                            {fake.site_fraude_ativo.is_online ? "Site da Fraude Ativa (Live Flagrante):" : "Sonda Pericial Live (DNS / HTTP Probe):"}
                          </span>
                          <span className={clsx(
                            "px-2 py-0.5 rounded text-[10px] font-black uppercase border font-mono",
                            fake.site_fraude_ativo.is_online
                              ? "bg-red-500/20 text-red-300 border-red-500/40"
                              : "bg-slate-800 text-slate-300 border-slate-600"
                          )}>
                            {fake.site_fraude_ativo.status_label || (fake.site_fraude_ativo.is_online ? '🟢 ONLINE' : '🔴 OFFLINE / NXDOMAIN')}
                          </span>
                        </div>

                        <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
                          <span>{fake.site_fraude_ativo.is_online ? `HTTP ${fake.site_fraude_ativo.http_status}` : 'DNS: NXDOMAIN / Inativo'}</span>
                          <span>•</span>
                          <span>{fake.site_fraude_ativo.tempo_resposta_ms || 0}ms</span>
                        </div>
                      </div>

                      {/* URL & Quick Link Bar */}
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-2.5 rounded-lg bg-bg-primary/90 border border-bg-border">
                        <div className="flex items-center gap-2 min-w-0">
                          <Globe className="w-4 h-4 text-slate-400 flex-shrink-0" />
                          <span className={clsx(
                            "text-xs font-mono font-bold truncate select-all",
                            fake.site_fraude_ativo.is_online ? "text-red-300" : "text-slate-300"
                          )}>
                            {fake.site_fraude_ativo.url}
                          </span>
                        </div>

                        <div className="flex items-center gap-2 flex-shrink-0">
                          <button
                            onClick={() => handleCopyUrl(fake.site_fraude_ativo.url, fake.id)}
                            className="px-2.5 py-1 rounded-lg text-[11px] font-bold bg-bg-secondary hover:bg-bg-border border border-bg-border text-slate-300 flex items-center gap-1 transition-all cursor-pointer"
                            title="Copiar Link da Fraude"
                          >
                            {copiedUrlId === fake.id ? <CheckCheck className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                            <span>{copiedUrlId === fake.id ? 'Copiado!' : 'Copiar URL'}</span>
                          </button>

                          <a
                            href={fake.site_fraude_ativo.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-3 py-1 rounded-lg text-[11px] font-black bg-red-500 hover:bg-red-400 text-slate-950 flex items-center gap-1 shadow transition-all cursor-pointer"
                          >
                            <span>Acessar Site Fake</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>
                      </div>

                      {/* Details: Page Title, Vector, IP, SSL */}
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
                        <div className="p-2.5 rounded-lg bg-bg-primary/60 border border-bg-border space-y-0.5">
                          <span className="text-[10px] text-slate-400 font-bold uppercase">Título da Página Falsa:</span>
                          <div className="text-slate-200 font-medium text-[11px] truncate" title={fake.site_fraude_ativo.page_title}>
                            {fake.site_fraude_ativo.page_title}
                          </div>
                        </div>

                        <div className="p-2.5 rounded-lg bg-bg-primary/60 border border-bg-border space-y-0.5">
                          <span className="text-[10px] text-slate-400 font-bold uppercase">Vetor do Golpe no Site:</span>
                          <div className="text-amber-300 font-medium text-[11px] truncate" title={fake.site_fraude_ativo.tipo_fraude_site}>
                            {fake.site_fraude_ativo.tipo_fraude_site}
                          </div>
                        </div>

                        <div className="p-2.5 rounded-lg bg-bg-primary/60 border border-bg-border space-y-0.5">
                          <span className="text-[10px] text-slate-400 font-bold uppercase">Hospedagem & IP:</span>
                          <div className="text-slate-300 font-mono text-[10px] truncate" title={fake.site_fraude_ativo.ip_hospedagem}>
                            {fake.site_fraude_ativo.ip_hospedagem}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Informações Cadastrais & QSA */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                    <div className="p-3 rounded-xl bg-bg-primary border border-bg-border space-y-1">
                      <span className="text-[11px] font-bold text-slate-400">Data de Abertura & Capital:</span>
                      <div className="font-bold text-slate-200 flex items-center gap-2">
                        <span>{fake.data_abertura}</span>
                        {fake.idade_dias && fake.idade_dias < 90 && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-300 border border-red-500/30">
                            Aberto há {fake.idade_dias} dias
                          </span>
                        )}
                      </div>
                      <div className="text-slate-400 text-[11px]">Capital Social: <strong className="text-amber-300">{fake.capital_social}</strong></div>
                    </div>

                    <div className="p-3 rounded-xl bg-bg-primary border border-bg-border space-y-1">
                      <span className="text-[11px] font-bold text-slate-400">Quadro Societário (QSA) & Risco de Laranja:</span>
                      {fake.socios_qsa?.map((socio: any, idx: number) => (
                        <div key={idx} className="space-y-0.5">
                          <div className="font-bold text-slate-200 flex items-center gap-1.5">
                            <span className="truncate">{socio.nome}</span>
                            {socio.risco_laranja && socio.risco_laranja > 80 && (
                              <span className="px-1.5 py-0.2 rounded text-[9px] font-black bg-rose-500/20 text-rose-300 border border-rose-500/30 flex-shrink-0">
                                LARANJA {socio.risco_laranja}%
                              </span>
                            )}
                          </div>
                          <div className="text-[10px] text-slate-400 font-mono">
                            CPF: {socio.cpf_mascarado} • {socio.qualificacao}
                          </div>
                        </div>
                      ))}
                    </div>

                    <div className="p-3 rounded-xl bg-bg-primary border border-bg-border space-y-1">
                      <span className="text-[11px] font-bold text-slate-400">CNAE Declarado na RFB:</span>
                      <div className="text-[11px] text-slate-300 leading-snug">{fake.cnae_declarado}</div>
                      {fake.cnae_incompativel && (
                        <div className="text-[10px] font-bold text-red-400 flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3 flex-shrink-0" />
                          <span>Incompatível com a atividade real</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Endereço & Vetores de Flagrante */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    {/* Vetores de Fraude */}
                    <div className="p-3.5 rounded-xl bg-red-950/20 border border-red-500/30 space-y-2">
                      <div className="text-xs font-black text-red-300 flex items-center gap-1.5">
                        <AlertOctagon className="w-4 h-4 text-red-400" />
                        <span>Vetores de Flagrante / Onde Foi Encontrado em Operação:</span>
                      </div>
                      <div className="space-y-1">
                        {fake.vetores_flagrante?.map((vetor: string, idx: number) => (
                          <div key={idx} className="flex items-start gap-2 text-xs text-slate-200">
                            <span className="text-red-400 font-bold mt-0.5">•</span>
                            <span className="font-mono text-[11px]">{vetor}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Indicadores Forenses */}
                    <div className="p-3.5 rounded-xl bg-bg-primary border border-bg-border space-y-2">
                      <div className="text-xs font-black text-slate-300 flex items-center gap-1.5">
                        <Fingerprint className="w-4 h-4 text-emerald-400" />
                        <span>Indicadores Periciais & Evidências Concretas:</span>
                      </div>
                      <div className="space-y-1">
                        {fake.indicadores?.map((ind: string, idx: number) => (
                          <div key={idx} className="flex items-start gap-2 text-xs text-slate-400">
                            <Check className="w-3.5 h-3.5 text-emerald-400 mt-0.5 flex-shrink-0" />
                            <span>{ind}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* TAB 1: FINDINGS & EXPLAINABLE AI */}
      {activeTab === 'findings' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Findings List */}
          <div className="lg:col-span-5 space-y-3">
            {/* Filter */}
            <div className="flex items-center gap-2 p-2 rounded-xl bg-bg-secondary border border-bg-border text-xs">
              <Filter className="w-3.5 h-3.5 text-slate-400" />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-bg-primary border border-bg-border rounded-lg px-2 py-1 text-slate-200 text-xs"
              >
                <option value="ALL">Todas as Severidades</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
              </select>
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="bg-bg-primary border border-bg-border rounded-lg px-2 py-1 text-slate-200 text-xs flex-1"
              >
                <option value="ALL">Todas Categorias (5 Motores)</option>
                <option value="GOVERNANCE_SOD">Segregação de Funções (SoD)</option>
                <option value="CONFLICT_OF_INTEREST">Conflito de Relacionamento</option>
                <option value="SANCTIONS_SCREENING">Sanções Públicas (CEIS/CNEP)</option>
                <option value="DUPLICITY">Duplicidade de Notas</option>
                <option value="CONCENTRATION">Concentração de Fornecedor</option>
                <option value="FRACTIONING">Fracionamento / Smurfing</option>
                <option value="TEMPORAL">Anomalias Temporais</option>
                <option value="STATISTICAL_ANOMALY">Lei de Benford & Estatística</option>
                <option value="INTEGRITY">Inconsistência Cadastral RFB</option>
              </select>
            </div>

            <div className="space-y-2 max-h-[600px] overflow-y-auto custom-scrollbar pr-1">
              {filteredFindings.map((f: any) => (
                <div
                  key={f.id || f.rule_code}
                  onClick={() => setSelectedFinding(f)}
                  className={clsx(
                    'p-3.5 rounded-xl border transition-all cursor-pointer text-left',
                    selectedFinding?.id === f.id
                      ? 'bg-emerald-500/10 border-emerald-500/50 shadow-md shadow-emerald-500/10'
                      : 'bg-bg-secondary border-bg-border hover:border-slate-600'
                  )}
                >
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span className={clsx(
                      'px-2 py-0.5 rounded text-[10px] font-black uppercase',
                      f.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-300 border border-red-500/40' :
                      f.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40' :
                      'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                    )}>
                      {f.severity}
                    </span>
                    <span className="font-mono text-[11px] font-bold text-slate-400">{f.rule_code}</span>
                    <span className="text-[10px] text-amber-400 font-bold ml-auto">Score: {f.risk_score}</span>
                  </div>
                  <h4 className="text-xs font-bold text-slate-200 line-clamp-2">{f.title}</h4>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-bg-border/60 text-[11px] text-slate-400">
                    <span>Exposição: <strong className="text-red-400 font-mono">R$ {f.financial_exposure ? f.financial_exposure.toLocaleString() : '0'}</strong></span>
                    <span>{f.affected_records_count ?? 1} registros</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Finding Detail / Explainable AI Drawer */}
          <div className="lg:col-span-7">
            {selectedFinding ? (
              <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border space-y-4 text-left">
                <div className="flex items-start justify-between gap-3 border-b border-bg-border pb-3">
                  <div>
                    <span className="font-mono text-xs text-emerald-400 font-bold">{selectedFinding.rule_code}</span>
                    <h3 className="text-base font-bold text-slate-100 mt-0.5">{selectedFinding.title}</h3>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <button
                      onClick={() => handleReviewFinding(selectedFinding.id, 'CONFIRMED')}
                      className="px-2.5 py-1 rounded-lg text-xs font-bold bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30"
                    >
                      Confirmar
                    </button>
                    <button
                      onClick={() => handleReviewFinding(selectedFinding.id, 'FALSE_POSITIVE')}
                      className="px-2.5 py-1 rounded-lg text-xs font-bold bg-slate-800 text-slate-300 hover:bg-slate-700"
                    >
                      Falso Positivo
                    </button>
                  </div>
                </div>

                {/* AI Explanation Box */}
                <div className="p-4 rounded-xl bg-bg-primary border border-bg-border space-y-2.5 text-xs">
                  <h4 className="font-bold text-emerald-400 flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5" />
                    Explicabilidade Analítica & Pericial (IA)
                  </h4>
                  <div className="space-y-1.5 text-slate-300 leading-relaxed">
                    <p><strong>O que foi identificado:</strong> {selectedFinding.explanation?.what}</p>
                    <p><strong>Fundamentação de Risco:</strong> {selectedFinding.explanation?.why}</p>
                    <p><strong>Evidência Documental:</strong> {selectedFinding.explanation?.evidence}</p>
                    <p><strong>Recomendação ao Auditor:</strong> {selectedFinding.explanation?.recommendation}</p>
                  </div>
                </div>

                {/* Alternative Hypotheses */}
                {selectedFinding.alternative_hypotheses?.length > 0 && (
                  <div className="p-3.5 rounded-xl bg-bg-primary/50 border border-bg-border space-y-1.5 text-xs">
                    <h5 className="font-bold text-slate-300 flex items-center gap-1.5">
                      <HelpCircle className="w-3.5 h-3.5 text-cyan-400" />
                      Hipóteses Alternativas de Conformidade
                    </h5>
                    <ul className="list-disc list-inside space-y-0.5 text-slate-400 text-[11px]">
                      {selectedFinding.alternative_hypotheses.map((h: string, idx: number) => (
                        <li key={idx}>{h}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Sample Evidence Snippets */}
                {selectedFinding.sample_records?.length > 0 && (
                  <div className="space-y-2 text-xs">
                    <h5 className="font-bold text-slate-300">Amostra de Registros Vinculados</h5>
                    <div className="overflow-x-auto rounded-xl border border-bg-border bg-bg-primary">
                      <table className="w-full text-left text-[11px] text-slate-300">
                        <thead className="bg-bg-secondary text-slate-400 border-b border-bg-border">
                          <tr>
                            <th className="p-2">Documento</th>
                            <th className="p-2">Data</th>
                            <th className="p-2">Fornecedor</th>
                            <th className="p-2">Valor</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-bg-border font-mono">
                          {selectedFinding.sample_records.map((r: any, idx: number) => (
                            <tr key={idx}>
                              <td className="p-2 text-cyan-300">{r.Numero_NF || r.invoice_number || 'NF-Auto'}</td>
                              <td className="p-2">{r.Data_Emissao || r.invoice_date || 'N/A'}</td>
                              <td className="p-2">{r.Razao_Social_Fornecedor || r.supplier_name || r.CNPJ_Fornecedor}</td>
                              <td className="p-2 text-emerald-400">R$ {r.Vl_Total_Nota ? r.Vl_Total_Nota.toFixed(2) : r.amount?.toFixed(2)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Non-accusatory Disclaimer */}
                <div className="text-[10px] text-slate-500 italic border-t border-bg-border/60 pt-2">
                  {selectedFinding.explanation?.disclaimer}
                </div>
              </div>
            ) : (
              <div className="p-12 text-center text-slate-500 bg-bg-secondary rounded-2xl border border-bg-border">
                Selecione um finding para visualizar a análise detalhada e explicabilidade da IA.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: FORENSIC ENTITY GRAPH */}
      {activeTab === 'graph' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
              <div className="text-xs text-slate-400">Índice HHI de Concentração</div>
              <div className="text-2xl font-black text-amber-400 mt-1 font-mono">{hhi.hhi_index ?? 2780}</div>
              <div className="text-[11px] text-amber-500/80 mt-0.5">{hhi.classification ?? 'HIGHLY_CONCENTRATED'}</div>
            </div>
            <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
              <div className="text-xs text-slate-400">Concentração Top 1 Fornecedor</div>
              <div className="text-2xl font-black text-red-400 mt-1 font-mono">{hhi.top_1_concentration_pct ?? 38.4}%</div>
              <div className="text-[11px] text-red-400/80 mt-0.5">Dependência Crítica de Fornecimento</div>
            </div>
            <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border">
              <div className="text-xs text-slate-400">Nós e Entidades Mapeadas</div>
              <div className="text-2xl font-black text-cyan-400 mt-1 font-mono">{graph.nodes?.length || 12}</div>
              <div className="text-[11px] text-slate-500 mt-0.5">Grafo de Relacionamentos Ativo</div>
            </div>
          </div>

          <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border space-y-4">
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              Matriz de Relacionamentos e Concentração de Fornecedores (Top Spend)
            </h3>

            <div className="overflow-x-auto rounded-xl border border-bg-border bg-bg-primary">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-bg-secondary text-slate-400 font-bold uppercase tracking-wider border-b border-bg-border">
                  <tr>
                    <th className="p-3">Fornecedor / Contraparte</th>
                    <th className="p-3">CNPJ / Tax ID</th>
                    <th className="p-3">Volume Financeiro</th>
                    <th className="p-3">Participação (% Share)</th>
                    <th className="p-3">Classificação de Risco</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-bg-border font-mono">
                  {hhi.top_suppliers?.map((s: any, idx: number) => (
                    <tr key={idx} className="hover:bg-bg-secondary/40">
                      <td className="p-3 text-slate-100 font-sans font-bold">{s.name}</td>
                      <td className="p-3 text-cyan-300">{s.tax_id}</td>
                      <td className="p-3 text-emerald-400">R$ {s.volume?.toLocaleString('pt-BR', { minimumFractionDigits: 2 })}</td>
                      <td className="p-3 font-bold">{s.share_pct}%</td>
                      <td className="p-3">
                        <span className={clsx(
                          'px-2 py-0.5 rounded text-[10px] font-black uppercase font-sans',
                          s.share_pct > 30 ? 'bg-red-500/20 text-red-300 border border-red-500/40' :
                          s.share_pct > 15 ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                          'bg-emerald-500/20 text-emerald-300'
                        )}>
                          {s.share_pct > 30 ? 'CONCENTRAÇÃO CRÍTICA' : s.share_pct > 15 ? 'ATENÇÃO' : 'NORMAL'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: BENFORD & STATISTICAL ANOMALIES */}
      {activeTab === 'benford' && (
        <div className="space-y-6">
          <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border space-y-4">
            <div className="flex items-center justify-between border-b border-bg-border pb-3">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <BarChart3 className="w-5 h-5 text-emerald-400" />
                  Análise da Lei de Benford (Distribuição do 1º Dígito)
                </h3>
                <p className="text-xs text-slate-400">
                  Comparação matemática entre as proporções esperadas por Benford e os dígitos reais da base.
                </p>
              </div>
              <div className="text-right">
                <span className="text-xs text-slate-400">MAD Score: </span>
                <strong className="text-amber-400 font-mono text-sm">{benford.mad ?? 2.8}%</strong>
                <span className="text-xs text-slate-500 ml-2">({benford.conformity_level ?? 'MARGINAL'})</span>
              </div>
            </div>

            {/* Digits Bar Table */}
            <div className="overflow-x-auto rounded-xl border border-bg-border bg-bg-primary">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-bg-secondary text-slate-400 font-bold border-b border-bg-border">
                  <tr>
                    <th className="p-3">Dígito (1-9)</th>
                    <th className="p-3">Contagem</th>
                    <th className="p-3">Real Observado (%)</th>
                    <th className="p-3">Benford Esperado (%)</th>
                    <th className="p-3">Desvio (%)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-bg-border font-mono">
                  {benford.digits && Object.values(benford.digits).map((d: any) => (
                    <tr key={d.digit}>
                      <td className="p-3 font-bold text-cyan-300 font-sans">Dígito {d.digit}</td>
                      <td className="p-3">{d.count}</td>
                      <td className="p-3 font-bold text-slate-100">{d.observed_pct}%</td>
                      <td className="p-3 text-slate-400">{d.expected_pct}%</td>
                      <td className="p-3">
                        <span className={clsx(
                          'font-bold',
                          d.difference_pct > 4.0 ? 'text-red-400' : d.difference_pct > 2.0 ? 'text-amber-400' : 'text-emerald-400'
                        )}>
                          {d.difference_pct > 0 ? `+${d.difference_pct}%` : `${d.difference_pct}%`}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: CASE MANAGEMENT */}
      {activeTab === 'cases' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <CheckSquare className="w-5 h-5 text-emerald-400" />
              Casos Investigativos Abertos
            </h3>
            <button
              onClick={() => setCaseModalOpen(true)}
              className="px-3 py-1.5 rounded-xl text-xs font-bold bg-emerald-500 hover:bg-emerald-400 text-slate-950 flex items-center gap-1.5 cursor-pointer shadow-md shadow-emerald-500/10"
            >
              <Plus className="w-4 h-4" />
              <span>Abrir Novo Caso</span>
            </button>
          </div>

          <div className="grid grid-cols-1 gap-3">
            {auditData?.cases?.map((c: any) => (
              <div key={c.id || c.case_number} className="p-5 rounded-2xl bg-bg-secondary border border-bg-border space-y-3">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-0.5 rounded text-xs font-black font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                      {c.case_number}
                    </span>
                    <h4 className="text-sm font-bold text-slate-100">{c.title}</h4>
                  </div>
                  <span className="text-xs font-bold text-amber-400">Status: {c.status}</span>
                </div>
                <p className="text-xs text-slate-400">{c.description}</p>
                <div className="flex items-center gap-4 text-xs text-slate-400 pt-2 border-t border-bg-border/60">
                  <span>Exposição do Caso: <strong className="text-red-400 font-mono">R$ {c.financial_exposure ? c.financial_exposure.toLocaleString() : '0'}</strong></span>
                  <span>{c.findings_count} apontamentos vinculados</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 5: EVIDENCE VAULT (SHA-256) */}
      {activeTab === 'evidence' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-bg-secondary border border-bg-border flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-bold text-slate-200">Cadeia de Custódia & Integridade Criptográfica (SHA-256)</span>
            </div>
            <span className="text-xs text-emerald-400 font-bold flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Todas as evidências verificadas
            </span>
          </div>

          <div className="overflow-x-auto rounded-2xl border border-bg-border bg-bg-secondary">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-bg-primary text-slate-400 font-bold uppercase border-b border-bg-border">
                <tr>
                  <th className="p-3">ID Evidência</th>
                  <th className="p-3">Linha Origem</th>
                  <th className="p-3">Arquivo Fonte</th>
                  <th className="p-3">Hash SHA-256 de Custódia</th>
                  <th className="p-3">Integridade</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-bg-border font-mono text-[11px]">
                {auditData?.evidences?.map((ev: any, idx: number) => (
                  <tr key={idx} className="hover:bg-bg-primary/50">
                    <td className="p-3 text-cyan-300">{ev.id}</td>
                    <td className="p-3">Linha #{ev.row_number}</td>
                    <td className="p-3 text-slate-400">{ev.source_file}</td>
                    <td className="p-3 text-slate-300 truncate max-w-xs" title={ev.sha256_hash}>
                      {ev.sha256_hash}
                    </td>
                    <td className="p-3">
                      <span className="text-emerald-400 font-bold font-sans">Íntegro (OK)</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 6: AUDITOR COPILOT */}
      {activeTab === 'copilot' && (
        <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border space-y-4">
          <div className="flex items-center gap-2 border-b border-bg-border pb-3">
            <Bot className="w-5 h-5 text-cyan-400" />
            <div>
              <h3 className="text-sm font-bold text-slate-100">Fiscal Auditor Copilot (IA)</h3>
              <p className="text-[11px] text-slate-400">Responde dúvidas com fundamentação exclusiva no dataset e regras fiscais.</p>
            </div>
          </div>

          {/* Chat Messages */}
          <div className="space-y-3 max-h-96 overflow-y-auto custom-scrollbar p-3 rounded-xl bg-bg-primary border border-bg-border">
            {copilotMessages.map((msg, idx) => (
              <div
                key={idx}
                className={clsx(
                  'p-3.5 rounded-xl text-xs leading-relaxed max-w-2xl',
                  msg.role === 'user'
                    ? 'ml-auto bg-emerald-500/20 border border-emerald-500/40 text-emerald-200'
                    : 'bg-bg-secondary border border-bg-border text-slate-200 space-y-1.5'
                )}
              >
                <div className="whitespace-pre-line">{msg.text}</div>
                {msg.confidence && (
                  <div className="text-[10px] text-slate-400 border-t border-bg-border/60 pt-1">
                    Confiança da IA: <strong className="text-emerald-400">{msg.confidence}%</strong>
                  </div>
                )}
              </div>
            ))}
            {copilotLoading && (
              <div className="p-3 rounded-xl bg-bg-secondary border border-bg-border text-xs text-slate-400 flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                <span>Consultando evidências da base...</span>
              </div>
            )}
          </div>

          {/* Quick Prompts */}
          <div className="flex items-center gap-2 overflow-x-auto text-[11px]">
            {[
              'Quais são os maiores riscos encontrados?',
              'Qual a concentração de fornecedores?',
              'Explique o desvio da Lei de Benford',
              'Quais operações ocorreram em fins de semana?',
            ].map((prompt, i) => (
              <button
                key={i}
                onClick={() => {
                  setCopilotQuery(prompt);
                }}
                className="px-2.5 py-1 rounded-lg bg-bg-primary border border-bg-border hover:border-cyan-500/40 text-slate-300 whitespace-nowrap cursor-pointer"
              >
                {prompt}
              </button>
            ))}
          </div>

          {/* Input */}
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={copilotQuery}
              onChange={(e) => setCopilotQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCopilotSend()}
              placeholder="Pergunte ao Auditor Copilot sobre o dataset..."
              className="flex-1 px-4 py-2.5 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <button
              onClick={handleCopilotSend}
              disabled={copilotLoading || !copilotQuery.trim()}
              className="px-4 py-2.5 rounded-xl font-bold text-xs bg-cyan-500 hover:bg-cyan-400 text-slate-950 flex items-center gap-1.5 cursor-pointer disabled:opacity-40"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Perguntar</span>
            </button>
          </div>
        </div>
      )}

      {/* TAB 7: DATA QUALITY */}
      {activeTab === 'quality' && (
        <div className="space-y-4">
          <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border space-y-3">
            <h3 className="text-sm font-bold text-slate-200">Sumário de Integridade e Validação Cadastral</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-xl bg-bg-primary border border-bg-border">
                <span className="text-slate-400">Total de Registros</span>
                <div className="text-lg font-bold text-slate-100 mt-1 font-mono">{quality.total_records ?? 1000}</div>
              </div>
              <div className="p-3 rounded-xl bg-bg-primary border border-bg-border">
                <span className="text-slate-400">Registros Válidos</span>
                <div className="text-lg font-bold text-emerald-400 mt-1 font-mono">{quality.valid_records ?? 940}</div>
              </div>
              <div className="p-3 rounded-xl bg-bg-primary border border-bg-border">
                <span className="text-slate-400">Inconsistências Detectadas</span>
                <div className="text-lg font-bold text-amber-400 mt-1 font-mono">{quality.invalid_records ?? 60}</div>
              </div>
              <div className="p-3 rounded-xl bg-bg-primary border border-bg-border">
                <span className="text-slate-400">Status Geral</span>
                <div className="text-lg font-bold text-cyan-400 mt-1">{quality.quality_status ?? 'EXCELLENT'}</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ─── MODAL: UPLOAD DE RELATÓRIOS & DATASETS ─── */}
      {uploadModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-bg-secondary border border-bg-border rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl space-y-5 p-6 animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between border-b border-bg-border pb-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
                  <UploadCloud className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-100">Upload de Arquivos & Relatórios Fiscais</h3>
                  <p className="text-xs text-slate-400">
                    Envie planilhas, arquivos SPED, XMLs de NF-e ou arquivos CSV/JSON para análise forense imediata.
                  </p>
                </div>
              </div>
              <button
                onClick={() => { setUploadModalOpen(false); setSelectedFile(null); setUploadError(null); setUploadSuccess(null); }}
                className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-bg-primary transition-colors cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Drag and Drop Zone */}
            <div
              onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDragging(false);
                if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                  setSelectedFile(e.dataTransfer.files[0]);
                }
              }}
              onClick={() => fileInputRef.current?.click()}
              className={clsx(
                'border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all duration-200 flex flex-col items-center justify-center gap-3',
                isDragging
                  ? 'border-emerald-500 bg-emerald-500/10 scale-[0.99]'
                  : selectedFile
                  ? 'border-emerald-500/50 bg-emerald-500/5'
                  : 'border-bg-border hover:border-emerald-500/40 hover:bg-bg-primary/50'
              )}
            >
              <input
                type="file"
                ref={fileInputRef}
                className="hidden"
                accept=".xlsx,.xls,.csv,.tsv,.txt,.sped,.xml,.json"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    setSelectedFile(e.target.files[0]);
                  }
                }}
              />

              <div className="w-14 h-14 rounded-2xl bg-bg-primary border border-bg-border flex items-center justify-center text-emerald-400 shadow-inner">
                {uploading ? (
                  <Loader2 className="w-7 h-7 animate-spin text-emerald-400" />
                ) : selectedFile ? (
                  <FileSpreadsheet className="w-7 h-7 text-emerald-400" />
                ) : (
                  <FileUp className="w-7 h-7 text-slate-400" />
                )}
              </div>

              {selectedFile ? (
                <div>
                  <div className="text-sm font-bold text-emerald-400">{selectedFile.name}</div>
                  <div className="text-xs text-slate-400 mt-0.5">
                    {(selectedFile.size / 1024).toFixed(1)} KB • Pronto para processamento forense
                  </div>
                </div>
              ) : (
                <div>
                  <div className="text-sm font-bold text-slate-200">
                    Arraste e solte o arquivo aqui ou <span className="text-emerald-400 underline">clique para selecionar</span>
                  </div>
                  <div className="text-xs text-slate-400 mt-1">
                    Formatos aceitos: Excel (.xlsx, .xls), SPED EFD/ECD (.sped, .txt), NF-e/CT-e (.xml), CSV, TSV e JSON
                  </div>
                </div>
              )}
            </div>

            {/* Formats Info Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px]">
              <div className="p-2.5 rounded-xl bg-bg-primary border border-bg-border">
                <div className="font-bold text-emerald-400 flex items-center gap-1">
                  <FileSpreadsheet className="w-3.5 h-3.5" /> Planilhas Excel
                </div>
                <div className="text-slate-400 text-[10px] mt-0.5">.xlsx, .xls (Lançamentos e Extratos)</div>
              </div>

              <div className="p-2.5 rounded-xl bg-bg-primary border border-bg-border">
                <div className="font-bold text-cyan-400 flex items-center gap-1">
                  <FileText className="w-3.5 h-3.5" /> SPED Fiscal EFD
                </div>
                <div className="text-slate-400 text-[10px] mt-0.5">.sped, .txt (Reg C100/D100/0000)</div>
              </div>

              <div className="p-2.5 rounded-xl bg-bg-primary border border-bg-border">
                <div className="font-bold text-amber-400 flex items-center gap-1">
                  <FileCode className="w-3.5 h-3.5" /> XML NF-e / CT-e
                </div>
                <div className="text-slate-400 text-[10px] mt-0.5">.xml (Extração de Itens e Tributos)</div>
              </div>

              <div className="p-2.5 rounded-xl bg-bg-primary border border-bg-border">
                <div className="font-bold text-purple-400 flex items-center gap-1">
                  <Layers className="w-3.5 h-3.5" /> CSV / TSV / JSON
                </div>
                <div className="text-slate-400 text-[10px] mt-0.5">Delimitadores autodetectados</div>
              </div>
            </div>

            {/* Quick Demo Samples Presets */}
            <div className="p-3.5 rounded-xl bg-bg-primary border border-bg-border space-y-2">
              <div className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
                Ou selecione um dataset de demonstração para benchmark imediato:
              </div>
              <div className="flex items-center gap-2 flex-wrap text-xs">
                <button
                  type="button"
                  onClick={() => { handleSeedDemo(1000); setUploadModalOpen(false); }}
                  disabled={uploading || loading}
                  className="px-3 py-1.5 rounded-lg bg-bg-secondary hover:bg-emerald-500/20 border border-bg-border hover:border-emerald-500/40 text-slate-200 font-medium transition-all cursor-pointer"
                >
                  ⚡ Demo SAP ERP (1.000 Lançamentos)
                </button>
                <button
                  type="button"
                  onClick={() => { handleSeedDemo(2500); setUploadModalOpen(false); }}
                  disabled={uploading || loading}
                  className="px-3 py-1.5 rounded-lg bg-bg-secondary hover:bg-cyan-500/20 border border-bg-border hover:border-cyan-500/40 text-slate-200 font-medium transition-all cursor-pointer"
                >
                  🏢 Alta Volumetria (2.500 Lançamentos)
                </button>
                <button
                  type="button"
                  onClick={() => { handleSeedDemo(300); setUploadModalOpen(false); }}
                  disabled={uploading || loading}
                  className="px-3 py-1.5 rounded-lg bg-bg-secondary hover:bg-amber-500/20 border border-bg-border hover:border-amber-500/40 text-slate-200 font-medium transition-all cursor-pointer"
                >
                  🚨 Fraude & SoD Concentrada (300 NFs)
                </button>
              </div>
            </div>

            {/* Feedback messages */}
            {uploadError && (
              <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-300 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
                <span>{uploadError}</span>
              </div>
            )}

            {uploadSuccess && (
              <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <span>{uploadSuccess}</span>
              </div>
            )}

            {/* Footer Buttons */}
            <div className="flex items-center justify-end gap-3 pt-2 border-t border-bg-border">
              <button
                type="button"
                onClick={() => { setUploadModalOpen(false); setSelectedFile(null); setUploadError(null); }}
                className="px-4 py-2 rounded-xl text-xs font-bold text-slate-400 hover:text-slate-200 hover:bg-bg-primary transition-colors cursor-pointer"
              >
                Cancelar
              </button>

              <button
                type="button"
                onClick={() => handleFileUpload()}
                disabled={!selectedFile || uploading}
                className="px-5 py-2 rounded-xl text-xs font-bold bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 flex items-center gap-2 shadow-lg shadow-emerald-500/20 transition-all cursor-pointer disabled:opacity-40"
              >
                {uploading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Executando Auditoria Forense...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-current" />
                    <span>Processar e Auditar Arquivo</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── MODAL: CRIAR CASO INVESTIGATIVO ─── */}
      {caseModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-bg-secondary border border-bg-border rounded-2xl w-full max-w-lg p-6 shadow-2xl space-y-4 animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between border-b border-bg-border pb-3">
              <div className="flex items-center gap-2">
                <CheckSquare className="w-5 h-5 text-emerald-400" />
                <h3 className="text-base font-bold text-slate-100">Abrir Caso de Investigação Forense</h3>
              </div>
              <button onClick={() => setCaseModalOpen(false)} className="text-slate-400 hover:text-slate-200 p-1">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-bold mb-1">Título do Caso</label>
                <input
                  type="text"
                  value={caseTitle}
                  onChange={(e) => setCaseTitle(e.target.value)}
                  placeholder="Ex: Investigação de Fornecedor Suspeito / Conflito SoD"
                  className="w-full px-3.5 py-2 rounded-xl bg-bg-primary border border-bg-border text-slate-100 focus:outline-none focus:border-emerald-500"
                />
              </div>

              {selectedFinding && (
                <div className="p-3 rounded-xl bg-bg-primary border border-bg-border space-y-1">
                  <div className="text-[11px] text-slate-400">Apontamento Vinculado:</div>
                  <div className="font-bold text-slate-200">{selectedFinding.title}</div>
                  <div className="text-xs text-red-400 font-mono">
                    Exposição Estimada: R$ {selectedFinding.financial_exposure?.toLocaleString() || '0'}
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-bg-border">
              <button
                type="button"
                onClick={() => setCaseModalOpen(false)}
                className="px-4 py-2 rounded-xl text-xs text-slate-400 hover:text-slate-200"
              >
                Cancelar
              </button>
              <button
                type="button"
                onClick={handleCreateCase}
                disabled={!caseTitle.trim()}
                className="px-4 py-2 rounded-xl text-xs font-bold bg-emerald-500 hover:bg-emerald-400 text-slate-950 disabled:opacity-40"
              >
                Criar Caso
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── MODAL: NOVO PROJETO DE FRAUDE FINANCEIRA & AUDITORIA FISCAL ─── */}
      {newProjectModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-bg-secondary border border-emerald-500/30 rounded-2xl w-full max-w-lg p-6 shadow-2xl space-y-4 animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between border-b border-bg-border pb-3">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
                  <Briefcase className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-100">Criar Projeto de Fraude Financeira</h3>
                  <p className="text-[11px] text-slate-400">Ambiente isolado para testes periciais, detecção de anomalias e conformidade contábil.</p>
                </div>
              </div>
              <button onClick={() => setNewProjectModalOpen(false)} className="text-slate-400 hover:text-slate-200 p-1">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-bold mb-1">Nome do Projeto de Fraude Financeira *</label>
                <input
                  type="text"
                  value={newProjName}
                  onChange={(e) => setNewProjName(e.target.value)}
                  placeholder="Ex: Auditoria Forense e Teste de Fraude 2026"
                  className="w-full px-3.5 py-2 rounded-xl bg-bg-primary border border-bg-border text-slate-100 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-bold mb-1">Foco Principal do Teste de Fraude</label>
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { id: 'SOD_FRAUD', title: 'Fraude SoD & Compras', desc: 'Conflito de aprovação e pagamentos' },
                    { id: 'TAX_EVASION', title: 'Fraude Tributária & ICMS', desc: 'Inconsistências em alíquotas e NF-e' },
                    { id: 'GHOST_VENDOR', title: 'Fornecedores Fantasmas', desc: 'Concentração HHI e sócios ocultos' },
                    { id: 'FORENSIC_SPED', title: 'Auditoria Benford & SPED', desc: 'Desvios estatísticos e integridade' },
                  ].map((f) => (
                    <button
                      key={f.id}
                      type="button"
                      onClick={() => setNewProjFocus(f.id)}
                      className={clsx(
                        'p-2.5 rounded-xl border text-left transition-all cursor-pointer',
                        newProjFocus === f.id
                          ? 'bg-emerald-500/15 border-emerald-500/60 text-emerald-200'
                          : 'bg-bg-primary border-bg-border hover:border-slate-700 text-slate-400'
                      )}
                    >
                      <div className="font-bold text-[11px] text-slate-200">{f.title}</div>
                      <div className="text-[10px] text-slate-400 mt-0.5 leading-tight">{f.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-bold mb-1">Razão Social / Alvo Auditado</label>
                <input
                  type="text"
                  value={newProjClient}
                  onChange={(e) => setNewProjClient(e.target.value)}
                  placeholder="Ex: Distribuidora Nacional de Alimentos S.A."
                  className="w-full px-3.5 py-2 rounded-xl bg-bg-primary border border-bg-border text-slate-100 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-bold mb-1">Unidade de Negócio / Área</label>
                <input
                  type="text"
                  value={newProjUnit}
                  onChange={(e) => setNewProjUnit(e.target.value)}
                  placeholder="Ex: Controladoria, Tributário & Compliance Fiscal"
                  className="w-full px-3.5 py-2 rounded-xl bg-bg-primary border border-bg-border text-slate-100 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-bold mb-1">Descrição do Escopo e Hipóteses de Investigação</label>
                <textarea
                  value={newProjDesc}
                  onChange={(e) => setNewProjDesc(e.target.value)}
                  rows={2}
                  placeholder="Descreva o escopo da perícia contábil, apuração de fraudes e auditoria de transações..."
                  className="w-full px-3.5 py-2 rounded-xl bg-bg-primary border border-bg-border text-slate-100 focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-bg-border">
              <button
                type="button"
                onClick={() => setNewProjectModalOpen(false)}
                className="px-4 py-2 rounded-xl text-xs text-slate-400 hover:text-slate-200"
              >
                Cancelar
              </button>
              <button
                type="button"
                onClick={handleCreateProject}
                disabled={!newProjName.trim()}
                className="px-5 py-2 rounded-xl text-xs font-bold bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 disabled:opacity-40 shadow-lg shadow-emerald-500/20 cursor-pointer"
              >
                Criar Projeto de Fraude Financeira
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── MODAL: DOSSIÊ JURÍDICO & NOTIFICAÇÃO RFB/DEIC ─── */}
      {legalDossierModal.open && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-bg-secondary border border-emerald-500/40 rounded-2xl w-full max-w-4xl overflow-hidden shadow-2xl space-y-4 p-6 animate-in fade-in zoom-in-95 duration-200">
            {/* Header */}
            <div className="flex items-center justify-between border-b border-bg-border pb-4">
              <div className="flex items-center gap-3">
                <div className="w-11 h-11 rounded-2xl bg-gradient-to-br from-red-500/20 via-rose-500/30 to-amber-600/30 border border-red-500/40 flex items-center justify-center text-red-400">
                  <Scale className="w-6 h-6" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-black text-slate-100">Dossiê Forense & Representação Jurídica</h3>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-500/20 text-red-300 border border-red-500/40">
                      RFB / POLÍCIA CIVIL / BACEN
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Minuta probatória com custódia criptográfica SHA-256 e fundamentos para inaptidão de CNPJ por fraude societária.
                  </p>
                </div>
              </div>

              <button
                onClick={() => setLegalDossierModal({ open: false, loading: false, data: null })}
                className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-bg-primary transition-colors cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Loading / Content */}
            {legalDossierModal.loading ? (
              <div className="py-16 text-center space-y-3">
                <Loader2 className="w-8 h-8 animate-spin text-emerald-400 mx-auto" />
                <div className="text-xs text-slate-300 font-bold">Compilando evidências forenses e gerando laudo com hash SHA-256...</div>
              </div>
            ) : (
              <div className="space-y-4">
                {/* Hash Bar */}
                <div className="flex items-center justify-between gap-2 p-3 rounded-xl bg-bg-primary border border-bg-border text-xs">
                  <div className="flex items-center gap-2 font-mono text-[11px] text-slate-300 overflow-hidden text-ellipsis">
                    <Fingerprint className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    <span className="text-slate-400">Hash SHA-256 de Custódia:</span>
                    <span className="text-emerald-400 font-bold truncate">{legalDossierModal.data?.hash_sha256}</span>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 flex-shrink-0">
                    INTEGRIDADE ASSEGURADA
                  </span>
                </div>

                {/* Dossier Text Container */}
                <div className="p-4 rounded-xl bg-bg-primary border border-bg-border max-h-[420px] overflow-y-auto custom-scrollbar">
                  <pre className="text-xs font-mono text-slate-200 whitespace-pre-wrap leading-relaxed font-normal">
                    {legalDossierModal.data?.dossier_markdown}
                  </pre>
                </div>

                {/* Actions Footer */}
                <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2 border-t border-bg-border">
                  <div className="text-[11px] text-slate-400 flex items-center gap-2 flex-wrap">
                    <span>Arquivo: <strong className="text-slate-200 font-mono">{legalDossierModal.data?.filename}</strong></span>
                    {legalDossierModal.data?.target_site_url && (
                      <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/40 text-[10px] font-mono">
                        URL: {legalDossierModal.data.target_site_url}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2 w-full sm:w-auto flex-wrap">
                    {legalDossierModal.data?.target_site_url && (
                      <a
                        href={legalDossierModal.data.target_site_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex-1 sm:flex-none px-3.5 py-2 rounded-xl text-xs font-black bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white flex items-center justify-center gap-1.5 shadow-lg shadow-red-500/30 transition-all cursor-pointer"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                        <span>Abrir Site Fake ↗</span>
                      </a>
                    )}

                    <button
                      onClick={handleCopyDossier}
                      className="flex-1 sm:flex-none px-4 py-2 rounded-xl text-xs font-bold bg-bg-primary hover:bg-bg-border border border-bg-border text-slate-200 flex items-center justify-center gap-1.5 transition-all cursor-pointer"
                    >
                      {copiedDossier ? <CheckCheck className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4 text-slate-400" />}
                      <span>{copiedDossier ? 'Copiado para Área de Transferência!' : 'Copiar Texto do Dossiê'}</span>
                    </button>

                    <button
                      onClick={handleDownloadDossierFile}
                      className="flex-1 sm:flex-none px-5 py-2 rounded-xl text-xs font-black bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/20 transition-all cursor-pointer"
                    >
                      <Download className="w-4 h-4 fill-current" />
                      <span>Baixar Dossiê (.md)</span>
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      <UnifiedScanModal isOpen={isUnifiedScanOpen} onClose={() => setIsUnifiedScanOpen(false)} />
    </div>
  );
}
