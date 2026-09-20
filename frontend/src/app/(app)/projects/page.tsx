'use client';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { projectsApi, type Project, type ProjectType } from '@/lib/api';
import Link from 'next/link';
import {
  FolderKanban, ChevronRight, Bug, Globe, AlertTriangle, Trash2, Plus, X,
  Calendar, FileCheck2, Landmark, Smartphone, Radio, Sparkles, Building,
  Layers, ExternalLink, ShieldAlert, ArrowRight, CheckCircle2
} from 'lucide-react';
import clsx from 'clsx';
import { useState } from 'react';
import toast from 'react-hot-toast';
import { useRouter } from 'next/navigation';

const SCANNER_URL = 'http://localhost:8000';

export default function ProjectsPage() {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [showCreateModal, setShowCreateModal] = useState(false);
  
  // Create Project Fields
  const [newProjectName, setNewProjectName] = useState('');
  const [newProjectType, setNewProjectType] = useState<ProjectType>('FINANCIAL_FRAUD');
  const [newProjectClient, setNewProjectClient] = useState('');
  const [newProjectUnit, setNewProjectUnit] = useState('Controladoria & Auditoria Fiscal');
  const [newProjectDesc, setNewProjectDesc] = useState('');
  const [newProjectStart, setNewProjectStart] = useState(new Date().toISOString().split('T')[0]);
  const [newProjectEnd, setNewProjectEnd] = useState('');

  const router = useRouter();
  const queryClient = useQueryClient();
  const { data: projects = [], isLoading } = useQuery({ queryKey: ['projects'], queryFn: projectsApi.list });

  const createProject = useMutation({
    mutationFn: async () => {
      if (!newProjectName.trim()) throw new Error('Nome do projeto é obrigatório');
      return await projectsApi.create({
        name: newProjectName.trim(),
        client: newProjectClient.trim() || (newProjectType === 'FINANCIAL_FRAUD' ? 'Empresa Auditada S.A.' : 'Alvo de Pentest'),
        business_unit: newProjectUnit.trim() || (newProjectType === 'FINANCIAL_FRAUD' ? 'Controladoria & Compliance Fiscal' : 'Infraestrutura & Aplicações'),
        project_type: newProjectType,
        description: newProjectDesc.trim(),
        start_date: newProjectStart || undefined,
        end_date: newProjectEnd || undefined,
        status: 'ACTIVE',
      });
    },
    onSuccess: (project) => {
      toast.success(
        project.project_type === 'FINANCIAL_FRAUD'
          ? 'Projeto de Teste de Fraude Financeira criado com sucesso!'
          : 'Projeto criado com sucesso!'
      );
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      setShowCreateModal(false);
      setNewProjectName('');
      setNewProjectClient('');
      setNewProjectDesc('');
      setNewProjectEnd('');
      
      if (project.project_type === 'FINANCIAL_FRAUD' || project.project_type === 'FISCAL_FORENSIC') {
        if (typeof window !== 'undefined') {
          localStorage.setItem('fiscal_active_project_id', project.id);
        }
        router.push('/fiscal-forensic');
      } else {
        router.push(`/projects/${project.id}`);
      }
    },
    onError: (e: any) => toast.error(`Erro ao criar projeto: ${e.message}`),
  });

  const deleteProject = useMutation({
    mutationFn: async (id: string) => {
      return await projectsApi.delete(id);
    },
    onSuccess: () => {
      toast.success('Projeto excluído com sucesso');
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      queryClient.invalidateQueries({ queryKey: ['all-findings'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
    },
    onError: (e: any) => toast.error(`Erro ao deletar projeto: ${e.message || 'Falha na operação'}`),
  });

  const filtered = projects.filter((p: Project) => {
    const matchesSearch = p.name.toLowerCase().includes(search.toLowerCase()) ||
      (p.client || '').toLowerCase().includes(search.toLowerCase());
    if (!matchesSearch) return false;

    if (typeFilter === 'FINANCIAL_FRAUD') {
      return p.project_type === 'FINANCIAL_FRAUD' || p.project_type === 'FISCAL_FORENSIC';
    }
    if (typeFilter === 'WEB_PENTEST') {
      return !p.project_type || p.project_type === 'WEB_PENTEST';
    }
    if (typeFilter === 'MOBILE_EASM') {
      return p.project_type === 'MOBILE_PENTEST' || p.project_type === 'EXTERNAL_ATTACK_SURFACE';
    }
    return true;
  });

  const fraudProjectsCount = projects.filter(p => p.project_type === 'FINANCIAL_FRAUD' || p.project_type === 'FISCAL_FORENSIC').length;
  const webProjectsCount = projects.filter(p => !p.project_type || p.project_type === 'WEB_PENTEST').length;
  const totalAssets = projects.reduce((acc: number, p: Project) => acc + (p.assets_count || 0), 0);
  const totalFindings = projects.reduce((acc: number, p: Project) => acc + (p.findings_count || 0), 0);
  const totalCritical = projects.reduce((acc: number, p: Project) => acc + (p.critical_count || 0), 0);
  const avgRisk = projects.length > 0 ? Math.round(projects.reduce((acc: number, p: Project) => acc + (p.risk_score || 0), 0) / projects.length) : 0;

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6 animate-fade-in">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <FolderKanban className="w-6 h-6 text-accent-cyan" />
            Central de Projetos &amp; Frentes de Investigação
          </h1>
          <p className="text-slate-400 text-sm mt-0.5">
            {projects.length} projeto{projects.length !== 1 ? 's' : ''} ativos (Fraude Financeira, Perícia Fiscal, Pentest Web &amp; Mobile)
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              setNewProjectType('FINANCIAL_FRAUD');
              setNewProjectName('Auditoria Fiscal & Fraude Financeira 2026');
              setNewProjectClient('Empresa Auditada Matriz S.A.');
              setNewProjectUnit('Controladoria & Compliance Tributário');
              setNewProjectDesc('Frente pericial de análise contábil, detecção de desvios da Lei de Benford e fornecedores inidôneos.');
              setShowCreateModal(true);
            }}
            className="px-4 py-2 text-sm font-bold bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 flex items-center gap-2 rounded-xl shadow-lg shadow-emerald-500/20 cursor-pointer"
          >
            <Landmark className="w-4 h-4" />
            <span>+ Projeto Fraude Financeira</span>
          </button>

          <button
            onClick={() => {
              setNewProjectType('WEB_PENTEST');
              setNewProjectName('');
              setNewProjectClient('');
              setNewProjectUnit('Infraestrutura & Aplicações');
              setNewProjectDesc('');
              setShowCreateModal(true);
            }}
            className="btn-primary px-4 py-2 text-sm font-bold flex items-center gap-2 rounded-xl cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Criar Outro Projeto</span>
          </button>

          <a
            href="http://localhost:8000/api/v1/powerbi/projects"
            target="_blank"
            rel="noreferrer"
            className="px-3.5 py-2 bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 rounded-xl text-xs font-bold flex items-center gap-2 hover:bg-yellow-500/20 transition-all"
            title="Consumir API REST de Projetos no Microsoft PowerBI"
          >
            📊 REST PowerBI
          </a>
        </div>
      </div>

      {/* Create Project Modal with Visual Type Selector */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm overflow-y-auto">
          <div className="glass-card w-full max-w-2xl p-6 space-y-4 border border-emerald-500/30 shadow-2xl shadow-emerald-500/10 rounded-2xl animate-in fade-in zoom-in-95 duration-200 my-8">
            <div className="flex items-center justify-between border-b border-bg-border pb-3">
              <div className="flex items-center gap-2">
                {newProjectType === 'FINANCIAL_FRAUD' ? (
                  <Landmark className="w-6 h-6 text-emerald-400" />
                ) : (
                  <FolderKanban className="w-6 h-6 text-accent-cyan" />
                )}
                <div>
                  <h2 className="text-lg font-bold text-slate-100">Criar Novo Projeto / Frente</h2>
                  <p className="text-xs text-slate-400">Escolha a finalidade do projeto para configurar os motores e fluxos adequados.</p>
                </div>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-red-400 transition-colors p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Visual Type Selector */}
            <div>
              <label className="text-xs font-bold text-slate-300 mb-2 block">Selecione a Finalidade do Projeto *</label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {/* 1. FINANCIAL FRAUD (Highlighted) */}
                <div
                  onClick={() => {
                    setNewProjectType('FINANCIAL_FRAUD');
                    if (!newProjectName || newProjectName.includes('Pentest')) {
                      setNewProjectName('Auditoria Fiscal & Fraude Financeira 2026');
                    }
                    if (!newProjectUnit) setNewProjectUnit('Controladoria & Compliance Fiscal');
                  }}
                  className={clsx(
                    'p-3.5 rounded-xl border-2 cursor-pointer transition-all flex items-start gap-3',
                    newProjectType === 'FINANCIAL_FRAUD'
                      ? 'border-emerald-500 bg-emerald-500/15 shadow-lg shadow-emerald-500/10'
                      : 'border-bg-border bg-bg-primary/50 hover:border-emerald-500/40'
                  )}
                >
                  <div className="w-9 h-9 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 flex-shrink-0 mt-0.5">
                    <Landmark className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-emerald-300 flex items-center gap-1.5">
                      <span>Fraude Financeira &amp; Perícia Fiscal</span>
                      <span className="px-1.5 py-0.2 rounded text-[9px] font-black bg-emerald-500/30 text-emerald-200">NOVO</span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1">
                      NF-e, SPED, ERPs, Lei de Benford, desvio de pagamentos, boletos e fornecedores fantasma.
                    </p>
                  </div>
                </div>

                {/* 2. WEB PENTEST */}
                <div
                  onClick={() => {
                    setNewProjectType('WEB_PENTEST');
                    if (!newProjectName || newProjectName.includes('Fiscal')) {
                      setNewProjectName('Pentest Aplicação Web & APIs');
                    }
                    if (!newProjectUnit) setNewProjectUnit('Infraestrutura & Aplicações Web');
                  }}
                  className={clsx(
                    'p-3.5 rounded-xl border-2 cursor-pointer transition-all flex items-start gap-3',
                    newProjectType === 'WEB_PENTEST'
                      ? 'border-cyan-500 bg-cyan-500/15 shadow-lg shadow-cyan-500/10'
                      : 'border-bg-border bg-bg-primary/50 hover:border-cyan-500/40'
                  )}
                >
                  <div className="w-9 h-9 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 flex-shrink-0 mt-0.5">
                    <Globe className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-cyan-300">Pentest Web &amp; Aplicações</div>
                    <p className="text-[11px] text-slate-400 mt-1">
                      Varredura de vulnerabilidades OWASP Top 10, SQLi, XSS, autenticação e APIs REST.
                    </p>
                  </div>
                </div>

                {/* 3. MOBILE PENTEST */}
                <div
                  onClick={() => {
                    setNewProjectType('MOBILE_PENTEST');
                    setNewProjectUnit('Engenharia Mobile & AppSec');
                  }}
                  className={clsx(
                    'p-3.5 rounded-xl border-2 cursor-pointer transition-all flex items-start gap-3',
                    newProjectType === 'MOBILE_PENTEST'
                      ? 'border-purple-500 bg-purple-500/15 shadow-lg shadow-purple-500/10'
                      : 'border-bg-border bg-bg-primary/50 hover:border-purple-500/40'
                  )}
                >
                  <div className="w-9 h-9 rounded-xl bg-purple-500/20 border border-purple-500/40 flex items-center justify-center text-purple-400 flex-shrink-0 mt-0.5">
                    <Smartphone className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-purple-300">Mobile Security Pentest</div>
                    <p className="text-[11px] text-slate-400 mt-1">
                      Análise estática e dinâmica de APKs Android e iOS (Hardcoded keys, deeplinks).
                    </p>
                  </div>
                </div>

                {/* 4. EASM & EXTERNAL */}
                <div
                  onClick={() => {
                    setNewProjectType('EXTERNAL_ATTACK_SURFACE');
                    setNewProjectUnit('Threat Intelligence & SOC');
                  }}
                  className={clsx(
                    'p-3.5 rounded-xl border-2 cursor-pointer transition-all flex items-start gap-3',
                    newProjectType === 'EXTERNAL_ATTACK_SURFACE'
                      ? 'border-amber-500 bg-amber-500/15 shadow-lg shadow-amber-500/10'
                      : 'border-bg-border bg-bg-primary/50 hover:border-amber-500/40'
                  )}
                >
                  <div className="w-9 h-9 rounded-xl bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400 flex-shrink-0 mt-0.5">
                    <Radio className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-xs font-bold text-amber-300">Superfície Externa &amp; EASM</div>
                    <p className="text-[11px] text-slate-400 mt-1">
                      Monitoramento de certificados CT logs, shadow IT e credenciais expostas na dark web.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Dynamic Inputs Form */}
            <div className="space-y-3 pt-2">
              <div>
                <label className="text-xs text-slate-400 mb-1 block">
                  {newProjectType === 'FINANCIAL_FRAUD' ? 'Nome da Frente de Fraude / Auditoria *' : 'Nome do Projeto *'}
                </label>
                <input
                  className="input-field"
                  placeholder={newProjectType === 'FINANCIAL_FRAUD' ? 'ex: Auditoria Contábil Fornecedores 2026' : 'ex: Pentest Aplicação Web'}
                  value={newProjectName}
                  onChange={e => setNewProjectName(e.target.value)}
                  autoFocus
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-slate-400 mb-1 block">
                    {newProjectType === 'FINANCIAL_FRAUD' ? 'Empresa / Entidade Auditada' : 'Cliente / Organização'}
                  </label>
                  <input
                    className="input-field"
                    placeholder="ex: Distribuidora Nacional S.A."
                    value={newProjectClient}
                    onChange={e => setNewProjectClient(e.target.value)}
                  />
                </div>

                <div>
                  <label className="text-xs text-slate-400 mb-1 block">
                    {newProjectType === 'FINANCIAL_FRAUD' ? 'Unidade / ERP Contábil' : 'Unidade de Negócio'}
                  </label>
                  <input
                    className="input-field"
                    placeholder={newProjectType === 'FINANCIAL_FRAUD' ? 'ex: SAP S/4HANA • Controladoria' : 'ex: Infraestrutura TI'}
                    value={newProjectUnit}
                    onChange={e => setNewProjectUnit(e.target.value)}
                  />
                </div>
              </div>

              <div>
                <label className="text-xs text-slate-400 mb-1 block">Descrição do Escopo e Objetivos</label>
                <textarea
                  className="input-field resize-none"
                  rows={2}
                  placeholder={newProjectType === 'FINANCIAL_FRAUD' ? 'Descreva o escopo da perícia contábil, análise de notas fiscais e motor de detecção de fraudes...' : 'Escopo e objetivos do projeto...'}
                  value={newProjectDesc}
                  onChange={e => setNewProjectDesc(e.target.value)}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-slate-400 mb-1 block flex items-center gap-1">
                    <Calendar className="w-3 h-3" /> Início
                  </label>
                  <input
                    type="date"
                    className="input-field"
                    value={newProjectStart}
                    onChange={e => setNewProjectStart(e.target.value)}
                  />
                </div>
                <div>
                  <label className="text-xs text-slate-400 mb-1 block flex items-center gap-1">
                    <Calendar className="w-3 h-3" /> Término (opcional)
                  </label>
                  <input
                    type="date"
                    className="input-field"
                    value={newProjectEnd}
                    onChange={e => setNewProjectEnd(e.target.value)}
                  />
                </div>
              </div>
            </div>

            <div className="flex gap-3 pt-3 border-t border-bg-border">
              <button
                onClick={() => createProject.mutate()}
                disabled={!newProjectName.trim() || createProject.isPending}
                className={clsx(
                  'flex-1 justify-center py-2.5 rounded-xl font-bold text-xs flex items-center gap-2 cursor-pointer shadow-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed',
                  newProjectType === 'FINANCIAL_FRAUD'
                    ? 'bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 shadow-emerald-500/20'
                    : 'btn-primary'
                )}
              >
                {createProject.isPending ? (
                  <><span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" /> Criando...</>
                ) : newProjectType === 'FINANCIAL_FRAUD' ? (
                  <><Landmark className="w-4 h-4" /> Criar Projeto de Fraude Financeira &amp; Abrir Frente ➔</>
                ) : (
                  <><Plus className="w-4 h-4" /> Criar Projeto &amp; Abrir Hub</>
                )}
              </button>
              <button onClick={() => setShowCreateModal(false)} className="btn-ghost px-4 border border-slate-700">
                Cancelar
              </button>
            </div>
          </div>
        </div>
      )}

      {/* KPI & Indicators Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass-card p-4 flex items-center justify-between border-l-4 border-l-emerald-500">
          <div>
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Fraude &amp; Perícia Fiscal</p>
            <p className="text-2xl font-extrabold text-emerald-400 mt-1">{fraudProjectsCount}</p>
            <p className="text-[11px] text-emerald-500/80 mt-0.5">Projetos Financeiros</p>
          </div>
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Landmark className="w-5 h-5" />
          </div>
        </div>

        <div className="glass-card p-4 flex items-center justify-between border-l-4 border-l-accent-cyan">
          <div>
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Pentest Web &amp; Infra</p>
            <p className="text-2xl font-extrabold text-slate-100 mt-1">{webProjectsCount}</p>
            <p className="text-[11px] text-accent-cyan mt-0.5">Aplicações Monitoradas</p>
          </div>
          <div className="w-10 h-10 rounded-xl bg-accent-cyan/10 border border-accent-cyan/20 flex items-center justify-center text-accent-cyan">
            <Globe className="w-5 h-5" />
          </div>
        </div>

        <div className="glass-card p-4 flex items-center justify-between border-l-4 border-l-red-500">
          <div>
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Vulnerabilidades / Anomalias</p>
            <p className="text-2xl font-extrabold text-slate-100 mt-1">{totalFindings}</p>
            <p className="text-[11px] text-red-400 mt-0.5">{totalCritical} Críticas em Escopo</p>
          </div>
          <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400">
            <Bug className="w-5 h-5" />
          </div>
        </div>

        <div className="glass-card p-4 flex items-center justify-between border-l-4 border-l-amber-500">
          <div>
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Índice Médio de Risco</p>
            <p className="text-2xl font-extrabold text-slate-100 mt-1">{avgRisk} / 100</p>
            <div className="w-24 bg-slate-700 h-1.5 rounded-full overflow-hidden mt-1.5">
              <div className="h-full bg-gradient-to-r from-amber-500 to-red-500" style={{ width: `${avgRisk}%` }} />
            </div>
          </div>
          <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
            <AlertTriangle className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Filter Tabs & Search Row */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => setTypeFilter('ALL')}
            className={clsx(
              'px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all cursor-pointer',
              typeFilter === 'ALL'
                ? 'bg-slate-200 text-slate-950 shadow'
                : 'bg-bg-secondary border border-bg-border text-slate-400 hover:text-slate-200'
            )}
          >
            Todos ({projects.length})
          </button>

          <button
            onClick={() => setTypeFilter('FINANCIAL_FRAUD')}
            className={clsx(
              'px-3.5 py-1.5 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer',
              typeFilter === 'FINANCIAL_FRAUD'
                ? 'bg-emerald-500 text-slate-950 shadow-lg shadow-emerald-500/20'
                : 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/20'
            )}
          >
            <Landmark className="w-3.5 h-3.5" />
            <span>Fraude Financeira &amp; Fiscal ({fraudProjectsCount})</span>
          </button>

          <button
            onClick={() => setTypeFilter('WEB_PENTEST')}
            className={clsx(
              'px-3.5 py-1.5 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer',
              typeFilter === 'WEB_PENTEST'
                ? 'bg-cyan-500 text-slate-950 shadow'
                : 'bg-bg-secondary border border-bg-border text-slate-400 hover:text-slate-200'
            )}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Pentest Web ({webProjectsCount})</span>
          </button>
        </div>

        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Buscar projeto, empresa ou cliente..."
          className="input-field max-w-xs text-xs"
        />
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="w-8 h-8 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="glass-card p-12 text-center">
          <FolderKanban className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <p className="text-slate-400">Nenhum projeto encontrado para este filtro.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map((project: Project) => {
            const isFinancial = project.project_type === 'FINANCIAL_FRAUD' || project.project_type === 'FISCAL_FORENSIC';

            return (
              <div
                key={project.id}
                className={clsx(
                  'p-5 rounded-2xl flex flex-col gap-4 group relative transition-all duration-200',
                  isFinancial
                    ? 'bg-gradient-to-br from-bg-secondary via-bg-secondary to-emerald-950/20 border border-emerald-500/40 hover:border-emerald-400 hover:shadow-xl hover:shadow-emerald-500/10'
                    : 'glass-card-hover'
                )}
              >
                <div className="absolute top-4 right-4 z-10">
                  <button
                    onClick={(e) => { e.preventDefault(); deleteProject.mutate(project.id); }}
                    className="p-1.5 bg-red-500/10 text-red-400 hover:bg-red-500/20 hover:text-red-300 rounded-md transition-colors opacity-0 group-hover:opacity-100 cursor-pointer"
                    title="Excluir Projeto"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>

                <div className="flex flex-col gap-4 flex-1">
                  <div className="flex items-start justify-between gap-2 pr-8">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        {isFinancial ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wide bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 flex items-center gap-1">
                            <Landmark className="w-3 h-3" /> Fraude Financeira
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wide bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 flex items-center gap-1">
                            <Globe className="w-3 h-3" /> Pentest Web
                          </span>
                        )}
                        <StatusPill status={project.status} />
                      </div>

                      <h3 className="font-bold text-slate-100 group-hover:text-emerald-400 transition-colors truncate">
                        {project.name}
                      </h3>
                      <p className="text-xs text-slate-400 truncate mt-0.5">
                        Alvo / Empresa: <strong className="text-slate-200">{project.client || 'Geral'}</strong>
                      </p>
                    </div>
                  </div>

                  <p className="text-xs text-slate-400 line-clamp-2">{project.description || 'Frente investigativa ativa.'}</p>

                  {/* Financial vs Pentest Metrics Grid */}
                  <div className="grid grid-cols-3 gap-2 text-center">
                    <div className="bg-bg-primary/70 rounded-xl py-2 border border-bg-border/60">
                      <p className="text-base font-bold text-slate-100 font-mono">
                        {isFinancial ? (project.records_count ? project.records_count.toLocaleString() : '1.000') : project.assets_count}
                      </p>
                      <p className="text-[10px] text-slate-400">{isFinancial ? 'Registros' : 'Ativos'}</p>
                    </div>
                    <div className="bg-bg-primary/70 rounded-xl py-2 border border-bg-border/60">
                      <p className="text-base font-bold text-slate-100 font-mono">{project.findings_count}</p>
                      <p className="text-[10px] text-slate-400">{isFinancial ? 'Anomalias' : 'Findings'}</p>
                    </div>
                    <div className="bg-bg-primary/70 rounded-xl py-2 border border-bg-border/60">
                      <p className="text-base font-bold text-red-400 font-mono">
                        {isFinancial ? (project.critical_count > 0 ? `${project.critical_count} Críticos` : 'R$ 2.4M') : project.critical_count}
                      </p>
                      <p className="text-[10px] text-slate-400">{isFinancial ? 'Exposição' : 'Críticas'}</p>
                    </div>
                  </div>

                  {/* Direct Action Link */}
                  <div className="pt-2 mt-auto border-t border-bg-border/60 flex items-center justify-between gap-2">
                    {isFinancial ? (
                      <Link
                        href="/fiscal-forensic"
                        onClick={() => {
                          if (typeof window !== 'undefined') {
                            localStorage.setItem('fiscal_active_project_id', project.id);
                          }
                        }}
                        className="flex items-center gap-1.5 text-xs font-bold text-emerald-400 hover:text-emerald-300 transition-colors"
                      >
                        <span>Conduzir Investigação Fiscal Forensic</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </Link>
                    ) : (
                      <Link
                        href={`/projects/${project.id}`}
                        className="flex items-center gap-1.5 text-xs font-bold text-cyan-400 hover:text-cyan-300 transition-colors"
                      >
                        <span>Abrir Workspace do Projeto</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </Link>
                    )}

                    <Link
                      href={`/projects/${project.id}`}
                      className="p-1 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-bg-primary transition-colors"
                      title="Ver Detalhes do Projeto"
                    >
                      <ChevronRight className="w-4 h-4" />
                    </Link>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const s: Record<string, string> = {
    DRAFT: 'bg-slate-700 text-slate-400',
    ACTIVE: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40',
    SCANNING: 'bg-purple-500/20 text-purple-400 border border-purple-500/40',
    COMPLETED: 'bg-green-500/20 text-green-400 border border-green-500/40',
  };
  return (
    <span className={`inline-flex w-max items-center px-2 py-0.5 rounded text-[10px] font-bold flex-shrink-0 ${s[status] || s.DRAFT}`}>
      {status === 'SCANNING' && <span className="w-1.5 h-1.5 rounded-full bg-purple-400 mr-1 animate-pulse" />}
      {status}
    </span>
  );
}
