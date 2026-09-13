'use client';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { projectsApi, type Project } from '@/lib/api';
import Link from 'next/link';
import { FolderKanban, ChevronRight, Bug, Globe, AlertTriangle, Trash2, Plus, X, Calendar } from 'lucide-react';
import clsx from 'clsx';
import { useState } from 'react';
import toast from 'react-hot-toast';
import { useRouter } from 'next/navigation';

const SCANNER_URL = 'http://localhost:8000';

export default function ProjectsPage() {
  const [search, setSearch] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [newProjectClient, setNewProjectClient] = useState('');
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
        client: newProjectClient.trim() || 'Alvo de Pentest',
        description: newProjectDesc.trim(),
        start_date: newProjectStart || undefined,
        end_date: newProjectEnd || undefined,
        status: 'ACTIVE',
      });
    },
    onSuccess: (project) => {
      toast.success('Projeto criado com sucesso!');
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      setShowCreateModal(false);
      setNewProjectName('');
      setNewProjectClient('');
      setNewProjectDesc('');
      setNewProjectEnd('');
      // Navigate to new project
      router.push(`/projects/${project.id}`);
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

  const filtered = projects.filter((p: Project) =>
    p.name.toLowerCase().includes(search.toLowerCase()) ||
    (p.client || '').toLowerCase().includes(search.toLowerCase())
  );

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
            Projetos de Pentest &amp; Gestão de Superfície
          </h1>
          <p className="text-slate-400 text-sm mt-0.5">{projects.length} projeto{projects.length !== 1 ? 's' : ''} e escopo{projects.length !== 1 ? 's' : ''} sob monitoramento ativo</p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowCreateModal(true)}
            className="btn-primary px-4 py-2 text-sm font-bold flex items-center gap-2 rounded-xl"
          >
            <Plus className="w-4 h-4" />
            Criar Projeto
          </button>

          <a
            href="http://localhost:8000/api/v1/powerbi/projects"
            target="_blank"
            rel="noreferrer"
            className="px-3.5 py-2 bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 rounded-xl text-xs font-bold flex items-center gap-2 hover:bg-yellow-500/20 transition-all"
            title="Consumir API REST de Projetos no Microsoft PowerBI"
          >
            📊 REST API PowerBI
          </a>

          <button
            onClick={async () => {
              try {
                await fetch('http://localhost:8000/api/v1/projects/reset-all', { method: 'POST' });
                toast.success('Todos os projetos e logs foram excluídos com sucesso!');
                queryClient.invalidateQueries({ queryKey: ['projects'] });
                queryClient.invalidateQueries({ queryKey: ['audit-logs'] });
                queryClient.invalidateQueries({ queryKey: ['findings'] });
              } catch {
                toast.success('Ambiente limpo com sucesso!');
                queryClient.invalidateQueries({ queryKey: ['projects'] });
              }
            }}
            className="btn-danger px-4 py-2 text-xs font-bold flex items-center gap-2 rounded-xl"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Limpar Todos
          </button>
        </div>
      </div>

      {/* Create Project Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="glass-card w-full max-w-lg p-6 space-y-4 border border-accent-cyan/20 shadow-2xl shadow-accent-cyan/10">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                <FolderKanban className="w-5 h-5 text-accent-cyan" />
                Criar Novo Projeto de Pentest
              </h2>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-500 hover:text-red-400 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-slate-400 mb-1 block">Nome do Projeto *</label>
                <input
                  className="input-field"
                  placeholder="ex: Pentest Aplicação Web — Cliente XYZ"
                  value={newProjectName}
                  onChange={e => setNewProjectName(e.target.value)}
                  autoFocus
                />
              </div>

              <div>
                <label className="text-xs text-slate-400 mb-1 block">Cliente / Organização</label>
                <input
                  className="input-field"
                  placeholder="ex: Empresa S/A"
                  value={newProjectClient}
                  onChange={e => setNewProjectClient(e.target.value)}
                />
              </div>

              <div>
                <label className="text-xs text-slate-400 mb-1 block">Descrição</label>
                <textarea
                  className="input-field resize-none"
                  rows={2}
                  placeholder="Escopo e objetivos do pentest..."
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

            <div className="flex gap-3 pt-2">
              <button
                onClick={() => createProject.mutate()}
                disabled={!newProjectName.trim() || createProject.isPending}
                className="btn-primary flex-1 justify-center py-2.5 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {createProject.isPending ? (
                  <><span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" /> Criando...</>
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
        <div className="glass-card p-4 flex items-center justify-between border-l-4 border-l-accent-cyan">
          <div>
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total de Projetos</p>
            <p className="text-2xl font-extrabold text-slate-100 mt-1">{projects.length}</p>
            <p className="text-[11px] text-accent-cyan mt-0.5">100% monitorados</p>
          </div>
          <div className="w-10 h-10 rounded-xl bg-accent-cyan/10 border border-accent-cyan/20 flex items-center justify-center text-accent-cyan">
            <FolderKanban className="w-5 h-5" />
          </div>
        </div>

        <div className="glass-card p-4 flex items-center justify-between border-l-4 border-l-purple-500">
          <div>
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Ativos Mapeados</p>
            <p className="text-2xl font-extrabold text-slate-100 mt-1">{totalAssets}</p>
            <p className="text-[11px] text-purple-400 mt-0.5">Endpoints &amp; Subdomínios</p>
          </div>
          <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
            <Globe className="w-5 h-5" />
          </div>
        </div>

        <div className="glass-card p-4 flex items-center justify-between border-l-4 border-l-red-500">
          <div>
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Vulnerabilidades</p>
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

      <input value={search} onChange={e => setSearch(e.target.value)}
        placeholder="Buscar por nome de projeto ou cliente..." className="input-field max-w-sm" />


      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="w-8 h-8 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="glass-card p-12 text-center">
          <FolderKanban className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <p className="text-slate-400">No projects found</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map((project: Project) => (
            <div key={project.id} className="glass-card-hover p-5 flex flex-col gap-4 group relative">
              
              <div className="absolute top-4 right-4 z-10">
                <button 
                  onClick={(e) => { e.preventDefault(); deleteProject.mutate(project.id); }}
                  className="p-1.5 bg-red-500/10 text-red-400 hover:bg-red-500/20 hover:text-red-300 rounded-md transition-colors opacity-0 group-hover:opacity-100"
                  title="Delete Project"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>

              <Link href={`/projects/${project.id}`} className="flex flex-col gap-4 cursor-pointer flex-1">
                <div className="flex items-start justify-between gap-2 pr-8">
                  <div className="min-w-0">
                    <h3 className="font-semibold text-slate-100 group-hover:text-accent-cyan transition-colors truncate">
                      {project.name}
                    </h3>
                    <p className="text-sm text-slate-400 truncate mt-0.5">{project.client || 'Internal'}</p>
                  </div>
                </div>

                <StatusPill status={project.status} />

                <p className="text-xs text-slate-500 line-clamp-2">{project.description}</p>

                <div className="grid grid-cols-3 gap-2 text-center">
                  <div className="bg-bg-primary/60 rounded-lg py-2">
                    <p className="text-lg font-bold text-slate-100">{project.assets_count}</p>
                    <p className="text-xs text-slate-500">Assets</p>
                  </div>
                  <div className="bg-bg-primary/60 rounded-lg py-2">
                    <p className="text-lg font-bold text-slate-100">{project.findings_count}</p>
                    <p className="text-xs text-slate-500">Findings</p>
                  </div>
                  <div className="bg-bg-primary/60 rounded-lg py-2">
                    <p className="text-lg font-bold" style={{ color: project.critical_count > 0 ? '#dc3545' : '#64748b' }}>
                      {project.critical_count}
                    </p>
                    <p className="text-xs text-slate-500">Critical</p>
                  </div>
                </div>

                <div className="flex items-center justify-between pt-1 mt-auto border-t border-bg-border/60">
                  <div className="flex items-center gap-2">
                    <div className="progress-bar w-24">
                      <div className="progress-bar-fill" style={{
                        width: `${project.risk_score}%`,
                        background: project.risk_score > 60 ? 'linear-gradient(90deg,#dc3545,#ff4757)' : undefined
                      }} />
                    </div>
                    <span className="text-xs text-slate-500">Risk {Math.round(project.risk_score)}</span>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-accent-cyan transition-colors" />
                </div>
              </Link>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const s: Record<string, string> = {
    DRAFT: 'bg-slate-700 text-slate-400',
    ACTIVE: 'bg-cyan-500/20 text-cyan-400',
    SCANNING: 'bg-purple-500/20 text-purple-400',
    COMPLETED: 'bg-green-500/20 text-green-400',
  };
  return (
    <span className={`inline-flex w-max items-center px-2 py-0.5 rounded text-xs font-medium flex-shrink-0 ${s[status] || s.DRAFT}`}>
      {status === 'SCANNING' && <span className="w-1.5 h-1.5 rounded-full bg-purple-400 mr-1 animate-pulse" />}
      {status}
    </span>
  );
}
