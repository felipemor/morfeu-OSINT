'use client';
import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import {
  FileText, Download, Shield, AlertTriangle, CheckCircle2,
  Clock, HardDrive, RefreshCw, Eye, Sparkles, Layers,
  ExternalLink, BarChart3, Lock, ShieldCheck, ArrowUpRight,
  Trash2, Landmark, BookOpen
} from 'lucide-react';
import clsx from 'clsx';

const SCANNER_URL = 'http://localhost:8000';

interface ReportFile {
  filename: string;
  size_kb: number;
  created_at: string;
  download_url: string;
}

interface Finding {
  id: string;
  title: string;
  severity: string;
  cvss_score: number;
  owasp_category?: string;
  cwe_id?: string;
  affected_url?: string;
  status?: string;
}

export default function ReportsPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'reports' | 'executive' | 'bacen'>('reports');
  const [isGenerating, setIsGenerating] = useState(false);

  const INITIAL_REPORTS: ReportFile[] = [
    {
      filename: 'relatorio_consolidado_pentest_bacen4893.json',
      size_kb: 48.5,
      created_at: 'Hoje às 19:45',
      download_url: '/data/relatorio_consolidado_pentest_bacen4893.json',
    },
    {
      filename: 'audit_pack_bacen_cmn4893_sha256.json',
      size_kb: 32.1,
      created_at: 'Hoje às 18:20',
      download_url: '/data/audit_pack_bacen_cmn4893_sha256.json',
    },
    {
      filename: 'laudo_mobile_pentest_masvs_v2.json',
      size_kb: 64.0,
      created_at: 'Hoje às 17:10',
      download_url: '/data/laudo_mobile_pentest_masvs_v2.json',
    }
  ];

  // Fetch reports list from backend or local registry
  const { data: reports = INITIAL_REPORTS, isLoading: loadingReports, refetch: refetchReports } = useQuery<ReportFile[]>({
    queryKey: ['reports-list'],
    queryFn: async () => {
      try {
        const res = await fetch(`${SCANNER_URL}/reports/all`);
        if (res.ok) return await res.json();
      } catch (e) {}

      if (typeof window !== 'undefined') {
        const stored = localStorage.getItem('generated_reports_registry');
        if (stored) {
          try {
            return JSON.parse(stored);
          } catch (e) {}
        }
      }
      return INITIAL_REPORTS;
    },
  });

  // Fetch findings for metrics
  const { data: findings = [] } = useQuery<Finding[]>({
    queryKey: ['findings-data'],
    queryFn: async () => {
      const res = await fetch('/data/findings.json');
      if (!res.ok) return [];
      return res.json();
    },
  });

  // Generate Consolidated PDF Mutation (Bacen / Enterprise Standard)
  const generateMasterReport = useMutation({
    mutationFn: async () => {
      setIsGenerating(true);
      try {
        const res = await fetch(`${SCANNER_URL}/reports/consolidated`, { method: 'POST' });
        if (res.ok) {
          const data = await res.json();
          return data;
        }
      } catch (e) {}

      // Autonomous Client-side Vector PDF Generation
      const { generateUnifiedMasterPdfBlob } = await import('@/lib/pdf-lib-unified-master');
      const pdfBytes = await generateUnifiedMasterPdfBlob({
        targetUrl: 'Infraestrutura Corporativa & Aplicações Críticas (SFSSA Platform)',
        perspective: 'BOTH',
        findings,
      });

      const filename = `laudo_consolidado_pentest_bacen4893_${new Date().toISOString().slice(0, 10)}_${Date.now().toString().slice(-4)}.pdf`;
      const blob = new Blob([pdfBytes as any], { type: 'application/pdf' });
      const downloadUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();

      // Save to local registry
      const newEntry: ReportFile = {
        filename,
        size_kb: Math.round(pdfBytes.length / 1024 * 10) / 10,
        created_at: new Date().toLocaleTimeString('pt-BR'),
        download_url: downloadUrl,
      };
      if (typeof window !== 'undefined') {
        const existing = JSON.parse(localStorage.getItem('generated_reports_registry') || '[]');
        localStorage.setItem('generated_reports_registry', JSON.stringify([newEntry, ...existing]));
      }

      return { filename, status: 'GENERATED' };
    },
    onSuccess: (data) => {
      toast.success('Laudo Técnico-Executivo em PDF (.PDF) gerado e baixado com sucesso!');
      refetchReports();
    },
    onError: (err: any) => {
      toast.error(`Falha: ${err.message || 'Erro ao processar relatório'}`);
    },
    onSettled: () => {
      setIsGenerating(false);
    },
  });

  // Delete Single Report File
  const deleteReport = useMutation({
    mutationFn: async (filename: string) => {
      try {
        const res = await fetch(`${SCANNER_URL}/reports/${encodeURIComponent(filename)}`, { method: 'DELETE' });
        if (res.ok) return await res.json();
      } catch (e) {}

      if (typeof window !== 'undefined') {
        const existing: ReportFile[] = JSON.parse(localStorage.getItem('generated_reports_registry') || '[]');
        const updated = existing.filter(r => r.filename !== filename);
        localStorage.setItem('generated_reports_registry', JSON.stringify(updated));
      }
      return { status: 'deleted' };
    },
    onSuccess: () => {
      toast.success('Arquivo de relatório excluído.');
      refetchReports();
    },
    onError: (e: any) => toast.error(e.message),
  });

  const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = findings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="badge-cyan text-xs font-semibold px-2 py-0.5 rounded uppercase tracking-wider flex items-center gap-1">
              <Landmark className="w-3 h-3" />
              Padrão Regulatório Bacen (CMN 4.893 / BCB 85) &amp; NIST SP 800-115
            </span>
            <span className="text-xs text-slate-400">• Laudo de Auditoria Regulatória</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <FileText className="w-6 h-6 text-accent-cyan" />
            Central de Relatórios &amp; Auditoria Bacen
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Relatórios executivos e técnicos com análise de falhas, impactos no negócio/regulatório, causa raiz, solução técnica e SLAs Bacen.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <a
            href="http://localhost:8000/api/v1/powerbi/overview"
            target="_blank"
            rel="noreferrer"
            className="px-3 py-2 bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 rounded-xl text-xs font-bold flex items-center gap-1.5 hover:bg-yellow-500/20 transition-all"
            title="Consumir APIs REST para PowerBI"
          >
            📊 REST APIs PowerBI
          </a>

          <button
            onClick={() => refetchReports()}
            className="btn-ghost flex items-center gap-2 text-xs"
            title="Atualizar lista"
          >
            <RefreshCw className="w-4 h-4 text-slate-400" />
            Atualizar
          </button>

          <button
            onClick={() => generateMasterReport.mutate()}
            disabled={isGenerating}
            className="btn-primary flex items-center gap-2 text-sm px-4 py-2.5 shadow-lg shadow-accent-cyan/20"
          >
            {isGenerating ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Compilando Laudo Bacen...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4 text-slate-900" />
                <span className="font-bold">Gerar Relatório Bacen (.PDF)</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="stat-card">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-slate-400">Relatórios no Servidor</p>
            <FileText className="w-4 h-4 text-accent-cyan" />
          </div>
          <p className="text-2xl font-bold text-slate-100 mt-2">{reports.length}</p>
          <p className="text-xs text-slate-500 mt-1">Laudos em PDF disponíveis</p>
        </div>

        <div className="stat-card">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-slate-400">SLA Bacen Crítico (&lt; 48h)</p>
            <AlertTriangle className="w-4 h-4 text-accent-red" />
          </div>
          <p className="text-2xl font-bold text-accent-red mt-2">{criticalCount}</p>
          <p className="text-xs text-slate-500 mt-1">Apontamentos com correção imediata</p>
        </div>

        <div className="stat-card">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-slate-400">SLA Bacen Alto (&lt; 7 dias)</p>
            <Shield className="w-4 h-4 text-accent-orange" />
          </div>
          <p className="text-2xl font-bold text-accent-orange mt-2">{highCount}</p>
          <p className="text-xs text-slate-500 mt-1">Plano de resposta prioritário</p>
        </div>

        <div className="stat-card">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-slate-400">Enquadramento Regulatório</p>
            <Landmark className="w-4 h-4 text-accent-green" />
          </div>
          <p className="text-2xl font-bold text-accent-green mt-2">CMN 4.893</p>
          <p className="text-xs text-slate-500 mt-1">Artigos 2º, 10, 11 e 12</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-bg-border gap-2">
        <button
          onClick={() => setActiveTab('reports')}
          className={clsx(
            'px-4 py-2.5 text-sm font-semibold flex items-center gap-2 border-b-2 transition-all',
            activeTab === 'reports'
              ? 'border-accent-cyan text-accent-cyan bg-accent-cyan/5'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          <FileText className="w-4 h-4" />
          Laudos em PDF ({reports.length})
        </button>

        <button
          onClick={() => setActiveTab('executive')}
          className={clsx(
            'px-4 py-2.5 text-sm font-semibold flex items-center gap-2 border-b-2 transition-all',
            activeTab === 'executive'
              ? 'border-accent-cyan text-accent-cyan bg-accent-cyan/5'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          <BarChart3 className="w-4 h-4" />
          Sumário Executivo de Governança
        </button>

        <button
          onClick={() => setActiveTab('bacen')}
          className={clsx(
            'px-4 py-2.5 text-sm font-semibold flex items-center gap-2 border-b-2 transition-all',
            activeTab === 'bacen'
              ? 'border-accent-cyan text-accent-cyan bg-accent-cyan/5'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          <Landmark className="w-4 h-4" />
          Conformidade Bacen &amp; LGPD
        </button>
      </div>

      {/* TAB 1: REPORTS LIST */}
      {activeTab === 'reports' && (
        <div className="card overflow-hidden">
          <div className="p-4 border-b border-bg-border flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <HardDrive className="w-4 h-4 text-accent-cyan" />
              Relatórios de Pentest Gerados no Servidor
            </h2>
            <span className="text-xs text-slate-500">Prontos para download ou apresentação a auditores</span>
          </div>

          {loadingReports ? (
            <div className="p-12 text-center text-slate-500 text-sm">
              <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-accent-cyan" />
              Carregando relatórios disponíveis...
            </div>
          ) : reports.length === 0 ? (
            <div className="p-12 text-center">
              <FileText className="w-12 h-12 text-slate-600 mx-auto mb-3" />
              <p className="text-base font-semibold text-slate-300">Nenhum relatório PDF gerado ainda</p>
              <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
                Clique no botão &quot;Gerar Relatório Bacen (.PDF)&quot; acima ou execute um pentest na aba Scanner.
              </p>
              <button
                onClick={() => generateMasterReport.mutate()}
                className="btn-primary text-xs mt-4"
              >
                Gerar Primeiro Laudo Bacen
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="table">
                <thead>
                  <tr>
                    <th>Nome do Arquivo</th>
                    <th>Tamanho</th>
                    <th>Data de Emissão</th>
                    <th>Classificação</th>
                    <th className="text-right">Ações</th>
                  </tr>
                </thead>
                <tbody>
                  {reports.map((rep) => (
                    <tr key={rep.filename} className="hover:bg-bg-tertiary/40 transition-colors">
                      <td className="font-mono text-xs text-accent-cyan flex items-center gap-2 py-3">
                        <FileText className="w-4 h-4 text-slate-400 flex-shrink-0" />
                        <span className="truncate max-w-md">{rep.filename}</span>
                      </td>
                      <td className="text-xs text-slate-300">{rep.size_kb} KB</td>
                      <td className="text-xs text-slate-400">
                        {new Date(rep.created_at).toLocaleString('pt-BR')}
                      </td>
                      <td>
                        <span className="badge-red text-[10px] px-2 py-0.5 rounded font-bold">
                          ESTRITAMENTE CONFIDENCIAL
                        </span>
                      </td>
                      <td className="text-right flex items-center justify-end gap-2 py-3">
                        <a
                          href={`${SCANNER_URL}${rep.download_url}`}
                          target="_blank"
                          rel="noreferrer"
                          className="btn-ghost text-xs inline-flex items-center gap-1.5 px-3 py-1.5 bg-accent-cyan/10 hover:bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/30 rounded font-semibold"
                        >
                          <Download className="w-3.5 h-3.5" />
                          Baixar PDF
                        </a>
                        <button
                          onClick={() => deleteReport.mutate(rep.filename)}
                          disabled={deleteReport.isPending}
                          className="p-1.5 rounded hover:bg-red-500/20 text-slate-500 hover:text-red-400 transition-colors"
                          title="Excluir arquivo de relatório"
                        >
                          <Trash2 className="w-4 h-4" />
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

      {/* TAB 2: EXECUTIVE SUMMARY */}
      {activeTab === 'executive' && (
        <div className="space-y-6">
          <div className="card p-5 space-y-4">
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Shield className="w-5 h-5 text-accent-cyan" />
              Sumário Executivo de Postura de Risco Cibernético &amp; Governança
            </h2>
            <p className="text-xs text-slate-300 leading-relaxed">
              Avaliação de segurança cibernética ofensiva executada sob a ótica dos princípios de confidencialidade,
              integridade e disponibilidade (CID), contemplando modelagem de ameaças e requisitos do Bacen.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              <div className="p-4 rounded-lg bg-bg-tertiary border border-accent-red/30">
                <p className="text-xs font-bold text-accent-red flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4" />
                  Falhas Críticas &amp; SLA Bacen
                </p>
                <p className="text-xs text-slate-300 mt-1">
                  Injeções de banco de dados e quebra de assinatura JWT. <b>SLA Regulatório: 24h a 48h</b>.
                </p>
              </div>

              <div className="p-4 rounded-lg bg-bg-tertiary border border-accent-orange/30">
                <p className="text-xs font-bold text-accent-orange flex items-center gap-1.5">
                  <Shield className="w-4 h-4" />
                  Quebra de Controle de Acesso
                </p>
                <p className="text-xs text-slate-300 mt-1">
                  IDOR em consultas transacionais e CORS com reflexão arbitrária. <b>SLA: até 7 dias</b>.
                </p>
              </div>

              <div className="p-4 rounded-lg bg-bg-tertiary border border-accent-cyan/30">
                <p className="text-xs font-bold text-accent-cyan flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4" />
                  Proteção Perimétrica &amp; WAF
                </p>
                <p className="text-xs text-slate-300 mt-1">
                  Ativação de regras OWASP Core Rule Set no WAF e cabeçalhos defensivos (CSP, HSTS).
                </p>
              </div>
            </div>
          </div>

          {/* Remediation Timeline with Bacen SLAs */}
          <div className="card p-5 space-y-4">
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Clock className="w-5 h-5 text-accent-cyan" />
              SLAs e Cronograma de Remediação Bacen (Art. 12 da Res. CMN 4.893)
            </h2>

            <div className="space-y-3">
              <div className="p-4 rounded-lg bg-bg-secondary border-l-4 border-accent-red border border-bg-border">
                <div className="flex items-center justify-between mb-1">
                  <p className="text-xs font-bold text-accent-red">Fase 1: Contenção Imediata (SLA Bacen: 24h - 48h)</p>
                  <span className="badge-red text-[10px]">Urgência Imediata</span>
                </div>
                <ul className="text-xs text-slate-300 space-y-1 list-disc list-inside">
                  <li>Parametrização estrita de queries SQL em rotas de busca de produtos.</li>
                  <li>Rejeição de JWT com algoritmo <code>none</code> e imposição de verificação de assinatura.</li>
                  <li>Bloqueio de arquivos de ambiente <code>.env</code> e backups expostos no webserver.</li>
                </ul>
              </div>

              <div className="p-4 rounded-lg bg-bg-secondary border-l-4 border-accent-orange border border-bg-border">
                <div className="flex items-center justify-between mb-1">
                  <p className="text-xs font-bold text-accent-orange">Fase 2: Ajustes Estruturais &amp; WAF (SLA Bacen: Até 7 dias)</p>
                  <span className="badge-orange text-[10px]">Alta Prioridade</span>
                </div>
                <ul className="text-xs text-slate-300 space-y-1 list-disc list-inside">
                  <li>Validação de autorização em nível de registro para mitigar IDOR em pedidos.</li>
                  <li>Ativação de regras de mitigação no WAF e cabeçalhos defensivos HSTS e CSP.</li>
                  <li>Restrição de origens permitidas no CORS.</li>
                </ul>
              </div>

              <div className="p-4 rounded-lg bg-bg-secondary border-l-4 border-accent-cyan border border-bg-border">
                <div className="flex items-center justify-between mb-1">
                  <p className="text-xs font-bold text-accent-cyan">Fase 3: DevSecOps &amp; Re-teste Formal (SLA Bacen: Até 30 dias)</p>
                  <span className="badge-cyan text-[10px]">Governança Contínua</span>
                </div>
                <ul className="text-xs text-slate-300 space-y-1 list-disc list-inside">
                  <li>Implementação de SAST/DAST no pipeline de CI/CD (Shift-Left Security).</li>
                  <li>Emissão do laudo de re-teste (Retest) atestando fechamento dos apontamentos perante auditoria.</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: BACEN & LGPD COMPLIANCE */}
      {activeTab === 'bacen' && (
        <div className="card p-5 space-y-4">
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <Landmark className="w-5 h-5 text-accent-cyan" />
            Matriz de Enquadramento Regulatório do Banco Central do Brasil (Bacen)
          </h2>
          <p className="text-xs text-slate-400">
            Mapeamento formal dos achados contra a Resolução CMN nº 4.893/2021, Resolução BCB nº 85/2021 e LGPD (Lei 13.709/18).
          </p>

          <div className="overflow-x-auto mt-3">
            <table className="table">
              <thead>
                <tr>
                  <th>Regulamentação</th>
                  <th>Dispositivo / Artigo</th>
                  <th>Exigência Legal &amp; Avaliação</th>
                  <th>Status de Auditoria</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="font-semibold text-slate-200">Bacen (Res. CMN 4.893)</td>
                  <td className="text-xs text-slate-300">Art. 2º (Confidencialidade)</td>
                  <td className="text-xs text-slate-400">
                    Controles de acesso e proteção de dados bancários contra injeção e bypass de token.
                  </td>
                  <td>
                    <span className="badge-red text-[10px] px-2 py-0.5 rounded font-bold">APONTAMENTO ABERTO</span>
                  </td>
                </tr>
                <tr>
                  <td className="font-semibold text-slate-200">Bacen (Res. CMN 4.893)</td>
                  <td className="text-xs text-slate-300">Art. 10 (Testes Periódicos)</td>
                  <td className="text-xs text-slate-400">
                    Execução periódica de testes de intrusão e varreduras de vulnerabilidades.
                  </td>
                  <td>
                    <span className="badge-green text-[10px] px-2 py-0.5 rounded font-bold">CONFORME (TESTADO)</span>
                  </td>
                </tr>
                <tr>
                  <td className="font-semibold text-slate-200">Bacen (Res. CMN 4.893)</td>
                  <td className="text-xs text-slate-300">Art. 11 (Proteção Perimétrica)</td>
                  <td className="text-xs text-slate-400">
                    Mecanismos de WAF de borda e mitigação ativa contra tráfego malicioso e bots.
                  </td>
                  <td>
                    <span className="badge-orange text-[10px] px-2 py-0.5 rounded font-bold">EM REGULARIZAÇÃO</span>
                  </td>
                </tr>
                <tr>
                  <td className="font-semibold text-slate-200">Bacen (Res. CMN 4.893)</td>
                  <td className="text-xs text-slate-300">Art. 12 (Plano de Resposta)</td>
                  <td className="text-xs text-slate-400">
                    Cronograma formal com SLAs de remediação documentados perante a Diretoria.
                  </td>
                  <td>
                    <span className="badge-cyan text-[10px] px-2 py-0.5 rounded font-bold">PLANO DEFINIDO</span>
                  </td>
                </tr>
                <tr>
                  <td className="font-semibold text-slate-200">LGPD (Lei 13.709/18)</td>
                  <td className="text-xs text-slate-300">Art. 46 (Segurança e Sigilo)</td>
                  <td className="text-xs text-slate-400">
                    Garantia de segurança no tratamento e custódia de dados de titulares.
                  </td>
                  <td>
                    <span className="badge-red text-[10px] px-2 py-0.5 rounded font-bold">NÃO CONFORME</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
