'use client';

import { useState } from 'react';
import {
  BarChart3, ExternalLink, Copy, Check, X, ShieldCheck, Database,
  ArrowRight, Sparkles, Server, Zap
} from 'lucide-react';
import toast from 'react-hot-toast';

interface PowerBIModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const POWERBI_ENDPOINTS = [
  {
    title: 'KPIs Executivos & Visão Geral',
    description: 'Resumo de vulnerabilidades por severidade, total de projetos e índice de risco.',
    url: 'http://localhost:8000/api/v1/powerbi/overview',
    category: 'Dashboard',
  },
  {
    title: 'Tabela de Achados & Vulnerabilidades',
    description: 'Dados detalhados de vulnerabilidades (CVSS v3.1, CWE, OWASP, URL e ativos).',
    url: 'http://localhost:8000/api/v1/powerbi/findings',
    category: 'Findings',
  },
  {
    title: 'Projetos de Pentest & Escopos',
    description: 'Relatório estruturado de projetos, clientes, datas e contagem de ativos.',
    url: 'http://localhost:8000/api/v1/powerbi/projects',
    category: 'Projects',
  },
  {
    title: 'Matriz de 32 Controles de Segurança',
    description: 'Status de conformidade regulatória (BACEN, NIST SP 800-115, CIS Controls).',
    url: 'http://localhost:8000/api/v1/powerbi/security-controls',
    category: 'Compliance',
  },
  {
    title: 'Inteligência Perimétrica & OSINT',
    description: 'Mapeamento de subdomínios, análise DMARC/SPF, WAF e buckets expostos.',
    url: 'http://localhost:8000/api/v1/powerbi/osint-perimeters',
    category: 'OSINT',
  },
  {
    title: 'Governança Mobile & OWASP MASVS',
    description: 'Resultados de auditorias de pacotes Android (.APK) e iOS (.IPA).',
    url: 'http://localhost:8000/api/v1/powerbi/mobile-governance',
    category: 'Mobile',
  },
  {
    title: 'Trilha de Auditoria Imutável',
    description: 'Logs criptográficos permanentes com hashes SHA-256 e detalhes de acessos.',
    url: 'http://localhost:8000/api/v1/powerbi/audit-trail',
    category: 'Audit',
  },
];

export default function PowerBIModal({ isOpen, onClose }: PowerBIModalProps) {
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleCopy = (url: string) => {
    navigator.clipboard.writeText(url);
    setCopiedUrl(url);
    toast.success('URL da API copiada para a área de transferência!');
    setTimeout(() => setCopiedUrl(null), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-4xl max-h-[90vh] bg-bg-secondary border border-yellow-500/40 rounded-2xl shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-5 bg-gradient-to-r from-yellow-500/20 via-amber-500/10 to-transparent border-b border-yellow-500/30 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-yellow-500/20 border border-yellow-500/40 flex items-center justify-center text-yellow-400">
              <BarChart3 className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
                Quer integrar ao Microsoft PowerBI?
                <span className="px-2 py-0.5 text-[10px] font-extrabold uppercase tracking-wider bg-yellow-500/20 text-yellow-300 border border-yellow-500/40 rounded-full">
                  REST API LIVE
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Conecte seus dashboards corporativos em tempo real utilizando nossos conjuntos de dados estruturados em JSON.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Quick instructions */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="space-y-1">
              <p className="text-xs font-bold text-yellow-400 uppercase tracking-wider flex items-center gap-1.5">
                <Zap className="w-4 h-4" /> Passo a Passo para Conexão em 1 Minuto:
              </p>
              <ol className="text-xs text-slate-300 list-decimal list-inside space-y-0.5">
                <li>Abra o **Microsoft PowerBI Desktop**.</li>
                <li>Clique em **Obter Dados (Get Data)** e escolha a opção **Web**.</li>
                <li>Cole qualquer uma das URLs de API abaixo e clique em **OK**.</li>
              </ol>
            </div>

            <a
              href="http://localhost:8000/api/v1/powerbi/overview"
              target="_blank"
              rel="noreferrer"
              className="px-4 py-2.5 bg-yellow-500 text-slate-950 font-bold rounded-xl text-xs flex items-center gap-2 hover:bg-yellow-400 transition-all shadow-lg flex-shrink-0"
            >
              <ExternalLink className="w-4 h-4" />
              Testar API Principal no Navegador
            </a>
          </div>

          {/* Endpoints List */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Database className="w-4 h-4 text-accent-cyan" />
              Conjuntos de Dados &amp; Endpoints REST Disponíveis
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {POWERBI_ENDPOINTS.map((endpoint, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-yellow-500/40 transition-all flex flex-col justify-between group"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-bold text-slate-100 group-hover:text-yellow-400 transition-colors">
                        {endpoint.title}
                      </span>
                      <span className="px-2 py-0.5 text-[10px] font-semibold bg-slate-800 text-slate-400 rounded">
                        {endpoint.category}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-snug">
                      {endpoint.description}
                    </p>
                    <div className="p-2 bg-slate-950/80 rounded border border-slate-800 font-mono text-[11px] text-amber-300/90 truncate">
                      {endpoint.url}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 pt-3 mt-3 border-t border-slate-800/80">
                    <button
                      onClick={() => handleCopy(endpoint.url)}
                      className="flex-1 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-semibold rounded-lg flex items-center justify-center gap-1.5 transition-colors"
                    >
                      {copiedUrl === endpoint.url ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-green-400" />
                          <span>Copiado!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copiar URL</span>
                        </>
                      )}
                    </button>

                    <a
                      href={endpoint.url}
                      target="_blank"
                      rel="noreferrer"
                      className="px-3 py-1.5 bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 text-[11px] font-semibold rounded-lg flex items-center justify-center gap-1 transition-colors"
                      title="Redirecionar diretamente para a API no navegador"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      <span>Abrir API</span>
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-slate-950 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Formato JSON Nativo compatível com PowerBI Desktop &amp; PowerBI Service</span>
          </div>

          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold rounded-xl transition-colors"
          >
            Fechar
          </button>
        </div>
      </div>
    </div>
  );
}
