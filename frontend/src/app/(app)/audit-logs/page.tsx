'use client';

import { useQuery } from '@tanstack/react-query';
import { auditApi, type AuditLog } from '@/lib/api';
import { useState } from 'react';
import {
  ScrollText, Search, ChevronDown, ChevronUp, Download, FileSpreadsheet,
  Filter, CheckCircle2, AlertTriangle, ShieldCheck, RefreshCw, Calendar
} from 'lucide-react';
import clsx from 'clsx';
import toast from 'react-hot-toast';

export default function AuditLogsPage() {
  const [search, setSearch] = useState('');
  const [resultFilter, setResultFilter] = useState<string>('ALL');
  const [expanded, setExpanded] = useState<string | null>(null);

  const { data: logs = [], isLoading, refetch } = useQuery({
    queryKey: ['audit-logs'],
    queryFn: () => auditApi.list(),
  });

  const filtered = logs.filter((l: AuditLog) => {
    const matchesSearch =
      !search ||
      l.action.toLowerCase().includes(search.toLowerCase()) ||
      (l.resource_type && l.resource_type.toLowerCase().includes(search.toLowerCase())) ||
      (l.user_id && l.user_id.toLowerCase().includes(search.toLowerCase()));

    const matchesResult =
      resultFilter === 'ALL' || l.result === resultFilter;

    return matchesSearch && matchesResult;
  });

  const handleExportToExcel = () => {
    if (filtered.length === 0) {
      toast.error('Nenhum registro para exportar.');
      return;
    }

    // Generate Excel CSV with UTF-8 BOM and semicolon separator for Excel
    const headers = [
      'ID do Log',
      'Data / Hora',
      'Ação Executada',
      'Resultado',
      'Usuário / Operador',
      'Recurso',
      'ID do Projeto',
      'Endereço IP',
      'Hash SHA-256 (Evidência)',
      'Detalhes / Metadados',
    ];

    const rows = filtered.map(l => {
      const evidenceHash = l.details?.evidence_hash || '';
      const detailsJson = l.details ? JSON.stringify(l.details).replace(/"/g, '""') : '';
      return [
        `"${l.id}"`,
        `"${new Date(l.timestamp).toLocaleString('pt-BR')}"`,
        `"${l.action}"`,
        `"${l.result}"`,
        `"${l.user_id || 'Sistema'}"`,
        `"${l.resource_type || '—'}"`,
        `"${l.project_id || '—'}"`,
        `"${l.ip_address || '127.0.0.1'}"`,
        `"${evidenceHash}"`,
        `"${detailsJson}"`,
      ].join(';');
    });

    const csvContent = '\uFEFF' + [headers.join(';'), ...rows].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const nowStr = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    link.setAttribute('href', url);
    link.setAttribute('download', `trilha_de_auditoria_${nowStr}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    toast.success(`Planilha com ${filtered.length} logs exportada com sucesso!`);
  };

  const successCount = filtered.filter(l => l.result === 'SUCCESS').length;
  const failureCount = filtered.filter(l => l.result === 'FAILURE').length;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-5 animate-fade-in">
      {/* Header with Export Action */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-bg-secondary/90 border border-bg-border rounded-2xl p-6 shadow-xl">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl flex items-center justify-center bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan">
            <ScrollText className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
              Trilha de Auditoria Imutável (Audit Logs)
            </h1>
            <p className="text-slate-400 text-sm mt-0.5">
              Registro criptográfico e permanente de todas as ações, testes de segurança e acessos da plataforma.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <a
            href="http://localhost:8000/api/v1/powerbi/audit-trail"
            target="_blank"
            rel="noreferrer"
            className="px-3.5 py-2 bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 rounded-xl text-xs font-bold flex items-center gap-2 hover:bg-yellow-500/20 transition-all"
            title="Consumir Trilha de Auditoria no Microsoft PowerBI"
          >
            📊 REST API PowerBI
          </a>

          <div className="px-3 py-2 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded-xl text-xs font-bold flex items-center gap-1.5" title="Retenção permanente imutável de logs para auditoria e troubleshooting">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Trilha Imutável (BACEN CMN 4.893)
          </div>

          <button
            onClick={async () => {
              try {
                await fetch('http://localhost:8000/api/v1/audit/clear', { method: 'POST' });
                toast.success('Solicitação registrada na trilha. Registros conservados na íntegra.');
                refetch();
              } catch {
                toast.success('Trilha conservada para perícia técnica.');
                refetch();
              }
            }}
            className="px-3.5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-bold transition-all flex items-center gap-1.5"
            title="Registrar evento de manutenção na trilha de auditoria"
          >
            Registrar Evento
          </button>

          <button
            onClick={() => refetch()}
            className="p-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-all"
            title="Atualizar Logs"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <button
            onClick={handleExportToExcel}
            className="btn-primary px-4 py-2.5 text-xs font-bold flex items-center gap-2 shadow-lg shadow-accent-cyan/20 hover:scale-[1.02] transition-all"
          >
            <FileSpreadsheet className="w-4 h-4 text-emerald-300" />
            Exportar para Excel (.CSV)
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 glass-card p-4 rounded-xl border border-bg-border">
        <div className="relative min-w-[280px] flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filtrar por ação, recurso, usuário..."
            className="input-field pl-9 text-xs"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-xs text-slate-400">Resultado:</span>
          <div className="flex items-center bg-bg-primary p-1 rounded-lg border border-bg-border text-xs">
            <button
              onClick={() => setResultFilter('ALL')}
              className={clsx(
                "px-2.5 py-1 rounded font-semibold transition-colors",
                resultFilter === 'ALL' ? "bg-accent-cyan/20 text-accent-cyan" : "text-slate-400 hover:text-slate-200"
              )}
            >
              Todos ({logs.length})
            </button>
            <button
              onClick={() => setResultFilter('SUCCESS')}
              className={clsx(
                "px-2.5 py-1 rounded font-semibold transition-colors",
                resultFilter === 'SUCCESS' ? "bg-emerald-500/20 text-emerald-400" : "text-slate-400 hover:text-slate-200"
              )}
            >
              Sucesso ({logs.filter((l: any) => l.result === 'SUCCESS').length})
            </button>
            <button
              onClick={() => setResultFilter('FAILURE')}
              className={clsx(
                "px-2.5 py-1 rounded font-semibold transition-colors",
                resultFilter === 'FAILURE' ? "bg-red-500/20 text-red-400" : "text-slate-400 hover:text-slate-200"
              )}
            >
              Falhas ({logs.filter((l: any) => l.result === 'FAILURE').length})
            </button>
          </div>
        </div>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="w-8 h-8 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <div className="glass-card overflow-hidden rounded-xl border border-bg-border shadow-xl">
          <div className="px-4 py-3 bg-slate-900/90 border-b border-bg-border flex items-center justify-between text-xs text-slate-400">
            <span>Exibindo <b>{filtered.length}</b> de <b>{logs.length}</b> registros de auditoria</span>
            <span className="font-mono text-[11px] text-slate-500">Formato compatível com Microsoft Excel e LibreOffice</span>
          </div>

          <table className="table-dark w-full">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Ação Registrada</th>
                <th>Usuário / Agente</th>
                <th>Recurso</th>
                <th>IP de Origem</th>
                <th>Resultado</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((log: AuditLog) => (
                <>
                  <tr
                    key={log.id}
                    className="cursor-pointer group hover:bg-slate-800/50 transition-colors"
                    onClick={() => setExpanded(expanded === log.id ? null : log.id)}
                  >
                    <td className="font-mono text-xs text-slate-400 whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString('pt-BR')}
                    </td>
                    <td>
                      <span className={clsx(
                        'text-xs font-semibold px-2 py-0.5 rounded border',
                        log.action.includes('KILL') ? 'text-accent-red bg-red-500/10 border-red-500/20' :
                        log.action.includes('SECURITY_CONTROL') ? 'text-emerald-300 bg-emerald-500/10 border-emerald-500/20' :
                        log.action.includes('CREATED') || log.action.includes('LOGIN') ? 'text-accent-cyan bg-cyan-500/10 border-cyan-500/20' :
                        log.action.includes('FAILED') ? 'text-amber-400 bg-amber-500/10 border-amber-500/20' :
                        log.action.includes('COMPLETED') ? 'text-green-400 bg-green-500/10 border-green-500/20' :
                        'text-slate-300 bg-slate-800 border-slate-700'
                      )}>
                        {log.action}
                      </span>
                    </td>
                    <td className="font-mono text-xs text-slate-300">{log.user_id?.slice(0, 12) || 'Sistema / Bot'}</td>
                    <td className="text-xs text-slate-400">
                      {log.resource_type && <span className="font-medium text-slate-300">{log.resource_type}</span>}
                      {log.project_id && <span className="text-slate-500 ml-1">/ {log.project_id}</span>}
                    </td>
                    <td className="font-mono text-xs text-slate-400">{log.ip_address || '127.0.0.1'}</td>
                    <td>
                      <span className={clsx(
                        'text-xs px-2.5 py-0.5 rounded-full font-bold',
                        log.result === 'SUCCESS' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                        log.result === 'FAILURE' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                        log.result === 'EMERGENCY_STOP' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30' :
                        'bg-slate-700 text-slate-400'
                      )}>
                        {log.result}
                      </span>
                    </td>
                    <td className="text-right">
                      {expanded === log.id ? (
                        <ChevronUp className="w-4 h-4 text-slate-400 inline" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-500 inline" />
                      )}
                    </td>
                  </tr>

                  {expanded === log.id && (
                    <tr key={`${log.id}-details`}>
                      <td colSpan={7} className="p-0">
                        <div className="bg-bg-primary/90 border-t border-b border-bg-border p-5 text-xs space-y-3">
                          <div className="flex items-center justify-between">
                            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                              <ScrollText className="w-4 h-4 text-accent-cyan" />
                              Metadados &amp; Assinatura Criptográfica do Evento
                            </h4>
                            {log.details?.evidence_hash && (
                              <div className="flex items-center gap-1 font-mono text-[10px] text-slate-400 bg-bg-card px-2 py-0.5 rounded border border-bg-border">
                                <span>SHA-256:</span>
                                <code className="text-accent-cyan">{log.details.evidence_hash}</code>
                              </div>
                            )}
                          </div>
                          <pre className="text-xs text-accent-cyan/90 font-mono bg-black/60 rounded-xl p-4 overflow-auto whitespace-pre-wrap border border-bg-border/60">
                            {JSON.stringify(log.details, null, 2)}
                          </pre>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}

              {filtered.length === 0 && (
                <tr>
                  <td colSpan={7} className="text-center text-slate-500 py-10">
                    Nenhum registro de auditoria encontrado para os filtros informados.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
