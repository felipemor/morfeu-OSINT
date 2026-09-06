'use client';
import { useEffect, useState } from 'react';
import { ScrollText, Lock, RefreshCw, FileText } from 'lucide-react';
import { morfeuXdrApi } from '@/lib/api';

export default function XDRAuditLogsPage() {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const loadLogs = async () => {
    setLoading(true);
    try {
      const data = await morfeuXdrApi.getAuditLogs();
      setLogs(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <Lock className="w-4 h-4 text-accent-green" /> Trilha de Auditoria Imutável (Append-Only)
          </h2>
          <p className="text-xs text-slate-400">
            Registro transacional auditável de todas as mutações, alterações de status e investigações no MorfeuXDR.
          </p>
        </div>

        <button onClick={loadLogs} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200">
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Atualizar Trilha
        </button>
      </div>

      <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/60 border-b border-bg-border text-slate-400 uppercase font-semibold text-[10px] tracking-wider">
              <tr>
                <th className="p-3.5">Operador / Ator</th>
                <th className="p-3.5">Ação Executada</th>
                <th className="p-3.5">Correlation ID</th>
                <th className="p-3.5">Resultado</th>
                <th className="p-3.5">Estado Anterior ➔ Novo</th>
                <th className="p-3.5">Data / Hora (UTC)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bg-border/60 text-slate-200">
              {logs.map((l) => (
                <tr key={l.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="p-3.5 font-bold text-slate-100">{l.actor}</td>
                  <td className="p-3.5 font-mono text-accent-cyan font-bold">{l.action}</td>
                  <td className="p-3.5 font-mono text-[10px] text-slate-400">{l.correlation_id || 'N/A'}</td>
                  <td className="p-3.5">
                    <span className="px-2 py-0.5 text-[10px] font-bold bg-accent-green/10 text-accent-green border border-accent-green/30 rounded uppercase">
                      {l.result}
                    </span>
                  </td>
                  <td className="p-3.5 font-mono text-[10px] text-slate-300">
                    {l.before_state?.status || 'INIT'} ➔ <strong className="text-slate-100">{l.after_state?.status || 'UPDATED'}</strong>
                  </td>
                  <td className="p-3.5 font-mono text-[10px] text-slate-400">
                    {l.timestamp ? new Date(l.timestamp).toUTCString() : 'Agora'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
