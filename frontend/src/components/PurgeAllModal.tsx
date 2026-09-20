'use client';
import { useState } from 'react';
import { systemApi } from '@/lib/api';
import { Trash2, AlertTriangle, Loader2, CheckCircle2, X, ShieldAlert } from 'lucide-react';
import clsx from 'clsx';

interface PurgeAllModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

export default function PurgeAllModal({ isOpen, onClose, onSuccess }: PurgeAllModalProps) {
  const [confirmText, setConfirmText] = useState('');
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handlePurge = async () => {
    if (confirmText.trim().toUpperCase() !== 'EXPURGAR') return;
    setLoading(true);
    setError(null);
    try {
      await systemApi.purgeAll();
      setDone(true);
      if (onSuccess) onSuccess();
    } catch (e: any) {
      setError(e.message || 'Erro ao resetar dados do sistema.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-lg bg-[#0d1117] border border-red-500/40 rounded-2xl shadow-2xl shadow-red-500/10 overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-white/10 bg-red-950/30 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-red-500/20 border border-red-500/40 text-red-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-black text-white">
                Expurgar & Resetar Todos os Dados
              </h2>
              <p className="text-xs text-red-300/80">
                Ação irreversível de limpeza total de todos os módulos.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-4">
          {!done ? (
            <>
              <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-xs text-red-200 leading-relaxed space-y-2">
                <p className="font-bold flex items-center gap-1.5 text-red-300">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0 text-red-400" />
                  Atenção: Os seguintes dados serão completamente excluídos:
                </p>
                <ul className="list-disc list-inside space-y-1 text-slate-300 pl-1">
                  <li>Todos os projetos, scans e relatórios em andamento</li>
                  <li>Todas as vulnerabilidades (findings) e ativos descobertos</li>
                  <li>Histórico de EASM, Dark Web Leaks e varreduras Shodan</li>
                  <li>Alertas de Brand Protection e histórico de Takedowns</li>
                  <li>Auditorias de Criptografia PQC e CBOMs registrados</li>
                  <li>Datasets e laudos do Fiscal Forensic AI</li>
                  <li>Histórico de consultas e incidentes de BIN / Boletos</li>
                </ul>
              </div>

              <div className="space-y-1.5">
                <label className="block text-xs font-bold text-slate-300">
                  Digite <span className="text-red-400 font-mono font-black">EXPURGAR</span> para confirmar a exclusão:
                </label>
                <input
                  type="text"
                  value={confirmText}
                  onChange={e => setConfirmText(e.target.value)}
                  placeholder="EXPURGAR"
                  className="w-full px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-sm text-white font-mono uppercase focus:outline-none focus:border-red-500 text-center tracking-widest font-black"
                />
              </div>

              {error && (
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-xs">
                  {error}
                </div>
              )}
            </>
          ) : (
            <div className="p-6 text-center space-y-3">
              <div className="w-12 h-12 rounded-full bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 flex items-center justify-center mx-auto">
                <CheckCircle2 className="w-6 h-6" />
              </div>
              <h3 className="text-base font-bold text-white">Todos os dados foram resetados!</h3>
              <p className="text-xs text-slate-400">
                A plataforma foi reiniciada com o estado limpo e seguro para novos testes.
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-white/10 bg-white/2 flex items-center justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-bold text-slate-400 hover:text-white rounded-xl hover:bg-white/5 transition-colors"
          >
            {done ? 'Concluir' : 'Cancelar'}
          </button>

          {!done && (
            <button
              onClick={handlePurge}
              disabled={loading || confirmText.trim().toUpperCase() !== 'EXPURGAR'}
              className="px-5 py-2 rounded-xl font-bold text-xs bg-red-600 hover:bg-red-500 text-white flex items-center gap-2 shadow-lg shadow-red-500/20 disabled:opacity-40 transition-all cursor-pointer"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Expurgando...</span>
                </>
              ) : (
                <>
                  <Trash2 className="w-4 h-4" />
                  <span>Confirmar Expurgar Tudo</span>
                </>
              )}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
