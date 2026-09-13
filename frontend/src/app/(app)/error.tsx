'use client';

import { useEffect } from 'react';
import { AlertTriangle, RefreshCw, LayoutDashboard } from 'lucide-react';
import Link from 'next/link';

export default function AppError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('Inner App Error Boundary:', error);
  }, [error]);

  return (
    <div className="p-8 max-w-xl mx-auto my-12 animate-fade-in">
      <div className="p-8 rounded-2xl bg-bg-secondary border border-red-500/30 shadow-2xl space-y-6 text-center">
        <div className="w-16 h-16 mx-auto rounded-2xl bg-red-500/15 border border-red-500/30 flex items-center justify-center text-red-400 shadow-lg">
          <AlertTriangle className="w-8 h-8 animate-pulse" />
        </div>

        <div className="space-y-2">
          <h2 className="text-xl font-bold text-slate-100">Erro no Módulo da Aplicação</h2>
          <p className="text-sm text-slate-400">
            Não foi possível renderizar a seção solicitada. Seus dados e varreduras permanecem preservados.
          </p>
          {error?.message && (
            <div className="mt-3 p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-left">
              <p className="text-xs font-mono text-red-400 break-all">{error.message}</p>
            </div>
          )}
        </div>

        <div className="flex flex-col sm:flex-row gap-3 justify-center pt-2">
          <button
            onClick={() => reset()}
            className="px-4 py-2.5 rounded-xl font-semibold text-xs bg-gradient-to-r from-accent-cyan via-blue-500 to-purple-600 text-slate-950 hover:brightness-110 shadow-lg flex items-center justify-center gap-2 transition-all"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Recarregar Módulo</span>
          </button>
          <Link
            href="/dashboard"
            className="px-4 py-2.5 rounded-xl font-semibold text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center justify-center gap-2 transition-all"
          >
            <LayoutDashboard className="w-4 h-4 text-accent-cyan" />
            <span>Dashboard Executivo</span>
          </Link>
        </div>
      </div>
    </div>
  );
}
