'use client';

import { useEffect } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('Global Application Error:', error);
  }, [error]);

  return (
    <html lang="pt-BR">
      <body className="bg-[#0a0e1a] text-slate-100 min-h-screen flex items-center justify-center p-6 font-sans">
        <div className="max-w-md w-full p-8 rounded-2xl bg-[#111827] border border-red-500/30 shadow-2xl space-y-6 text-center">
          <div className="w-16 h-16 mx-auto rounded-2xl bg-red-500/15 border border-red-500/30 flex items-center justify-center text-red-400 shadow-lg">
            <AlertTriangle className="w-8 h-8 animate-pulse" />
          </div>

          <div className="space-y-2">
            <h1 className="text-xl font-bold text-slate-100">Erro Crítico de Execução</h1>
            <p className="text-sm text-slate-400">
              Ocorreu uma falha inesperada na renderização da aplicação. Todos os registros locais foram preservados.
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
              className="px-4 py-2.5 rounded-xl font-semibold text-xs bg-gradient-to-r from-red-500 to-rose-600 text-white hover:brightness-110 shadow-lg flex items-center justify-center gap-2 transition-all"
            >
              <RefreshCw className="w-4 h-4" />
              <span>Tentar Novamente</span>
            </button>
            <a
              href="/dashboard"
              className="px-4 py-2.5 rounded-xl font-semibold text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center justify-center gap-2 transition-all"
            >
              <Home className="w-4 h-4" />
              <span>Ir para Dashboard</span>
            </a>
          </div>
        </div>
      </body>
    </html>
  );
}
