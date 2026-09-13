import Link from 'next/link';
import { FileQuestion, Home, ArrowLeft } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="min-h-screen bg-[#0a0e1a] text-slate-100 flex items-center justify-center p-6">
      <div className="max-w-md w-full p-8 rounded-2xl bg-[#111827] border border-bg-border shadow-2xl space-y-6 text-center animate-fade-in">
        <div className="w-16 h-16 mx-auto rounded-2xl bg-accent-cyan/15 border border-accent-cyan/30 flex items-center justify-center text-accent-cyan shadow-lg">
          <FileQuestion className="w-8 h-8" />
        </div>

        <div className="space-y-2">
          <span className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-accent-cyan to-blue-500 font-mono">
            404
          </span>
          <h1 className="text-xl font-bold text-slate-100">Página Não Encontrada</h1>
          <p className="text-sm text-slate-400">
            A rota que você tentou acessar não existe ou foi realocada na estrutura do portal.
          </p>
        </div>

        <div className="pt-2">
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-xs bg-gradient-to-r from-accent-cyan to-blue-500 text-slate-950 hover:brightness-110 shadow-lg transition-all"
          >
            <Home className="w-4 h-4" />
            <span>Voltar ao Dashboard</span>
          </Link>
        </div>
      </div>
    </div>
  );
}
