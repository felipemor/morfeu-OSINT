'use client';
import { useState } from 'react';
import dynamic from 'next/dynamic';
import { Sparkles, Trash2, Search, Crosshair } from 'lucide-react';
import Link from 'next/link';
import LanguageSelector from '@/components/LanguageSelector';
import { useLanguage } from '@/context/LanguageContext';

const UnifiedScanModal = dynamic(() => import('@/components/UnifiedScanModal'), { ssr: false });
const PurgeAllModal = dynamic(() => import('@/components/PurgeAllModal'), { ssr: false });

export default function GlobalActionsBar() {
  const [isUnifiedOpen, setIsUnifiedOpen] = useState(false);
  const [isPurgeOpen, setIsPurgeOpen] = useState(false);
  const { t } = useLanguage();

  return (
    <>
      <div className="fixed top-3 right-6 z-40 flex items-center gap-2 bg-[#0d1117]/90 backdrop-blur-md border border-white/10 px-3 py-1.5 rounded-2xl shadow-2xl">
        {/* Language Selector (PT/EN/ES) */}
        <LanguageSelector />

        {/* Unified Scan 1-Click */}
        <button
          onClick={() => setIsUnifiedOpen(true)}
          className="flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-black bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 shadow-md shadow-cyan-500/20 transition-all cursor-pointer group"
          title="Executar Scan Unificado 360°"
        >
          <Sparkles className="w-3.5 h-3.5 fill-current text-slate-950 group-hover:rotate-12 transition-transform" />
          <span className="tracking-tight font-extrabold">{t('nav.unifiedScan', '⚡ Scan Unificado 360°')}</span>
        </button>

        {/* Pentest Hub Multi-URL link */}
        <Link
          href="/pentest-hub"
          className="hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-semibold bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 transition-colors"
          title="Pentest Hub"
        >
          <Crosshair className="w-3.5 h-3.5 text-cyan-400" />
          <span>{t('nav.hubPentest', 'Hub Pentest')}</span>
        </Link>

        {/* Purge All */}
        <button
          onClick={() => setIsPurgeOpen(true)}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-semibold bg-red-950/30 hover:bg-red-900/50 text-red-300 border border-red-500/30 transition-colors cursor-pointer"
          title="Reset Geral"
        >
          <Trash2 className="w-3.5 h-3.5 text-red-400" />
          <span className="hidden md:inline">{t('nav.resetAll', 'Reset Geral')}</span>
        </button>
      </div>

      <UnifiedScanModal isOpen={isUnifiedOpen} onClose={() => setIsUnifiedOpen(false)} />
      <PurgeAllModal isOpen={isPurgeOpen} onClose={() => setIsPurgeOpen(false)} onSuccess={() => window.location.reload()} />
    </>
  );
}
