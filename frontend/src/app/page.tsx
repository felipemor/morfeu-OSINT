'use client';
import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { authApi } from '@/lib/api';
import { Shield, Sparkles } from 'lucide-react';

export default function HomePage() {
  const router = useRouter();

  useEffect(() => {
    if (!authApi.isLoggedIn()) {
      authApi.login('fsec.costa@gmail.com', 'admin');
    }
    router.replace('/dashboard');
  }, [router]);

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-bg-primary text-slate-100 p-6">
      <div className="flex flex-col items-center gap-4 max-w-sm text-center">
        <div className="relative w-16 h-16 rounded-2xl bg-bg-card border border-accent-cyan/40 flex items-center justify-center shadow-lg shadow-accent-cyan/10 overflow-hidden">
          <img src="/morfeusec-logo.png" alt="morfeusec OSINT" className="w-full h-full object-cover scale-110" />
        </div>
        <div>
          <h2 className="text-lg font-extrabold tracking-tight text-slate-100">morfeusec OSINT</h2>
          <p className="text-xs text-accent-cyan font-mono uppercase tracking-widest mt-0.5">Carregando Plataforma...</p>
        </div>
        <div className="w-36 h-1 bg-slate-800 rounded-full overflow-hidden mt-2">
          <div className="w-full h-full bg-accent-cyan animate-pulse" />
        </div>
      </div>
    </div>
  );
}

