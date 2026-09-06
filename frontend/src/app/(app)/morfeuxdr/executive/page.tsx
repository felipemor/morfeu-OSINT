'use client';
import { useEffect, useState } from 'react';
import { BarChart3, TrendingDown, ShieldAlert, Award } from 'lucide-react';
import { morfeuXdrApi } from '@/lib/api';

export default function ExecutiveViewPage() {
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    async function load() {
      try {
        const res = await morfeuXdrApi.getOverview();
        setData(res);
      } catch (e) {
        console.error(e);
      }
    }
    load();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-bold text-slate-100">Visão Executiva CISO — Resumo de Risco Corporativo</h2>
        <p className="text-xs text-slate-400">
          Painel de alto nível para governança executiva, postura de segurança e tendência de incidentes.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-2">
          <span className="text-xs text-slate-400 font-bold uppercase">Postura Global MorfeuXDR</span>
          <div className="text-4xl font-black text-slate-100">{data?.security_score || 87.4} / 100</div>
          <p className="text-xs text-accent-green font-semibold">↑ +3.1 pontos nos últimos 30 dias</p>
        </div>

        <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-2">
          <span className="text-xs text-slate-400 font-bold uppercase">Tempo Médio para Resposta (MTTR)</span>
          <div className="text-4xl font-black text-accent-cyan">{data?.mttr_hours} horas</div>
          <p className="text-xs text-slate-400">Diminuição de 45% no tempo de contenção</p>
        </div>

        <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-2">
          <span className="text-xs text-slate-400 font-bold uppercase">Incidentes Críticos em Aberto</span>
          <div className="text-4xl font-black text-red-500">{data?.critical_findings || 2}</div>
          <p className="text-xs text-red-400 font-semibold">100% sob investigação ativa</p>
        </div>
      </div>
    </div>
  );
}
