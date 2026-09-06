'use client';
import { useEffect, useState } from 'react';
import { Zap, CheckCircle2, ShieldAlert } from 'lucide-react';
import { morfeuXdrApi } from '@/lib/api';

export default function ActiveResponsePage() {
  const [responses, setResponses] = useState<any[]>([]);

  useEffect(() => {
    async function load() {
      try {
        const data = await morfeuXdrApi.getActiveResponse();
        setResponses(data);
      } catch (e) {
        console.error(e);
      }
    }
    load();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-bold text-slate-100">Histórico de Active Response (Respostas Defensivas)</h2>
        <p className="text-xs text-slate-400">
          Ações automáticas e manuais disparadas no agente Wazuh (Bloqueio de IP no Firewall, encerramento de processo e isolamento).
        </p>
      </div>

      <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-4">
        {responses.map((ar) => (
          <div key={ar.id} className="p-4 rounded-lg bg-bg-secondary border border-bg-border flex items-center justify-between">
            <div className="space-y-1 text-xs">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 font-mono text-[10px] font-bold bg-accent-green/10 text-accent-green border border-accent-green/30 rounded uppercase">
                  {ar.status}
                </span>
                <span className="font-bold text-slate-200">{ar.command}</span>
              </div>
              <p className="text-slate-400">IP Alvo: <code className="text-red-400 font-mono">{ar.target_ip}</code> em <strong className="text-slate-300">{ar.agent}</strong></p>
            </div>
            <CheckCircle2 className="w-5 h-5 text-accent-green" />
          </div>
        ))}
      </div>
    </div>
  );
}
