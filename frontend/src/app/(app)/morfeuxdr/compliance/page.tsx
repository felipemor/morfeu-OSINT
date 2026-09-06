'use client';
import { useEffect, useState } from 'react';
import { CheckSquare, ShieldCheck, AlertTriangle } from 'lucide-react';
import { morfeuXdrApi } from '@/lib/api';

export default function CompliancePage() {
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    async function load() {
      try {
        const res = await morfeuXdrApi.getCompliance();
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
        <h2 className="text-base font-bold text-slate-100">Conformidade e Frameworks Regulatórios</h2>
        <p className="text-xs text-slate-400">
          Mapeamento automático dos achados XDR para NIST 800-53, ISO 27001, CIS Controls, LGPD, BACEN e PCI DSS.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {data?.frameworks?.map((fw: any, idx: number) => (
          <div key={idx} className="bg-bg-card border border-bg-border rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100">{fw.name}</h3>
              <span className={`px-2 py-0.5 text-[9px] font-bold rounded uppercase border ${
                fw.status === 'COMPLIANT'
                  ? 'bg-accent-green/10 text-accent-green border-accent-green/30'
                  : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
              }`}>
                {fw.status}
              </span>
            </div>

            <div className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">Score de Conformidade:</span>
                <span className="font-mono font-bold text-slate-100">{fw.score}%</span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                <div className="bg-accent-green h-full rounded-full" style={{ width: `${fw.score}%` }} />
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
