'use client';
import { useEffect, useState } from 'react';
import { Grid, Shield, Check, X, Lock } from 'lucide-react';
import { microsegmentationApi } from '@/lib/api';

export default function SegmentationMatrixPage() {
  const [zones, setZones] = useState<any[]>([]);

  useEffect(() => {
    async function load() {
      try {
        const data = await microsegmentationApi.getZones();
        setZones(data);
      } catch (e) {
        console.error(e);
      }
    }
    load();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-bold text-slate-100">Matriz de Segmentação Inter-Zonas</h2>
        <p className="text-xs text-slate-400">
          Matriz de controle de permissões de tráfego entre zonas de segurança corporativas.
        </p>
      </div>

      {/* Grid Matrix Table */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-6 overflow-x-auto shadow-lg">
        <table className="w-full text-xs text-left border-collapse">
          <thead>
            <tr>
              <th className="p-3 border-b border-r border-bg-border bg-slate-900/40 text-slate-400 uppercase text-[10px] font-bold">
                Origem \ Destino
              </th>
              {zones.map((z) => (
                <th key={z.id} className="p-3 border-b border-bg-border text-center font-bold text-slate-200" style={{ color: z.color }}>
                  {z.name}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-bg-border/60">
            {zones.map((srcZone) => (
              <tr key={srcZone.id} className="hover:bg-slate-800/30">
                <td className="p-3 border-r border-bg-border font-bold text-slate-200" style={{ color: srcZone.color }}>
                  {srcZone.name}
                </td>
                {zones.map((dstZone) => {
                  const isSame = srcZone.id === dstZone.id;
                  const isAllowed = (srcZone.name.includes('DMZ') && dstZone.name.includes('Mobile')) ||
                                    (srcZone.name.includes('Mobile') && dstZone.name.includes('App')) ||
                                    (srcZone.name.includes('App') && dstZone.name.includes('Database'));
                  return (
                    <td key={dstZone.id} className="p-3 text-center border-r border-bg-border/40">
                      {isSame ? (
                        <span className="px-2 py-1 text-[10px] bg-slate-800 text-slate-400 rounded">INTRA-ZONE</span>
                      ) : isAllowed ? (
                        <span className="inline-flex items-center gap-1 px-2 py-1 text-[10px] font-bold bg-accent-green/10 text-accent-green border border-accent-green/30 rounded">
                          <Check className="w-3 h-3" /> ALLOWED
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-1 text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/30 rounded">
                          <Lock className="w-3 h-3" /> DENIED
                        </span>
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
