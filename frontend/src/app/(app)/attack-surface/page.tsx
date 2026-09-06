'use client';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { assetsApi, type Asset } from '@/lib/api';
import { useState } from 'react';
import { Globe, Search, Trash2 } from 'lucide-react';
import toast from 'react-hot-toast';
import clsx from 'clsx';

const SCANNER_URL = 'http://localhost:8000';

export default function AttackSurfacePage() {
  const [search, setSearch] = useState('');
  const queryClient = useQueryClient();
  const { data: assets = [], isLoading } = useQuery({ queryKey: ['all-assets'], queryFn: () => assetsApi.list() });

  const deleteAsset = useMutation({
    mutationFn: async (id: string) => {
      const res = await fetch(`${SCANNER_URL}/assets/${id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error('Failed to delete asset');
      return res.json();
    },
    onSuccess: () => {
      toast.success('Asset deleted successfully');
      queryClient.invalidateQueries({ queryKey: ['all-assets'] });
    },
    onError: () => toast.error('Failed to delete asset'),
  });

  const filtered = assets.filter((a: Asset) =>
    !search ||
    a.value.toLowerCase().includes(search.toLowerCase()) ||
    a.title?.toLowerCase().includes(search.toLowerCase())
  );

  const byType = assets.reduce((acc: any, a: Asset) => {
    acc[a.asset_type] = (acc[a.asset_type] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Attack Surface</h1>
        <p className="text-slate-400 text-sm mt-0.5">{assets.length} assets discovered across all projects</p>
      </div>

      {/* Type breakdown */}
      <div className="flex gap-3 flex-wrap">
        {Object.entries(byType).map(([type, count]) => (
          <div key={type} className="glass-card px-4 py-2 flex items-center gap-2">
            <span className="text-xs font-semibold text-accent-cyan">{type}</span>
            <span className="text-xs bg-accent-cyan/10 text-accent-cyan px-2 py-0.5 rounded-full font-bold">{count as number}</span>
          </div>
        ))}
      </div>

      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
        <input value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search asset..." className="input-field pl-9" />
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="w-8 h-8 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <div className="glass-card overflow-hidden">
          <table className="table-dark">
            <thead>
              <tr><th>Asset</th><th>Type</th><th>IP</th><th>Port</th><th>Server</th><th>Technologies</th><th>Criticality</th><th>Action</th></tr>
            </thead>
            <tbody>
              {filtered.map((a: Asset) => (
                <tr key={a.id} className="group">
                  <td>
                    <p className="font-mono text-sm text-slate-200 font-medium">{a.value}</p>
                    {a.title && <p className="text-xs text-slate-500">{a.title}</p>}
                  </td>
                  <td><span className="text-xs bg-slate-700 text-slate-300 px-2 py-0.5 rounded">{a.asset_type}</span></td>
                  <td><span className="font-mono text-xs text-slate-400">{a.ip_address || '—'}</span></td>
                  <td><span className="font-mono text-xs text-slate-400">{a.port || '—'}</span></td>
                  <td><span className="text-xs text-slate-400">{a.server || '—'}</span></td>
                  <td>
                    <div className="flex flex-wrap gap-1">
                      {a.technologies.slice(0, 4).map((t: string) => (
                        <span key={t} className="text-xs bg-accent-cyan/10 text-accent-cyan px-1.5 py-0.5 rounded">{t}</span>
                      ))}
                    </div>
                  </td>
                  <td>
                    <span className={clsx('text-xs px-2 py-0.5 rounded font-medium',
                      a.business_criticality === 'CRITICAL' ? 'bg-red-500/20 text-red-300' :
                      a.business_criticality === 'HIGH' ? 'bg-orange-500/20 text-orange-300' :
                      'bg-slate-700 text-slate-400')}>
                      {a.business_criticality}
                    </span>
                  </td>
                  <td>
                    <button 
                      onClick={() => deleteAsset.mutate(a.id)}
                      className="p-1.5 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors opacity-0 group-hover:opacity-100"
                      title="Delete Asset"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={8} className="text-center text-slate-500 py-8">No assets found</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
