'use client';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useState, useEffect } from 'react';
import {
  Shield, LayoutDashboard, FolderKanban, Globe,
  Bug, ScrollText, ChevronLeft, ChevronRight, LogOut, User, Crosshair, FileText, Radar, ShieldCheck, Smartphone, Activity, Network, ShieldAlert, BarChart2, BarChart3, ExternalLink, Sparkles
} from 'lucide-react';
import { authApi } from '@/lib/api';
import clsx from 'clsx';
import PowerBIModal from '@/components/PowerBIModal';
import UnifiedMasterReportModal from '@/components/UnifiedMasterReportModal';

const navigation = [
  { name: 'Grafana Analytics', href: '/grafana-analytics', icon: BarChart2 },
  { name: 'Dashboard Executivo', href: '/dashboard', icon: LayoutDashboard },
  { name: 'MorfeuXDR', href: '/morfeuxdr', icon: ShieldAlert },
  { name: 'Mobile Analytics', href: '/mobile-dashboard', icon: Activity },
  { name: 'Microsegmentação', href: '/microsegmentation', icon: Network },
  { name: 'Scanner', href: '/scan', icon: Crosshair },
  { name: 'Mobile Pentest (APK/iOS)', href: '/mobile-pentest', icon: Smartphone },
  { name: 'OSINT Intelligence', href: '/osint', icon: Radar },
  { name: 'Controles de Segurança', href: '/security-controls', icon: ShieldCheck },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Projects', href: '/projects', icon: FolderKanban },
  { name: 'Attack Surface', href: '/attack-surface', icon: Globe },
  { name: 'Findings', href: '/findings', icon: Bug },
  { name: 'Audit Logs', href: '/audit-logs', icon: ScrollText },
];

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const [collapsed, setCollapsed] = useState(false);
  const [user, setUser] = useState<any>(null);
  const [isPowerBIOpen, setIsPowerBIOpen] = useState(false);
  const [isMasterReportOpen, setIsMasterReportOpen] = useState(false);

  useEffect(() => {
    setUser(authApi.getUser());
  }, []);

  const handleLogout = () => {
    authApi.logout();
    router.push('/login');
  };

  return (
    <>
      <aside className={clsx(
        'flex flex-col h-screen sticky top-0 border-r border-bg-border transition-all duration-300 bg-bg-secondary/95 backdrop-blur-sm z-30',
        collapsed ? 'w-16' : 'w-64'
      )}>
        {/* Logo */}
        <div className="flex items-center gap-3 px-4 py-4 border-b border-bg-border">
          <div className="flex-shrink-0 w-9 h-9 rounded-lg flex items-center justify-center overflow-hidden"
            style={{ background: '#0a101d', border: '1px solid rgba(0,212,255,0.4)', boxShadow: '0 0 15px rgba(0,212,255,0.25)' }}>
            <img src="/morfeusec-logo.png" alt="morfeusec OSINT" className="w-full h-full object-cover scale-110" />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <p className="text-sm font-extrabold text-slate-100 truncate tracking-tight" title="morfeusec OSINT">morfeusec OSINT</p>
            </div>
          )}
          <button onClick={() => setCollapsed(!collapsed)}
            className="ml-auto text-slate-500 hover:text-slate-300 transition-colors flex-shrink-0">
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* PowerBI & Big-4 Master Report Buttons */}
        <div className="p-2 border-b border-bg-border/60 space-y-1.5">
          <button
            onClick={() => setIsPowerBIOpen(true)}
            className={clsx(
              "w-full px-3 py-2 rounded-xl font-bold text-xs flex items-center gap-2.5 transition-all shadow-md",
              "bg-gradient-to-r from-yellow-500/20 via-amber-500/20 to-yellow-500/10 border border-yellow-500/40 text-yellow-300 hover:border-yellow-400 hover:text-yellow-200 group"
            )}
            title="Quer integrar ao Microsoft PowerBI? Clique para ver as APIs REST e os endpoints."
          >
            <BarChart3 className="w-4 h-4 flex-shrink-0 text-yellow-400 group-hover:scale-110 transition-transform" />
            {!collapsed && (
              <span className="truncate flex-1 text-left">Quer integrar ao PowerBI?</span>
            )}
          </button>

          <button
            onClick={() => setIsMasterReportOpen(true)}
            className={clsx(
              "w-full px-3 py-2 rounded-xl font-bold text-xs flex items-center gap-2.5 transition-all shadow-md",
              "bg-gradient-to-r from-emerald-500/20 via-accent-cyan/20 to-emerald-500/10 border border-emerald-500/40 text-emerald-300 hover:border-accent-cyan hover:text-emerald-200 group"
            )}
            title="Gerar Relatório Máster Unificado 360° (Scanner + 32 Controles BACEN + Malware Scan) para Auditores e Analistas."
          >
            <Sparkles className="w-4 h-4 flex-shrink-0 text-accent-cyan group-hover:rotate-12 transition-transform" />
            {!collapsed && (
              <span className="truncate flex-1 text-left font-extrabold">Laudo Consolidado de Auditoria</span>
            )}
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-3 px-2 space-y-0.5 overflow-y-auto">
          {navigation.map(item => {
            const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
            return (
              <Link key={item.href} href={item.href}
                className={clsx('sidebar-item', isActive && 'active', collapsed && 'justify-center px-0')}>
                <item.icon className={clsx('flex-shrink-0', collapsed ? 'w-5 h-5' : 'w-4 h-4')} />
                {!collapsed && <span className="truncate">{item.name}</span>}
              </Link>
            );
          })}
        </nav>

        {/* User & Author Footer */}
        <div className="border-t border-bg-border p-3 space-y-2">
          {!collapsed ? (
            <>
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0"
                  style={{ background: 'linear-gradient(135deg,#00d4ff22,#9c27b022)' }}>
                  <User className="w-4 h-4 text-slate-300" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-medium text-slate-200 truncate">{user?.full_name || 'Operator'}</p>
                  <p className="text-xs text-slate-500 truncate">{user?.role || 'PENTESTER'}</p>
                </div>
                <button onClick={handleLogout} className="text-slate-500 hover:text-accent-red transition-colors" title="Logout">
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
              <div className="pt-2 border-t border-bg-border/50 text-[10px] text-slate-400 leading-tight">
                <p className="text-slate-400 font-medium">Escrito por:</p>
                <p className="text-accent-cyan font-mono truncate select-all">Felipe Costa</p>
                <p className="text-slate-400 font-mono text-[9px] truncate select-all">fsec.costa@gmail.com</p>
              </div>
            </>
          ) : (
            <button onClick={handleLogout} className="w-full flex justify-center text-slate-500 hover:text-accent-red transition-colors p-1" title="Logout">
              <LogOut className="w-4 h-4" />
            </button>
          )}
        </div>
      </aside>

      <PowerBIModal isOpen={isPowerBIOpen} onClose={() => setIsPowerBIOpen(false)} />
      <UnifiedMasterReportModal isOpen={isMasterReportOpen} onClose={() => setIsMasterReportOpen(false)} />
    </>
  );
}


