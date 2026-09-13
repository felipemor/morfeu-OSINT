'use client';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useState, useEffect } from 'react';
import dynamic from 'next/dynamic';
import {
  Shield, LayoutDashboard, FolderKanban, Globe,
  Bug, ScrollText, ChevronLeft, ChevronRight, ChevronDown, LogOut, User, Crosshair, FileText, Radar, ShieldCheck, Smartphone, Activity, Network, ShieldAlert, BarChart2, BarChart3, ExternalLink, Sparkles, Users, Crown, Code2, Award, FileCheck2, Layers, Search, Bot, Wrench, CheckSquare
} from 'lucide-react';
import { authApi } from '@/lib/api';
import clsx from 'clsx';
import CommandPalette from '@/components/CommandPalette';

// Dynamic imports para otimização do FCP e redução do bundle inicial
const PowerBIModal = dynamic(() => import('@/components/PowerBIModal'), { ssr: false });
const UnifiedMasterReportModal = dynamic(() => import('@/components/UnifiedMasterReportModal'), { ssr: false });
const SecurityCopilotModal = dynamic(() => import('@/components/SecurityCopilotModal'), { ssr: false });

const navigationCategories = [
  {
    id: 'governance',
    title: 'Governança & Analytics',
    items: [
      { name: 'Dashboard Executivo', href: '/dashboard', icon: LayoutDashboard },
      { name: 'Governança Tri-Pilar', href: '/executive-governance', icon: ShieldCheck },
      { name: 'Grafana Analytics', href: '/grafana-analytics', icon: BarChart2 },
    ]
  },
  {
    id: 'offensive',
    title: 'Operações Ofensivas & EASM',
    items: [
      { name: 'Scanner Multi-URLs', href: '/scan', icon: Crosshair },
      { name: 'Attack Surface', href: '/attack-surface', icon: Globe },
      { name: 'OSINT Intelligence', href: '/osint', icon: Radar },
      { name: 'Mobile Pentest (APK/iOS)', href: '/mobile-pentest', icon: Smartphone },
    ]
  },
  {
    id: 'vulnerabilities',
    title: 'Vulnerabilidades & Risco',
    items: [
      { name: 'Central de Findings', href: '/findings', icon: Bug },
      { name: 'Guia de Remediação', href: '/remediation', icon: Wrench },
      { name: 'Evidence Vault (SHA-256)', href: '/evidence-vault', icon: FileCheck2 },
      { name: 'Correlation & Risco', href: '/correlation', icon: Network },
    ]
  },
  {
    id: 'posture',
    title: 'Postura & Compliance',
    items: [
      { name: 'Controles de Segurança', href: '/security-controls', icon: ShieldCheck },
      { name: 'AppSec / ASPM Posture', href: '/aspm', icon: Code2 },
      { name: 'Compliance & BACEN', href: '/compliance', icon: Award },
    ]
  },
  {
    id: 'operations',
    title: 'Operações & Sistema',
    items: [
      { name: 'Projetos', href: '/projects', icon: FolderKanban },
      { name: 'Central de Reports', href: '/reports', icon: FileText },
      { name: 'Hub de Conectores', href: '/integrations', icon: Layers },
      { name: 'Audit Logs', href: '/audit-logs', icon: ScrollText },
    ]
  },
];

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const [collapsed, setCollapsed] = useState(false);
  const [user, setUser] = useState<any>(null);
  const [isPowerBIOpen, setIsPowerBIOpen] = useState(false);
  const [isMasterReportOpen, setIsMasterReportOpen] = useState(false);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);
  
  // Categorias expandidas por padrão. Se houver caminho ativo, a categoria correspondente é expandida.
  const [openCategories, setOpenCategories] = useState<Record<string, boolean>>({
    governance: true,
    offensive: true,
    vulnerabilities: true,
    posture: true,
    operations: true,
  });

  useEffect(() => {
    (window as any).__openCommandPalette = () => setIsCommandPaletteOpen(true);
    (window as any).__openCopilot = () => setIsCopilotOpen(true);
  }, []);

  useEffect(() => {
    setUser(authApi.getUser());
  }, []);

  const toggleCategory = (catId: string) => {
    setOpenCategories(prev => ({ ...prev, [catId]: !prev[catId] }));
  };

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

        {/* Global Tools Header Buttons */}
        <div className="p-2 border-b border-bg-border/60 space-y-1.5">
          {/* Global Search / Command Palette (Ctrl+K) */}
          <button
            onClick={() => setIsCommandPaletteOpen(true)}
            className={clsx(
              "w-full px-3 py-2 rounded-xl font-bold text-xs flex items-center gap-2.5 transition-all shadow-md",
              "bg-slate-900/90 border border-slate-700 text-slate-300 hover:border-accent-cyan hover:text-accent-cyan group"
            )}
            title="Abrir busca global da plataforma (CTRL + K)"
          >
            <Search className="w-4 h-4 flex-shrink-0 text-accent-cyan group-hover:scale-110 transition-transform" />
            {!collapsed && (
              <div className="flex items-center justify-between flex-1">
                <span className="truncate text-left">Busca Global</span>
                <kbd className="px-1.5 py-0.5 text-[9px] font-mono bg-slate-800 border border-slate-700 text-slate-400 rounded">
                  Ctrl+K
                </kbd>
              </div>
            )}
          </button>

          {/* Security Copilot (AI Analyst) */}
          <button
            onClick={() => setIsCopilotOpen(true)}
            className={clsx(
              "w-full px-3 py-2 rounded-xl font-bold text-xs flex items-center gap-2.5 transition-all shadow-md",
              "bg-gradient-to-r from-purple-500/20 via-accent-cyan/20 to-purple-500/10 border border-purple-500/40 text-purple-200 hover:border-accent-cyan hover:text-accent-cyan group"
            )}
            title="Abrir Security Copilot — IA Analista de Postura e Governança"
          >
            <Bot className="w-4 h-4 flex-shrink-0 text-accent-cyan group-hover:scale-110 transition-transform" />
            {!collapsed && (
              <span className="truncate flex-1 text-left font-extrabold">Security Copilot (IA)</span>
            )}
          </button>

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
              <span className="truncate flex-1 text-left">PowerBI REST APIs</span>
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
              <span className="truncate flex-1 text-left font-extrabold">Laudo Consolidado</span>
            )}
          </button>
        </div>

        {/* Categorized Nav */}
        <nav className="flex-1 py-3 px-2 space-y-3 overflow-y-auto custom-scrollbar">
          {user?.role === 'ADMIN' && (
            <Link
              href="/admin/users"
              className={clsx(
                'sidebar-item font-bold text-amber-300 bg-amber-500/10 border border-amber-500/30 hover:bg-amber-500/20 mb-2',
                (pathname === '/admin/users' || pathname.startsWith('/admin/users/')) && 'active',
                collapsed && 'justify-center px-0'
              )}
            >
              <Crown className={clsx('flex-shrink-0 text-amber-400', collapsed ? 'w-5 h-5' : 'w-4 h-4')} />
              {!collapsed && <span className="truncate">Gerenciamento de Acessos</span>}
            </Link>
          )}

          {navigationCategories.map(cat => {
            const hasActiveChild = cat.items.some(item => pathname === item.href || pathname.startsWith(item.href + '/'));
            const isOpen = openCategories[cat.id] ?? true;

            return (
              <div key={cat.id} className="space-y-1">
                {!collapsed && (
                  <button
                    onClick={() => toggleCategory(cat.id)}
                    className="w-full flex items-center justify-between px-2 py-1 text-[11px] font-bold tracking-wider text-slate-400 uppercase hover:text-accent-cyan transition-colors"
                  >
                    <span className="truncate">{cat.title}</span>
                    <ChevronDown className={clsx('w-3 h-3 transition-transform duration-200', !isOpen && '-rotate-90')} />
                  </button>
                )}

                {(isOpen || collapsed) && (
                  <div className="space-y-0.5">
                    {cat.items.map(item => {
                      const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
                      return (
                        <Link
                          key={item.href}
                          href={item.href}
                          className={clsx('sidebar-item', isActive && 'active', collapsed && 'justify-center px-0')}
                          title={collapsed ? item.name : undefined}
                        >
                          <item.icon className={clsx('flex-shrink-0', collapsed ? 'w-5 h-5' : 'w-4 h-4')} />
                          {!collapsed && <span className="truncate">{item.name}</span>}
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>
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

      {isPowerBIOpen && <PowerBIModal isOpen={isPowerBIOpen} onClose={() => setIsPowerBIOpen(false)} />}
      {isMasterReportOpen && <UnifiedMasterReportModal isOpen={isMasterReportOpen} onClose={() => setIsMasterReportOpen(false)} />}
      <CommandPalette isOpen={isCommandPaletteOpen} onClose={() => setIsCommandPaletteOpen(false)} />
      {isCopilotOpen && <SecurityCopilotModal isOpen={isCopilotOpen} onClose={() => setIsCopilotOpen(false)} />}
    </>
  );
}




