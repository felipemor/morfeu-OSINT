'use client';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useState, useEffect } from 'react';
import dynamic from 'next/dynamic';
import {
  Shield, LayoutDashboard, FolderKanban, Globe,
  Bug, ScrollText, ChevronLeft, ChevronRight, ChevronDown, LogOut, User, Crosshair, FileText, Radar, ShieldCheck, Smartphone, Activity, Network, ShieldAlert, BarChart2, BarChart3, ExternalLink, Sparkles, Users, Crown, Code2, Award, FileCheck2, Layers, Search, Bot, Wrench, CheckSquare, Lock, CreditCard, Radio, Compass, Key
} from 'lucide-react';
import { authApi } from '@/lib/api';
import clsx from 'clsx';
import CommandPalette from '@/components/CommandPalette';

// Dynamic imports para otimização do FCP e redução do bundle inicial
const PowerBIModal = dynamic(() => import('@/components/PowerBIModal'), { ssr: false });
const UnifiedMasterReportModal = dynamic(() => import('@/components/UnifiedMasterReportModal'), { ssr: false });
const SecurityCopilotModal = dynamic(() => import('@/components/SecurityCopilotModal'), { ssr: false });
const UnifiedScanModal = dynamic(() => import('@/components/UnifiedScanModal'), { ssr: false });
const PurgeAllModal = dynamic(() => import('@/components/PurgeAllModal'), { ssr: false });

import { useLanguage } from '@/context/LanguageContext';

const navigationCategories = [
  {
    id: 'apex_governance',
    key: 'suite.governance',
    title: 'HEIMDALL APEX™ (C-Level & Boardroom)',
    badge: 'GOVERNANCE',
    items: [
      { key: 'menu.dashboard', name: 'Executive Master Dashboard', href: '/dashboard', icon: LayoutDashboard },
      { key: 'menu.executiveGovernance', name: 'Governança Tri-Pilar (Estratégico)', href: '/executive-governance', icon: ShieldCheck },
      { key: 'menu.grafanaAnalytics', name: 'Grafana Cyber Analytics', href: '/grafana-analytics', icon: BarChart2 },
      { key: 'menu.compliance', name: 'Compliance & BACEN Res. 85', href: '/compliance', icon: Award },
    ]
  },
  {
    id: 'offensive_red',
    key: 'suite.offensive',
    title: 'HEIMDALL RED™ (Pentest & EASM)',
    badge: 'OFFENSIVE',
    items: [
      { key: 'menu.pentestHub', name: 'Pentest Hub (Multi-Scanner)', href: '/pentest-hub', icon: Crosshair },
      { key: 'menu.easm', name: 'EASM & Dark Web Tor Monitor', href: '/easm', icon: Radio },
      { key: 'menu.attackSurface', name: 'Attack Surface Management (ASM)', href: '/attack-surface', icon: Globe },
      { key: 'menu.osint', name: 'OSINT Recon Intelligence', href: '/osint', icon: Radar },
      { key: 'menu.mobilePentest', name: 'Mobile Pentest (APK & iOS)', href: '/mobile-pentest', icon: Smartphone },
    ]
  },
  {
    id: 'fraudintel_brand',
    key: 'suite.antifraud',
    title: 'FRAUDINTEL & BRANDSHIELD™ (Anti-Fraude)',
    badge: 'ANTI-FRAUD',
    items: [
      { key: 'menu.fraudintel', name: 'FRAUDINTEL Investigation Engine', href: '/fraudintel', icon: Compass },
      { key: 'menu.brandProtection', name: 'Brand Protection & Takedown Radar', href: '/brand-protection', icon: ShieldAlert },
      { key: 'menu.fiscalForensic', name: 'Fiscal Forensic & Clones de CNPJ', href: '/fiscal-forensic', icon: FileCheck2 },
      { key: 'menu.boletoValidator', name: 'Validador de Boletos & Defesa BIN', href: '/boleto-validator', icon: CreditCard },
    ]
  },
  {
    id: 'aegis_posture',
    key: 'suite.defensive',
    title: 'AEGIS LATTICE & SOC™ (Criptografia & Postura Defensiva)',
    badge: 'DEFENSIVE',
    items: [
      { key: 'menu.cryptoPki', name: 'Certificados & PKI Studio', href: '/crypto-pki', icon: Key },
      { key: 'menu.aegislattice', name: 'AegisLattice Post-Quantum Defense', href: '/aegislattice', icon: ShieldCheck },
      { key: 'menu.findings', name: 'Central de Findings & Riscos', href: '/findings', icon: Bug },
      { key: 'menu.remediation', name: 'Guia de Remediação Priorizada', href: '/remediation', icon: Wrench },
      { key: 'menu.evidenceVault', name: 'Evidence Vault (SHA-256 Custódia)', href: '/evidence-vault', icon: Lock },
      { key: 'menu.correlation', name: 'Correlation & Risco Cruzado', href: '/correlation', icon: Network },
    ]
  },
  {
    id: 'code_quality_appsec',
    key: 'suite.appsec',
    title: 'HEIMDALL CODE QUALITY™ (AppSec & Refactor)',
    badge: 'APPSEC',
    items: [
      { key: 'menu.codeHumanizer', name: 'AI Code Humanizer & Refactor', href: '/code-humanizer', icon: Sparkles },
      { key: 'menu.aspm', name: 'AppSec / ASPM Posture Gates', href: '/aspm', icon: Code2 },
    ]
  },
  {
    id: 'operations_management',
    key: 'suite.management',
    title: 'Gestão & Trilha de Auditoria',
    badge: 'CORE',
    items: [
      { key: 'menu.projects', name: 'Projetos & Workspaces', href: '/projects', icon: FolderKanban },
      { key: 'menu.reports', name: 'Central de Relatórios PDF/XLSX', href: '/reports', icon: FileText },
      { key: 'menu.integrations', name: 'Conectores SIEM & Cloud Hub', href: '/integrations', icon: Layers },
      { key: 'menu.auditLogs', name: 'Audit Trail Imutável (Compliance)', href: '/audit-logs', icon: ScrollText },
    ]
  },
];

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const { t } = useLanguage();
  const [collapsed, setCollapsed] = useState(false);
  const [user, setUser] = useState<any>(null);
  const [isPowerBIOpen, setIsPowerBIOpen] = useState(false);
  const [isMasterReportOpen, setIsMasterReportOpen] = useState(false);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);
  const [isUnifiedScanOpen, setIsUnifiedScanOpen] = useState(false);
  const [isPurgeOpen, setIsPurgeOpen] = useState(false);
  
  // Categorias de produtos expandidas por padrão
  const [openCategories, setOpenCategories] = useState<Record<string, boolean>>({
    apex_governance: true,
    offensive_red: true,
    fraudintel_brand: true,
    aegis_posture: true,
    code_quality_appsec: true,
    operations_management: true,
  });

  useEffect(() => {
    (window as any).__openCommandPalette = () => setIsCommandPaletteOpen(true);
    (window as any).__openCopilot = () => setIsCopilotOpen(true);
    (window as any).__openUnifiedScan = () => setIsUnifiedScanOpen(true);
    (window as any).__openPurgeAll = () => setIsPurgeOpen(true);
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
          <div className="flex-shrink-0 w-9 h-9 rounded-xl flex items-center justify-center overflow-hidden bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-400/40 text-cyan-400 shadow-lg shadow-cyan-500/20">
            <Shield className="w-5 h-5 fill-current" />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <p className="text-sm font-black text-white truncate tracking-tight" title="Heimdall Security">
                HEIMDALL
              </p>
              <p className="text-[10px] font-bold text-cyan-400 font-mono -mt-0.5">SECURITY</p>
            </div>
          )}
          <button onClick={() => setCollapsed(!collapsed)}
            className="ml-auto text-slate-500 hover:text-slate-300 transition-colors flex-shrink-0">
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Global Tools Header Buttons */}
        <div className="p-2 border-b border-bg-border/60 space-y-1.5">
          {/* 1-Click Unified Scan Trigger */}
          <button
            onClick={() => setIsUnifiedScanOpen(true)}
            className={clsx(
              "w-full px-3 py-2 rounded-xl font-black text-xs flex items-center gap-2.5 transition-all shadow-lg",
              "bg-gradient-to-r from-cyan-500/25 via-blue-500/20 to-purple-500/25 border border-cyan-400/50 text-cyan-200 hover:border-cyan-300 hover:text-white group"
            )}
            title="Executar Scan Unificado em todos os módulos simultâneos"
          >
            <Sparkles className="w-4 h-4 flex-shrink-0 text-cyan-400 group-hover:rotate-12 transition-transform" />
            {!collapsed && (
              <span className="truncate flex-1 text-left tracking-tight">{t('nav.unifiedScan', 'Scan Unificado 360°')}</span>
            )}
          </button>

          {/* Global Search / Command Palette (Ctrl+K) */}
          <button
            onClick={() => setIsCommandPaletteOpen(true)}
            className={clsx(
              "w-full px-3 py-2 rounded-xl font-bold text-xs flex items-center gap-2.5 transition-all shadow-md",
              "bg-slate-900/90 border border-slate-700 text-slate-300 hover:border-accent-cyan hover:text-accent-cyan group"
            )}
            title={t('nav.globalSearch', 'Busca Global') + ' (CTRL + K)'}
          >
            <Search className="w-4 h-4 flex-shrink-0 text-accent-cyan group-hover:scale-110 transition-transform" />
            {!collapsed && (
              <div className="flex items-center justify-between flex-1">
                <span className="truncate text-left">{t('nav.globalSearch', 'Busca Global')}</span>
                <kbd className="px-1.5 py-0.5 text-[9px] font-mono bg-slate-800 border border-slate-700 text-slate-400 rounded">
                  Ctrl+K
                </kbd>
              </div>
            )}
          </button>

          {/* Security Copilot (Raven AI) */}
          <button
            onClick={() => setIsCopilotOpen(true)}
            className={clsx(
              "w-full px-3 py-2 rounded-xl font-bold text-xs flex items-center gap-2.5 transition-all shadow-md",
              "bg-gradient-to-r from-purple-500/20 via-accent-cyan/20 to-purple-500/10 border border-purple-500/40 text-purple-200 hover:border-accent-cyan hover:text-accent-cyan group"
            )}
            title="Raven AI — Posture Analysis & Copilot"
          >
            <Bot className="w-4 h-4 flex-shrink-0 text-accent-cyan group-hover:scale-110 transition-transform" />
            {!collapsed && (
              <span className="truncate flex-1 text-left font-extrabold">{t('nav.ravenCopilot', 'Raven AI Copilot')}</span>
            )}
          </button>

          <button
            onClick={() => setIsMasterReportOpen(true)}
            className={clsx(
              "w-full px-3 py-2 rounded-xl font-bold text-xs flex items-center gap-2.5 transition-all shadow-md",
              "bg-gradient-to-r from-emerald-500/20 via-accent-cyan/20 to-emerald-500/10 border border-emerald-500/40 text-emerald-300 hover:border-accent-cyan hover:text-emerald-200 group"
            )}
            title="Gerar Laudo Consolidado 360°"
          >
            <Sparkles className="w-4 h-4 flex-shrink-0 text-accent-cyan group-hover:rotate-12 transition-transform" />
            {!collapsed && (
              <span className="truncate flex-1 text-left font-extrabold">{t('nav.masterReport', 'Laudo Consolidado')}</span>
            )}
          </button>

          {/* Global Purge All Button */}
          <button
            onClick={() => setIsPurgeOpen(true)}
            className={clsx(
              "w-full px-3 py-1.5 rounded-xl font-medium text-[11px] flex items-center gap-2 transition-all",
              "bg-red-950/20 border border-red-500/20 text-red-400/80 hover:border-red-500/50 hover:text-red-300 hover:bg-red-950/40 group"
            )}
            title="Expurgar e resetar dados"
          >
            <ShieldAlert className="w-3.5 h-3.5 flex-shrink-0 text-red-400 group-hover:scale-110 transition-transform" />
            {!collapsed && (
              <span className="truncate flex-1 text-left">{t('nav.resetAll', 'Reset Geral / Purge')}</span>
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
                    <span className="truncate">{t(cat.key, cat.title)}</span>
                    <ChevronDown className={clsx('w-3 h-3 transition-transform duration-200', !isOpen && '-rotate-90')} />
                  </button>
                )}

                {(isOpen || collapsed) && (
                  <div className="space-y-0.5">
                    {cat.items.map(item => {
                      const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
                      const translatedName = t(item.key, item.name);
                      return (
                        <Link
                          key={item.href}
                          href={item.href}
                          className={clsx('sidebar-item', isActive && 'active', collapsed && 'justify-center px-0')}
                          title={collapsed ? translatedName : undefined}
                        >
                          <item.icon className={clsx('flex-shrink-0', collapsed ? 'w-5 h-5' : 'w-4 h-4')} />
                          {!collapsed && <span className="truncate">{translatedName}</span>}
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
                <p className="text-slate-400 font-mono text-[9px] truncate select-all">felipe_c@myyahoo.com</p>
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
      {isUnifiedScanOpen && <UnifiedScanModal isOpen={isUnifiedScanOpen} onClose={() => setIsUnifiedScanOpen(false)} />}
      {isPurgeOpen && <PurgeAllModal isOpen={isPurgeOpen} onClose={() => setIsPurgeOpen(false)} onSuccess={() => router.refresh()} />}
    </>
  );
}




