'use client';

import { useState, useEffect, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  Search, Globe, Bug, ShieldCheck, FileText, ScrollText,
  Server, ShieldAlert, Cpu, ArrowRight, X, Command, Code2, Network, Shield
} from 'lucide-react';
import clsx from 'clsx';

interface SearchItem {
  id: string;
  title: string;
  category: 'Asset' | 'Application' | 'Finding' | 'Control' | 'Risk' | 'Report' | 'Audit' | 'Navigation';
  subtitle: string;
  href: string;
  badge?: string;
}

const GLOBAL_SEARCH_ITEMS: SearchItem[] = [
  // Navigation
  { id: 'nav-tri-governance', title: 'Governança Tri-Pilar (Web + Mobile + Controles)', category: 'Navigation', subtitle: 'Laudo Consolidado Unificado, Score Ponderado & Gestão Executiva', href: '/executive-governance' },
  { id: 'nav-dash', title: 'Dashboard Executivo', category: 'Navigation', subtitle: 'Score de Saúde, 12M Trend, KPIs & Drill-Downs', href: '/dashboard' },
  { id: 'nav-aspm', title: 'AppSec / ASPM Posture', category: 'Navigation', subtitle: 'Checkmarx, GitHub AS, Quality Gates & Inventário de Apps', href: '/aspm' },
  { id: 'nav-compliance', title: 'Compliance & Controles (BACEN, PCI, CIS)', category: 'Navigation', subtitle: 'Matriz Regulatória, Catálogo CTRL-* & Audit Pack', href: '/compliance' },
  { id: 'nav-correlation', title: 'Security Correlation & Risk Engine', category: 'Navigation', subtitle: 'Grafo Multi-Plano, Risco Dinâmico & Aceite de Risco', href: '/correlation' },
  { id: 'nav-evidence', title: 'Evidence Vault (SHA-256)', category: 'Navigation', subtitle: 'Cofre de Evidências Auditáveis Criptografadas', href: '/evidence-vault' },
  { id: 'nav-integrations', title: 'Hub de Conectores Corporativos', category: 'Navigation', subtitle: 'Checkmarx, Microsoft, Snyk, Veracode, Akamai, CrowdStrike', href: '/integrations' },
  { id: 'nav-scanner', title: 'Scanner Multi-URLs & Pentest', category: 'Navigation', subtitle: 'Avaliação Ativa & Passiva de Superfície Externa', href: '/scan' },
  { id: 'nav-mobile', title: 'Mobile Pentest (APK/iOS)', category: 'Navigation', subtitle: 'Auditoria Estática e Dinâmica OWASP MASVS', href: '/mobile-pentest' },
  { id: 'nav-osint', title: 'OSINT Intelligence & Recon', category: 'Navigation', subtitle: 'Mapeamento de Perímetro e Enumeração DNS/SSL', href: '/osint' },


  // Applications
  { id: 'app-pix', title: 'Pix Core Transaction Engine', category: 'Application', subtitle: 'PIX-CORE-API — Retail Banking — Score 96.0', href: '/aspm', badge: 'CRITICAL' },
  { id: 'app-ib', title: 'Internet Banking Web Portal', category: 'Application', subtitle: 'IB-WEB-APP — Digital Channels — Score 91.5', href: '/aspm', badge: 'CRITICAL' },
  { id: 'app-credit', title: 'Credit Decisioning Engine', category: 'Application', subtitle: 'CREDIT-DECISION-SVC — Credit & Lending — Score 93.0', href: '/aspm', badge: 'HIGH' },
  { id: 'app-of', title: 'Open Finance Regulatory APIs', category: 'Application', subtitle: 'OPEN-FINANCE-API — BACEN Compliance — Score 98.0', href: '/aspm', badge: 'CRITICAL' },

  // Master Controls
  { id: 'ctrl-waf', title: 'CTRL-WAF-001: WAF L7 & Edge Shielding', category: 'Control', subtitle: 'BACEN Res. 4.893 Art. 3º / PCI DSS Req 6.4', href: '/compliance', badge: 'COMPLIANT' },
  { id: 'ctrl-tls', title: 'CTRL-TLS-001: Criptografia Forte TLS 1.2/1.3 & HSTS', category: 'Control', subtitle: 'NIST CSF PR.DS-2 / ISO 27001 8.20', href: '/compliance', badge: 'COMPLIANT' },
  { id: 'ctrl-dns', title: 'CTRL-DNS-001: E-mail Anti-Spoofing DMARC/SPF/CAA', category: 'Control', subtitle: 'RFC 7489 / CIS Controls v8 #9.5', href: '/compliance', badge: 'COMPLIANT' },
  { id: 'ctrl-iam', title: 'CTRL-IAM-001: Autenticação Forte MFA & FAPI 1.0', category: 'Control', subtitle: 'BACEN Art. 3º I / Open Finance Security', href: '/compliance', badge: 'COMPLIANT' },
  { id: 'ctrl-appsec', title: 'CTRL-APPSEC-001: Quality Gates CI/CD & SAST/SCA', category: 'Control', subtitle: 'Checkmarx + GitHub AS Quality Gates', href: '/compliance', badge: 'COMPLIANT' },

  // Assets
  { id: 'ast-shield', title: 'bancostellantis.com.br', category: 'Asset', subtitle: 'Internet-Facing Web Application — 104.18.22.10 — Akamai Shielded', href: '/attack-surface', badge: 'PROD' },
  { id: 'ast-pix', title: 'api-pix.bancostellantis.com.br', category: 'Asset', subtitle: 'Core Payment Gateway — 198.51.100.22 — Internal DMZ', href: '/attack-surface', badge: 'PROD' },
  { id: 'ast-of', title: 'openbanking.bancostellantis.com.br', category: 'Asset', subtitle: 'Regulatory Open Finance Gateway — 198.51.100.45', href: '/attack-surface', badge: 'PROD' },

  // Findings & Risks
  { id: 'fnd-csp', title: 'FND-000389: CSP Header Missing Strict Nonce', category: 'Finding', subtitle: 'Internet Banking Web — Medium — SLA On Track (480h left)', href: '/findings', badge: 'MEDIUM' },
  { id: 'fnd-rate', title: 'FND-000412: Inadequate Rate Limiting on Key Consultation', category: 'Finding', subtitle: 'Pix Core API — High — Mitigated by Akamai WAF Rule #4812', href: '/findings', badge: 'HIGH' },
];

export default function CommandPalette({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const router = useRouter();
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (isOpen) {
          onClose();
        } else {
          // Open
          (window as any).__openCommandPalette?.();
        }
      }
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const filteredItems = useMemo(() => {
    if (!query.trim()) return GLOBAL_SEARCH_ITEMS.slice(0, 8);
    const q = query.toLowerCase();
    return GLOBAL_SEARCH_ITEMS.filter(
      item =>
        item.title.toLowerCase().includes(q) ||
        item.subtitle.toLowerCase().includes(q) ||
        item.category.toLowerCase().includes(q)
    );
  }, [query]);

  const handleSelect = (item: SearchItem) => {
    onClose();
    router.push(item.href);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-black/70 backdrop-blur-md animate-fadeIn">
      <div
        className="w-full max-w-2xl bg-bg-secondary border border-bg-border rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[80vh]"
        onClick={e => e.stopPropagation()}
        style={{ boxShadow: '0 0 40px rgba(0, 212, 255, 0.15)' }}
      >
        {/* Header Search Input */}
        <div className="flex items-center gap-3 px-5 py-4 border-b border-bg-border bg-bg-primary/50">
          <Search className="w-5 h-5 text-accent-cyan flex-shrink-0 animate-pulse" />
          <input
            type="text"
            autoFocus
            placeholder="Pesquisar ativos, aplicações, controles BACEN/PCI, findings, riscos ou navegar... (ESC para fechar)"
            value={query}
            onChange={e => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            className="flex-1 bg-transparent border-none text-slate-100 text-sm focus:outline-none placeholder-slate-500 font-medium"
          />
          {query && (
            <button onClick={() => setQuery('')} className="text-slate-400 hover:text-slate-200">
              <X className="w-4 h-4" />
            </button>
          )}
          <kbd className="px-2 py-1 text-[10px] font-mono bg-bg-border text-slate-400 rounded-md border border-slate-700">
            ESC
          </kbd>
        </div>

        {/* Results List */}
        <div className="overflow-y-auto flex-1 p-2 space-y-1">
          {filteredItems.length === 0 ? (
            <div className="p-8 text-center text-slate-400">
              <Search className="w-8 h-8 mx-auto text-slate-600 mb-2" />
              <p className="text-sm font-medium">Nenhum resultado encontrado para &quot;{query}&quot;</p>
              <p className="text-xs text-slate-500 mt-1">Tente pesquisar por &quot;Pix&quot;, &quot;BACEN&quot;, &quot;WAF&quot;, &quot;ASPM&quot; ou &quot;Correlation&quot;.</p>
            </div>
          ) : (
            filteredItems.map((item, idx) => (
              <button
                key={item.id}
                onClick={() => handleSelect(item)}
                onMouseEnter={() => setSelectedIndex(idx)}
                className={clsx(
                  'w-full flex items-center justify-between gap-3 px-4 py-3 rounded-xl text-left transition-all',
                  idx === selectedIndex ? 'bg-accent-cyan/15 border border-accent-cyan/40 text-slate-100' : 'hover:bg-slate-800/40 border border-transparent text-slate-300'
                )}
              >
                <div className="flex items-center gap-3 min-w-0 flex-1">
                  <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 bg-slate-900 border border-slate-700">
                    {item.category === 'Application' && <Code2 className="w-4 h-4 text-accent-cyan" />}
                    {item.category === 'Control' && <ShieldCheck className="w-4 h-4 text-emerald-400" />}
                    {item.category === 'Asset' && <Globe className="w-4 h-4 text-blue-400" />}
                    {item.category === 'Finding' && <Bug className="w-4 h-4 text-amber-400" />}
                    {item.category === 'Navigation' && <ArrowRight className="w-4 h-4 text-indigo-400" />}
                    {item.category === 'Risk' && <ShieldAlert className="w-4 h-4 text-rose-400" />}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-semibold truncate">{item.title}</p>
                      {item.badge && (
                        <span className={clsx(
                          'px-1.5 py-0.5 text-[10px] font-mono font-bold rounded',
                          item.badge === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                          item.badge === 'COMPLIANT' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' :
                          'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                        )}>
                          {item.badge}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-400 truncate mt-0.5">{item.subtitle}</p>
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-shrink-0 text-xs text-slate-500 font-mono">
                  <span>{item.category}</span>
                  <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                </div>
              </button>
            ))
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2.5 bg-bg-primary/80 border-t border-bg-border flex items-center justify-between text-[11px] text-slate-400">
          <div className="flex items-center gap-3">
            <span>Navegue com <kbd className="px-1 py-0.5 bg-bg-border rounded text-slate-300">↑</kbd> <kbd className="px-1 py-0.5 bg-bg-border rounded text-slate-300">↓</kbd></span>
            <span>Pressione <kbd className="px-1.5 py-0.5 bg-bg-border rounded text-slate-300">ENTER</kbd> para selecionar</span>
          </div>
          <span className="text-accent-cyan font-mono">morfeusec Global Search</span>
        </div>
      </div>
    </div>
  );
}
