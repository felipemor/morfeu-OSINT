'use client';
import { useState } from 'react';
import { Check, ChevronDown, ChevronRight, Shield, Globe, Cpu, Network, Layers, Zap } from 'lucide-react';

export interface TestModule {
  id: string;
  name: string;
  category: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  intrusionLevel: 1 | 2 | 3; // 1=Passivo, 2=Ativo Seguro, 3=Intrusivo Total
  owasp?: string;
  cwe?: string;
}

export const ALL_TEST_MODULES: TestModule[] = [
  // ── Reconhecimento & OSINT ───────────────────────────────────────────────────
  { id: 'dns-enum', name: 'DNS Enumeration', category: 'Reconhecimento & OSINT', description: 'Enumeração completa de registros DNS (A, MX, NS, TXT, SPF, DKIM)', severity: 'MEDIUM', intrusionLevel: 1 },
  { id: 'subdomain-discovery', name: 'Subdomain Discovery', category: 'Reconhecimento & OSINT', description: 'Descoberta de subdomínios via wordlist e brute-force passivo', severity: 'HIGH', intrusionLevel: 1 },
  { id: 'whois-footprint', name: 'WHOIS & Footprinting', category: 'Reconhecimento & OSINT', description: 'Coleta de informações públicas via WHOIS, ARIN, RIPE', severity: 'LOW', intrusionLevel: 1 },
  { id: 'google-dorking', name: 'Google Dorking', category: 'Reconhecimento & OSINT', description: 'Busca por dados sensíveis expostos via Google e Shodan', severity: 'HIGH', intrusionLevel: 1 },
  { id: 'email-harvest', name: 'Email Harvesting', category: 'Reconhecimento & OSINT', description: 'Coleta de emails corporativos expostos publicamente', severity: 'MEDIUM', intrusionLevel: 1 },
  { id: 'tech-fingerprint', name: 'Technology Fingerprinting', category: 'Reconhecimento & OSINT', description: 'Identificação de tecnologias, frameworks e versões em uso', severity: 'MEDIUM', intrusionLevel: 1 },

  // ── Web Application (OWASP Top 10) ───────────────────────────────────────────
  { id: 'sqli', name: 'SQL Injection', category: 'Web Application (OWASP Top 10)', description: 'Testes de injeção SQL em todos os parâmetros (GET, POST, Headers, Cookies)', severity: 'CRITICAL', intrusionLevel: 2, owasp: 'A03:2021', cwe: 'CWE-89' },
  { id: 'xss-reflected', name: 'XSS — Reflected & Stored', category: 'Web Application (OWASP Top 10)', description: 'Cross-Site Scripting refletido, armazenado e DOM-based', severity: 'HIGH', intrusionLevel: 2, owasp: 'A03:2021', cwe: 'CWE-79' },
  { id: 'broken-auth', name: 'Broken Authentication', category: 'Web Application (OWASP Top 10)', description: 'Testes de autenticação fraca, session fixation, token predictability', severity: 'CRITICAL', intrusionLevel: 2, owasp: 'A07:2021', cwe: 'CWE-287' },
  { id: 'broken-access', name: 'Broken Access Control', category: 'Web Application (OWASP Top 10)', description: 'IDOR, escalada de privilégio, acesso a recursos não autorizados', severity: 'CRITICAL', intrusionLevel: 2, owasp: 'A01:2021', cwe: 'CWE-284' },
  { id: 'security-misconfig', name: 'Security Misconfiguration', category: 'Web Application (OWASP Top 10)', description: 'Headers HTTP ausentes, CORS mal configurado, diretórios expostos', severity: 'HIGH', intrusionLevel: 1, owasp: 'A05:2021', cwe: 'CWE-16' },
  { id: 'csrf', name: 'CSRF — Cross-Site Request Forgery', category: 'Web Application (OWASP Top 10)', description: 'Testes de falsificação de requisição cross-site', severity: 'HIGH', intrusionLevel: 2, owasp: 'A01:2021', cwe: 'CWE-352' },
  { id: 'ssrf', name: 'SSRF — Server-Side Request Forgery', category: 'Web Application (OWASP Top 10)', description: 'Testes de requisição forjada no servidor para acesso a recursos internos', severity: 'CRITICAL', intrusionLevel: 3, owasp: 'A10:2021', cwe: 'CWE-918' },
  { id: 'xxe', name: 'XXE Injection', category: 'Web Application (OWASP Top 10)', description: 'Injeção de entidades XML para LFI/SSRF', severity: 'HIGH', intrusionLevel: 2, owasp: 'A05:2021', cwe: 'CWE-611' },
  { id: 'insecure-deserialization', name: 'Insecure Deserialization', category: 'Web Application (OWASP Top 10)', description: 'Exploração de desserialização insegura para RCE', severity: 'CRITICAL', intrusionLevel: 3, owasp: 'A08:2021', cwe: 'CWE-502' },
  { id: 'vulnerable-components', name: 'Vulnerable & Outdated Components', category: 'Web Application (OWASP Top 10)', description: 'Identificação de componentes com CVEs conhecidas', severity: 'HIGH', intrusionLevel: 1, owasp: 'A06:2021', cwe: 'CWE-1104' },

  // ── Exploração Intrusiva ──────────────────────────────────────────────────────
  { id: 'brute-force', name: 'Authentication Brute Force', category: 'Exploração Intrusiva', description: 'Brute force em portais de login, SSH, FTP e painéis admin', severity: 'CRITICAL', intrusionLevel: 3, cwe: 'CWE-307' },
  { id: 'path-traversal', name: 'Path Traversal & LFI/RFI', category: 'Exploração Intrusiva', description: 'Travessia de diretórios e inclusão de arquivos locais/remotos', severity: 'CRITICAL', intrusionLevel: 3, cwe: 'CWE-22' },
  { id: 'file-upload', name: 'File Upload Exploitation', category: 'Exploração Intrusiva', description: 'Bypass de validação de upload para webshell ou RCE', severity: 'CRITICAL', intrusionLevel: 3, cwe: 'CWE-434' },
  { id: 'cmd-injection', name: 'Command Injection', category: 'Exploração Intrusiva', description: 'Injeção de comandos OS via parâmetros da aplicação', severity: 'CRITICAL', intrusionLevel: 3, cwe: 'CWE-78' },
  { id: 'business-logic', name: 'Business Logic Testing', category: 'Exploração Intrusiva', description: 'Manipulação de fluxos de negócio, preços, quantidades e permissões', severity: 'HIGH', intrusionLevel: 2 },
  { id: 'open-redirect', name: 'Open Redirect', category: 'Exploração Intrusiva', description: 'Redirecionamento para domínios externos não autorizados', severity: 'MEDIUM', intrusionLevel: 2, cwe: 'CWE-601' },
  { id: 'clickjacking', name: 'Clickjacking', category: 'Exploração Intrusiva', description: 'Ausência de X-Frame-Options e Content Security Policy', severity: 'MEDIUM', intrusionLevel: 1 },

  // ── Infraestrutura & Rede ─────────────────────────────────────────────────────
  { id: 'port-scan', name: 'Port Scanning', category: 'Infraestrutura & Rede', description: 'Varredura de portas TCP/UDP para descoberta de serviços', severity: 'MEDIUM', intrusionLevel: 2 },
  { id: 'service-fingerprint', name: 'Service Fingerprinting', category: 'Infraestrutura & Rede', description: 'Identificação de serviços e versões em execução', severity: 'MEDIUM', intrusionLevel: 1 },
  { id: 'ssl-tls', name: 'SSL/TLS Analysis', category: 'Infraestrutura & Rede', description: 'Protocolos fracos, certificados expirados, Heartbleed, BEAST, POODLE', severity: 'HIGH', intrusionLevel: 1 },
  { id: 'http-headers', name: 'HTTP Security Headers', category: 'Infraestrutura & Rede', description: 'Verificação de CSP, HSTS, X-Frame-Options, X-Content-Type-Options', severity: 'MEDIUM', intrusionLevel: 1 },
  { id: 'cors-analysis', name: 'CORS Misconfiguration', category: 'Infraestrutura & Rede', description: 'Análise de política CORS para acesso cross-origin não autorizado', severity: 'HIGH', intrusionLevel: 2 },

  // ── API Security ──────────────────────────────────────────────────────────────
  { id: 'api-discovery', name: 'API Endpoint Discovery', category: 'API Security', description: 'Descoberta de endpoints via fuzzing, Swagger e JavaScript analysis', severity: 'HIGH', intrusionLevel: 2 },
  { id: 'bola', name: 'BOLA — Broken Object Level Auth', category: 'API Security', description: 'Acesso não autorizado a objetos de outros usuários via IDs', severity: 'CRITICAL', intrusionLevel: 3, cwe: 'CWE-639' },
  { id: 'excessive-data', name: 'Excessive Data Exposure', category: 'API Security', description: 'APIs que retornam dados além do necessário (PII, tokens, etc.)', severity: 'HIGH', intrusionLevel: 2 },
  { id: 'mass-assignment', name: 'Mass Assignment', category: 'API Security', description: 'Modificação de campos protegidos via requisições de API', severity: 'HIGH', intrusionLevel: 2 },
  { id: 'rate-limit', name: 'Rate Limiting & DoS', category: 'API Security', description: 'Ausência de rate limiting para endpoints críticos', severity: 'MEDIUM', intrusionLevel: 2 },
  { id: 'jwt-attack', name: 'JWT Token Attacks', category: 'API Security', description: 'Algoritmo none, key confusion, weak secrets em JWTs', severity: 'CRITICAL', intrusionLevel: 3, cwe: 'CWE-345' },
];

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  'Reconhecimento & OSINT': <Globe className="w-4 h-4" />,
  'Web Application (OWASP Top 10)': <Shield className="w-4 h-4" />,
  'Exploração Intrusiva': <Zap className="w-4 h-4" />,
  'Infraestrutura & Rede': <Network className="w-4 h-4" />,
  'API Security': <Layers className="w-4 h-4" />,
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-yellow-400',
  LOW: 'text-green-400',
};

const INTRUSION_LABELS: Record<number, { label: string; color: string }> = {
  1: { label: 'Passivo', color: 'text-green-400 bg-green-500/10 border-green-500/30' },
  2: { label: 'Ativo', color: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30' },
  3: { label: 'Intrusivo', color: 'text-red-400 bg-red-500/10 border-red-500/30' },
};

interface TestModuleSelectorProps {
  selected: string[];
  onChange: (selected: string[]) => void;
  maxIntrusionLevel?: 1 | 2 | 3;
}

export default function TestModuleSelector({
  selected,
  onChange,
  maxIntrusionLevel = 3,
}: TestModuleSelectorProps) {
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    new Set(['Web Application (OWASP Top 10)', 'Exploração Intrusiva'])
  );

  const categories = Array.from(new Set(ALL_TEST_MODULES.map(m => m.category)));

  const filteredModules = ALL_TEST_MODULES.filter(m => m.intrusionLevel <= maxIntrusionLevel);

  function toggleCategory(cat: string) {
    setExpandedCategories(prev => {
      const n = new Set(prev);
      if (n.has(cat)) n.delete(cat);
      else n.add(cat);
      return n;
    });
  }

  function toggleModule(id: string) {
    if (selected.includes(id)) {
      onChange(selected.filter(s => s !== id));
    } else {
      onChange([...selected, id]);
    }
  }

  function toggleCategory_select(cat: string) {
    const catModules = filteredModules.filter(m => m.category === cat).map(m => m.id);
    const allSelected = catModules.every(id => selected.includes(id));
    if (allSelected) {
      onChange(selected.filter(id => !catModules.includes(id)));
    } else {
      const toAdd = catModules.filter(id => !selected.includes(id));
      onChange([...selected, ...toAdd]);
    }
  }

  function selectAll() {
    onChange(filteredModules.map(m => m.id));
  }

  function selectNone() {
    onChange([]);
  }

  function selectByIntrusion(level: 1 | 2 | 3) {
    onChange(filteredModules.filter(m => m.intrusionLevel <= level).map(m => m.id));
  }

  const totalAvailable = filteredModules.length;

  return (
    <div className="space-y-3">
      {/* Quick select bar */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-slate-500">Seleção rápida:</span>
        <button
          onClick={() => selectByIntrusion(1)}
          className="px-2.5 py-1 rounded text-xs border border-green-500/30 text-green-400 hover:bg-green-500/10 transition-colors"
        >
          ✓ Passivos ({filteredModules.filter(m => m.intrusionLevel === 1).length})
        </button>
        <button
          onClick={() => selectByIntrusion(2)}
          className="px-2.5 py-1 rounded text-xs border border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10 transition-colors"
        >
          ⚡ Ativos ({filteredModules.filter(m => m.intrusionLevel <= 2).length})
        </button>
        <button
          onClick={selectAll}
          className="px-2.5 py-1 rounded text-xs border border-red-500/30 text-red-400 hover:bg-red-500/10 transition-colors"
        >
          💥 Todos / Intrusivos ({totalAvailable})
        </button>
        <button
          onClick={selectNone}
          className="px-2.5 py-1 rounded text-xs border border-slate-600 text-slate-400 hover:bg-slate-700 transition-colors ml-auto"
        >
          Limpar
        </button>
        <span className="text-xs text-accent-cyan font-semibold">
          {selected.length}/{totalAvailable} selecionados
        </span>
      </div>

      {/* Categories */}
      {categories.map(cat => {
        const catModules = filteredModules.filter(m => m.category === cat);
        if (catModules.length === 0) return null;
        const isExpanded = expandedCategories.has(cat);
        const selectedInCat = catModules.filter(m => selected.includes(m.id)).length;
        const allSelectedInCat = selectedInCat === catModules.length;
        const someSelectedInCat = selectedInCat > 0 && !allSelectedInCat;

        return (
          <div key={cat} className="border border-bg-border rounded-xl overflow-hidden">
            {/* Category header */}
            <div
              className={`flex items-center gap-3 px-4 py-3 cursor-pointer transition-colors ${
                isExpanded ? 'bg-bg-secondary/60' : 'bg-bg-primary/40'
              } hover:bg-bg-secondary/80`}
            >
              {/* Checkbox for category */}
              <button
                onClick={e => { e.stopPropagation(); toggleCategory_select(cat); }}
                className={`w-5 h-5 rounded flex items-center justify-center flex-shrink-0 border transition-colors ${
                  allSelectedInCat
                    ? 'bg-accent-cyan border-accent-cyan'
                    : someSelectedInCat
                    ? 'bg-accent-cyan/40 border-accent-cyan/60'
                    : 'border-slate-600 bg-transparent hover:border-accent-cyan/50'
                }`}
              >
                {(allSelectedInCat || someSelectedInCat) && (
                  <Check className="w-3 h-3 text-bg-primary" />
                )}
              </button>

              <div
                className="flex-1 flex items-center gap-2 min-w-0"
                onClick={() => toggleCategory(cat)}
              >
                <span className={`flex-shrink-0 ${selectedInCat > 0 ? 'text-accent-cyan' : 'text-slate-500'}`}>
                  {CATEGORY_ICONS[cat] || <Cpu className="w-4 h-4" />}
                </span>
                <span className="text-sm font-semibold text-slate-200">{cat}</span>
                <span className="text-xs text-slate-500 ml-1">
                  {selectedInCat > 0 ? (
                    <span className="text-accent-cyan">{selectedInCat}/</span>
                  ) : ''}
                  {catModules.length} módulos
                </span>
              </div>
              <div onClick={() => toggleCategory(cat)}>
                {isExpanded
                  ? <ChevronDown className="w-4 h-4 text-slate-500" />
                  : <ChevronRight className="w-4 h-4 text-slate-500" />
                }
              </div>
            </div>

            {/* Module list */}
            {isExpanded && (
              <div className="divide-y divide-bg-border/30">
                {catModules.map(mod => {
                  const isSelected = selected.includes(mod.id);
                  const intrusion = INTRUSION_LABELS[mod.intrusionLevel];

                  return (
                    <div
                      key={mod.id}
                      onClick={() => toggleModule(mod.id)}
                      className={`flex items-start gap-3 px-4 py-2.5 cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-accent-cyan/5 border-l-2 border-l-accent-cyan'
                          : 'hover:bg-white/[0.02] border-l-2 border-l-transparent'
                      }`}
                    >
                      {/* Checkbox */}
                      <div
                        className={`w-4 h-4 mt-0.5 rounded flex items-center justify-center flex-shrink-0 border transition-colors ${
                          isSelected
                            ? 'bg-accent-cyan border-accent-cyan'
                            : 'border-slate-600 bg-transparent'
                        }`}
                      >
                        {isSelected && <Check className="w-2.5 h-2.5 text-bg-primary" />}
                      </div>

                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`text-sm font-medium ${isSelected ? 'text-slate-100' : 'text-slate-300'}`}>
                            {mod.name}
                          </span>
                          <span className={`text-[10px] font-bold ${SEVERITY_COLORS[mod.severity]}`}>
                            {mod.severity}
                          </span>
                          <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium ${intrusion.color}`}>
                            {intrusion.label}
                          </span>
                          {mod.owasp && (
                            <span className="text-[10px] text-purple-400 opacity-60">{mod.owasp}</span>
                          )}
                        </div>
                        <p className="text-xs text-slate-500 mt-0.5 line-clamp-1">{mod.description}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
