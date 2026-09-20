'use client';

import React, { createContext, useContext, useState, useEffect } from 'react';

export type Locale = 'pt' | 'en' | 'es';

export interface LanguageOption {
  code: Locale;
  label: string;
  flag: string;
  name: string;
}

export const LANGUAGES: LanguageOption[] = [
  { code: 'pt', label: 'PT', flag: '🇧🇷', name: 'Português' },
  { code: 'en', label: 'EN', flag: '🇺🇸', name: 'English' },
  { code: 'es', label: 'ES', flag: '🇪🇸', name: 'Español' },
];

export const DICTIONARY: Record<Locale, Record<string, string>> = {
  pt: {
    // Top Bar & Global Actions
    'nav.unifiedScan': '⚡ Scan Unificado 360°',
    'nav.globalSearch': 'Busca Global',
    'nav.ravenCopilot': 'Raven AI Copilot',
    'nav.masterReport': 'Laudo Consolidado',
    'nav.resetAll': 'Reset Geral',
    'nav.hubPentest': 'Hub Pentest',
    'nav.logout': 'Encerrar Sessão',
    'nav.language': 'Idioma',

    // Product Suites
    'suite.governance': 'HEIMDALL APEX™ (C-Level & Boardroom)',
    'suite.governance.desc': 'Governança C-Level, Tri-Pilar e Boardroom Compliance.',
    'suite.offensive': 'HEIMDALL RED™ (Pentest & EASM)',
    'suite.offensive.desc': 'Pentest Autônomo, EASM Dark Web e Mobile Pentest.',
    'suite.antifraud': 'FRAUDINTEL & BRANDSHIELD™ (Anti-Fraude)',
    'suite.antifraud.desc': 'Investigação de Fraudes, Takedowns e Clones de CNPJ.',
    'suite.defensive': 'AEGIS LATTICE & SOC™ (Criptografia & Postura Defensiva)',
    'suite.defensive.desc': 'Postura Defensiva, Criptografia PQC e Custódia SHA-256.',
    'suite.appsec': 'HEIMDALL CODE QUALITY™ (AppSec & Refactor)',
    'suite.appsec.desc': 'AI Code Humanizer, AST Refactor e SAST/ASPM Gates.',
    'suite.management': 'Gestão & Trilha de Auditoria',

    // Menu Navigation Items
    'menu.dashboard': 'Executive Master Dashboard',
    'menu.executiveGovernance': 'Governança Tri-Pilar (Estratégico)',
    'menu.grafanaAnalytics': 'Grafana Cyber Analytics',
    'menu.compliance': 'Compliance & BACEN Res. 85',
    'menu.pentestHub': 'Pentest Hub (Multi-Scanner)',
    'menu.easm': 'EASM & Dark Web Tor Monitor',
    'menu.attackSurface': 'Attack Surface Management (ASM)',
    'menu.osint': 'OSINT Recon Intelligence',
    'menu.mobilePentest': 'Mobile Pentest (APK & iOS)',
    'menu.fraudintel': 'FRAUDINTEL Investigation Engine',
    'menu.brandProtection': 'Brand Protection & Takedown Radar',
    'menu.fiscalForensic': 'Fiscal Forensic & Clones de CNPJ',
    'menu.boletoValidator': 'Validador de Boletos & Defesa BIN',
    'menu.findings': 'Central de Findings & Riscos',
    'menu.remediation': 'Guia de Remediação Priorizada',
    'menu.evidenceVault': 'Evidence Vault (SHA-256 Custódia)',
    'menu.correlation': 'Correlation & Risco Cruzado',
    'menu.cryptoPki': 'Certificados & PKI Studio',
    'menu.aegislattice': 'AegisLattice Post-Quantum Defense',
    'menu.codeHumanizer': 'AI Code Humanizer & Refactor',
    'menu.aspm': 'AppSec / ASPM Posture Gates',
    'menu.projects': 'Projetos & Workspaces',
    'menu.reports': 'Central de Relatórios PDF/XLSX',
    'menu.integrations': 'Conectores SIEM & Cloud Hub',
    'menu.auditLogs': 'Audit Trail Imutável (Compliance)',

    // Dashboard Cards & KPIs
    'dash.title': 'Executive Cybersecurity Posture Dashboard',
    'dash.subtitle': 'Plataforma Corporativa de Inteligência Defensiva e Gestão de Riscos',
    'dash.healthScore': 'Security Health Score',
    'dash.totalAssets': 'Ativos Totais / Internet-Facing',
    'dash.criticalFindings': 'Vulnerabilidades Críticas',
    'dash.slaCompliance': 'Conformidade SLA de Remediação',
    'dash.avgMttr': 'MTTR Médio Corporativo',
    'dash.controlsCoverage': 'Cobertura de Controles de Segurança',
    'dash.activeSuites': 'Suítes de Produtos Ativos',
    'dash.operationalSuites': '5 / 5 SUÍTES OPERACIONAIS',
    'dash.historicalEvolution': 'Evolução Histórica da Postura & Análise de Retenção',
    'dash.businessUnits': 'Visão Hierárquica por Unidade de Negócio & Aplicação',
    'dash.zeroCriticals': 'Zero Críticas em Produção',
    'dash.days': 'dias',

    // Pentest Hub
    'hub.title': 'Pentest Hub',
    'hub.subtitle': 'Consórcio integrado de ferramentas ofensivas, automação em lote e inteligência adversária.',
    'hub.readyTitle': 'Pronto para Execução Ofensiva',
    'hub.readyDesc': 'Selecione os alvos na coluna à esquerda e clique em Executar para iniciar a coleta.',
    'hub.executing': 'Orquestrando motor ofensivo...',
    'hub.executeTool': 'Executar Ferramenta',
    'hub.history': 'Histórico',
    'hub.copyJson': 'Copiar JSON',
    'hub.findingsFound': 'Findings Identificados',

    // Raven AI
    'raven.name': 'Raven AI',
    'raven.role': 'Inteligência Tática & Cibersegurança',
    'raven.greeting': 'Olá! Sou a Raven, a Inteligência Tática e Especialista em Cibersegurança da Heimdall Security.',
    'raven.askPlaceholder': 'Digite sua dúvida técnica ou comando de investigação...',
  },

  en: {
    // Top Bar & Global Actions
    'nav.unifiedScan': '⚡ 360° Unified Scan',
    'nav.globalSearch': 'Global Search',
    'nav.ravenCopilot': 'Raven AI Copilot',
    'nav.masterReport': 'Consolidated Audit Dossier',
    'nav.resetAll': 'Global Reset',
    'nav.hubPentest': 'Pentest Hub',
    'nav.logout': 'Sign Out',
    'nav.language': 'Language',

    // Product Suites
    'suite.governance': 'HEIMDALL APEX™ (C-Level & Boardroom)',
    'suite.governance.desc': 'C-Level Governance, Tri-Pillar Matrix & Boardroom Compliance.',
    'suite.offensive': 'HEIMDALL RED™ (Pentest & EASM)',
    'suite.offensive.desc': 'Autonomous Pentest, Dark Web EASM & Mobile AppSec.',
    'suite.antifraud': 'FRAUDINTEL & BRANDSHIELD™ (Anti-Fraud)',
    'suite.antifraud.desc': 'Digital Fraud Investigation, Takedowns & Brand Impersonation.',
    'suite.defensive': 'AEGIS LATTICE & SOC™ (Cryptography & Defensive Posture)',
    'suite.defensive.desc': 'Defensive Posture, PQC Cryptography & SHA-256 Custody.',
    'suite.appsec': 'HEIMDALL CODE QUALITY™ (AppSec & Refactor)',
    'suite.appsec.desc': 'AI Code Humanizer, AST Refactoring Engine & SAST Gates.',
    'suite.management': 'Management & Audit Trail',

    // Menu Navigation Items
    'menu.dashboard': 'Executive Master Dashboard',
    'menu.executiveGovernance': 'Tri-Pillar Governance (Strategic)',
    'menu.grafanaAnalytics': 'Grafana Cyber Analytics',
    'menu.compliance': 'Compliance & Regulatory Matrix',
    'menu.pentestHub': 'Pentest Hub (Multi-Scanner)',
    'menu.easm': 'EASM & Dark Web Tor Monitor',
    'menu.attackSurface': 'Attack Surface Management (ASM)',
    'menu.osint': 'OSINT Recon Intelligence',
    'menu.mobilePentest': 'Mobile Pentest (APK & iOS)',
    'menu.fraudintel': 'FRAUDINTEL Investigation Engine',
    'menu.brandProtection': 'Brand Protection & Takedown Radar',
    'menu.fiscalForensic': 'Fiscal Forensic & Entity Clones',
    'menu.boletoValidator': 'Boleto Validator & BIN Defense',
    'menu.findings': 'Findings & Risk Center',
    'menu.remediation': 'Prioritized Remediation Guide',
    'menu.evidenceVault': 'Evidence Vault (SHA-256 Chain)',
    'menu.correlation': 'Cross-Layer Risk Correlation',
    'menu.cryptoPki': 'Certificates & PKI Studio',
    'menu.aegislattice': 'AegisLattice Post-Quantum Defense',
    'menu.codeHumanizer': 'AI Code Humanizer & Refactor',
    'menu.aspm': 'AppSec / ASPM Posture Gates',
    'menu.projects': 'Projects & Workspaces',
    'menu.reports': 'PDF / XLSX Reports Center',
    'menu.integrations': 'SIEM & Cloud Connectors Hub',
    'menu.auditLogs': 'Immutable Audit Trail (Compliance)',

    // Dashboard Cards & KPIs
    'dash.title': 'Executive Cybersecurity Posture Dashboard',
    'dash.subtitle': 'Enterprise Defensive Intelligence & Executive Risk Governance',
    'dash.healthScore': 'Security Health Score',
    'dash.totalAssets': 'Total Assets / Internet-Facing',
    'dash.criticalFindings': 'Critical Vulnerabilities',
    'dash.slaCompliance': 'Remediation SLA Compliance',
    'dash.avgMttr': 'Corporate Average MTTR',
    'dash.controlsCoverage': 'Security Controls Coverage',
    'dash.activeSuites': 'Active Commercial Product Suites',
    'dash.operationalSuites': '5 / 5 OPERATIONAL SUITES',
    'dash.historicalEvolution': 'Historical Posture Evolution & Retention Analysis',
    'dash.businessUnits': 'Hierarchical Breakdown by Business Unit & Application',
    'dash.zeroCriticals': 'Zero Criticals in Production',
    'dash.days': 'days',

    // Pentest Hub
    'hub.title': 'Pentest Hub',
    'hub.subtitle': 'Unified consortium of offensive engines, batch automation & adversary intelligence.',
    'hub.readyTitle': 'Ready for Offensive Execution',
    'hub.readyDesc': 'Select targets on the left column and click Execute to start collection and assessment.',
    'hub.executing': 'Orchestrating offensive engine...',
    'hub.executeTool': 'Execute Engine',
    'hub.history': 'History',
    'hub.copyJson': 'Copy JSON',
    'hub.findingsFound': 'Discovered Findings',

    // Raven AI
    'raven.name': 'Raven AI',
    'raven.role': 'Tactical Intelligence & Cybersecurity',
    'raven.greeting': 'Hello! I am Raven, the Tactical Intelligence and Cybersecurity Assistant for Heimdall Security.',
    'raven.askPlaceholder': 'Enter your technical query or investigation command...',
  },

  es: {
    // Top Bar & Global Actions
    'nav.unifiedScan': '⚡ Escaneo Unificado 360°',
    'nav.globalSearch': 'Búsqueda Global',
    'nav.ravenCopilot': 'Raven AI Copilot',
    'nav.masterReport': 'Expediente Consolidado',
    'nav.resetAll': 'Reinicio General',
    'nav.hubPentest': 'Hub Pentest',
    'nav.logout': 'Cerrar Sesión',
    'nav.language': 'Idioma',

    // Product Suites
    'suite.governance': 'HEIMDALL APEX™ (C-Level & Directorio)',
    'suite.governance.desc': 'Gobernanza C-Level, Matriz Tri-Pilar y Cumplimiento Normativo.',
    'suite.offensive': 'HEIMDALL RED™ (Pentest & EASM)',
    'suite.offensive.desc': 'Pentest Autónomo, EASM Dark Web y AppSec Móvil.',
    'suite.antifraud': 'FRAUDINTEL & BRANDSHIELD™ (Anti-Fraude)',
    'suite.antifraud.desc': 'Investigación de Fraudes, Takedowns y Suplantación de Marca.',
    'suite.defensive': 'AEGIS LATTICE & SOC™ (Criptografía & Postura Defensiva)',
    'suite.defensive.desc': 'Postura Defensiva, Criptografía PQC y Custodia SHA-256.',
    'suite.appsec': 'HEIMDALL CODE QUALITY™ (AppSec & Refactor)',
    'suite.appsec.desc': 'AI Code Humanizer, Motor AST y Filtros SAST/ASPM.',
    'suite.management': 'Gestión & Pista de Auditoría',

    // Menu Navigation Items
    'menu.dashboard': 'Executive Master Dashboard',
    'menu.executiveGovernance': 'Gobernanza Tri-Pilar (Estratégico)',
    'menu.grafanaAnalytics': 'Grafana Cyber Analytics',
    'menu.compliance': 'Cumplimiento & Normativas BACEN/PCI',
    'menu.pentestHub': 'Pentest Hub (Multi-Scanner)',
    'menu.easm': 'EASM & Monitor Dark Web Tor',
    'menu.attackSurface': 'Attack Surface Management (ASM)',
    'menu.osint': 'Inteligencia OSINT Recon',
    'menu.mobilePentest': 'Pentest Móvil (APK & iOS)',
    'menu.fraudintel': 'Motor de Investigación FRAUDINTEL',
    'menu.brandProtection': 'Brand Protection & Radar Takedown',
    'menu.fiscalForensic': 'Forense Fiscal & Clones de Empresa',
    'menu.boletoValidator': 'Validador de Boletos & Defensa BIN',
    'menu.findings': 'Central de Findings & Riesgos',
    'menu.remediation': 'Guía de Remediación Priorizada',
    'menu.evidenceVault': 'Bóveda de Evidencias (SHA-256)',
    'menu.correlation': 'Correlación de Riesgo Cruzado',
    'menu.cryptoPki': 'Certificados & PKI Studio',
    'menu.aegislattice': 'Defensa Post-Cuántica AegisLattice',
    'menu.codeHumanizer': 'AI Code Humanizer & Refactor',
    'menu.aspm': 'Filtros de Calidad AppSec / ASPM',
    'menu.projects': 'Proyectos & Espacios de Trabajo',
    'menu.reports': 'Central de Informes PDF/XLSX',
    'menu.integrations': 'Conectores SIEM & Cloud Hub',
    'menu.auditLogs': 'Pista de Auditoría Inmutable (Compliance)',

    // Dashboard Cards & KPIs
    'dash.title': 'Executive Cybersecurity Posture Dashboard',
    'dash.subtitle': 'Plataforma Corporativa de Inteligencia Defensiva y Gobernanza de Riesgos',
    'dash.healthScore': 'Security Health Score',
    'dash.totalAssets': 'Activos Totales / Expuestos a Internet',
    'dash.criticalFindings': 'Vulnerabilidades Críticas',
    'dash.slaCompliance': 'Cumplimiento SLA de Remediación',
    'dash.avgMttr': 'MTTR Promedio Corporativo',
    'dash.controlsCoverage': 'Cobertura de Controles de Seguridad',
    'dash.activeSuites': 'Suites de Productos Activos',
    'dash.operationalSuites': '5 / 5 SUITES OPERACIONALES',
    'dash.historicalEvolution': 'Evolución Histórica de la Postura & Retención',
    'dash.businessUnits': 'Visión Jerárquica por Unidad de Negocio & Aplicación',
    'dash.zeroCriticals': 'Cero Críticas en Producción',
    'dash.days': 'días',

    // Pentest Hub
    'hub.title': 'Pentest Hub',
    'hub.subtitle': 'Consorcio integrado de herramientas ofensivas, automatización en lote e inteligencia adversaria.',
    'hub.readyTitle': 'Listo para Ejecución Ofensiva',
    'hub.readyDesc': 'Seleccione los objetivos en la columna izquierda y presione Ejecutar para iniciar el análisis.',
    'hub.executing': 'Orquestando motor ofensivo...',
    'hub.executeTool': 'Ejecutar Herramienta',
    'hub.history': 'Historial',
    'hub.copyJson': 'Copiar JSON',
    'hub.findingsFound': 'Hallazgos Identificados',

    // Raven AI
    'raven.name': 'Raven AI',
    'raven.role': 'Inteligencia Táctica & Ciberseguridad',
    'raven.greeting': '¡Hola! Soy Raven, la Inteligencia Táctica y Especialista en Ciberseguridad de Heimdall Security.',
    'raven.askPlaceholder': 'Escriba su consulta técnica o comando de investigación...',
  },
};

interface LanguageContextType {
  locale: Locale;
  setLocale: (l: Locale) => void;
  t: (key: string, defaultText?: string) => string;
  languages: LanguageOption[];
}

const LanguageContext = createContext<LanguageContextType>({
  locale: 'pt',
  setLocale: () => {},
  t: (k, d) => d || k,
  languages: LANGUAGES,
});

export function LanguageProvider({ children }: { children: React.ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>('pt');

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('heimdall_locale') as Locale;
      if (saved && (saved === 'pt' || saved === 'en' || saved === 'es')) {
        setLocaleState(saved);
        document.documentElement.lang = saved;
      }
    }
  }, []);

  const setLocale = (newLocale: Locale) => {
    setLocaleState(newLocale);
    if (typeof window !== 'undefined') {
      localStorage.setItem('heimdall_locale', newLocale);
      document.documentElement.lang = newLocale;
    }
  };

  const t = (key: string, defaultText?: string): string => {
    const table = DICTIONARY[locale] || DICTIONARY.pt;
    return table[key] || defaultText || key;
  };

  return (
    <LanguageContext.Provider value={{ locale, setLocale, t, languages: LANGUAGES }}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage() {
  return useContext(LanguageContext);
}
