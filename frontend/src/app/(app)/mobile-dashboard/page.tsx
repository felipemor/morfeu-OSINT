'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import {
  Smartphone, Shield, ShieldAlert, ShieldCheck, AlertTriangle,
  CheckCircle2, Lock, Key, Terminal, Layers, ExternalLink, RefreshCw,
  Copy, Check, FileSpreadsheet, Download, Cpu, Zap, Eye, ChevronRight,
  Binary, AlertCircle, BarChart3, TrendingUp, Activity, CheckSquare,
  XCircle, Filter, ArrowUpRight, Search, PlusCircle, Trash2
} from 'lucide-react';
import { mobilePentestApi, MobileScanResult } from '@/lib/api';
import clsx from 'clsx';
import toast from 'react-hot-toast';

interface FleetApp {
  id: string;
  name: string;
  package_name: string;
  platform: 'Android' | 'iOS' | 'Multi-Platform';
  app_version: string;
  target_sdk: string;
  last_audit_date: string;
  risk_score: number;
  risk_grade: 'A+' | 'B' | 'C' | 'F';
  release_status: 'RELEASE_APPROVED' | 'RELEASE_BLOCKED' | 'CONDITIONAL_APPROVAL';
  findings: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  masvs_scores: {
    storage: number;
    crypto: number;
    network: number;
    platform: number;
    resilience: number;
  };
  secrets_count: number;
  ssl_pinning: boolean;
  root_detection: boolean;
  allow_backup: boolean;
}

const INITIAL_FLEET: FleetApp[] = [
  {
    id: 'app-001',
    name: 'Banco Stellantis Mobile Banking',
    package_name: 'com.stellantis.finance.banking',
    platform: 'Android',
    app_version: 'v4.2.0',
    target_sdk: 'Android 14 (API 34)',
    last_audit_date: 'Hoje, 00:25',
    risk_score: 78,
    risk_grade: 'F',
    release_status: 'RELEASE_BLOCKED',
    findings: { critical: 1, high: 3, medium: 2, low: 0 },
    masvs_scores: { storage: 35, crypto: 40, network: 50, platform: 55, resilience: 20 },
    secrets_count: 3,
    ssl_pinning: false,
    root_detection: false,
    allow_backup: true,
  },
  {
    id: 'app-002',
    name: 'Stellantis Connect & Telematics',
    package_name: 'com.stellantis.connected.vehicle',
    platform: 'iOS',
    app_version: 'v3.1.2',
    target_sdk: 'iOS 17.4',
    last_audit_date: 'Ontem, 18:40',
    risk_score: 42,
    risk_grade: 'B',
    release_status: 'CONDITIONAL_APPROVAL',
    findings: { critical: 0, high: 2, medium: 3, low: 1 },
    masvs_scores: { storage: 75, crypto: 65, network: 70, platform: 80, resilience: 60 },
    secrets_count: 1,
    ssl_pinning: true,
    root_detection: false,
    allow_backup: false,
  },
  {
    id: 'app-003',
    name: 'Stellantis Dealer Portal & Sales',
    package_name: 'com.stellantis.dealer.app',
    platform: 'Android',
    app_version: 'v2.8.0',
    target_sdk: 'Android 14 (API 34)',
    last_audit_date: '03/09/2026',
    risk_score: 22,
    risk_grade: 'A+',
    release_status: 'RELEASE_APPROVED',
    findings: { critical: 0, high: 0, medium: 2, low: 4 },
    masvs_scores: { storage: 90, crypto: 85, network: 95, platform: 90, resilience: 80 },
    secrets_count: 0,
    ssl_pinning: true,
    root_detection: true,
    allow_backup: false,
  },
  {
    id: 'app-004',
    name: 'Stellantis Secure Token 2FA',
    package_name: 'com.stellantis.auth.token2fa',
    platform: 'Multi-Platform',
    app_version: 'v1.4.0',
    target_sdk: 'API 34 / iOS 17',
    last_audit_date: '02/09/2026',
    risk_score: 15,
    risk_grade: 'A+',
    release_status: 'RELEASE_APPROVED',
    findings: { critical: 0, high: 0, medium: 1, low: 2 },
    masvs_scores: { storage: 95, crypto: 95, network: 100, platform: 90, resilience: 90 },
    secrets_count: 0,
    ssl_pinning: true,
    root_detection: true,
    allow_backup: false,
  },
];

export default function MobileExecutiveDashboardPage() {
  const [fleet, setFleet] = useState<FleetApp[]>(INITIAL_FLEET);
  const [filterPlatform, setFilterPlatform] = useState<string>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedApp, setSelectedApp] = useState<FleetApp | null>(INITIAL_FLEET[0]);
  const [isExporting, setIsExporting] = useState<boolean>(false);
  const [resetConfirmOpen, setResetConfirmOpen] = useState<boolean>(false);

  const handleResetFleet = () => {
    setFleet([]);
    setSelectedApp(null);
    setFilterPlatform('ALL');
    setFilterStatus('ALL');
    setSearchQuery('');
    setResetConfirmOpen(false);
    toast.success('Dados do dashboard zerados com sucesso.', { icon: '🗑️' });
  };

  // Filtered fleet
  const filteredFleet = fleet.filter((app) => {
    if (filterPlatform !== 'ALL' && app.platform !== filterPlatform) return false;
    if (filterStatus !== 'ALL' && app.release_status !== filterStatus) return false;
    if (searchQuery && !app.name.toLowerCase().includes(searchQuery.toLowerCase()) && !app.package_name.toLowerCase().includes(searchQuery.toLowerCase())) {
      return false;
    }
    return true;
  });

  // Fleet Statistics
  const totalApps = fleet.length;
  const criticalVulnsTotal = fleet.reduce((acc, a) => acc + a.findings.critical, 0);
  const highVulnsTotal = fleet.reduce((acc, a) => acc + a.findings.high, 0);
  const totalSecretsExposed = fleet.reduce((acc, a) => acc + a.secrets_count, 0);
  const blockedReleases = fleet.filter(a => a.release_status === 'RELEASE_BLOCKED').length;
  const avgRiskScore = Math.round(fleet.reduce((acc, a) => acc + a.risk_score, 0) / (totalApps || 1));

  const handleExportExecutiveReport = async (lang: 'pt' | 'en') => {
    if (!selectedApp) return;
    setIsExporting(true);
    toast.loading(`Gerando Laudo Executivo Consolidado de Gestão Mobile (${lang.toUpperCase()})...`, { id: 'm-exec-pdf' });
    try {
      const payload: MobileScanResult = {
        id: `exec-${selectedApp!.id}`,
        package_name: selectedApp.package_name,
        filename: `${selectedApp.package_name}-${selectedApp.app_version}.apk`,
        file_size_bytes: 38402910,
        file_size_mb: 36.6,
        app_version: selectedApp.app_version,
        target_sdk: selectedApp.target_sdk,
        platform: selectedApp.platform,
        min_sdk: 'Android 8.0 (API 26)',
        scanned_at: new Date().toISOString(),
        scan_duration_ms: 4820,
        risk_score: selectedApp.risk_score,
        risk_grade: selectedApp.risk_grade === 'F' ? 'F (CRÍTICO - Release Bloqueada)' : selectedApp.risk_grade === 'A+' ? 'A+ (SEGURO - Release Aprovada)' : 'C (MODERADO)',
        findings_summary: {
          total: selectedApp.findings.critical + selectedApp.findings.high + selectedApp.findings.medium + selectedApp.findings.low,
          critical: selectedApp.findings.critical,
          high: selectedApp.findings.high,
          medium: selectedApp.findings.medium,
          low: selectedApp.findings.low,
          info: 0,
        },
        owasp_masvs_scores: {
          'MASVS-STORAGE': selectedApp.masvs_scores.storage,
          'MASVS-CRYPTO': selectedApp.masvs_scores.crypto,
          'MASVS-AUTH': 85,
          'MASVS-NETWORK': selectedApp.masvs_scores.network,
          'MASVS-PLATFORM': selectedApp.masvs_scores.platform,
          'MASVS-CODE': 70,
          'MASVS-RESILIENCE': selectedApp.masvs_scores.resilience,
        },
        manifest_audit: {
          debuggable: false,
          allow_backup: selectedApp.allow_backup,
          uses_cleartext_traffic: !selectedApp.ssl_pinning,
          exported_components_count: 2,
          exported_activities: [],
          exported_receivers: [],
          exported_providers: [],
        },
        permissions: [
          { permission: 'android.permission.INTERNET', name: 'INTERNET', description: 'Comunicação Externa', severity: 'INFO', security_impact: 'Permite comunicação com servidores de API.' },
          { permission: 'android.permission.SYSTEM_ALERT_WINDOW', name: 'OVERLAY', description: 'Sobreposição de Tela', severity: selectedApp.findings.critical > 0 ? 'CRITICAL' : 'INFO', security_impact: 'Vetor crítico para ataques de Tapjacking e roubo de credenciais.' }
        ],
        hardcoded_secrets: selectedApp.secrets_count > 0 ? [
          { secret_type: 'AWS Access Key ID', masked_value: 'AKIAIOSFODNN7EXAMPLE', severity: 'CRITICAL', cwe_id: 'CWE-798' },
          { secret_type: 'Firebase Realtime Database', masked_value: 'https://prod-db.firebaseio.com', severity: 'HIGH', cwe_id: 'CWE-200' },
        ] : [],
        crypto_issues: [],
        network_issues: selectedApp.ssl_pinning ? [] : [{ title: 'Ausência de SSL Pinning', severity: 'HIGH', cwe_id: 'CWE-295', masvs_category: 'MASVS-NETWORK', description: 'Vulnerável a ataques de Man-in-the-Middle com certificados locais falsificados.' }],
        anti_reversing: {
          root_jailbreak_detection_present: selectedApp.root_detection,
          frida_xposed_hooks_detection: selectedApp.root_detection,
          code_obfuscation_applied: true,
          integrity_signature_check: true,
          status: selectedApp.root_detection ? 'BLINDADO' : 'VULNERÁVEL A FRIDA / ROOT',
        },
        findings: [
          ...(selectedApp.findings.critical > 0 ? [{
            id: 'MOB-VULN-001',
            title: 'Chaves Estáticas de Nuvem Hardcoded (AWS / GCP)',
            severity: 'CRITICAL',
            cwe_id: 'CWE-798: Hardcoded Credentials',
            masvs_id: 'MASVS-STORAGE-1',
            cvss_score: 9.3,
            description: 'Identificadas credenciais corporativas estáticas em texto claro no bytecode descompilado.',
            recommendation: 'Remover chaves estáticas e adotar autenticação dinâmica com tokens efêmeros via AWS STS / Vault.',
          }] : []),
          ...(selectedApp.findings.high > 0 ? [{
            id: 'MOB-VULN-002',
            title: 'Ausência de SSL Certificate Pinning & Falha Anti-MitM',
            severity: 'HIGH',
            cwe_id: 'CWE-295: Improper Certificate Validation',
            masvs_id: 'MASVS-NETWORK-1',
            cvss_score: 7.8,
            description: 'O aplicativo móvel aceita CAs injetadas no armazenamento de certificados de usuário do Android/iOS.',
            recommendation: 'Implementar validação rigorosa de SPKI Pinning e expiração controlada no NetworkSecurityConfig.',
          }] : []),
          ...(selectedApp.allow_backup ? [{
            id: 'MOB-VULN-003',
            title: 'Backup de Dados Habilitado no Manifesto (allowBackup=true)',
            severity: 'HIGH',
            cwe_id: 'CWE-200: Information Exposure',
            masvs_id: 'MASVS-STORAGE-2',
            cvss_score: 7.2,
            description: 'Permite extração completa do SQLite e SharedPreferences sem criptografia através do comando adb backup.',
            recommendation: 'Definir explicitamente android:allowBackup="false" no AndroidManifest.xml.',
          }] : [])
        ]
      };

      await mobilePentestApi.downloadPdf(payload, lang);
      toast.success('Relatório Executivo PDF baixado com sucesso!', { id: 'm-exec-pdf' });
    } catch (e: any) {
      toast.error(`Erro ao gerar PDF: ${e.message}`, { id: 'm-exec-pdf' });
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 animate-fade-in">

      {/* Reset Confirmation Modal */}
      {resetConfirmOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-bg-card border border-red-500/40 rounded-2xl shadow-2xl p-8 max-w-sm w-full mx-4 space-y-5">
            <div className="flex items-center gap-3">
              <span className="p-2.5 rounded-xl bg-red-500/10 border border-red-500/30">
                <Trash2 className="w-5 h-5 text-red-400" />
              </span>
              <div>
                <h2 className="text-base font-bold text-slate-100">Zerar Dados do Dashboard?</h2>
                <p className="text-xs text-slate-400 mt-0.5">Esta ação é irreversível na sessão atual.</p>
              </div>
            </div>
            <p className="text-sm text-slate-300">
              Todos os <span className="font-bold text-red-400">{fleet.length} aplicativo(s)</span> do parque de apps serão removidos da visualização. Você poderá carregar novos scans via <span className="text-accent-cyan font-semibold">Upload APK/IPA</span>.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setResetConfirmOpen(false)}
                className="flex-1 py-2.5 rounded-lg bg-bg-primary border border-bg-border text-slate-300 text-sm font-medium hover:bg-slate-700 transition-all cursor-pointer"
              >
                Cancelar
              </button>
              <button
                onClick={handleResetFleet}
                className="flex-1 py-2.5 rounded-lg bg-red-500 hover:bg-red-600 text-white text-sm font-bold transition-all flex items-center justify-center gap-2 shadow-lg shadow-red-500/20 cursor-pointer"
              >
                <Trash2 className="w-4 h-4" />
                Confirmar Reset
              </button>
            </div>
          </div>
        </div>
      )}
      {/* Header Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-bg-border pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-lg bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20">
              <Activity className="w-5 h-5 text-accent-cyan" />
            </span>
            <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-3">
              Dashboard Executivo Mobile &amp; Fleet Governance
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/30 uppercase tracking-wider font-mono">
                OWASP MASVS L1/L2
              </span>
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Painel consolidado para monitoramento de risco contínuo, governança de postura de segurança em apps móveis (.APK &amp; .IPA), controle de esteira CI/CD e auditoria de conformidade corporativa.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <Link
            href="/mobile-pentest"
            className="px-3.5 py-2 rounded-lg bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan hover:bg-accent-cyan/20 text-xs font-semibold transition-all flex items-center gap-1.5 shadow-sm"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            Novo Scan SAST/DAST (Upload APK)
          </Link>

          <button
            onClick={() => handleExportExecutiveReport('pt')}
            disabled={isExporting || !selectedApp}
            className="px-3.5 py-2 rounded-lg bg-bg-card border border-bg-border hover:border-slate-600 text-xs font-medium text-slate-200 transition-all flex items-center gap-1.5 shadow-sm hover:text-accent-cyan cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Download className="w-3.5 h-3.5 text-accent-cyan" />
            Relatório Executivo PDF (PT)
          </button>

          <button
            onClick={() => handleExportExecutiveReport('en')}
            disabled={isExporting || !selectedApp}
            className="px-3.5 py-2 rounded-lg bg-bg-card border border-bg-border hover:border-slate-600 text-xs font-medium text-slate-200 transition-all flex items-center gap-1.5 shadow-sm hover:text-accent-cyan cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Download className="w-3.5 h-3.5 text-accent-cyan" />
            Executive Report (EN)
          </button>

          <button
            onClick={handleResetFleet}
            className="px-3.5 py-2 rounded-lg bg-red-500/10 border border-red-500/30 hover:bg-red-500/20 text-xs font-semibold text-red-400 transition-all flex items-center gap-1.5 shadow-sm cursor-pointer"
            title="Zerar todos os dados do dashboard"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Zerar Dados
          </button>
        </div>
      </div>

      {/* Top 5 KPI Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="p-4 rounded-xl bg-bg-card border border-bg-border relative overflow-hidden group hover:border-accent-cyan/40 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Parque de Apps</span>
            <Smartphone className="w-4 h-4 text-accent-cyan" />
          </div>
          <div className="text-2xl font-extrabold text-slate-100">{totalApps}</div>
          <p className="text-[11px] text-slate-400 mt-1 flex items-center gap-1">
            <span className="text-accent-cyan font-bold">100%</span> auditados no MASVS
          </p>
          <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-accent-cyan/30" />
        </div>

        <div className="p-4 rounded-xl bg-bg-card border border-bg-border relative overflow-hidden group hover:border-red-500/40 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Falhas Críticas</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-extrabold text-red-400">{criticalVulnsTotal}</div>
          <p className="text-[11px] text-red-300 mt-1">SLA: 24h a 48h (Urgente)</p>
          <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-red-500" />
        </div>

        <div className="p-4 rounded-xl bg-bg-card border border-bg-border relative overflow-hidden group hover:border-amber-500/40 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Risco Alto &amp; Médio</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-extrabold text-amber-400">{highVulnsTotal}</div>
          <p className="text-[11px] text-slate-400 mt-1">Requer correções no sprint</p>
          <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-amber-500" />
        </div>

        <div className="p-4 rounded-xl bg-bg-card border border-bg-border relative overflow-hidden group hover:border-purple-500/40 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Chaves Hardcoded</span>
            <Key className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-extrabold text-purple-400">{totalSecretsExposed}</div>
          <p className="text-[11px] text-purple-300 mt-1">Tokens/AWS em bytecode</p>
          <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-purple-500" />
        </div>

        <div className="p-4 rounded-xl bg-bg-card border border-bg-border relative overflow-hidden group hover:border-red-500/40 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Quality Gate CI/CD</span>
            <XCircle className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-extrabold text-red-400">{blockedReleases} Bloqueado(s)</div>
          <p className="text-[11px] text-slate-400 mt-1">Bloqueio automático de release</p>
          <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-red-500" />
        </div>
      </div>

      {/* Main Governance Content: Fleet Table & Deep Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Fleet Management Table */}
        <div className="lg:col-span-2 space-y-4">
          <div className="p-5 rounded-xl bg-bg-card border border-bg-border space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Smartphone className="w-4 h-4 text-accent-cyan" />
                  Inventário e Governança do Parque de Apps
                </h2>
                <p className="text-xs text-slate-400">Controle de conformidade por pacote e aprovação de deploy</p>
              </div>

              {/* Filters */}
              <div className="flex items-center gap-2 flex-wrap">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
                  <input
                    type="text"
                    placeholder="Filtrar pacote..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-8 pr-3 py-1.5 rounded-lg bg-bg-primary border border-bg-border text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-cyan/50 w-36 sm:w-44"
                  />
                </div>

                <select
                  value={filterPlatform}
                  onChange={(e) => setFilterPlatform(e.target.value)}
                  className="px-2.5 py-1.5 rounded-lg bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-accent-cyan/50"
                >
                  <option value="ALL">Todas Plataformas</option>
                  <option value="Android">Android (.apk)</option>
                  <option value="iOS">iOS (.ipa)</option>
                </select>

                <select
                  value={filterStatus}
                  onChange={(e) => setFilterStatus(e.target.value)}
                  className="px-2.5 py-1.5 rounded-lg bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-accent-cyan/50"
                >
                  <option value="ALL">Todos os Status</option>
                  <option value="RELEASE_BLOCKED">Bloqueados</option>
                  <option value="RELEASE_APPROVED">Aprovados</option>
                  <option value="CONDITIONAL_APPROVAL">Condicionais</option>
                </select>
              </div>
            </div>

            {/* Apps Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-bg-primary text-slate-400 uppercase text-[10px] tracking-wider border-y border-bg-border">
                  <tr>
                    <th className="px-3.5 py-3">Aplicativo / Pacote</th>
                    <th className="px-3.5 py-3">Plataforma</th>
                    <th className="px-3.5 py-3 text-center">Score / Grau</th>
                    <th className="px-3.5 py-3 text-center">Vulnerabilidades</th>
                    <th className="px-3.5 py-3 text-center">Controles Chave</th>
                    <th className="px-3.5 py-3 text-center">Deploy Status</th>
                    <th className="px-3.5 py-3 text-right">Ação</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-bg-border">
                  {filteredFleet.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-3.5 py-12 text-center">
                        <div className="flex flex-col items-center gap-3 text-slate-500">
                          <Smartphone className="w-10 h-10 opacity-30" />
                          <p className="text-sm font-medium">Nenhum aplicativo no parque de apps.</p>
                          <p className="text-xs">Utilize o botão <span className="text-accent-cyan font-semibold">Novo Scan SAST/DAST</span> para adicionar um APK ou IPA.</p>
                        </div>
                      </td>
                    </tr>
                  )}
                  {filteredFleet.map((app) => {
                    const isSelected = selectedApp?.id === app.id;
                    const gradeColor =
                      app.risk_grade === 'A+' ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30' :
                        app.risk_grade === 'B' ? 'text-amber-400 bg-amber-500/10 border-amber-500/30' :
                          'text-red-400 bg-red-500/10 border-red-500/30';

                    const statusBadge =
                      app.release_status === 'RELEASE_APPROVED'
                        ? { text: 'APROVADO', color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30' }
                        : app.release_status === 'CONDITIONAL_APPROVAL'
                          ? { text: 'CONDICIONAL', color: 'text-amber-400 bg-amber-500/10 border-amber-500/30' }
                          : { text: 'BLOQUEADO', color: 'text-red-400 bg-red-500/10 border-red-500/30' };

                    return (
                      <tr
                        key={app.id}
                        onClick={() => setSelectedApp(app)}
                        className={clsx(
                          'hover:bg-bg-primary/80 transition-colors cursor-pointer',
                          isSelected && 'bg-accent-cyan/5 border-l-2 border-l-accent-cyan'
                        )}
                      >
                        <td className="px-3.5 py-3.5">
                          <div className="font-bold text-slate-100 flex items-center gap-1.5">
                            {app.name}
                          </div>
                          <div className="text-[11px] text-slate-400 font-mono mt-0.5">{app.package_name}</div>
                          <div className="text-[10px] text-slate-500 mt-0.5">{app.app_version} • {app.target_sdk}</div>
                        </td>

                        <td className="px-3.5 py-3.5">
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[11px] font-medium border border-slate-700">
                            {app.platform}
                          </span>
                        </td>

                        <td className="px-3.5 py-3.5 text-center">
                          <div className="font-bold text-sm text-slate-100">{app.risk_score}/100</div>
                          <span className={clsx('inline-block text-[10px] font-extrabold px-2 py-0.5 rounded border mt-0.5', gradeColor)}>
                            GRAU {app.risk_grade}
                          </span>
                        </td>

                        <td className="px-3.5 py-3.5 text-center">
                          <div className="flex items-center justify-center gap-1 font-mono text-[11px]">
                            {app.findings.critical > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/40" title="Críticas">
                                {app.findings.critical}C
                              </span>
                            )}
                            {app.findings.high > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/40" title="Altas">
                                {app.findings.high}H
                              </span>
                            )}
                            {app.findings.medium > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/40" title="Médias">
                                {app.findings.medium}M
                              </span>
                            )}
                            {app.findings.critical === 0 && app.findings.high === 0 && app.findings.medium === 0 && (
                              <span className="text-emerald-400 font-medium">0 Críticas</span>
                            )}
                          </div>
                          {app.secrets_count > 0 && (
                            <div className="text-[10px] text-purple-400 font-semibold mt-1">
                              {app.secrets_count} chave(s) exposta(s)
                            </div>
                          )}
                        </td>

                        <td className="px-3.5 py-3.5 text-center">
                          <div className="flex items-center justify-center gap-2">
                            <span
                              title={app.ssl_pinning ? 'SSL Pinning Ativo' : 'SSL Pinning Ausente'}
                              className={clsx('text-[10px] px-1.5 py-0.5 rounded font-mono', app.ssl_pinning ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/10 text-red-400 border border-red-500/30')}
                            >
                              PINNING
                            </span>
                            <span
                              title={app.root_detection ? 'Anti-Root / Frida Ativo' : 'Anti-Root Ausente'}
                              className={clsx('text-[10px] px-1.5 py-0.5 rounded font-mono', app.root_detection ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/10 text-red-400 border border-red-500/30')}
                            >
                              ANTI-ROOT
                            </span>
                          </div>
                        </td>

                        <td className="px-3.5 py-3.5 text-center">
                          <span className={clsx('px-2.5 py-1 rounded text-[10px] font-bold border uppercase tracking-wide', statusBadge.color)}>
                            {statusBadge.text}
                          </span>
                        </td>

                        <td className="px-3.5 py-3.5 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedApp(app);
                            }}
                            className="px-2.5 py-1 rounded bg-bg-primary hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors border border-bg-border"
                          >
                            Inspecionar
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* OWASP MASVS Breakdown Matrix across Fleet */}
          <div className="p-5 rounded-xl bg-bg-card border border-bg-border space-y-4">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Layers className="w-4 h-4 text-accent-cyan" />
              Matriz de Aderência MASVS v2.0 do Aplicativo Selecionado
            </h3>

            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              {selectedApp ? ([
                { name: 'Armazenamento', code: 'MASVS-STORAGE', score: selectedApp.masvs_scores.storage, desc: 'allowBackup e SQLite' },
                { name: 'Criptografia', code: 'MASVS-CRYPTO', score: selectedApp.masvs_scores.crypto, desc: 'AES-GCM & Keystore' },
                { name: 'Rede & TLS', code: 'MASVS-NETWORK', score: selectedApp.masvs_scores.network, desc: 'SSL Pinning & Cleartext' },
                { name: 'Plataforma / OS', code: 'MASVS-PLATFORM', score: selectedApp.masvs_scores.platform, desc: 'IPC & Overlays' },
                { name: 'Resiliência', code: 'MASVS-RESILIENCE', score: selectedApp.masvs_scores.resilience, desc: 'Anti-Root & Frida' },
              ].map((m) => {
                const isCompliant = m.score >= 70;
                const isPartial = m.score >= 50 && m.score < 70;
                const barColor = isCompliant ? 'bg-emerald-500' : isPartial ? 'bg-amber-500' : 'bg-red-500';
                const textColor = isCompliant ? 'text-emerald-400' : isPartial ? 'text-amber-400' : 'text-red-400';

                return (
                  <div key={m.code} className="p-3 rounded-lg bg-bg-primary border border-bg-border space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-slate-400 font-mono">{m.code}</span>
                      <span className={clsx('text-xs font-extrabold', textColor)}>{m.score}%</span>
                    </div>
                    <div className="text-xs font-bold text-slate-200">{m.name}</div>
                    <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                      <div className={clsx('h-full rounded-full transition-all duration-500', barColor)} style={{ width: `${m.score}%` }} />
                    </div>
                    <div className="text-[10px] text-slate-500 truncate">{m.desc}</div>
                  </div>
                );
              })) : (
                <p className="col-span-5 text-sm text-slate-500 text-center py-4">Selecione um aplicativo para visualizar a matriz MASVS.</p>
              )}
            </div>
          </div>
        </div>

        {/* Right 1 Col: Selected App Deep Threat Inspection */}
        <div className="space-y-4">
          {selectedApp ? (
            <div className="p-5 rounded-xl bg-bg-card border border-bg-border space-y-4">
              <div className="flex items-center justify-between border-b border-bg-border pb-3">
                <div>
                  <span className="text-[10px] text-slate-400 uppercase font-mono tracking-wider">Inspeção Detalhada</span>
                  <h3 className="text-base font-bold text-slate-100">{selectedApp.name}</h3>
                </div>
                <span className={clsx(
                  'px-2.5 py-1 rounded text-xs font-extrabold border',
                  selectedApp.risk_grade === 'F' ? 'bg-red-500/10 text-red-400 border-red-500/30' :
                    selectedApp.risk_grade === 'A+' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' :
                      'bg-amber-500/10 text-amber-400 border-amber-500/30'
                )}>
                  GRAU {selectedApp.risk_grade}
                </span>
              </div>

              {/* Release Decision Card */}
              <div className={clsx(
                'p-3.5 rounded-lg border flex items-start gap-3',
                selectedApp.release_status === 'RELEASE_BLOCKED' ? 'bg-red-500/10 border-red-500/30 text-red-300' :
                  selectedApp.release_status === 'RELEASE_APPROVED' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' :
                    'bg-amber-500/10 border-amber-500/30 text-amber-300'
              )}>
                {selectedApp.release_status === 'RELEASE_BLOCKED' ? (
                  <ShieldAlert className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                ) : (
                  <ShieldCheck className="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5" />
                )}
                <div className="text-xs space-y-1">
                  <div className="font-bold text-slate-100">
                    {selectedApp.release_status === 'RELEASE_BLOCKED' ? 'Deploy Bloqueado para Produção' :
                      selectedApp.release_status === 'RELEASE_APPROVED' ? 'Deploy Autorizado para Publicação' :
                        'Aprovação Condicional (Revisão Necessária)'}
                  </div>
                  <p className="text-[11px] text-slate-300">
                    {selectedApp.release_status === 'RELEASE_BLOCKED'
                      ? 'Identificadas vulnerabilidades críticas (chaves de nuvem e ausência de SSL Pinning) que violam os critérios de segurança.'
                      : 'Aplicativo em plena conformidade com as diretrizes OWASP MASVS e BACEN CMN 4.893.'}
                  </p>
                </div>
              </div>

              {/* Quick Specs */}
              <div className="space-y-2 text-xs">
                <div className="flex justify-between py-1.5 border-b border-bg-border/60">
                  <span className="text-slate-400">Pacote / ID:</span>
                  <span className="font-mono text-slate-200 text-[11px]">{selectedApp.package_name}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-bg-border/60">
                  <span className="text-slate-400">Versão / SDK:</span>
                  <span className="text-slate-200">{selectedApp.app_version} ({selectedApp.target_sdk})</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-bg-border/60">
                  <span className="text-slate-400">Última Auditoria:</span>
                  <span className="text-slate-200">{selectedApp.last_audit_date}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-bg-border/60">
                  <span className="text-slate-400">Chaves Vazadas:</span>
                  <span className={clsx('font-bold', selectedApp.secrets_count > 0 ? 'text-red-400' : 'text-emerald-400')}>
                    {selectedApp.secrets_count > 0 ? `${selectedApp.secrets_count} Chave(s) Detectada(s)` : 'Nenhuma Chave Exposta'}
                  </span>
                </div>
                <div className="flex justify-between py-1.5">
                  <span className="text-slate-400">Backup no Manifesto:</span>
                  <span className={clsx('font-bold', selectedApp.allow_backup ? 'text-red-400' : 'text-emerald-400')}>
                    {selectedApp.allow_backup ? 'allowBackup="true" (Vulnerável)' : 'allowBackup="false" (Protegido)'}
                  </span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="pt-2 space-y-2">
                <button
                  onClick={() => handleExportExecutiveReport('pt')}
                  disabled={isExporting}
                  className="w-full py-2.5 rounded-lg bg-accent-cyan hover:bg-accent-cyan/90 text-bg-primary font-bold text-xs transition-all flex items-center justify-center gap-2 shadow-lg shadow-accent-cyan/10 cursor-pointer"
                >
                  <Download className="w-4 h-4" />
                  Baixar Laudo Executivo PDF (PT)
                </button>

                <Link
                  href="/mobile-pentest"
                  className="w-full py-2 rounded-lg bg-bg-primary hover:bg-slate-800 text-slate-300 font-medium text-xs transition-all flex items-center justify-center gap-1.5 border border-bg-border"
                >
                  <Terminal className="w-3.5 h-3.5 text-accent-cyan" />
                  Abrir Scanner &amp; Descompilação SAST
                </Link>
              </div>
            </div>
          ) : (
            <div className="p-8 rounded-xl bg-bg-card border border-bg-border flex flex-col items-center justify-center gap-3 text-center min-h-[220px]">
              <Shield className="w-10 h-10 text-slate-600" />
              <p className="text-sm font-semibold text-slate-400">Nenhum app selecionado</p>
              <p className="text-xs text-slate-500">Clique em um aplicativo na tabela para inspecionar seus detalhes de segurança.</p>
            </div>
          )}

          {/* Hardening & BACEN SLA Compliance */}
          <div className="p-5 rounded-xl bg-bg-card border border-bg-border space-y-3">
            <h4 className="text-xs font-bold text-slate-100 flex items-center gap-1.5 uppercase tracking-wider">
              <ShieldCheck className="w-4 h-4 text-accent-cyan" />
              SLAs Regulatórios (BACEN CMN 4.893 &amp; LGPD)
            </h4>
            <div className="space-y-2 text-[11px]">
              <div className="p-2 rounded bg-bg-primary border border-bg-border flex items-center justify-between">
                <span className="text-slate-300">Críticas (AWS / Secret Keys):</span>
                <span className="text-red-400 font-bold">24h a 48h</span>
              </div>
              <div className="p-2 rounded bg-bg-primary border border-bg-border flex items-center justify-between">
                <span className="text-slate-300">Altas (SSL Pinning / Backup):</span>
                <span className="text-amber-400 font-bold">Até 7 dias</span>
              </div>
              <div className="p-2 rounded bg-bg-primary border border-bg-border flex items-center justify-between">
                <span className="text-slate-300">Médias (Cifras AES/ECB):</span>
                <span className="text-blue-400 font-bold">Até 30 dias</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
