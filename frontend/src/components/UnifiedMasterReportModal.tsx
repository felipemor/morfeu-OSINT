'use client';

import { useState } from 'react';
import {
  FileText, Download, ShieldCheck, Bug, Radio, Flame, Sparkles, X,
  CheckCircle2, AlertTriangle, Layers, Lock, Server, Terminal, FileSpreadsheet,
  Check
} from 'lucide-react';
import toast from 'react-hot-toast';

const API_BASE = 'http://localhost:8000';

interface UnifiedMasterReportModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function UnifiedMasterReportModal({ isOpen, onClose }: UnifiedMasterReportModalProps) {
  const [targetUrl, setTargetUrl] = useState('');
  const [perspective, setPerspective] = useState<'BOTH' | 'AUDITOR' | 'ANALYST'>('BOTH');
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [isGeneratingXlsx, setIsGeneratingXlsx] = useState(false);

  if (!isOpen) return null;

  const handleDownloadPdf = async () => {
    setIsGeneratingPdf(true);
    toast.loading('Compilando Laudo Técnico-Executivo Consolidado de Auditoria em PDF...', { id: 'master-pdf' });

    try {
      const res = await fetch(`${API_BASE}/api/v1/reports/unified-master/pdf`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: targetUrl, perspective }),
      });

      if (!res.ok) throw new Error('Falha ao gerar laudo técnico-executivo PDF');

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `laudo_tecnico_executivo_auditoria_${new Date().toISOString().slice(0, 10)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      toast.dismiss('master-pdf');
      toast.success('Laudo Técnico-Executivo (PDF) exportado com sucesso!');
    } catch (e: any) {
      toast.dismiss('master-pdf');
      toast.error(`Erro: ${e.message || 'Falha ao conectar ao servidor'}`);
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  const handleDownloadXlsx = async () => {
    setIsGeneratingXlsx(true);
    toast.loading('Gerando Matriz Consolidada de Auditoria (.XLSX)...', { id: 'master-xlsx' });

    try {
      const res = await fetch(`${API_BASE}/api/v1/reports/unified-master/xlsx`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: targetUrl }),
      });

      if (!res.ok) throw new Error('Falha ao gerar matriz de auditoria Excel');

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `matriz_consolidada_auditoria_${new Date().toISOString().slice(0, 10)}.xlsx`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      toast.dismiss('master-xlsx');
      toast.success('Matriz Consolidada de Auditoria (.XLSX) exportada com sucesso!');
    } catch (e: any) {
      toast.dismiss('master-xlsx');
      toast.error(`Erro: ${e.message || 'Falha de conexão com backend'}`);
    } finally {
      setIsGeneratingXlsx(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-4xl max-h-[92vh] bg-bg-secondary border border-accent-cyan/40 rounded-2xl shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-5 bg-gradient-to-r from-emerald-500/20 via-accent-cyan/15 to-transparent border-b border-bg-border flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-accent-cyan/20 border border-accent-cyan/40 flex items-center justify-center text-accent-cyan">
              <FileText className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
                Laudo Técnico-Executivo Consolidado de Auditoria e Conformidade
                <span className="px-2.5 py-0.5 text-[10px] font-extrabold uppercase tracking-wider bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded-full">
                  AUDITORIA &amp; REMEDIAÇÃO
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Avaliação Consolidada 360°: Segurança Web, 32 Controles BACEN/NIST, Malware Scan e MASVS.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Target URL Input */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
            <label className="text-xs font-bold text-slate-200 flex items-center gap-2">
              <Server className="w-4 h-4 text-accent-cyan" />
              Alvo / Escopo de Auditoria Consolidada:
            </label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="input-field font-mono text-xs w-full"
              placeholder="Digite aqui..."
            />
          </div>

          {/* 3 Pillars Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-accent-cyan/40 transition-all space-y-2">
              <div className="flex items-center gap-2 text-accent-cyan font-bold text-xs">
                <Bug className="w-4 h-4" /> 1. Vulnerabilidades Web
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Varredura OWASP Top 10, SQLi, XSS, SSRF, bypass de WAF e verificação de cabeçalhos de segurança.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-emerald-400/40 transition-all space-y-2">
              <div className="flex items-center gap-2 text-emerald-400 font-bold text-xs">
                <ShieldCheck className="w-4 h-4" /> 2. 32 Controles BACEN/NIST
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Matriz de 32 controles (CMN 4.893 / BCB 85), com assinaturas SHA-256 e logs de conformidade.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-purple-400/40 transition-all space-y-2">
              <div className="flex items-center gap-2 text-purple-400 font-bold text-xs">
                <Radio className="w-4 h-4" /> 3. Malware Scan &amp; MASVS
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Análise de assinaturas YARA, engenharia reversa mobile (APK/iOS), segredos e detecção de root.
              </p>
            </div>
          </div>

          {/* Dual Perspective Selection */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-400" />
              Selecione o Foco do Relatório (Perspectiva Dupla):
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <button
                onClick={() => setPerspective('BOTH')}
                className={`p-3 rounded-xl border text-left transition-all ${
                  perspective === 'BOTH'
                    ? 'bg-accent-cyan/15 border-accent-cyan text-slate-100 shadow-[0_0_15px_rgba(0,212,255,0.15)]'
                    : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <p className="text-xs font-bold flex items-center gap-1.5">
                  <Check className="w-3.5 h-3.5 text-accent-cyan" /> 360° Unificado (Recomendado)
                </p>
                <p className="text-[10px] text-slate-400 mt-1">
                  Inclui KPIs do Auditor + Guias Técnicos de Correção para Analistas e Devs.
                </p>
              </button>

              <button
                onClick={() => setPerspective('AUDITOR')}
                className={`p-3 rounded-xl border text-left transition-all ${
                  perspective === 'AUDITOR'
                    ? 'bg-emerald-500/15 border-emerald-500 text-slate-100 shadow-[0_0_15px_rgba(16,185,129,0.15)]'
                    : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <p className="text-xs font-bold flex items-center gap-1.5 text-emerald-300">
                  👨‍💼 Visão do Auditor
                </p>
                <p className="text-[10px] text-slate-400 mt-1">
                  Foco em Enquadramento BACEN CMN 4.893, Hashes SHA-256 e Assinatura Executiva.
                </p>
              </button>

              <button
                onClick={() => setPerspective('ANALYST')}
                className={`p-3 rounded-xl border text-left transition-all ${
                  perspective === 'ANALYST'
                    ? 'bg-purple-500/15 border-purple-500 text-slate-100 shadow-[0_0_15px_rgba(168,85,247,0.15)]'
                    : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <p className="text-xs font-bold flex items-center gap-1.5 text-purple-300">
                  🛠️ Visão Analista / Dev
                </p>
                <p className="text-[10px] text-slate-400 mt-1">
                  Foco em Causa Raiz, Payloads cURL/HTTP, Código de Correção e SLAs.
                </p>
              </button>
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="px-6 py-4 bg-slate-950 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <Lock className="w-4 h-4 text-emerald-400" />
            <span>Assinado Digitalmente via Hash SHA-256</span>
          </div>

          <div className="flex items-center gap-3 w-full sm:w-auto">
            <button
              onClick={handleDownloadXlsx}
              disabled={isGeneratingXlsx}
              className="flex-1 sm:flex-none px-4 py-2.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-bold rounded-xl text-xs flex items-center justify-center gap-2 transition-all"
            >
              <FileSpreadsheet className="w-4 h-4" />
              {isGeneratingXlsx ? 'Gerando Planilha...' : 'Exportar Planilha de Auditoria (.XLSX)'}
            </button>

            <button
              onClick={handleDownloadPdf}
              disabled={isGeneratingPdf}
              className="flex-1 sm:flex-none px-5 py-2.5 bg-accent-cyan text-slate-950 font-extrabold rounded-xl text-xs flex items-center justify-center gap-2 hover:bg-cyan-300 transition-all shadow-lg shadow-cyan-500/20"
            >
              <Download className="w-4 h-4" />
              {isGeneratingPdf ? 'Gerando Laudo PDF...' : 'Exportar Laudo Técnico-Executivo (PDF)'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
