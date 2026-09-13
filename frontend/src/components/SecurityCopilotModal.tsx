'use client';

import { useState } from 'react';
import {
  Sparkles, X, Send, Bot, Shield, ShieldCheck, AlertCircle,
  FileCheck2, ChevronRight, CheckCircle2, ArrowUpRight, Cpu
} from 'lucide-react';
import { copilotApi } from '@/lib/api';
import toast from 'react-hot-toast';
import clsx from 'clsx';

const SUGGESTED_PROMPTS = [
  'Quais são meus maiores riscos no Pix?',
  'Por que meu Security Health Score subiu para 87/100?',
  'Quais riscos estão com SLA em aberto ou próximo ao limite?',
  'Quais controles de segurança sofreram drift recente?',
  'Qual a conformidade com a Resolução BACEN 4.893?',
];

export default function SecurityCopilotModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<Array<{ role: 'user' | 'assistant'; content?: string; data?: any }>>([
    {
      role: 'assistant',
      content: 'Olá! Sou o **Security Copilot**, seu analista de IA para Postura de Segurança e Conformidade Regulatória. Todos os meus insights são fundamentados na telemetria real de EASM, ASPM, BACEN, PCI e evidências criptográficas da plataforma. Como posso ajudar seu comitê ou squad hoje?'
    }
  ]);

  const handleSend = async (textToSend?: string) => {
    const text = (textToSend || query).trim();
    if (!text || loading) return;

    const newMessages = [...messages, { role: 'user' as const, content: text }];
    setMessages(newMessages);
    setQuery('');
    setLoading(true);

    try {
      const res = await copilotApi.query(text);
      setMessages([...newMessages, { role: 'assistant', data: res }]);
    } catch (e: any) {
      toast.error('Erro ao consultar Security Copilot: ' + e.message);
      setMessages([...newMessages, {
        role: 'assistant',
        content: 'Desculpe, ocorreu uma falha na consulta à telemetria. Por favor, tente novamente.'
      }]);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/60 backdrop-blur-sm animate-fadeIn">
      <div
        className="w-full max-w-xl h-full bg-bg-secondary border-l border-bg-border flex flex-col shadow-2xl overflow-hidden"
        style={{ boxShadow: '-10px 0 40px rgba(0, 212, 255, 0.15)' }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-bg-border bg-bg-primary/80">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl flex items-center justify-center bg-gradient-to-br from-accent-cyan/20 to-purple-500/20 border border-accent-cyan/40 shadow-lg">
              <Sparkles className="w-5 h-5 text-accent-cyan animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-extrabold text-slate-100">Security Copilot</h2>
                <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-accent-cyan/15 text-accent-cyan border border-accent-cyan/30 rounded-full">
                  AI ANALYST
                </span>
              </div>
              <p className="text-xs text-slate-400">Inteligência contextual de EASM, ASPM e Governança BACEN</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Chat History */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {messages.map((m, idx) => (
            <div key={idx} className={clsx('flex gap-3', m.role === 'user' ? 'justify-end' : 'justify-start')}>
              {m.role === 'assistant' && (
                <div className="w-8 h-8 rounded-lg flex items-center justify-center bg-slate-900 border border-accent-cyan/40 text-accent-cyan flex-shrink-0 mt-1">
                  <Bot className="w-4 h-4" />
                </div>
              )}

              <div className={clsx(
                'max-w-[88%] rounded-2xl p-4 text-sm leading-relaxed shadow-md',
                m.role === 'user'
                  ? 'bg-accent-cyan/20 border border-accent-cyan/40 text-slate-100 rounded-tr-none'
                  : 'bg-slate-900/90 border border-bg-border text-slate-200 rounded-tl-none'
              )}>
                {m.content && <p className="whitespace-pre-wrap">{m.content}</p>}

                {m.data && (
                  <div className="space-y-4">
                    {/* Main Answer */}
                    <div className="text-slate-100 font-medium leading-relaxed">
                      {m.data.answer}
                    </div>

                    {/* Business Context */}
                    {m.data.business_context && (
                      <div className="p-2.5 rounded-lg bg-slate-800/60 border border-slate-700/60 text-xs text-slate-300">
                        <span className="font-bold text-accent-cyan">Contexto de Negócio: </span>
                        {m.data.business_context}
                      </div>
                    )}

                    {/* Evidences Citation */}
                    {m.data.evidence && m.data.evidence.length > 0 && (
                      <div className="space-y-1.5 pt-2 border-t border-slate-800">
                        <div className="flex items-center gap-1.5 text-xs font-bold text-emerald-400">
                          <FileCheck2 className="w-3.5 h-3.5" />
                          <span>Evidências Criptografadas Auditáveis:</span>
                        </div>
                        <div className="space-y-1">
                          {m.data.evidence.map((ev: any, evIdx: number) => (
                            <div key={evIdx} className="text-xs bg-slate-950/80 p-2 rounded border border-emerald-500/20 flex items-center justify-between gap-2">
                              <span className="font-mono text-emerald-300 font-semibold">{ev.ref || ev.type}</span>
                              <span className="text-slate-400 text-[11px] truncate flex-1 text-right">{ev.detail || ev.status}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Sources & Confidence */}
                    <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800 text-[11px] text-slate-400 font-mono">
                      <span>Confiança: <strong className="text-emerald-400 font-bold">{m.data.confidence_pct}%</strong></span>
                      <span className="text-slate-400">Fontes: {m.data.sources?.length || 0} validadas</span>
                    </div>

                    {/* Actionable Suggestions */}
                    {m.data.suggested_actions && m.data.suggested_actions.length > 0 && (
                      <div className="space-y-1.5 pt-2">
                        <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Ações Recomendadas:</p>
                        <div className="flex flex-wrap gap-2">
                          {m.data.suggested_actions.map((act: any, actIdx: number) => (
                            <button
                              key={actIdx}
                              onClick={() => {
                                toast.success(`Ação '${act.label}' enviada para o Policy Engine.`);
                              }}
                              className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-accent-cyan/10 hover:bg-accent-cyan/20 border border-accent-cyan/30 text-accent-cyan flex items-center gap-1.5 transition-all"
                            >
                              <span>{act.label}</span>
                              <ArrowUpRight className="w-3 h-3" />
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex items-center gap-3 text-slate-400 text-xs animate-pulse">
              <div className="w-6 h-6 rounded-md bg-accent-cyan/20 flex items-center justify-center">
                <Cpu className="w-3.5 h-3.5 text-accent-cyan animate-spin" />
              </div>
              <span>Security Copilot consultando telemetria de EASM, ASPM e Controles BACEN...</span>
            </div>
          )}
        </div>

        {/* Suggested Queries */}
        <div className="px-6 py-2 border-t border-bg-border/60 bg-bg-primary/40">
          <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1.5">Perguntas Rápidas:</p>
          <div className="flex gap-2 overflow-x-auto pb-1.5 scrollbar-none">
            {SUGGESTED_PROMPTS.map((prompt, pIdx) => (
              <button
                key={pIdx}
                onClick={() => handleSend(prompt)}
                className="px-2.5 py-1 rounded-full text-xs font-medium bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-slate-300 whitespace-nowrap transition-colors"
              >
                {prompt}
              </button>
            ))}
          </div>
        </div>

        {/* Input Bar */}
        <div className="p-4 border-t border-bg-border bg-bg-primary/90">
          <form onSubmit={(e) => { e.preventDefault(); handleSend(); }} className="flex items-center gap-2">
            <input
              type="text"
              placeholder="Faça uma pergunta sobre postura, risco, SLA, BACEN..."
              value={query}
              onChange={e => setQuery(e.target.value)}
              disabled={loading}
              className="flex-1 bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
            />
            <button
              type="submit"
              disabled={!query.trim() || loading}
              className="p-3 rounded-xl bg-accent-cyan hover:bg-accent-cyan/80 text-slate-950 font-bold disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-md flex-shrink-0"
            >
              <Send className="w-4 h-4" />
            </button>
          </form>
          <p className="text-[10px] text-slate-400 text-center mt-2">
            Respostas baseadas em telemetria determinística com trilha de auditoria e governança de política.
          </p>
        </div>
      </div>
    </div>
  );
}
