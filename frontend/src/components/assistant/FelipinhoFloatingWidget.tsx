'use client';

import React, { useState, useRef, useEffect } from 'react';
import {
  Bot, MessageSquare, X, Minimize2, Maximize2, Send, Sparkles,
  Terminal, Shield, Copy, Check, Trash2, RefreshCw, Cpu, HelpCircle,
  ChevronRight, Smartphone, Radar, Layers, Zap
} from 'lucide-react';
import { felipinhoApi } from '@/lib/api';
import clsx from 'clsx';
import toast from 'react-hot-toast';

interface Message {
  id: string;
  sender: 'user' | 'raven';
  text: string;
  timestamp: string;
  suggestedActions?: string[];
}

export default function RavenFloatingWidget() {
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome-1',
      sender: 'raven',
      text: `### 🛡️ Olá! Sou a **Raven**, a Inteligência Tática e Especialista em Cibersegurança da **Heimdall Security**.

Estou pronta para analisar sua postura e apoiar investigações em:
* 📱 **Mobile AppSec:** Análise de APK/IPA, descompilação e conformidade **OWASP MASVS**.
* 🌐 **OSINT & Superfície de Ataque:** Mapeamento de DNS, subdomínios, certificados e infraestrutura exposta.
* 🛡️ **Defesa & Governança:** Avaliação dos controles de segurança e laudos executivos BACEN/PCI.
* 🔍 **Inteligência Anti-Fraude:** Investigação de domínios clonados, boletos adulterados e takedowns.

*Selecione um tópico rápido ou digite sua consulta técnica:*`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      suggestedActions: [
        'Como interpretar o score MASVS do Mobile?',
        'O que fazer ao detectar um clone de CNPJ ou domínio fake?',
        'Como funciona a verificação dos 32 Controles BACEN?',
        'Como exportar laudos periciais com custódia SHA-256?',
      ],
    },
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen && !isMinimized) {
      scrollToBottom();
    }
  }, [messages, isOpen, isMinimized]);

  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend || inputMessage).trim();
    if (!text || isLoading) return;

    const userMsg: Message = {
      id: `usr-${Date.now()}`,
      sender: 'user',
      text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputMessage('');
    setIsLoading(true);

    try {
      const data = await felipinhoApi.chat(text);
      const aiMsg: Message = {
        id: `raven-${Date.now()}`,
        sender: 'raven',
        text: data.response,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        suggestedActions: data.suggested_actions,
      };
      setMessages((prev) => [...prev, aiMsg]);
    } catch (err) {
      const errorMsg: Message = {
        id: `err-${Date.now()}`,
        sender: 'raven',
        text: 'Desculpe, ocorreu uma oscilação na conexão com o motor de inteligência Raven. Por favor, tente novamente.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    toast.success('Resposta copiada!');
    setTimeout(() => setCopiedId(null), 2000);
  };

  const clearChat = () => {
    setMessages([
      {
        id: `welcome-${Date.now()}`,
        sender: 'raven',
        text: 'Conversa reiniciada. Qual investigação ou análise tática deseja executar?',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        suggestedActions: [
          'Como interpretar o score MASVS do Mobile?',
          'O que fazer ao detectar um clone de CNPJ ou domínio fake?',
          'Como funciona a verificação dos 32 Controles BACEN?',
        ],
      },
    ]);
  };

  return (
    <div className="fixed bottom-6 right-6 z-50">
      {/* Floating Trigger Button */}
      {!isOpen && (
        <button
          onClick={() => {
            setIsOpen(true);
            setIsMinimized(false);
          }}
          className="relative group flex items-center gap-3 px-4 py-3 rounded-full bg-gradient-to-r from-slate-900 via-slate-900 to-[#0c182b] border border-accent-cyan/40 text-slate-100 shadow-[0_0_25px_rgba(0,212,255,0.3)] hover:shadow-[0_0_35px_rgba(0,212,255,0.5)] transition-all duration-300 hover:scale-105 active:scale-95 cursor-pointer"
        >
          {/* Animated Glowing Cyber Ring */}
          <div className="absolute -inset-0.5 rounded-full bg-gradient-to-r from-accent-cyan to-purple-500 opacity-30 group-hover:opacity-75 blur-sm transition-opacity" />

          {/* Avatar Icon */}
          <div className="relative w-9 h-9 rounded-full bg-slate-950 border-2 border-accent-cyan/60 flex items-center justify-center overflow-hidden flex-shrink-0 shadow-inner text-cyan-400">
            <Bot className="w-5 h-5" />
            <span className="absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full bg-emerald-400 border-2 border-slate-900 animate-ping" />
            <span className="absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full bg-emerald-400 border-2 border-slate-900" />
          </div>

          <div className="relative text-left hidden sm:block">
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-bold text-slate-100 font-mono tracking-tight">Raven AI</span>
              <span className="px-1.5 py-0.2 rounded bg-accent-cyan/20 text-accent-cyan text-[9px] font-extrabold uppercase font-mono">
                ONLINE
              </span>
            </div>
            <p className="text-[10px] text-slate-400">Inteligência Tática &amp; Suporte</p>
          </div>
        </button>
      )}

      {/* Floating Chat Modal */}
      {isOpen && (
        <div
          className={clsx(
            'flex flex-col bg-bg-card/95 backdrop-blur-md border border-accent-cyan/30 rounded-2xl shadow-[0_10px_40px_rgba(0,0,0,0.8),0_0_20px_rgba(0,212,255,0.15)] transition-all duration-300 overflow-hidden',
            isMinimized
              ? 'w-80 h-14'
              : 'w-[90vw] sm:w-[440px] h-[580px] max-h-[85vh]'
          )}
        >
          {/* Modal Header */}
          <div className="px-4 py-3 bg-gradient-to-r from-slate-900 via-[#0c182b] to-slate-900 border-b border-bg-border flex items-center justify-between flex-shrink-0">
            <div className="flex items-center gap-2.5">
              <div className="relative w-9 h-9 rounded-full bg-slate-950 border border-accent-cyan/60 flex items-center justify-center overflow-hidden flex-shrink-0 text-cyan-400">
                <Bot className="w-5 h-5" />
                <span className="absolute bottom-0 right-0 w-2 h-2 rounded-full bg-emerald-400 border border-slate-900" />
              </div>
              <div>
                <div className="flex items-center gap-1.5">
                  <h3 className="text-xs font-bold text-slate-100 tracking-tight font-mono">Raven AI</h3>
                  <span className="px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 text-[9px] font-bold font-mono">
                    HEIMDALL
                  </span>
                </div>
                <p className="text-[10px] text-slate-400">Assistente Tático &amp; Cibersegurança</p>
              </div>
            </div>

            <div className="flex items-center gap-1">
              <button
                onClick={clearChat}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-bg-secondary transition-colors"
                title="Limpar conversa"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setIsMinimized(!isMinimized)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-bg-secondary transition-colors"
                title={isMinimized ? 'Expandir' : 'Minimizar'}
              >
                {isMinimized ? <Maximize2 className="w-3.5 h-3.5" /> : <Minimize2 className="w-3.5 h-3.5" />}
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-accent-red hover:bg-bg-secondary transition-colors"
                title="Fechar"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Modal Body / Chat Feed */}
          {!isMinimized && (
            <>
              <div className="flex-1 p-4 overflow-y-auto space-y-4 text-xs">
                {messages.map((msg) => {
                  const isUser = msg.sender === 'user';
                  return (
                    <div
                      key={msg.id}
                      className={clsx('flex flex-col', isUser ? 'items-end' : 'items-start')}
                    >
                      <div
                        className={clsx(
                          'max-w-[90%] rounded-xl p-3.5 relative group shadow-md leading-relaxed whitespace-pre-wrap',
                          isUser
                            ? 'bg-accent-cyan/15 border border-accent-cyan/30 text-slate-100 rounded-tr-none'
                            : 'bg-bg-secondary/90 border border-bg-border text-slate-200 rounded-tl-none'
                        )}
                      >
                        {!isUser && (
                          <div className="flex items-center justify-between border-b border-bg-border/60 pb-1.5 mb-2 text-[10px] text-slate-400">
                            <span className="flex items-center gap-1.5 font-mono text-accent-cyan font-bold">
                              <Bot className="w-3.5 h-3.5" />
                              Raven AI
                            </span>
                            <button
                              onClick={() => handleCopy(msg.text, msg.id)}
                              className="opacity-0 group-hover:opacity-100 hover:text-accent-cyan transition-opacity"
                              title="Copiar resposta"
                            >
                              {copiedId === msg.id ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        )}

                        <div className="text-xs space-y-1.5 prose-dark font-sans">
                          {msg.text}
                        </div>

                        <div className="text-[9px] text-slate-500 text-right mt-1.5">
                          {msg.timestamp}
                        </div>
                      </div>

                      {/* Suggested quick action chips below AI response */}
                      {!isUser && msg.suggestedActions && msg.suggestedActions.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1.5 max-w-[95%]">
                          {msg.suggestedActions.map((action, i) => (
                            <button
                              key={i}
                              onClick={() => handleSendMessage(action)}
                              className="text-[11px] font-medium px-2.5 py-1 rounded-lg bg-bg-secondary/80 border border-bg-border hover:border-accent-cyan/50 text-slate-300 hover:text-accent-cyan transition-all text-left flex items-center gap-1 shadow-sm"
                            >
                              <ChevronRight className="w-3 h-3 text-accent-cyan flex-shrink-0" />
                              <span>{action}</span>
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}

                {isLoading && (
                  <div className="flex items-center gap-2 text-xs text-slate-400 bg-bg-secondary/70 p-3 rounded-xl border border-bg-border max-w-[70%]">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin text-accent-cyan" />
                    <span>Felipinho está interpretando sua dúvida...</span>
                  </div>
                )}

                <div ref={messagesEndRef} />
              </div>

              {/* Chat Input Bar */}
              <div className="p-3 bg-bg-secondary/80 border-t border-bg-border">
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    handleSendMessage();
                  }}
                  className="flex items-center gap-2"
                >
                  <input
                    type="text"
                    value={inputMessage}
                    onChange={(e) => setInputMessage(e.target.value)}
                    placeholder="Pergunte ao Felipinho sobre qualquer tela..."
                    className="flex-1 bg-bg-card border border-bg-border rounded-xl px-3.5 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-accent-cyan focus:ring-1 focus:ring-accent-cyan transition-all"
                  />
                  <button
                    type="submit"
                    disabled={!inputMessage.trim() || isLoading}
                    className="p-2.5 rounded-xl bg-accent-cyan hover:bg-cyan-400 text-slate-950 font-bold transition-all disabled:opacity-40 disabled:cursor-not-allowed shadow-md shadow-accent-cyan/20 cursor-pointer"
                    title="Enviar mensagem"
                  >
                    <Send className="w-4 h-4" />
                  </button>
                </form>
                <div className="flex items-center justify-between text-[9px] text-slate-500 mt-1.5 px-1">
                  <span>Raven AI • Assistente Oficial</span>
                  <span>Escrito por Felipe Costa - felipe_c@myyahoo.com</span>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
