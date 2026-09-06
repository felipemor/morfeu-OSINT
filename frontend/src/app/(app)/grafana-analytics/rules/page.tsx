'use client';

import React, { useState } from 'react';
import {
  ShieldCheck,
  Zap,
  Plus,
  Sliders,
  CheckCircle,
  Radio,
  Server,
  Layers,
  AlertTriangle,
  Lock,
  Play,
  Trash2,
  Edit,
  ArrowRight
} from 'lucide-react';
import toast from 'react-hot-toast';

interface Rule {
  id: string;
  name: string;
  category: string;
  honeypot_condition: string;
  ebpf_condition: string;
  wazuh_condition: string;
  action: string;
  severity: string;
  enabled: boolean;
  triggers_count: number;
}

export default function CorrelationRulesPage() {
  const [rules, setRules] = useState<Rule[]>(defaultRules);
  const [showModal, setShowModal] = useState(false);
  const [newRuleName, setNewRuleName] = useState('');
  const [newHoneypotCond, setNewHoneypotCond] = useState('');
  const [newEbpfCond, setNewEbpfCond] = useState('');
  const [newWazuhCond, setNewWazuhCond] = useState('');
  const [newAction, setNewAction] = useState('ISOLATE_EBPF_HOST');

  const handleToggleRule = (id: string) => {
    setRules((prev) =>
      prev.map((r) => {
        if (r.id === id) {
          const updated = !r.enabled;
          toast.success(`Regra "${r.name}" ${updated ? 'ativada' : 'desativada'}!`);
          return { ...r, enabled: updated };
        }
        return r;
      })
    );
  };

  const handleTestRule = (rule: Rule) => {
    toast.success(
      `Disparo de teste da Regra #${rule.id}: Ação automatizada "${rule.action}" executada!`
    );
  };

  const handleCreateRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleName) {
      toast.error('Informe o nome da regra de correlação');
      return;
    }

    const created: Rule = {
      id: `RULE-${Math.floor(100 + Math.random() * 900)}`,
      name: newRuleName,
      category: 'CUSTOM CORRELATION',
      honeypot_condition: newHoneypotCond || 'Qualquer Probe no Honeypot',
      ebpf_condition: newEbpfCond || 'Tráfego Lateral Não Autorizado',
      wazuh_condition: newWazuhCond || 'Wazuh Alert Level > 10',
      action: newAction,
      severity: 'HIGH',
      enabled: true,
      triggers_count: 0
    };

    setRules([created, ...rules]);
    setShowModal(false);
    setNewRuleName('');
    setNewHoneypotCond('');
    setNewEbpfCond('');
    setNewWazuhCond('');
    toast.success('Nova regra de correlação criada com sucesso!');
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-bg-card border border-accent-cyan/20 p-6 rounded-xl relative overflow-hidden flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div className="absolute top-0 right-0 w-96 h-96 bg-accent-cyan/5 rounded-full filter blur-3xl pointer-events-none" />
        <div>
          <div className="flex items-center gap-3">
            <Sliders className="h-6 w-6 text-accent-cyan" />
            <h1 className="text-2xl font-bold text-text-primary">
              Regras de Correlação Unificada (XDR + eBPF + Honeypot)
            </h1>
            <span className="bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold">
              CORRELATION ENGINE ACTIVE
            </span>
          </div>
          <p className="text-text-muted text-sm mt-1 max-w-3xl">
            Motor de regras inteligentes que correlaciona sondagens no Honeypot, anomalias no tráfego de rede via eBPF e alertas de segurança do Wazuh XDR para acionar respostas automatizadas e isolamento imediato.
          </p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-accent-cyan text-bg-primary font-bold rounded-lg text-sm hover:opacity-90 transition shadow-lg shadow-accent-cyan/20"
        >
          <Plus className="h-4 w-4" />
          Criar Regra de Correlação
        </button>
      </div>

      {/* Rules List */}
      <div className="space-y-4">
        {rules.map((rule) => (
          <div
            key={rule.id}
            className="bg-bg-card border border-border-default rounded-xl p-6 hover:border-accent-cyan/50 transition space-y-4"
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-border-default/60 pb-4">
              <div className="flex items-center gap-3">
                <span className="text-xs font-mono bg-bg-primary border border-border-default text-accent-cyan px-2.5 py-1 rounded-md font-bold">
                  {rule.id}
                </span>
                <div>
                  <h3 className="font-bold text-text-primary text-base flex items-center gap-2">
                    {rule.name}
                  </h3>
                  <span className="text-xs text-text-muted">{rule.category}</span>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <span
                  className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold ${
                    rule.severity === 'CRITICAL'
                      ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                      : rule.severity === 'HIGH'
                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                  }`}
                >
                  {rule.severity}
                </span>

                <button
                  onClick={() => handleToggleRule(rule.id)}
                  className={`px-3 py-1 rounded-lg text-xs font-mono font-semibold transition ${
                    rule.enabled
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      : 'bg-bg-primary text-text-muted border border-border-default'
                  }`}
                >
                  {rule.enabled ? 'ATIVADA' : 'DESATIVADA'}
                </button>

                <button
                  onClick={() => handleTestRule(rule)}
                  className="flex items-center gap-1 px-3 py-1 bg-bg-primary border border-border-default hover:border-accent-cyan text-text-primary rounded-lg text-xs font-mono transition"
                >
                  <Play className="h-3 w-3 text-accent-cyan" /> Testar
                </button>
              </div>
            </div>

            {/* Correlation Flow Visualization */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 bg-bg-primary p-4 rounded-xl border border-border-default/50 text-xs">
              <div className="space-y-1">
                <span className="text-text-muted font-mono flex items-center gap-1.5 text-[11px]">
                  <Radio className="h-3.5 w-3.5 text-accent-cyan" /> 1. PROBE HONEYPOT
                </span>
                <p className="text-text-primary font-medium">{rule.honeypot_condition}</p>
              </div>

              <div className="space-y-1">
                <span className="text-text-muted font-mono flex items-center gap-1.5 text-[11px]">
                  <Layers className="h-3.5 w-3.5 text-purple-400" /> 2. FLUXO eBPF
                </span>
                <p className="text-text-primary font-medium">{rule.ebpf_condition}</p>
              </div>

              <div className="space-y-1">
                <span className="text-text-muted font-mono flex items-center gap-1.5 text-[11px]">
                  <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" /> 3. SIEM WAZUH
                </span>
                <p className="text-text-primary font-medium">{rule.wazuh_condition}</p>
              </div>

              <div className="space-y-1 bg-bg-card p-3 rounded-lg border border-accent-cyan/30">
                <span className="text-accent-cyan font-mono flex items-center gap-1.5 text-[11px] font-bold">
                  <Zap className="h-3.5 w-3.5 text-amber-400" /> AÇÃO AUTOMATIZADA
                </span>
                <p className="text-text-primary font-bold text-xs">{rule.action}</p>
              </div>
            </div>

            <div className="flex justify-between items-center text-xs text-text-muted font-mono pt-1">
              <span>Disparos registrados no Grafana: {rule.triggers_count} vezes</span>
              <span>Motor: Morfeu Correlation Engine v3.4</span>
            </div>
          </div>
        ))}
      </div>

      {/* Modal for Creating New Rule */}
      {showModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-bg-card border border-border-default rounded-xl w-full max-w-xl p-6 space-y-4 shadow-2xl">
            <h2 className="text-lg font-bold text-text-primary flex items-center gap-2">
              <Plus className="h-5 w-5 text-accent-cyan" />
              Criar Nova Regra de Correlação
            </h2>

            <form onSubmit={handleCreateRule} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-text-muted uppercase mb-1">
                  Nome da Regra
                </label>
                <input
                  type="text"
                  required
                  value={newRuleName}
                  onChange={(e) => setNewRuleName(e.target.value)}
                  placeholder="Ex: Detecção de Movimentação Lateral de Ransomware"
                  className="w-full bg-bg-primary border border-border-default rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-text-muted uppercase mb-1">
                  Condição 1: Trigger no Honeypot
                </label>
                <input
                  type="text"
                  value={newHoneypotCond}
                  onChange={(e) => setNewHoneypotCond(e.target.value)}
                  placeholder="Ex: SSH Bruteforce na Porta 2222"
                  className="w-full bg-bg-primary border border-border-default rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-text-muted uppercase mb-1">
                  Condição 2: Filtro eBPF Microsegmentação
                </label>
                <input
                  type="text"
                  value={newEbpfCond}
                  onChange={(e) => setNewEbpfCond(e.target.value)}
                  placeholder="Ex: Conexão TCP para porta 445 (SMB) em host de Produção"
                  className="w-full bg-bg-primary border border-border-default rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-text-muted uppercase mb-1">
                  Condição 3: Alerta Wazuh XDR
                </label>
                <input
                  type="text"
                  value={newWazuhCond}
                  onChange={(e) => setNewWazuhCond(e.target.value)}
                  placeholder="Ex: Rule 5710 (Host key changed / Privilege Escalation)"
                  className="w-full bg-bg-primary border border-border-default rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-text-muted uppercase mb-1">
                  Ação Automatizada MorfeuSec
                </label>
                <select
                  value={newAction}
                  onChange={(e) => setNewAction(e.target.value)}
                  className="w-full bg-bg-primary border border-border-default rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent-cyan"
                >
                  <option value="ISOLATE_EBPF_HOST">Aplicar Política eBPF Isolamento Total do Host Alvo</option>
                  <option value="WAZUH_ACTIVE_RESPONSE">Disparar Wazuh Active Response (Block IP Firewall)</option>
                  <option value="GENERATE_CRITICAL_INCIDENT">Gerar Incidente Crítico SOC & Notificar PagerDuty</option>
                </select>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-border-default">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 bg-bg-primary border border-border-default text-text-primary rounded-lg text-sm"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-accent-cyan text-bg-primary font-bold rounded-lg text-sm hover:opacity-90"
                >
                  Salvar Regra
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

const defaultRules: Rule[] = [
  {
    id: 'RULE-101',
    name: 'Movimentação Lateral Pós-Probe em Honeypot SSH',
    category: 'ADVANCED THREAT CORRELATION',
    honeypot_condition: 'SSH Bruteforce na Porta 2222',
    ebpf_condition: 'Fluxo TCP Lateral Não Autorizado para Banco de Dados MySQL',
    wazuh_condition: 'Wazuh Level > 10 (Trojan / Rootkit Alert)',
    action: 'Política eBPF de Isolamento Total do IP Alvo + Alerta SOC',
    severity: 'CRITICAL',
    enabled: true,
    triggers_count: 12
  },
  {
    id: 'RULE-102',
    name: 'Tentativa de RCE via Spring Actuator Web Decoy',
    category: 'WEB EXPLOIT CORRELATION',
    honeypot_condition: 'POST Malicioso no Decoy HTTP Porta 8080',
    ebpf_condition: 'Execução de processo curl/wget não mapeado na política',
    wazuh_condition: 'Wazuh Rule 31101 (Web Attack Detected)',
    action: 'Bloqueio Imediato do IP no Firewall Wazuh Active Response',
    severity: 'HIGH',
    enabled: true,
    triggers_count: 5
  }
];
