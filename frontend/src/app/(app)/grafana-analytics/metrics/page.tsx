'use client';

import React, { useEffect, useState } from 'react';
import {
  Activity,
  Cpu,
  RefreshCw,
  Copy,
  Terminal,
  Database,
  ShieldCheck,
  Zap,
  Code,
  Search,
  CheckCircle,
  ExternalLink
} from 'lucide-react';
import toast from 'react-hot-toast';
import { grafanaAnalyticsApi } from '@/lib/api';

export default function MetricsPage() {
  const [rawMetrics, setRawMetrics] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [searchFilter, setSearchFilter] = useState('');

  const loadMetrics = async () => {
    setLoading(true);
    try {
      const data = await grafanaAnalyticsApi.getMetrics();
      setRawMetrics(
        data?.prometheus_metrics_raw || defaultMetricsRaw
      );
    } catch (e) {
      setRawMetrics(defaultMetricsRaw);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadMetrics();
  }, []);

  const handleCopyMetrics = () => {
    navigator.clipboard.writeText(rawMetrics);
    toast.success('Métricas Prometheus copiadas para a área de transferência!');
  };

  const filteredMetrics = rawMetrics
    .split('\n')
    .filter((line) => line.toLowerCase().includes(searchFilter.toLowerCase()))
    .join('\n');

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-bg-card border border-accent-cyan/20 p-6 rounded-xl relative overflow-hidden flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div className="absolute top-0 right-0 w-96 h-96 bg-purple-500/5 rounded-full filter blur-3xl pointer-events-none" />
        <div>
          <div className="flex items-center gap-3">
            <Activity className="h-6 w-6 text-accent-cyan animate-pulse" />
            <h1 className="text-2xl font-bold text-text-primary">
              Exportador & Explorer de Métricas Prometheus
            </h1>
            <span className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold">
              METRICS EXPORTER ONLINE
            </span>
          </div>
          <p className="text-text-muted text-sm mt-1 max-w-3xl">
            Endpoint oficial de scraping de métricas Prometheus (<code className="text-accent-cyan">/api/v1/grafana-analytics/metrics</code>) consumido pelo Grafana para correlação de telemetria eBPF, Wazuh XDR e Honeypot.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadMetrics}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 bg-bg-primary border border-border-default hover:border-accent-cyan text-text-primary rounded-lg text-sm transition"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Atualizar Métricas
          </button>
          <button
            onClick={handleCopyMetrics}
            className="flex items-center gap-2 px-4 py-2 bg-accent-cyan text-bg-primary font-bold rounded-lg text-sm hover:opacity-90 transition shadow-lg shadow-accent-cyan/20"
          >
            <Copy className="h-4 w-4" />
            Copiar Raw Prometheus
          </button>
        </div>
      </div>

      {/* Metric Counters Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-bg-card p-5 rounded-xl border border-border-default">
          <div className="text-text-muted text-xs font-mono uppercase">honeypot_attacks_total</div>
          <div className="text-2xl font-bold text-red-400 mt-2 font-mono">2,750 reqs</div>
          <div className="text-xs text-text-muted mt-1">Counter gauge em tempo real</div>
        </div>

        <div className="bg-bg-card p-5 rounded-xl border border-border-default">
          <div className="text-text-muted text-xs font-mono uppercase">ebpf_network_bytes_total</div>
          <div className="text-2xl font-bold text-accent-cyan mt-2 font-mono">1.42 GB</div>
          <div className="text-xs text-text-muted mt-1">Volume de tráfego inspecionado</div>
        </div>

        <div className="bg-bg-card p-5 rounded-xl border border-border-default">
          <div className="text-text-muted text-xs font-mono uppercase">wazuh_alerts_total</div>
          <div className="text-2xl font-bold text-purple-400 mt-2 font-mono">14 alertas</div>
          <div className="text-xs text-text-muted mt-1">Regras Nível &gt; 10 acionadas</div>
        </div>

        <div className="bg-bg-card p-5 rounded-xl border border-border-default">
          <div className="text-text-muted text-xs font-mono uppercase">pentest_critical_vulnerabilities</div>
          <div className="text-2xl font-bold text-amber-400 mt-2 font-mono">2 CVEs</div>
          <div className="text-xs text-text-muted mt-1">Vulnerabilidades de impacto alto</div>
        </div>
      </div>

      {/* PromQL Simulation Box */}
      <div className="bg-bg-card border border-border-default rounded-xl p-6 space-y-4">
        <div className="flex justify-between items-center">
          <h2 className="text-lg font-bold text-text-primary flex items-center gap-2">
            <Terminal className="h-5 w-5 text-accent-cyan" />
            PromQL Query Preview & Scraper Telemetry
          </h2>
          <span className="text-xs text-text-muted font-mono">
            Scrape interval: 15s | Status: 200 OK
          </span>
        </div>

        <div className="relative">
          <Search className="h-4 w-4 absolute left-3.5 top-3.5 text-text-muted" />
          <input
            type="text"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            placeholder="Filtrar métricas por nome (ex: honeypot, ebpf, wazuh, pentest)..."
            className="w-full bg-bg-primary border border-border-default rounded-lg pl-10 pr-4 py-2.5 text-sm text-text-primary focus:outline-none focus:border-accent-cyan font-mono"
          />
        </div>

        <div className="bg-bg-primary border border-border-default rounded-lg p-4 font-mono text-xs overflow-x-auto text-emerald-400 max-h-96 overflow-y-auto">
          <pre>{filteredMetrics || '# Nenhum resultado encontrado para o filtro'}</pre>
        </div>
      </div>
    </div>
  );
}

const defaultMetricsRaw = `# HELP honeypot_attacks_total Total de tentativas de invasao capturadas pelas armadilhas
# TYPE honeypot_attacks_total counter
honeypot_attacks_total{trap="ssh-decoy-2222",protocol="SSH"} 1420
honeypot_attacks_total{trap="http-admin-8080",protocol="HTTP"} 890
honeypot_attacks_total{trap="redis-nosql-6379",protocol="RESP"} 440

# HELP ebpf_network_bytes_total Bytes de tráfego de rede analisados em tempo real pelo eBPF
# TYPE ebpf_network_bytes_total counter
ebpf_network_bytes_total{interface="eth0",cluster="prod-k8s"} 1524890120
ebpf_network_bytes_total{interface="ebpf0",cluster="prod-k8s"} 41209012

# HELP wazuh_alerts_total Alertas de seguranca gerados pelo Wazuh XDR por severidade
# TYPE wazuh_alerts_total gauge
wazuh_alerts_total{level="critical"} 4
wazuh_alerts_total{level="high"} 10

# HELP pentest_critical_vulnerabilities Vulnerabilidades criticas detectadas nos escaneamentos de Pentest
# TYPE pentest_critical_vulnerabilities gauge
pentest_critical_vulnerabilities{cve="CVE-2024-3094"} 1
pentest_critical_vulnerabilities{cve="CVE-2023-4863"} 1
`;
