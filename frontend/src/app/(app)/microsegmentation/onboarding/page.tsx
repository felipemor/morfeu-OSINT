'use client';
import { useState } from 'react';
import Link from 'next/link';
import { DownloadCloud, Copy, Check, Cpu, Cloud, Server, ShieldCheck, ArrowRight, Network } from 'lucide-react';
import toast from 'react-hot-toast';

export default function MicrosegmentationOnboardingPage() {
  const [collectorHost, setCollectorHost] = useState('192.168.1.100');
  const [activePlatform, setActivePlatform] = useState<'K8S' | 'LINUX' | 'AWS' | 'DOCKER'>('K8S');
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    toast.success('Comando copiado para a área de transferência!');
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const getCommands = () => {
    const host = collectorHost || 'SEU_COLLECTOR_IP';
    switch (activePlatform) {
      case 'K8S':
        return [
          {
            title: '1. Adicionar Repositório Helm do Cilium & Hubble eBPF',
            cmd: `helm repo add cilium https://helm.cilium.io/\nhelm repo update`
          },
          {
            title: '2. Instalar Cilium CNI com Observabilidade eBPF Ativa',
            cmd: `helm install cilium cilium/cilium --version 1.15.5 \\\n  --namespace kube-system \\\n  --set hubble.enabled=true \\\n  --set hubble.relay.enabled=true \\\n  --set hubble.ui.enabled=true \\\n  --set global.bpf.masquerade=true`
          },
          {
            title: '3. Apontar o Hubble Relay para o Collector da Plataforma',
            cmd: `kubectl -n kube-system set env deployment/hubble-relay COLLECTOR_ENDPOINT="grpcs://${host}:4244"`
          }
        ];
      case 'LINUX':
        return [
          {
            title: '1. Baixar Agente de Microsegmentação eBPF para Linux (x86_64)',
            cmd: `curl -sSL https://packages.internal.sec/microseg-agent-linux.tar.gz | tar -xzf -`
          },
          {
            title: '2. Instalar Módulo eBPF Daemon com IP do Collector',
            cmd: `sudo ./install.sh --collector-ip="${host}" --mode=monitoring --zone="Production-Linux"`
          },
          {
            title: '3. Iniciar Daemon de Coleta eBPF',
            cmd: `sudo systemctl enable microseg-ebpf && sudo systemctl start microseg-ebpf`
          }
        ];
      case 'AWS':
        return [
          {
            title: '1. Habilitar VPC Flow Logs na AWS (CloudWatch Logs)',
            cmd: `aws ec2 create-flow-logs \\\n  --resource-ids vpc-0a1b2c3d4e5f6g7h8 \\\n  --resource-type VPC \\\n  --traffic-type ALL \\\n  --log-destination-type cloud-watch-logs \\\n  --log-group-name /aws/vpc/microseg-flows`
          },
          {
            title: '2. Configurar Role IAM de Leitura para o Ingestor',
            cmd: `aws iam create-role --role-name MicrosegFlowsRole --assume-role-policy-document file://trust-policy.json`
          }
        ];
      case 'DOCKER':
        return [
          {
            title: '1. Executar Container de Telemetria eBPF (Sidecar Daemon)',
            cmd: `docker run -d \\\n  --name microseg-ebpf-sidecar \\\n  --privileged \\\n  --net=host \\\n  -v /sys/fs/bpf:/sys/fs/bpf \\\n  -v /proc:/host/proc:ro \\\n  -e COLLECTOR_URL="https://${host}:8443" \\\n  microseg/ebpf-collector:latest`
          }
        ];
    }
  };

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
          <DownloadCloud className="w-5 h-5 text-accent-cyan" /> Guia de Instalação e Conexão eBPF (Microsegmentação)
        </h2>
        <p className="text-xs text-slate-400">
          Siga os passos abaixo para conectar clusters Kubernetes, instâncias Linux, AWS VPC ou containers Docker ao motor de Microsegmentação.
        </p>
      </div>

      {/* Step 1: Input Collector Host */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-4 shadow-lg">
        <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
          <span className="w-6 h-6 rounded-full bg-accent-cyan text-slate-950 text-xs font-black flex items-center justify-center">1</span>
          <span>Informe o Endereço IP / Hostname do Coletor de Telemetria</span>
        </div>
        <p className="text-xs text-slate-400">
          Ao alterar o IP abaixo, os comandos de instalação eBPF serão atualizados em tempo real!
        </p>

        <div className="flex flex-col sm:flex-row items-center gap-3">
          <input
            type="text"
            value={collectorHost}
            onChange={(e) => setCollectorHost(e.target.value)}
            placeholder="Ex: 192.168.1.100 ou hubble.prod.k8s.internal"
            className="px-4 py-2 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 font-mono text-sm focus:outline-none focus:border-accent-cyan w-full sm:w-80"
          />
          <span className="text-xs text-accent-green font-semibold flex items-center gap-1">
            <ShieldCheck className="w-4 h-4" /> Scripts dinâmicos atualizados!
          </span>
        </div>
      </div>

      {/* Step 2: Platform Selector */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-6 shadow-lg">
        <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
          <span className="w-6 h-6 rounded-full bg-accent-cyan text-slate-950 text-xs font-black flex items-center justify-center">2</span>
          <span>Selecione a Plataforma de Infraestrutura</span>
        </div>

        {/* Platform Tabs */}
        <div className="flex flex-wrap gap-2 border-b border-bg-border pb-3">
          <button
            onClick={() => setActivePlatform('K8S')}
            className={`px-4 py-2 text-xs font-bold rounded-lg transition-all ${
              activePlatform === 'K8S'
                ? 'bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/40'
                : 'bg-bg-secondary text-slate-400 hover:text-slate-200'
            }`}
          >
            ☸️ Kubernetes (Cilium & Hubble eBPF)
          </button>
          <button
            onClick={() => setActivePlatform('LINUX')}
            className={`px-4 py-2 text-xs font-bold rounded-lg transition-all ${
              activePlatform === 'LINUX'
                ? 'bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/40'
                : 'bg-bg-secondary text-slate-400 hover:text-slate-200'
            }`}
          >
            🐧 Linux Host (VM / Bare-Metal eBPF Daemon)
          </button>
          <button
            onClick={() => setActivePlatform('AWS')}
            className={`px-4 py-2 text-xs font-bold rounded-lg transition-all ${
              activePlatform === 'AWS'
                ? 'bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/40'
                : 'bg-bg-secondary text-slate-400 hover:text-slate-200'
            }`}
          >
            ☁️ AWS Cloud (VPC Flow Logs Ingestor)
          </button>
          <button
            onClick={() => setActivePlatform('DOCKER')}
            className={`px-4 py-2 text-xs font-bold rounded-lg transition-all ${
              activePlatform === 'DOCKER'
                ? 'bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/40'
                : 'bg-bg-secondary text-slate-400 hover:text-slate-200'
            }`}
          >
            🐳 Docker Containers (Sidecar Daemon)
          </button>
        </div>

        {/* Commands List */}
        <div className="space-y-4">
          {getCommands().map((step, idx) => (
            <div key={idx} className="space-y-2">
              <h4 className="text-xs font-bold text-slate-200">{step.title}</h4>
              <div className="relative group">
                <pre className="p-4 rounded-lg bg-slate-950 font-mono text-xs text-accent-cyan overflow-x-auto border border-bg-border leading-relaxed">
                  {step.cmd}
                </pre>
                <button
                  onClick={() => copyToClipboard(step.cmd, idx)}
                  className="absolute top-2.5 right-2.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-semibold rounded border border-slate-600 flex items-center gap-1.5 transition-all"
                >
                  {copiedIndex === idx ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-accent-green" /> Copiado!
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" /> Copiar Comando
                    </>
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Step 3: Network Ports Verification */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-3 shadow-lg">
        <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
          <span className="w-6 h-6 rounded-full bg-accent-cyan text-slate-950 text-xs font-black flex items-center justify-center">3</span>
          <span>Verificação de Portas de Comunicação eBPF</span>
        </div>
        <p className="text-xs text-slate-400">
          Requisitos de rede para sincronização de políticas Zero Trust e fluxos eBPF:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs pt-2">
          <div className="bg-bg-secondary p-3 rounded-lg border border-bg-border">
            <span className="font-mono font-bold text-accent-cyan block">Porta 4240 (TCP)</span>
            <span className="text-slate-400 text-[11px]">Cilium Health & Cluster Mesh Communication</span>
          </div>
          <div className="bg-bg-secondary p-3 rounded-lg border border-bg-border">
            <span className="font-mono font-bold text-purple-400 block">Porta 4244 (TCP/gRPC)</span>
            <span className="text-slate-400 text-[11px]">Hubble Relay Flow Observability Stream</span>
          </div>
          <div className="bg-bg-secondary p-3 rounded-lg border border-bg-border">
            <span className="font-mono font-bold text-accent-green block">Porta 8443 (TCP/mTLS)</span>
            <span className="text-slate-400 text-[11px]">Microsegmentation Agent Collector API</span>
          </div>
        </div>
      </div>

      {/* Step 4: Link to Network Map */}
      <div className="bg-bg-card border border-accent-cyan/30 rounded-xl p-6 flex items-center justify-between gap-4">
        <div>
          <h4 className="text-sm font-bold text-slate-100">Visualizar Fluxos no Mapa Topológico</h4>
          <p className="text-xs text-slate-400 mt-0.5">
            Após a execução do coletor eBPF, os ativos e fluxos aparecerão em tempo real no Network Map.
          </p>
        </div>
        <Link
          href="/microsegmentation/network-map"
          className="flex items-center gap-2 px-4 py-2 text-xs font-bold bg-accent-cyan text-slate-950 rounded-lg hover:bg-cyan-400 transition-all flex-shrink-0"
        >
          Abrir Network Map <ArrowRight className="w-4 h-4" />
        </Link>
      </div>
    </div>
  );
}
