'use client';
import { useState } from 'react';
import Link from 'next/link';
import { DownloadCloud, Copy, Check, Terminal, ShieldCheck, Server, AlertCircle, ArrowRight } from 'lucide-react';
import toast from 'react-hot-toast';

export default function AgentOnboardingPage() {
  const [managerIp, setManagerIp] = useState('192.168.1.100');
  const [activeOs, setActiveOs] = useState<'WINDOWS' | 'UBUNTU' | 'RHEL' | 'MACOS'>('WINDOWS');
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    toast.success('Comando copiado para a área de transferência!');
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  // Commands based on OS and IP input
  const getCommands = () => {
    const ip = managerIp || 'SEU_SERVER_IP';
    switch (activeOs) {
      case 'WINDOWS':
        return [
          {
            title: '1. Baixar o Agente Oficial (PowerShell Admin)',
            cmd: `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.0-1.msi -OutFile wazuh-agent.msi`
          },
          {
            title: '2. Instalar e Apontar para o Wazuh Manager',
            cmd: `msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER='${ip}' WAZUH_REGISTRATION_SERVER='${ip}'`
          },
          {
            title: '3. Iniciar o Serviço do Agente',
            cmd: `NET START WazuhSvc`
          }
        ];
      case 'UBUNTU':
        return [
          {
            title: '1. Adicionar Repositório GPG da Wazuh',
            cmd: `curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg\necho "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list\nsudo apt-get update`
          },
          {
            title: '2. Instalar o Agente Configurando o IP do Manager',
            cmd: `sudo WAZUH_MANAGER="${ip}" apt-get install wazuh-agent`
          },
          {
            title: '3. Ativar e Iniciar o Serviço',
            cmd: `sudo systemctl daemon-reload && sudo systemctl enable wazuh-agent && sudo systemctl start wazuh-agent`
          }
        ];
      case 'RHEL':
        return [
          {
            title: '1. Importar Chaves e Repositório RPM',
            cmd: `rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH\ncat << EOF > /etc/yum.repos.d/wazuh.repo\n[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-\$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1\nEOF`
          },
          {
            title: '2. Instalar Agente',
            cmd: `sudo WAZUH_MANAGER="${ip}" yum install wazuh-agent`
          },
          {
            title: '3. Iniciar Serviço',
            cmd: `sudo systemctl daemon-reload && sudo systemctl enable wazuh-agent && sudo systemctl start wazuh-agent`
          }
        ];
      case 'MACOS':
        return [
          {
            title: '1. Baixar o Pacote .pkg',
            cmd: `curl -O https://packages.wazuh.com/4.x/macos/wazuh-agent-4.8.0-1.pkg`
          },
          {
            title: '2. Configurar Variável e Instalar',
            cmd: `sudo echo "WAZUH_MANAGER='${ip}'" > /tmp/wazuh_envs && sudo installer -pkg wazuh-agent-4.8.0-1.pkg -target /`
          },
          {
            title: '3. Iniciar Serviço',
            cmd: `sudo /Library/Ossec/bin/wazuh-control start`
          }
        ];
    }
  };

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
          <DownloadCloud className="w-5 h-5 text-red-500" /> Guia de Instalação & Conexão de Agentes Wazuh
        </h2>
        <p className="text-xs text-slate-400">
          Siga o passo a passo interativo para conectar qualquer computador, servidor ou máquina virtual ao MorfeuXDR.
        </p>
      </div>

      {/* Step 1: Input Manager IP */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-4 shadow-lg">
        <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
          <span className="w-6 h-6 rounded-full bg-red-500 text-slate-950 text-xs font-black flex items-center justify-center">1</span>
          <span>Informe o Endereço IP do seu Servidor Wazuh Manager</span>
        </div>
        <p className="text-xs text-slate-400">
          Ao alterar o IP abaixo, os comandos de instalação serão atualizados automaticamente em tempo real!
        </p>

        <div className="flex flex-col sm:flex-row items-center gap-3">
          <input
            type="text"
            value={managerIp}
            onChange={(e) => setManagerIp(e.target.value)}
            placeholder="Ex: 192.168.1.100 ou 10.0.0.5"
            className="px-4 py-2 bg-bg-secondary border border-bg-border rounded-lg text-slate-100 font-mono text-sm focus:outline-none focus:border-red-500 w-full sm:w-80"
          />
          <span className="text-xs text-accent-green font-semibold flex items-center gap-1">
            <ShieldCheck className="w-4 h-4" /> Comandos prontos para cópia!
          </span>
        </div>
      </div>

      {/* Step 2: OS Selector & Commands */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-6 shadow-lg">
        <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
          <span className="w-6 h-6 rounded-full bg-red-500 text-slate-950 text-xs font-black flex items-center justify-center">2</span>
          <span>Selecione o Sistema Operacional da Máquina Cliente</span>
        </div>

        {/* OS Tabs */}
        <div className="flex flex-wrap gap-2 border-b border-bg-border pb-3">
          <button
            onClick={() => setActiveOs('WINDOWS')}
            className={`px-4 py-2 text-xs font-bold rounded-lg transition-all ${
              activeOs === 'WINDOWS'
                ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                : 'bg-bg-secondary text-slate-400 hover:text-slate-200'
            }`}
          >
            🪟 Windows (10 / 11 / Server)
          </button>
          <button
            onClick={() => setActiveOs('UBUNTU')}
            className={`px-4 py-2 text-xs font-bold rounded-lg transition-all ${
              activeOs === 'UBUNTU'
                ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                : 'bg-bg-secondary text-slate-400 hover:text-slate-200'
            }`}
          >
            🐧 Linux (Ubuntu / Debian)
          </button>
          <button
            onClick={() => setActiveOs('RHEL')}
            className={`px-4 py-2 text-xs font-bold rounded-lg transition-all ${
              activeOs === 'RHEL'
                ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                : 'bg-bg-secondary text-slate-400 hover:text-slate-200'
            }`}
          >
            🎩 Linux (RHEL / CentOS / Rocky)
          </button>
          <button
            onClick={() => setActiveOs('MACOS')}
            className={`px-4 py-2 text-xs font-bold rounded-lg transition-all ${
              activeOs === 'MACOS'
                ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                : 'bg-bg-secondary text-slate-400 hover:text-slate-200'
            }`}
          >
            🍎 macOS
          </button>
        </div>

        {/* Step-by-Step Command Blocks */}
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

      {/* Step 3: Network Requirements Check */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-6 space-y-3 shadow-lg">
        <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
          <span className="w-6 h-6 rounded-full bg-red-500 text-slate-950 text-xs font-black flex items-center justify-center">3</span>
          <span>Verificação de Portas de Rede & Firewall</span>
        </div>
        <p className="text-xs text-slate-400">
          Certifique-se de que o firewall da sua rede/nuvem permite o tráfego nas seguintes portas no servidor Wazuh:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs pt-2">
          <div className="bg-bg-secondary p-3 rounded-lg border border-bg-border">
            <span className="font-mono font-bold text-accent-cyan block">Porta 1514 (UDP/TCP)</span>
            <span className="text-slate-400 text-[11px]">Envio de eventos de segurança dos agentes</span>
          </div>
          <div className="bg-bg-secondary p-3 rounded-lg border border-bg-border">
            <span className="font-mono font-bold text-purple-400 block">Porta 1515 (TCP)</span>
            <span className="text-slate-400 text-[11px]">Registro e autenticação de novos agentes</span>
          </div>
          <div className="bg-bg-secondary p-3 rounded-lg border border-bg-border">
            <span className="font-mono font-bold text-accent-green block">Porta 55000 (TCP)</span>
            <span className="text-slate-400 text-[11px]">Comunicação da API REST com o MorfeuXDR</span>
          </div>
        </div>
      </div>

      {/* Step 4: Verification Link */}
      <div className="bg-bg-card border border-accent-green/30 rounded-xl p-6 flex items-center justify-between gap-4">
        <div>
          <h4 className="text-sm font-bold text-slate-100">Pronto! Verifique seus Agentes Conectados</h4>
          <p className="text-xs text-slate-400 mt-0.5">
            Após executar a instalação no dispositivo, ele aparecerá na aba Wazuh Modules com status ONLINE.
          </p>
        </div>
        <Link
          href="/morfeuxdr/wazuh-modules"
          className="flex items-center gap-2 px-4 py-2 text-xs font-bold bg-accent-green text-slate-950 rounded-lg hover:bg-emerald-400 transition-all flex-shrink-0"
        >
          Ver Inventário de Agentes <ArrowRight className="w-4 h-4" />
        </Link>
      </div>
    </div>
  );
}
