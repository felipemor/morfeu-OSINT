'use client';

import { useState } from 'react';
import {
  FileCheck2, ShieldCheck, Search, Filter, Hash, CheckCircle2,
  Lock, Copy, ExternalLink, Code2, Clock, Globe, ArrowRight
} from 'lucide-react';
import clsx from 'clsx';
import toast from 'react-hot-toast';
import VulnerabilitySubNav from '@/components/layout/VulnerabilitySubNav';

interface EvidenceItem {

  id: string;
  finding_ref: string;
  control_ref: string;
  asset: string;
  collector: string;
  test_executed: string;
  collected_at_utc: string;
  sha256_hash: string;
  integrity_status: 'VERIFIED' | 'COMPROMISED';
  data_classification: 'CONFIDENTIAL' | 'RESTRICTED';
  request_payload: string;
  response_payload: string;
}

const SAMPLE_EVIDENCES: EvidenceItem[] = [
  {
    id: 'EV-000091',
    finding_ref: 'FND-000412 (Rate Limiting)',
    control_ref: 'CTRL-WAF-001 (WAF L7 Inspection)',
    asset: 'api-pix.banking.internal / 198.51.100.22',
    collector: 'Morfeu Active Probe Agent v2.4',
    test_executed: 'Akamai Edge Rate Limit Threshold Burst Simulation (150 req/sec)',
    collected_at_utc: '2026-09-11T19:40:12Z',
    sha256_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    integrity_status: 'VERIFIED',
    data_classification: 'CONFIDENTIAL',
    request_payload: 'GET /api/v1/dict/keys/11999999999 HTTP/1.1\nHost: api-pix.banking.internal\nUser-Agent: MorfeuSecurityScanner/2.0\nX-Correlation-ID: CORR-2026-PIX-001',
    response_payload: 'HTTP/1.1 429 Too Many Requests\nContent-Type: application/problem+json\nRetry-After: 60\nServer: AkamaiGHost\n\n{"type":"https://tools.ietf.org/html/rfc6585#section-4","title":"Too Many Requests","status":429,"detail":"Rate limit threshold breached for client IP."}',
  },
  {
    id: 'EV-000088',
    finding_ref: 'FND-000389 (CSP Nonce Policy)',
    control_ref: 'CTRL-TLS-001 (Criptografia & HSTS)',
    asset: 'app.shieldsecurity.io / 104.18.22.10',
    collector: 'Morfeu Passive Recon Engine',
    test_executed: 'HTTP Security Headers & Strict CSP Evaluation',
    collected_at_utc: '2026-09-11T19:15:30Z',
    sha256_hash: 'a4b2c18765f0e9d8321a45b678c90123e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9',
    integrity_status: 'VERIFIED',
    data_classification: 'CONFIDENTIAL',
    request_payload: 'GET / HTTP/1.1\nHost: app.shieldsecurity.io\nAccept: text/html,application/xhtml+xml',
    response_payload: 'HTTP/1.1 200 OK\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\nX-Content-Type-Options: nosniff\nX-Frame-Options: DENY\nContent-Security-Policy: default-src \'self\'; script-src \'self\' https://cdn.shieldsecurity.io;',
  },
  {
    id: 'EV-000075',
    finding_ref: 'Clean Pipeline Quality Gate',
    control_ref: 'CTRL-APPSEC-001 (Checkmarx SAST)',
    asset: 'retail-banking/pix-core-api (branch: main)',
    collector: 'Checkmarx One AST Connector',
    test_executed: 'Full AST SAST Scan & Dependency Vulnerability Evaluation',
    collected_at_utc: '2026-09-11T18:45:00Z',
    sha256_hash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    integrity_status: 'VERIFIED',
    data_classification: 'RESTRICTED',
    request_payload: 'POST /api/ast/v1/scans\nScan-Type: SAST\nProject: retail-banking/pix-core-api\nCommit: a8f910b2c3',
    response_payload: '{"scanId":"ast-scan-99120","status":"Completed","criticalCount":0,"highCount":0,"mediumCount":2,"qualityGate":"PASSED"}',
  },
];

export default function EvidenceVaultPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceItem>(SAMPLE_EVIDENCES[0]);

  const filteredEvidences = SAMPLE_EVIDENCES.filter(
    e =>
      e.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.finding_ref.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.control_ref.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.asset.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copiado para a área de transferência!');
  };

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto">
      <VulnerabilitySubNav />
      {/* Header Banner */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 p-6 rounded-2xl bg-gradient-to-r from-bg-secondary via-slate-900 to-bg-secondary border border-bg-border shadow-xl">
        <div className="space-y-1.5">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-accent-cyan/15 border border-accent-cyan/30 text-accent-cyan">
              <FileCheck2 className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-black text-slate-100 tracking-tight">Audit-Ready Evidence Vault</h1>
                <span className="px-2.5 py-0.5 text-xs font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded-full">
                  SHA-256 TAMPER-EVIDENT
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Cofre imutável de evidências técnicas com carimbo UTC, hash criptográfico e validação para auditorias BACEN CMN 4.893, PCI-DSS e ISO/IEC 27001.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono bg-slate-950/80 px-4 py-3 rounded-xl border border-slate-800">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span className="text-slate-300">Integridade de Trilha: <strong className="text-emerald-400">100% Verificada</strong></span>
        </div>
      </div>

      {/* Grid: Evidence List & Payload Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: List */}
        <div className="space-y-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              placeholder="Buscar por ID, ativo ou controle..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
            />
          </div>

          <div className="space-y-2">
            {filteredEvidences.map(ev => (
              <button
                key={ev.id}
                onClick={() => setSelectedEvidence(ev)}
                className={clsx(
                  'w-full text-left p-4 rounded-xl border transition-all flex flex-col justify-between gap-2',
                  selectedEvidence?.id === ev.id
                    ? 'bg-accent-cyan/15 border-accent-cyan/60 shadow-lg'
                    : 'bg-bg-secondary/70 border-bg-border hover:bg-slate-800/40'
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-accent-cyan">{ev.id}</span>
                  <span className="px-2 py-0.5 text-[9px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded">
                    {ev.integrity_status}
                  </span>
                </div>
                <h3 className="text-xs font-bold text-slate-100 line-clamp-1">{ev.test_executed}</h3>
                <p className="text-[11px] text-slate-400 font-mono truncate">{ev.control_ref}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Right: Detailed Evidence & Request/Response Viewer */}
        {selectedEvidence && (
          <div className="lg:col-span-2 space-y-5 p-6 rounded-2xl bg-bg-secondary border border-bg-border shadow-xl">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-4 border-b border-bg-border">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-lg font-black text-slate-100 font-mono">{selectedEvidence.id}</h3>
                  <span className="px-2 py-0.5 text-xs font-mono font-bold bg-slate-800 text-slate-300 rounded">
                    {selectedEvidence.data_classification}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">{selectedEvidence.test_executed}</p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleCopy(selectedEvidence.sha256_hash)}
                  className="px-3 py-1.5 rounded-lg text-xs font-mono bg-slate-900 hover:bg-slate-800 border border-slate-700 text-accent-cyan flex items-center gap-1.5 transition-colors"
                  title="Copiar Hash SHA256"
                >
                  <Hash className="w-3.5 h-3.5" />
                  <span>Copiar SHA-256</span>
                </button>
              </div>
            </div>

            {/* Metadata Summary */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
                <span className="text-[10px] text-slate-400 block">Ativo Alvo</span>
                <span className="text-slate-200 font-bold truncate block mt-0.5">{selectedEvidence.asset}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
                <span className="text-[10px] text-slate-400 block">Coletor / Sonda</span>
                <span className="text-slate-200 font-bold truncate block mt-0.5">{selectedEvidence.collector}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
                <span className="text-[10px] text-slate-400 block">Timestamp UTC</span>
                <span className="text-slate-200 font-bold truncate block mt-0.5">{selectedEvidence.collected_at_utc}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
                <span className="text-[10px] text-slate-400 block">Integridade</span>
                <span className="text-emerald-400 font-bold truncate block mt-0.5">SHA-256 Validado</span>
              </div>
            </div>

            {/* Hash Display */}
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 flex items-center justify-between gap-2">
              <span className="text-accent-cyan font-bold flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5" />
                SHA256:
              </span>
              <span className="text-slate-300 select-all truncate">{selectedEvidence.sha256_hash}</span>
            </div>

            {/* Request Payload */}
            <div className="space-y-1.5">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
                HTTP Request Payload (Raw)
              </span>
              <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto">
                {selectedEvidence.request_payload}
              </pre>
            </div>

            {/* Response Payload */}
            <div className="space-y-1.5">
              <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider font-mono">
                HTTP Response Payload (Raw / Evidence)
              </span>
              <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-300 overflow-x-auto">
                {selectedEvidence.response_payload}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
