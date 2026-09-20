'use client';

import { useState } from 'react';
import {
  Key,
  Shield,
  FileCode,
  Download,
  Copy,
  Check,
  Plus,
  Trash2,
  Sparkles,
  Lock,
  Globe,
  Server,
  UserCheck,
  FileSignature,
  Mail,
  RefreshCw,
  Sliders,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
  Code2,
  Layers,
  Terminal,
  FileArchive,
  ClipboardPaste,
  FileText,
  Search,
  X,
  UploadCloud,
  CheckCheck
} from 'lucide-react';
import clsx from 'clsx';
import { certificatesApi, CertificateGeneratePayload } from '@/lib/api';

interface SANEntry {
  type: string;
  value: string;
  oid?: string;
}

interface CustomAttrEntry {
  oid_or_name: string;
  value: string;
}

export default function CryptoPKIPage() {
  // Modal / Drawer state for Pasting CSR
  const [isCsrModalOpen, setIsCsrModalOpen] = useState(false);
  const [pastedCsr, setPastedCsr] = useState('');
  const [csrSuccessToast, setCsrSuccessToast] = useState<string | null>(null);

  // Form State (Subject Attributes)
  const [commonNames, setCommonNames] = useState<string[]>(['api.enterprise.com.br']);
  const [newCnInput, setNewCnInput] = useState('');
  
  const [country, setCountry] = useState('BR');
  const [state, setState] = useState('SP');
  const [locality, setLocality] = useState('São Paulo');
  const [organization, setOrganization] = useState('Morfeu Security Lab');
  const [organizationalUnit, setOrganizationalUnit] = useState('Cryptography & Cyber Defense Division');
  const [email, setEmail] = useState('security@morfeu.local');

  // Custom Subject Attributes
  const [customAttrs, setCustomAttrs] = useState<CustomAttrEntry[]>([]);
  const [newAttrKey, setNewAttrKey] = useState('');
  const [newAttrVal, setNewAttrVal] = useState('');

  // SANs
  const [sanList, setSanList] = useState<SANEntry[]>([
    { type: 'DNS', value: 'api.enterprise.com.br' },
    { type: 'DNS', value: '*.enterprise.com.br' },
    { type: 'IP', value: '192.168.1.100' },
  ]);
  const [newSanType, setNewSanType] = useState('DNS');
  const [newSanValue, setNewSanValue] = useState('');
  const [newSanOid, setNewSanOid] = useState('1.3.6.1.4.1.311.20.2.3');

  // Cryptographic Parameters
  const [keyAlgorithm, setKeyAlgorithm] = useState('RSA_2048');
  const [certProfile, setCertProfile] = useState('MUTUAL_TLS');
  const [issuanceMode, setIssuanceMode] = useState('PRIVATE_LETS_ENCRYPT');
  const [validityDays, setValidityDays] = useState(90);
  const [keyPassword, setKeyPassword] = useState('');

  // Custom Key Usages
  const [customUsages, setCustomUsages] = useState({
    digital_signature: true,
    key_encipherment: true,
    key_agreement: false,
    content_commitment: false,
    server_auth: true,
    client_auth: true,
    code_signing: false,
    email_protection: false,
  });

  // Output & Loading State
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeFileTab, setActiveFileTab] = useState<'crt' | 'pem' | 'key' | 'csr' | 'inspector' | 'guides'>('crt');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Common Names Handlers
  const handleAddCN = () => {
    if (!newCnInput.trim()) return;
    if (!commonNames.includes(newCnInput.trim())) {
      setCommonNames([...commonNames, newCnInput.trim()]);
    }
    setNewCnInput('');
  };

  const handleRemoveCN = (index: number) => {
    if (commonNames.length <= 1) return;
    setCommonNames(commonNames.filter((_, i) => i !== index));
  };

  // Custom Subject Attributes Handlers
  const handleAddCustomAttr = () => {
    if (!newAttrKey.trim() || !newAttrVal.trim()) return;
    setCustomAttrs([...customAttrs, { oid_or_name: newAttrKey.trim(), value: newAttrVal.trim() }]);
    setNewAttrKey('');
    setNewAttrVal('');
  };

  const handleRemoveCustomAttr = (index: number) => {
    setCustomAttrs(customAttrs.filter((_, i) => i !== index));
  };

  // SANs Handlers
  const handleAddSAN = () => {
    if (!newSanValue.trim()) return;
    setSanList([
      ...sanList,
      {
        type: newSanType,
        value: newSanValue.trim(),
        oid: newSanType === 'OTHERNAME' ? (newSanOid || '1.3.6.1.4.1.311.20.2.3') : undefined,
      },
    ]);
    setNewSanValue('');
  };

  const handleRemoveSAN = (index: number) => {
    setSanList(sanList.filter((_, i) => i !== index));
  };

  // Sample CSR for testing
  const handleLoadSampleCsr = () => {
    const sample = `-----BEGIN CERTIFICATE REQUEST-----
MIIC1zCCAb8CAQAwgYsxCzAJBgNVBAYTAkJSMQswCQYDVQQIEwJTUDESMBAGA1UE
BxMJU2FvIFBhdWxvMR0wGwYDVQQKExRGaW50ZWNoIFNlY3VyaXR5IFNBMSMwIQYD
VQQLExpDcnlwdG9ncmFwaHkgJiBTZWN1cml0eTExHzAdBgNVBAMTFnNlY3VyZS5l
bnRlcnByaXNlLmNvbS5icjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AM1X7H5LrkQhM3i1s4+Kz3IuY2PZzQ6E4N1Wp8gR7m7qV6n5X5t9A8sZ1qR3o5t
Y8u2w7x8y9z0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b
6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7
d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e
AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAMk3X8P2L6n9K1m0q9v4z7w2x1y8u
7v6w5x4y3z2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c
5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4
e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2
-----END CERTIFICATE REQUEST-----`;
    setPastedCsr(sample);
  };

  // Upload CSR File
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setPastedCsr(content);
      }
    };
    reader.readAsText(file);
  };

  // Autofill Form from Pasted CSR
  const handleAutofillFromCsr = async () => {
    if (!pastedCsr.trim()) {
      setError('Por favor, cole um CSR válido no campo de texto.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const data = await certificatesApi.parseCsr(pastedCsr.trim());
      if (data.valid) {
        if (data.common_names?.length) setCommonNames(data.common_names);
        if (data.country) setCountry(data.country);
        if (data.state) setState(data.state);
        if (data.locality) setLocality(data.locality);
        if (data.organization) setOrganization(data.organization);
        if (data.organizational_unit) setOrganizationalUnit(data.organizational_unit);
        if (data.email) setEmail(data.email);
        if (data.sans?.length) setSanList(data.sans);

        setIsCsrModalOpen(false);
        setCsrSuccessToast(`CSR decodificado! ${data.common_names?.length || 0} CNs e ${data.san_count || 0} SANs importados para o formulário.`);
        setTimeout(() => setCsrSuccessToast(null), 5000);
      } else {
        setError(data.error || 'CSR inválido');
      }
    } catch (err: any) {
      setError(err.message || 'Falha ao processar o CSR colado.');
    } finally {
      setLoading(false);
    }
  };

  // Direct Sign Pasted CSR (Issue Certificate directly)
  const handleSignPastedCsrDirect = async () => {
    if (!pastedCsr.trim()) {
      setError('Por favor, cole um CSR válido antes de emitir.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await certificatesApi.signCsr({
        csr_pem: pastedCsr.trim(),
        cert_profile: certProfile,
        issuance_mode: issuanceMode,
        validity_days: validityDays,
        custom_usages: certProfile === 'CUSTOM' ? customUsages : undefined,
      });
      setResult(res);
      setIsCsrModalOpen(false);
      setActiveFileTab('crt');
      setCsrSuccessToast('Certificado emitido e assinado a partir do seu CSR!');
      setTimeout(() => setCsrSuccessToast(null), 5000);
    } catch (err: any) {
      setError(err.message || 'Falha ao assinar o CSR.');
    } finally {
      setLoading(false);
    }
  };

  // Generate Full Artifacts (Mode: New Key & Cert)
  const handleGenerate = async () => {
    if (commonNames.length === 0) {
      setError('Adicione pelo menos um Common Name (CN).');
      return;
    }

    setLoading(true);
    setError(null);

    const payload: CertificateGeneratePayload = {
      common_names: commonNames,
      country,
      state,
      locality,
      organization,
      organizational_unit: organizationalUnit,
      email,
      custom_attributes: customAttrs,
      san_list: sanList,
      key_algorithm: keyAlgorithm,
      cert_profile: certProfile,
      issuance_mode: issuanceMode,
      validity_days: validityDays,
      key_password: keyPassword.trim() ? keyPassword : undefined,
      custom_usages: certProfile === 'CUSTOM' ? customUsages : undefined,
    };

    try {
      const res = await certificatesApi.generate(payload);
      setResult(res);
      setActiveFileTab('crt');
    } catch (err: any) {
      setError(err.message || 'Falha ao emitir certificado criptográfico.');
    } finally {
      setLoading(false);
    }
  };

  // Copy helper
  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Individual file download helper
  const handleDownloadFile = (content: string, filename: string, mime: string = 'text/plain') => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Batch ZIP download helper
  const handleDownloadZip = async () => {
    if (!result?.files) return;
    const baseName = (result.metadata?.primary_common_name || commonNames[0] || 'certificate').replace(/[^a-zA-Z0-9_-]/g, '_');
    try {
      const blob = await certificatesApi.downloadBundle({
        filename_base: baseName,
        key_pem: result.files.key,
        csr_pem: result.files.csr,
        crt_pem: result.files.crt,
        pem_fullchain: result.files.pem,
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${baseName}_pki_bundle.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      // Fallback: download individual files
      handleDownloadFile(result.files.crt, `${baseName}.crt`);
      handleDownloadFile(result.files.pem, `${baseName}.pem`);
      handleDownloadFile(result.files.csr, `${baseName}.csr`);
      if (result.files.key && !result.files.key.includes('NÃO DISPONÍVEL')) {
        handleDownloadFile(result.files.key, `${baseName}.key`);
      }
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto text-slate-100">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-bg-border pb-5">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-indigo-500/20 via-purple-500/20 to-cyan-500/20 border border-purple-500/40 flex items-center justify-center text-purple-400 shadow-lg shadow-purple-500/10">
            <Key className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-black tracking-tight flex items-center gap-2">
              AegisLattice PKI &amp; Certificate Studio
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-purple-500/20 border border-purple-500/40 text-purple-300">
                X.509 PKCS#10 ENGINE
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Geração de Chaves Assimétricas, CSR, SANs avançados, Importação de CSR e Emissão Let&apos;s Encrypt (Público &amp; Privado).
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => { setIsCsrModalOpen(true); setError(null); }}
            className="px-4 py-2.5 rounded-xl text-xs font-bold bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white flex items-center gap-2 shadow-lg shadow-cyan-500/20 transition-all cursor-pointer"
          >
            <ClipboardPaste className="w-4 h-4" />
            <span>Colar CSR Existente</span>
          </button>
        </div>
      </div>

      {/* Success Toast */}
      {csrSuccessToast && (
        <div className="p-4 rounded-xl bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-xs font-bold flex items-center gap-2 shadow-lg animate-fade-in">
          <CheckCheck className="w-5 h-5 text-emerald-400" />
          <span>{csrSuccessToast}</span>
        </div>
      )}

      {/* Modal / Drawer para Colar CSR */}
      {isCsrModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-2xl p-6 rounded-2xl bg-bg-secondary border border-cyan-500/40 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-bg-border pb-3">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-cyan-500/20 text-cyan-400 flex items-center justify-center">
                  <ClipboardPaste className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-black text-slate-100">Colar Certificate Signing Request (CSR)</h3>
                  <p className="text-[11px] text-slate-400">Cole seu CSR PEM para preencher o formulário ou emitir o certificado diretamente.</p>
                </div>
              </div>
              <button
                onClick={() => setIsCsrModalOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-bg-primary transition-colors cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Quick Actions inside Modal */}
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <span className="text-slate-400">Conteúdo do CSR (PEM):</span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleLoadSampleCsr}
                  className="px-2.5 py-1 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-[11px] font-bold flex items-center gap-1 transition-all cursor-pointer"
                >
                  <FileText className="w-3 h-3" /> Carregar Exemplo de Teste
                </button>
                <label className="px-2.5 py-1 rounded-lg bg-bg-primary hover:bg-bg-border text-slate-300 border border-bg-border text-[11px] font-bold flex items-center gap-1 transition-all cursor-pointer">
                  <UploadCloud className="w-3.5 h-3.5 text-cyan-400" /> Subir Arquivo .csr
                  <input
                    type="file"
                    accept=".csr,.pem,.req,.txt"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </label>
              </div>
            </div>

            <textarea
              rows={8}
              value={pastedCsr}
              onChange={(e) => setPastedCsr(e.target.value)}
              placeholder="Cole aqui o bloco completo:&#10;-----BEGIN CERTIFICATE REQUEST-----&#10;MIIC1zCCAb8CAQAwgYsxCzAJBgNVBAYTAkJSMQswCQYDVQQIEwJTUDESMBAGA1UE...&#10;-----END CERTIFICATE REQUEST-----"
              className="w-full p-3.5 rounded-xl bg-bg-primary border border-bg-border text-xs text-cyan-200 focus:outline-none focus:border-cyan-500 font-mono leading-relaxed resize-y shadow-inner"
            />

            {error && (
              <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <div className="flex flex-col sm:flex-row gap-3 pt-2">
              <button
                type="button"
                onClick={handleAutofillFromCsr}
                disabled={loading || !pastedCsr.trim()}
                className="flex-1 py-3 px-4 rounded-xl font-bold text-xs bg-bg-primary hover:bg-bg-border border border-cyan-500/40 text-cyan-300 flex items-center justify-center gap-2 transition-all cursor-pointer disabled:opacity-50"
              >
                <Search className="w-4 h-4" />
                <span>Decodificar &amp; Autopreencher Formulário</span>
              </button>

              <button
                type="button"
                onClick={handleSignPastedCsrDirect}
                disabled={loading || !pastedCsr.trim()}
                className="flex-1 py-3 px-4 rounded-xl font-bold text-xs bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 transition-all cursor-pointer disabled:opacity-50"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Emitindo Certificado...</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4" />
                    <span>Emitir &amp; Assinar Certificado Agora (.crt)</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Form: Configuration */}
        <div className="lg:col-span-7 space-y-6">
          {/* Profile & Issuance Mode */}
          <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border space-y-4">
            <h2 className="text-xs font-black uppercase tracking-wider text-purple-400 flex items-center gap-2">
              <Sliders className="w-4 h-4" /> 1. Finalidade do Certificado &amp; Modo de Emissão
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Profile Preset */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-300">Perfil de Uso (Key Usage / EKU)</label>
                <select
                  value={certProfile}
                  onChange={(e) => setCertProfile(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-purple-500 font-medium"
                >
                  <option value="MUTUAL_TLS">Mutual TLS (mTLS — Client + Server Auth)</option>
                  <option value="WEB_SERVER">Web Server / HTTPS (TLS Server Auth)</option>
                  <option value="CLIENT_AUTH">Client Authenticator (TLS Client Auth)</option>
                  <option value="CODE_SIGNING">Code Signing (Assinatura de Software)</option>
                  <option value="EMAIL_PROTECTION">S/MIME (Criptografia de E-mail)</option>
                  <option value="CUSTOM">Personalizado (Custom Usages)</option>
                </select>
              </div>

              {/* Issuance Mode */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-300">Autoridade Emissora</label>
                <select
                  value={issuanceMode}
                  onChange={(e) => setIssuanceMode(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-purple-500 font-medium"
                >
                  <option value="PRIVATE_LETS_ENCRYPT">Let&apos;s Encrypt Privado (Internal Root + Intermediate R3)</option>
                  <option value="PUBLIC_LETS_ENCRYPT">Let&apos;s Encrypt Público (CSR ACME / Certbot Ready)</option>
                  <option value="SELF_SIGNED_CA">Autoassinado Direto (Self-Signed Root)</option>
                </select>
              </div>
            </div>

            {/* Custom Usages Checkboxes if CUSTOM */}
            {certProfile === 'CUSTOM' && (
              <div className="p-3.5 rounded-xl bg-bg-primary border border-bg-border space-y-2">
                <span className="text-[11px] font-bold text-slate-400">Selecione as Extensões e Key Usages:</span>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                  {Object.entries(customUsages).map(([key, val]) => (
                    <label key={key} className="flex items-center gap-2 cursor-pointer text-slate-300 text-[11px]">
                      <input
                        type="checkbox"
                        checked={val}
                        onChange={(e) => setCustomUsages({ ...customUsages, [key]: e.target.checked })}
                        className="rounded border-bg-border text-purple-600 focus:ring-0"
                      />
                      <span className="capitalize">{key.replace('_', ' ')}</span>
                    </label>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Subject Attributes Form */}
          <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-black uppercase tracking-wider text-cyan-400 flex items-center gap-2">
                <Globe className="w-4 h-4" /> 2. Subject Attributes (DN Distinto)
              </h2>
              <button
                type="button"
                onClick={() => { setIsCsrModalOpen(true); setError(null); }}
                className="px-2.5 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-[11px] font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-sm"
              >
                <ClipboardPaste className="w-3.5 h-3.5" /> Já tem um CSR? Cole aqui
              </button>
            </div>

            {/* Common Names Manager */}
            <div className="space-y-2">
              <label className="text-xs font-bold text-slate-300">
                Common Names (CN) <span className="text-slate-500 font-normal">(O primeiro será o CN primário)</span>
              </label>
              
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newCnInput}
                  onChange={(e) => setNewCnInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), handleAddCN())}
                  placeholder="ex: api.dominio.com.br ou *.dominio.com.br"
                  className="flex-1 px-3 py-2 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
                <button
                  type="button"
                  onClick={handleAddCN}
                  className="px-3.5 py-2 rounded-xl bg-cyan-500/20 text-cyan-300 hover:bg-cyan-500/30 border border-cyan-500/30 text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" /> Adicionar CN
                </button>
              </div>

              {/* Chips */}
              <div className="flex flex-wrap gap-2 pt-1">
                {commonNames.map((cn, idx) => (
                  <span
                    key={idx}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono"
                  >
                    {idx === 0 && <span className="text-[10px] font-bold bg-cyan-500/30 px-1 rounded text-cyan-200">PRI</span>}
                    {cn}
                    {commonNames.length > 1 && (
                      <button
                        type="button"
                        onClick={() => handleRemoveCN(idx)}
                        className="text-cyan-400/60 hover:text-red-400 transition-colors ml-0.5 cursor-pointer"
                      >
                        ×
                      </button>
                    )}
                  </span>
                ))}
              </div>
            </div>

            {/* Standard Subject Fields */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-slate-400">País (Country C)</label>
                <input
                  type="text"
                  maxLength={2}
                  value={country}
                  onChange={(e) => setCountry(e.target.value.toUpperCase())}
                  placeholder="BR"
                  className="w-full px-3 py-2 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono uppercase"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-slate-400">Estado (State ST)</label>
                <input
                  type="text"
                  value={state}
                  onChange={(e) => setState(e.target.value)}
                  placeholder="SP"
                  className="w-full px-3 py-2 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-slate-400">Cidade (Locality L)</label>
                <input
                  type="text"
                  value={locality}
                  onChange={(e) => setLocality(e.target.value)}
                  placeholder="São Paulo"
                  className="w-full px-3 py-2 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-slate-400">Organização (O)</label>
                <input
                  type="text"
                  value={organization}
                  onChange={(e) => setOrganization(e.target.value)}
                  placeholder="Nome da Empresa"
                  className="w-full px-3 py-2 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-slate-400">Unidade Organizacional (OU)</label>
                <input
                  type="text"
                  value={organizationalUnit}
                  onChange={(e) => setOrganizationalUnit(e.target.value)}
                  placeholder="ex: IT Security / DevOps"
                  className="w-full px-3 py-2 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-[11px] font-semibold text-slate-400">E-mail de Contato (E)</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="security@empresa.com.br"
                className="w-full px-3 py-2 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            {/* Custom Attributes Extender */}
            <div className="border-t border-bg-border/60 pt-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-300">Atributos Customizados Adicionais</span>
                <span className="text-[10px] text-slate-500">Ex: TITLE, STREET, SERIALNUMBER ou OID</span>
              </div>

              <div className="flex gap-2">
                <input
                  type="text"
                  value={newAttrKey}
                  onChange={(e) => setNewAttrKey(e.target.value)}
                  placeholder="Nome ou OID (ex: TITLE)"
                  className="w-1/3 px-3 py-1.5 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
                <input
                  type="text"
                  value={newAttrVal}
                  onChange={(e) => setNewAttrVal(e.target.value)}
                  placeholder="Valor do atributo"
                  className="flex-1 px-3 py-1.5 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                />
                <button
                  type="button"
                  onClick={handleAddCustomAttr}
                  className="px-3 py-1.5 rounded-xl bg-bg-primary border border-bg-border text-slate-300 hover:text-cyan-300 text-xs font-bold cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" />
                </button>
              </div>

              {customAttrs.length > 0 && (
                <div className="space-y-1 pt-1">
                  {customAttrs.map((attr, idx) => (
                    <div key={idx} className="flex items-center justify-between px-3 py-1.5 rounded-lg bg-bg-primary border border-bg-border text-xs">
                      <span className="font-mono text-cyan-300">{attr.oid_or_name}:</span>
                      <span className="text-slate-300 truncate max-w-xs">{attr.value}</span>
                      <button onClick={() => handleRemoveCustomAttr(idx)} className="text-red-400 hover:text-red-300 cursor-pointer">
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Subject Alternative Names (SANs) */}
          <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border space-y-4">
            <h2 className="text-xs font-black uppercase tracking-wider text-emerald-400 flex items-center gap-2">
              <Layers className="w-4 h-4" /> 3. Subject Alternative Names (SAN)
            </h2>

            {/* SAN Input Row */}
            <div className="grid grid-cols-1 md:grid-cols-12 gap-2">
              <div className="md:col-span-3">
                <select
                  value={newSanType}
                  onChange={(e) => setNewSanType(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-bg-primary border border-bg-border text-xs text-emerald-300 font-bold focus:outline-none focus:border-emerald-500"
                >
                  <option value="DNS">DNS</option>
                  <option value="IP">IP</option>
                  <option value="URI">URI</option>
                  <option value="EMAIL">email</option>
                  <option value="RID">RID (OID)</option>
                  <option value="DIRNAME">dirName</option>
                  <option value="OTHERNAME">otherName</option>
                </select>
              </div>

              <div className={newSanType === 'OTHERNAME' ? 'md:col-span-4' : 'md:col-span-7'}>
                <input
                  type="text"
                  value={newSanValue}
                  onChange={(e) => setNewSanValue(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), handleAddSAN())}
                  placeholder={
                    newSanType === 'DNS' ? 'ex: subdomain.empresa.com' :
                    newSanType === 'IP' ? 'ex: 10.0.0.1 ou ::1' :
                    newSanType === 'URI' ? 'ex: spiffe://cluster/ns/prod/sa/app' :
                    newSanType === 'EMAIL' ? 'ex: ops@empresa.com' :
                    newSanType === 'RID' ? 'ex: 1.3.6.1.4.1.9999' :
                    newSanType === 'DIRNAME' ? 'ex: CN=App,O=Empresa,C=BR' :
                    'Valor (ex: user@REALM.COM)'
                  }
                  className="w-full px-3 py-2 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              {newSanType === 'OTHERNAME' && (
                <div className="md:col-span-3">
                  <input
                    type="text"
                    value={newSanOid}
                    onChange={(e) => setNewSanOid(e.target.value)}
                    placeholder="OID (ex: 1.3.6.1.4.1.311.20.2.3)"
                    className="w-full px-2 py-2 rounded-xl bg-bg-primary border border-bg-border text-[11px] text-slate-200 focus:outline-none focus:border-emerald-500 font-mono"
                  />
                </div>
              )}

              <div className="md:col-span-2">
                <button
                  type="button"
                  onClick={handleAddSAN}
                  className="w-full py-2 px-3 rounded-xl bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30 border border-emerald-500/30 text-xs font-bold flex items-center justify-center gap-1 transition-all cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" /> Adicionar
                </button>
              </div>
            </div>

            {/* SAN Table / List */}
            <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
              {sanList.map((san, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between px-3 py-1.5 rounded-xl bg-bg-primary border border-bg-border text-xs font-mono"
                >
                  <div className="flex items-center gap-2">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300">
                      {san.type}
                    </span>
                    <span className="text-slate-200">{san.value}</span>
                    {san.oid && <span className="text-[10px] text-slate-500">OID: {san.oid}</span>}
                  </div>
                  <button
                    type="button"
                    onClick={() => handleRemoveSAN(idx)}
                    className="text-slate-500 hover:text-red-400 transition-colors p-1 cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Key Parameters & Action */}
          <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border space-y-4">
            <h2 className="text-xs font-black uppercase tracking-wider text-purple-400 flex items-center gap-2">
              <Key className="w-4 h-4" /> 4. Parâmetros Criptográficos da Chave
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-slate-400">Algoritmo da Chave</label>
                <select
                  value={keyAlgorithm}
                  onChange={(e) => setKeyAlgorithm(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-purple-500 font-mono"
                >
                  <option value="RSA_2048">RSA 2048 bits (Padrão)</option>
                  <option value="RSA_3072">RSA 3072 bits (Alto)</option>
                  <option value="RSA_4096">RSA 4096 bits (Máximo)</option>
                  <option value="ECDSA_P256">ECDSA P-256 (NIST Curve)</option>
                  <option value="ECDSA_P384">ECDSA P-384 (NIST Curve)</option>
                  <option value="ECDSA_P521">ECDSA P-521 (NIST Curve)</option>
                  <option value="ED25519">Ed25519 (Edwards Curve)</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-slate-400">Validade (Dias)</label>
                <input
                  type="number"
                  min={1}
                  max={3650}
                  value={validityDays}
                  onChange={(e) => setValidityDays(parseInt(e.target.value) || 90)}
                  className="w-full px-3 py-2 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-purple-500 font-mono"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-slate-400">Senha PEM (Opcional)</label>
                <input
                  type="password"
                  value={keyPassword}
                  onChange={(e) => setKeyPassword(e.target.value)}
                  placeholder="Deixe vazio p/ sem senha"
                  className="w-full px-3 py-2 rounded-xl bg-bg-primary border border-bg-border text-xs text-slate-200 focus:outline-none focus:border-purple-500"
                />
              </div>
            </div>

            {/* Generate Button */}
            <div className="pt-2">
              <button
                type="button"
                onClick={handleGenerate}
                disabled={loading}
                className="w-full py-3.5 px-6 rounded-xl font-black text-sm bg-gradient-to-r from-purple-500 via-indigo-600 to-cyan-500 hover:from-purple-400 hover:to-cyan-400 text-white flex items-center justify-center gap-2 shadow-xl shadow-purple-500/20 disabled:opacity-50 transition-all cursor-pointer"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-5 h-5 animate-spin" />
                    <span>Gerando Chave, CSR &amp; Certificado X.509...</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-5 h-5" />
                    <span>Gerar Chave Privada, CSR &amp; Certificados</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {error && (
            <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-sm flex items-center gap-3">
              <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
              <div className="flex-1">
                <span className="font-bold">Aviso: </span>
                <span>{error}</span>
              </div>
            </div>
          )}
        </div>

        {/* Right Pane: Artifacts & Inspection Terminal */}
        <div className="lg:col-span-5 space-y-4">
          {result ? (
            <div className="p-5 rounded-2xl bg-bg-secondary border border-bg-border space-y-4 shadow-2xl">
              <div className="flex items-center justify-between border-b border-bg-border pb-3">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  <span className="font-black text-sm text-slate-100">Artefatos Emitidos com Sucesso</span>
                </div>
                <button
                  onClick={handleDownloadZip}
                  className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-400 hover:to-indigo-500 text-white text-xs font-bold flex items-center gap-1.5 shadow-md shadow-purple-500/20 cursor-pointer"
                >
                  <FileArchive className="w-3.5 h-3.5" /> Baixar Tudo (.ZIP)
                </button>
              </div>

              {/* Navigation Tabs */}
              <div className="flex flex-wrap gap-1 p-1 bg-bg-primary rounded-xl border border-bg-border text-xs">
                {[
                  { id: 'crt', label: '.crt (Cert)', icon: Shield },
                  { id: 'pem', label: '.pem (Bundle)', icon: Layers },
                  { id: 'csr', label: '.csr (Req)', icon: FileCode },
                  { id: 'key', label: '.key (Chave)', icon: Key },
                  { id: 'inspector', label: 'Inspeção X.509', icon: Terminal },
                  { id: 'guides', label: 'Comandos & Deploy', icon: Code2 },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveFileTab(tab.id as any)}
                    className={clsx(
                      'px-2.5 py-1.5 rounded-lg font-bold flex items-center gap-1.5 transition-all text-xs cursor-pointer',
                      activeFileTab === tab.id
                        ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                        : 'text-slate-400 hover:text-slate-200'
                    )}
                  >
                    <tab.icon className="w-3.5 h-3.5" />
                    <span>{tab.label}</span>
                  </button>
                ))}
              </div>

              {/* Tab: .crt */}
              {activeFileTab === 'crt' && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">Certificado X.509 End-Entity</span>
                    <div className="flex gap-2">
                      <button
                        onClick={() => handleCopy(result.files.crt, 'crt')}
                        className="px-2.5 py-1 rounded bg-bg-primary border border-bg-border text-slate-300 hover:text-purple-300 flex items-center gap-1 cursor-pointer"
                      >
                        {copiedKey === 'crt' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>Copiar</span>
                      </button>
                      <button
                        onClick={() => handleDownloadFile(result.files.crt, `${result.metadata?.primary_common_name || 'certificate'}.crt`)}
                        className="px-2.5 py-1 rounded bg-bg-primary border border-bg-border text-purple-300 hover:bg-purple-500/10 flex items-center gap-1 font-bold cursor-pointer"
                      >
                        <Download className="w-3.5 h-3.5" /> Baixar .crt
                      </button>
                    </div>
                  </div>
                  <pre className="p-3.5 rounded-xl bg-bg-primary border border-bg-border font-mono text-[11px] text-emerald-300 overflow-x-auto max-h-72 leading-relaxed">
                    {result.files.crt}
                  </pre>
                </div>
              )}

              {/* Tab: .pem */}
              {activeFileTab === 'pem' && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">Fullchain Bundle (Certificado + CA Intermediária)</span>
                    <div className="flex gap-2">
                      <button
                        onClick={() => handleCopy(result.files.pem, 'pem')}
                        className="px-2.5 py-1 rounded bg-bg-primary border border-bg-border text-slate-300 hover:text-purple-300 flex items-center gap-1 cursor-pointer"
                      >
                        {copiedKey === 'pem' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>Copiar</span>
                      </button>
                      <button
                        onClick={() => handleDownloadFile(result.files.pem, `${result.metadata?.primary_common_name || 'certificate'}.pem`)}
                        className="px-2.5 py-1 rounded bg-bg-primary border border-bg-border text-purple-300 hover:bg-purple-500/10 flex items-center gap-1 font-bold cursor-pointer"
                      >
                        <Download className="w-3.5 h-3.5" /> Baixar .pem
                      </button>
                    </div>
                  </div>
                  <pre className="p-3.5 rounded-xl bg-bg-primary border border-bg-border font-mono text-[11px] text-cyan-300 overflow-x-auto max-h-72 leading-relaxed">
                    {result.files.pem}
                  </pre>
                </div>
              )}

              {/* Tab: .csr */}
              {activeFileTab === 'csr' && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">PKCS#10 Certificate Signing Request</span>
                    <div className="flex gap-2">
                      <button
                        onClick={() => handleCopy(result.files.csr, 'csr')}
                        className="px-2.5 py-1 rounded bg-bg-primary border border-bg-border text-slate-300 hover:text-purple-300 flex items-center gap-1 cursor-pointer"
                      >
                        {copiedKey === 'csr' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>Copiar</span>
                      </button>
                      <button
                        onClick={() => handleDownloadFile(result.files.csr, `${result.metadata?.primary_common_name || 'certificate'}.csr`)}
                        className="px-2.5 py-1 rounded bg-bg-primary border border-bg-border text-purple-300 hover:bg-purple-500/10 flex items-center gap-1 font-bold cursor-pointer"
                      >
                        <Download className="w-3.5 h-3.5" /> Baixar .csr
                      </button>
                    </div>
                  </div>
                  <pre className="p-3.5 rounded-xl bg-bg-primary border border-bg-border font-mono text-[11px] text-amber-300 overflow-x-auto max-h-72 leading-relaxed">
                    {result.files.csr}
                  </pre>
                </div>
              )}

              {/* Tab: .key */}
              {activeFileTab === 'key' && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-red-400 font-bold flex items-center gap-1">
                      <Lock className="w-3.5 h-3.5" /> Chave Privada
                    </span>
                    <div className="flex gap-2">
                      <button
                        onClick={() => handleCopy(result.files.key, 'key')}
                        className="px-2.5 py-1 rounded bg-bg-primary border border-bg-border text-slate-300 hover:text-purple-300 flex items-center gap-1 cursor-pointer"
                      >
                        {copiedKey === 'key' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>Copiar</span>
                      </button>
                      {result.files.key && !result.files.key.includes('NÃO DISPONÍVEL') && (
                        <button
                          onClick={() => handleDownloadFile(result.files.key, `${result.metadata?.primary_common_name || 'certificate'}.key`)}
                          className="px-2.5 py-1 rounded bg-bg-primary border border-bg-border text-red-300 hover:bg-red-500/10 flex items-center gap-1 font-bold cursor-pointer"
                        >
                          <Download className="w-3.5 h-3.5" /> Baixar .key
                        </button>
                      )}
                    </div>
                  </div>
                  <pre className="p-3.5 rounded-xl bg-bg-primary border border-red-500/30 font-mono text-[11px] text-red-300 overflow-x-auto max-h-72 leading-relaxed">
                    {result.files.key}
                  </pre>
                </div>
              )}

              {/* Tab: Inspector */}
              {activeFileTab === 'inspector' && result.metadata && (
                <div className="space-y-3 text-xs">
                  <div className="p-3.5 rounded-xl bg-bg-primary border border-bg-border space-y-2.5">
                    <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Metadados X.509 Extraídos</div>
                    <div className="space-y-1.5 font-mono text-[11px]">
                      <div>
                        <span className="text-slate-500">Subject: </span>
                        <span className="text-slate-200">{result.metadata.subject_dn}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Issuer: </span>
                        <span className="text-slate-200">{result.metadata.issuer_dn}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Serial: </span>
                        <span className="text-purple-300">{result.metadata.serial_number_hex}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">SHA-256: </span>
                        <span className="text-emerald-300 break-all">{result.metadata.fingerprint_sha256}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Validade: </span>
                        <span className="text-cyan-300">{result.metadata.validity_days} dias ({new Date(result.metadata.valid_from).toLocaleDateString()} até {new Date(result.metadata.valid_to).toLocaleDateString()})</span>
                      </div>
                      {result.metadata.san_list?.length > 0 && (
                        <div>
                          <span className="text-slate-500">SANs ({result.metadata.san_count}): </span>
                          <span className="text-slate-300">
                            {result.metadata.san_list.map((s: any) => `${s.type}:${s.value}`).join(', ')}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Tab: Guides */}
              {activeFileTab === 'guides' && result.guides && (
                <div className="space-y-3 text-xs">
                  <div className="p-3 rounded-xl bg-bg-primary border border-bg-border space-y-1.5">
                    <span className="font-bold text-cyan-300">Comando Certbot ACME (Let&apos;s Encrypt Público):</span>
                    <pre className="p-2 rounded bg-bg-secondary font-mono text-[11px] text-slate-300 overflow-x-auto">
                      {result.guides.acme_certbot_command}
                    </pre>
                  </div>

                  <div className="p-3 rounded-xl bg-bg-primary border border-bg-border space-y-1.5">
                    <span className="font-bold text-purple-300">Verificação OpenSSL:</span>
                    <pre className="p-2 rounded bg-bg-secondary font-mono text-[11px] text-slate-300 overflow-x-auto">
                      {result.guides.openssl_verify_command}
                    </pre>
                  </div>

                  <div className="p-3 rounded-xl bg-bg-primary border border-bg-border space-y-1.5">
                    <span className="font-bold text-emerald-300">Configuração Nginx / Proxy Reverso:</span>
                    <pre className="p-2 rounded bg-bg-secondary font-mono text-[11px] text-slate-300 overflow-x-auto">
                      {result.guides.nginx_snippet}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="p-8 rounded-2xl bg-bg-secondary border border-bg-border text-center space-y-4 flex flex-col items-center justify-center min-h-[420px]">
              <div className="w-16 h-16 rounded-2xl bg-bg-primary border border-bg-border flex items-center justify-center text-purple-400">
                <Shield className="w-8 h-8" />
              </div>
              <div className="space-y-1 max-w-sm">
                <h3 className="font-bold text-slate-200 text-sm">Pronto para Emitir</h3>
                <p className="text-xs text-slate-400">
                  Configure os Subject Attributes e SANs à esquerda (ou clique em &quot;Já tem um CSR? Cole aqui&quot;) e clique no botão para gerar sua chave, CSR e certificados X.509 (.crt, .pem, .key).
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
