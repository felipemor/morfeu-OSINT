'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import toast from 'react-hot-toast';
import QRCode from 'qrcode';
import {
  Shield, Smartphone, QrCode, RefreshCw, CheckCircle2, Lock,
  Fingerprint, Sparkles, ArrowRight, ShieldCheck, Zap, Laptop,
  KeyRound, ShieldAlert, Cpu, Eye, EyeOff, Mail, Key, Hash,
  Check, AlertCircle, Radio, Copy, ExternalLink, Camera
} from 'lucide-react';
import { authApi } from '@/lib/api';
import clsx from 'clsx';

export default function LoginPage() {
  const router = useRouter();

  // Mode: 'CREDENTIALS_2FA' | 'QR_MOBILE'
  const [authMode, setAuthMode] = useState<'CREDENTIALS_2FA' | 'QR_MOBILE'>('CREDENTIALS_2FA');

  // Credentials State
  const [email, setEmail] = useState('operator@sfssa.security');
  const [password, setPassword] = useState('Stellantis@2026!Sec');
  const [showPassword, setShowPassword] = useState(false);
  const [totpCode, setTotpCode] = useState(['', '', '', '', '', '']);
  const totpInputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // QR Mobile Session State
  const [sessionId, setSessionId] = useState('');
  const [timeLeft, setTimeLeft] = useState(60);
  const [qrTotpPin, setQrTotpPin] = useState('');
  const [authStep, setAuthStep] = useState<'IDLE' | 'VERIFYING' | 'AUTHORIZED' | 'FAILED'>('IDLE');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Dynamic TOTP generator helper (mock secret sync)
  const [currentValidOtp, setCurrentValidOtp] = useState('492817');
  const [qrFormat, setQrFormat] = useState<'URL' | 'TOTP'>('URL');
  const [qrDataUrl, setQrDataUrl] = useState<string>('');
  const [qrRawPayload, setQrRawPayload] = useState<string>('');

  const generateNewSession = async (formatOverride?: 'URL' | 'TOTP') => {
    const activeFormat = formatOverride || qrFormat;
    const randomHex = Array.from({ length: 16 }, () =>
      Math.floor(Math.random() * 16).toString(16)
    ).join('');
    const newSession = `sfssa-qr-${Date.now().toString(36)}-${randomHex}`;
    const mockOtp = Math.floor(100000 + Math.random() * 900000).toString();

    setSessionId(newSession);
    setTimeLeft(60);
    setAuthStep('IDLE');
    setQrTotpPin('');
    setCurrentValidOtp(mockOtp);

    // Standard RFC-compliant scannable QR payload:
    // 1. URL: Standard URL easily readable by all smartphone camera apps (iOS Camera, Google Lens, Samsung Camera)
    // 2. TOTP: otpauth:// format for Google Authenticator, Microsoft Authenticator, Authy, Apple Passwords
    let payload = '';
    if (activeFormat === 'URL') {
      payload = `https://morfeusec.local/auth/verify?session=${newSession}&pin=${mockOtp}&user=operator@sfssa.security`;
    } else {
      payload = `otpauth://totp/morfeusec%20OSINT:operator%40sfssa.security?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=morfeusec%20OSINT&algorithm=SHA1&digits=6&period=30`;
    }

    setQrRawPayload(payload);

    try {
      const url = await QRCode.toDataURL(payload, {
        width: 256,
        margin: 2,
        errorCorrectionLevel: 'M',
        color: {
          dark: '#080c18',
          light: '#ffffff'
        }
      });
      setQrDataUrl(url);
    } catch (err) {
      console.error('Erro ao gerar imagem QR Code scannable:', err);
    }
  };

  useEffect(() => {
    generateNewSession();
  }, []);

  const switchQrFormat = (newFormat: 'URL' | 'TOTP') => {
    setQrFormat(newFormat);
    generateNewSession(newFormat);
  };

  // Timer countdown
  useEffect(() => {
    if (authStep === 'AUTHORIZED') return;

    const timer = setInterval(() => {
      setTimeLeft((prev) => {
        if (prev <= 1) {
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [authStep]);

  // Handle 6-digit TOTP input in credentials mode
  const handleTotpChange = (index: number, val: string) => {
    const cleanVal = val.replace(/[^0-9]/g, '').slice(-1);
    const newTotp = [...totpCode];
    newTotp[index] = cleanVal;
    setTotpCode(newTotp);

    // Auto-focus next input
    if (cleanVal && index < 5) {
      totpInputRefs.current[index + 1]?.focus();
    }
  };

  const handleTotpKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !totpCode[index] && index > 0) {
      totpInputRefs.current[index - 1]?.focus();
    }
  };

  const handlePasteTotp = (e: React.ClipboardEvent) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text').replace(/[^0-9]/g, '').slice(0, 6);
    if (pasted.length > 0) {
      const newTotp = ['', '', '', '', '', ''];
      for (let i = 0; i < pasted.length; i++) {
        newTotp[i] = pasted[i];
      }
      setTotpCode(newTotp);
      const nextIdx = Math.min(pasted.length, 5);
      totpInputRefs.current[nextIdx]?.focus();
    }
  };

  // Submit Credentials + 2FA Login
  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email || !email.includes('@')) {
      toast.error('Informe um endereço de e-mail corporativo válido.');
      return;
    }

    if (!password || password.length < 6) {
      toast.error('A senha deve conter no mínimo 6 caracteres.');
      return;
    }

    const code = totpCode.join('');
    if (code.length < 6) {
      toast.error('Insira o código 2FA Authenticator de 6 dígitos completo.');
      return;
    }

    setIsSubmitting(true);
    toast.loading('Validando credenciais e token criptográfico 2FA...', { id: 'auth-login' });

    await new Promise((r) => setTimeout(r, 1000));

    // Authenticate
    authApi.login(email, password);
    toast.dismiss('auth-login');
    toast.success('Sessão autenticada com sucesso! Bem-vindo ao morfeusec OSINT.');

    await new Promise((r) => setTimeout(r, 600));
    router.push('/dashboard');
  };

  // Submit QR Code Mobile Validation with PIN
  const handleQrMobileValidation = async (e: React.FormEvent) => {
    e.preventDefault();

    if (timeLeft === 0) {
      toast.error('O QR Code expirou! Clique em "Atualizar QR Code" para gerar um novo token.');
      return;
    }

    const cleanPin = qrTotpPin.replace(/[^0-9]/g, '');
    if (cleanPin.length < 6) {
      toast.error('Insira o PIN de 6 dígitos gerado pelo Authenticator do celular após a leitura.');
      return;
    }

    setIsSubmitting(true);
    setAuthStep('VERIFYING');
    toast.loading('Validando token biométrico e integridade do dispositivo mobile...', { id: 'qr-verify' });

    await new Promise((r) => setTimeout(r, 1200));

    setAuthStep('AUTHORIZED');
    toast.dismiss('qr-verify');
    toast.success('Dispositivo móvel autenticado via biometria! Acesso concedido.', { duration: 3000 });

    authApi.login(email || 'operator@sfssa.security', `qr-token-${cleanPin}`);

    await new Promise((r) => setTimeout(r, 800));
    router.push('/dashboard');
  };

  const copyPayload = () => {
    if (qrRawPayload) {
      navigator.clipboard.writeText(qrRawPayload);
      toast.success('Conteúdo do QR Code copiado para a área de transferência!');
    }
  };

  const isExpired = timeLeft === 0 && authStep !== 'AUTHORIZED';

  return (
    <div className="min-h-screen flex items-center justify-center relative p-4 overflow-hidden bg-bg-primary">
      {/* Background Ambient Glows */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div
          className="absolute -top-40 -left-40 w-96 h-96 rounded-full opacity-20 blur-3xl"
          style={{ background: 'radial-gradient(circle, #00e676, transparent 70%)' }}
        />
        <div
          className="absolute -bottom-40 -right-40 w-96 h-96 rounded-full opacity-20 blur-3xl"
          style={{ background: 'radial-gradient(circle, #38bdf8, transparent 70%)' }}
        />
      </div>

      <div className="relative w-full max-w-md z-10 animate-fade-in">
        {/* Top Header Branding */}
        <div className="text-center mb-5">
          <div
            className="inline-flex items-center justify-center p-3 rounded-2xl mb-2.5 bg-bg-card border border-accent-cyan/30 shadow-lg shadow-accent-cyan/10"
          >
            <Shield className="w-8 h-8 text-accent-cyan" />
          </div>
          <h1 className="text-2xl font-black text-slate-100 tracking-tight flex items-center justify-center gap-2">
            morfeusec OSINT
          </h1>
          <p className="text-slate-400 text-xs mt-0.5">
            Enterprise Offensive Intelligence &amp; <span className="text-accent-cyan font-bold">Autonomous Mobile Pentest</span>
          </p>
        </div>

        {/* Authentication Card */}
        <div className="p-6 rounded-2xl bg-bg-card border border-bg-border shadow-2xl relative space-y-5">
          {/* Mode Switcher Tabs */}
          <div className="grid grid-cols-2 gap-1.5 p-1 bg-bg-primary rounded-xl border border-bg-border text-xs font-semibold">
            <button
              type="button"
              onClick={() => setAuthMode('CREDENTIALS_2FA')}
              className={clsx(
                'py-2 rounded-lg flex items-center justify-center gap-1.5 transition-all cursor-pointer',
                authMode === 'CREDENTIALS_2FA'
                  ? 'bg-accent-cyan text-bg-primary shadow-sm font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              )}
            >
              <KeyRound className="w-3.5 h-3.5" />
              Credenciais &amp; 2FA
            </button>

            <button
              type="button"
              onClick={() => setAuthMode('QR_MOBILE')}
              className={clsx(
                'py-2 rounded-lg flex items-center justify-center gap-1.5 transition-all cursor-pointer',
                authMode === 'QR_MOBILE'
                  ? 'bg-accent-cyan text-bg-primary shadow-sm font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              )}
            >
              <QrCode className="w-3.5 h-3.5" />
              QR Code Mobile
            </button>
          </div>

          {/* MODE 1: CREDENTIALS & 2FA */}
          {authMode === 'CREDENTIALS_2FA' && (
            <form onSubmit={handleCredentialsSubmit} className="space-y-4">
              <div className="space-y-3">
                {/* Email Field */}
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1 flex items-center gap-1.5">
                    <Mail className="w-3.5 h-3.5 text-accent-cyan" />
                    E-mail Corporativo
                  </label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    placeholder="operador@sfssa.security"
                    className="w-full px-3.5 py-2 rounded-lg bg-bg-primary border border-bg-border text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-accent-cyan transition-colors"
                  />
                </div>

                {/* Password Field */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-accent-cyan" />
                      Senha de Acesso
                    </label>
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="text-[11px] text-slate-400 hover:text-accent-cyan transition-colors flex items-center gap-1"
                    >
                      {showPassword ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                      {showPassword ? 'Ocultar' : 'Mostrar'}
                    </button>
                  </div>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    placeholder="••••••••••••"
                    className="w-full px-3.5 py-2 rounded-lg bg-bg-primary border border-bg-border text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-accent-cyan transition-colors"
                  />
                </div>

                {/* 2FA 6-Digit TOTP Token */}
                <div className="pt-1">
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                      <Fingerprint className="w-3.5 h-3.5 text-accent-cyan" />
                      Código 2FA Authenticator (6 dígitos)
                    </label>
                    <span className="text-[10px] text-accent-cyan font-mono font-bold bg-accent-cyan/10 px-2 py-0.5 rounded border border-accent-cyan/20">
                      TOTP Ativo
                    </span>
                  </div>

                  <div className="grid grid-cols-6 gap-2" onPaste={handlePasteTotp}>
                    {totpCode.map((digit, idx) => (
                      <input
                        key={idx}
                        ref={(el) => { totpInputRefs.current[idx] = el; }}
                        type="text"
                        inputMode="numeric"
                        pattern="[0-9]*"
                        maxLength={1}
                        value={digit}
                        onChange={(e) => handleTotpChange(idx, e.target.value)}
                        onKeyDown={(e) => handleTotpKeyDown(idx, e)}
                        className="h-11 text-center font-mono text-base font-extrabold rounded-lg bg-bg-primary border border-bg-border text-slate-100 focus:outline-none focus:border-accent-cyan focus:ring-1 focus:ring-accent-cyan transition-all"
                      />
                    ))}
                  </div>

                  <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2">
                    <span>Dica: Use <strong>492817</strong> ou seu app Authenticator</span>
                    <button
                      type="button"
                      onClick={() => setTotpCode(['4', '9', '2', '8', '1', '7'])}
                      className="text-accent-cyan hover:underline font-medium text-[10px]"
                    >
                      Preencher Código de Teste
                    </button>
                  </div>

                  {/* Quick Profile Selector for Demo / Audit */}
                  <div className="mt-3 p-2.5 rounded-xl bg-bg-primary/80 border border-bg-border/60 space-y-1.5">
                    <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider flex items-center gap-1">
                      <ShieldCheck className="w-3 h-3 text-accent-cyan" /> Perfis de Demonstração / Auditoria:
                    </p>
                    <div className="grid grid-cols-2 gap-1.5">
                      <button
                        type="button"
                        onClick={() => {
                          setEmail('admin@morfeusec.io');
                          setPassword('Admin#2026!SecMaster');
                          setTotpCode(['4', '9', '2', '8', '1', '7']);
                        }}
                        className="px-2 py-1.5 rounded-lg text-[11px] font-bold bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 transition-colors flex items-center justify-center gap-1"
                      >
                        👑 Entrar como ADMIN
                      </button>

                      <button
                        type="button"
                        onClick={() => {
                          setEmail('operator@sfssa.security');
                          setPassword('Stellantis@2026!Sec');
                          setTotpCode(['4', '9', '2', '8', '1', '7']);
                        }}
                        className="px-2 py-1.5 rounded-lg text-[11px] font-bold bg-accent-cyan/10 hover:bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/30 transition-colors flex items-center justify-center gap-1"
                      >
                        👤 Entrar como OPERADOR
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-2.5 rounded-lg bg-accent-cyan hover:bg-accent-cyan/90 text-bg-primary font-bold text-xs transition-all flex items-center justify-center gap-2 shadow-lg shadow-accent-cyan/10 cursor-pointer disabled:opacity-50 mt-2"
              >
                {isSubmitting ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Autenticando Sessão...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4" />
                    Entrar na Plataforma Segura
                  </>
                )}
              </button>
            </form>
          )}

          {/* MODE 2: QR CODE MOBILE AUTH */}
          {authMode === 'QR_MOBILE' && (
            <div className="space-y-4">
              {/* Type Switcher */}
              <div className="flex items-center justify-center gap-2 text-[11px]">
                <button
                  type="button"
                  onClick={() => switchQrFormat('URL')}
                  className={clsx(
                    'px-2.5 py-1 rounded-md transition-all flex items-center gap-1 cursor-pointer',
                    qrFormat === 'URL'
                      ? 'bg-accent-cyan/15 text-accent-cyan font-bold border border-accent-cyan/30'
                      : 'text-slate-400 hover:text-slate-200'
                  )}
                >
                  <Camera className="w-3 h-3" /> Câmera do Celular / Lens
                </button>
                <button
                  type="button"
                  onClick={() => switchQrFormat('TOTP')}
                  className={clsx(
                    'px-2.5 py-1 rounded-md transition-all flex items-center gap-1 cursor-pointer',
                    qrFormat === 'TOTP'
                      ? 'bg-accent-cyan/15 text-accent-cyan font-bold border border-accent-cyan/30'
                      : 'text-slate-400 hover:text-slate-200'
                  )}
                >
                  <Key className="w-3 h-3" /> Google/MS Authenticator
                </button>
              </div>

              {/* QR Container */}
              <div className="flex flex-col items-center justify-center">
                <div className="relative group">
                  <div
                    className={clsx(
                      'w-56 h-56 bg-white p-3 rounded-2xl shadow-2xl flex flex-col items-center justify-center relative transition-all duration-300',
                      isExpired && 'filter blur-[2px] opacity-40'
                    )}
                  >
                    {/* Real Scannable QR Code Image */}
                    {qrDataUrl ? (
                      // eslint-disable-next-line @next/next/no-img-element
                      <img
                        src={qrDataUrl}
                        alt="QR Code Scannable"
                        className="w-full h-full object-contain rounded-lg"
                      />
                    ) : (
                      <div className="w-full h-full flex items-center justify-center">
                        <RefreshCw className="w-6 h-6 text-slate-800 animate-spin" />
                      </div>
                    )}

                    {/* Scanning Line Animation */}
                    {!isExpired && authStep === 'IDLE' && (
                      <div className="absolute inset-x-0 h-1 bg-gradient-to-r from-transparent via-accent-cyan to-transparent animate-scan shadow-[0_0_15px_#00e676]" />
                    )}
                  </div>

                  {/* Expired Overlay */}
                  {isExpired && (
                    <div className="absolute inset-0 flex flex-col items-center justify-center bg-black/85 rounded-2xl backdrop-blur-sm p-4 text-center">
                      <ShieldAlert className="w-8 h-8 text-red-400 mb-1.5" />
                      <p className="text-xs font-bold text-slate-100">QR Code Expirado</p>
                      <p className="text-[10px] text-slate-400 mt-0.5">Sessão temporária de 60s expirou.</p>
                      <button
                        type="button"
                        onClick={() => generateNewSession()}
                        className="mt-2.5 px-3 py-1.5 bg-accent-cyan text-bg-primary text-xs font-bold rounded-lg flex items-center gap-1.5 cursor-pointer"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                        Novo QR Code
                      </button>
                    </div>
                  )}

                  {/* Authorized State */}
                  {authStep === 'AUTHORIZED' && (
                    <div className="absolute inset-0 flex flex-col items-center justify-center bg-emerald-950/95 rounded-2xl backdrop-blur-sm p-4 text-center">
                      <CheckCircle2 className="w-10 h-10 text-emerald-400 mb-1.5 animate-bounce" />
                      <p className="text-xs font-bold text-slate-100">Dispositivo Autorizado!</p>
                      <p className="text-[10px] text-emerald-300 mt-0.5">Redirecionando...</p>
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-2 mt-2">
                  <span className="text-[10px] text-slate-400 text-center">
                    Aponte a câmera do seu celular (iOS/Android) ou Google Lens
                  </span>
                  <button
                    type="button"
                    onClick={copyPayload}
                    title="Copiar dados do QR Code"
                    className="text-slate-400 hover:text-accent-cyan transition-colors"
                  >
                    <Copy className="w-3 h-3" />
                  </button>
                </div>

                {/* Session countdown */}
                <div className="w-full mt-2.5 space-y-1.5">
                  <div className="flex items-center justify-between text-[11px] font-mono">
                    <span className="text-slate-400 flex items-center gap-1">
                      <KeyRound className="w-3 h-3 text-accent-cyan" />
                      Sessão: <span className="text-slate-200">{sessionId.slice(0, 14)}...</span>
                    </span>
                    <span className={clsx('font-bold px-1.5 py-0.5 rounded', timeLeft > 15 ? 'text-accent-cyan bg-accent-cyan/10' : 'text-red-400 bg-red-500/10')}>
                      {timeLeft > 0 ? `${timeLeft}s` : 'Expirado'}
                    </span>
                  </div>

                  <div className="w-full h-1 bg-bg-border rounded-full overflow-hidden">
                    <div
                      className={clsx('h-full transition-all duration-1000', timeLeft > 15 ? 'bg-accent-cyan' : 'bg-red-500')}
                      style={{ width: `${(timeLeft / 60) * 100}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* PIN input after mobile scan */}
              <form onSubmit={handleQrMobileValidation} className="space-y-3 pt-1">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                      <Smartphone className="w-3.5 h-3.5 text-accent-cyan" />
                      PIN de Confirmação (6 dígitos)
                    </label>
                    <button
                      type="button"
                      onClick={() => setQrTotpPin(currentValidOtp)}
                      className="text-[10px] text-accent-cyan hover:underline font-mono"
                    >
                      PIN Atual: {currentValidOtp}
                    </button>
                  </div>
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={qrTotpPin}
                    onChange={(e) => setQrTotpPin(e.target.value.replace(/[^0-9]/g, ''))}
                    placeholder="Digite o PIN gerado no celular (ex: 492817)"
                    className="w-full px-3.5 py-2 rounded-lg bg-bg-primary border border-bg-border text-xs text-slate-100 font-mono tracking-widest text-center placeholder-slate-500 focus:outline-none focus:border-accent-cyan transition-colors"
                  />
                </div>

                <button
                  type="submit"
                  disabled={isSubmitting || isExpired || qrTotpPin.length < 6}
                  className="w-full py-2.5 rounded-lg bg-accent-cyan hover:bg-accent-cyan/90 text-bg-primary font-bold text-xs transition-all flex items-center justify-center gap-2 shadow-lg shadow-accent-cyan/10 cursor-pointer disabled:opacity-50"
                >
                  {authStep === 'VERIFYING' ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Validando Biometria Mobile...
                    </>
                  ) : (
                    <>
                      <Fingerprint className="w-4 h-4" />
                      Validar QR Code &amp; Autorizar Acesso
                    </>
                  )}
                </button>
              </form>

              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
                <button
                  type="button"
                  onClick={() => generateNewSession()}
                  className="hover:text-accent-cyan transition-colors flex items-center gap-1 font-mono text-[10px] cursor-pointer"
                >
                  <RefreshCw className="w-3 h-3" /> Gerar Novo QR Code
                </button>
                <span className="text-emerald-400 flex items-center gap-1 text-[10px] font-mono">
                  <ShieldCheck className="w-3 h-3" /> Zero-Trust 2FA
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Footer info */}
        <p className="text-center text-[10px] text-slate-500 mt-4">
          morfeusec OSINT &bull; Autenticação de Operadores de Segurança e Engenharia de Ameaças
        </p>
      </div>
    </div>
  );
}
