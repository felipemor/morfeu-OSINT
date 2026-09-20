/**
 * Heimdall Security — Proprietary Anti-Tamper & Code Protection Shield
 * 
 * Protects intellectual property, prevents unauthorized frame embedding,
 * blocks source scraping, and enforces runtime integrity.
 */

export function initAntiTamperProtection(): () => void {
  if (typeof window === 'undefined') return () => {};

  // 1. Console Warning Banner
  try {
    const bannerStyle = 'color: #00d4ff; font-size: 20px; font-weight: 900; text-shadow: 0 0 10px rgba(0, 212, 255, 0.5);';
    const warningStyle = 'color: #ef4444; font-size: 13px; font-weight: bold;';
    const descStyle = 'color: #94a3b8; font-size: 11px;';

    console.log('%c🛡️ HEIMDALL SECURITY — PROPRIETARY PLATFORM', bannerStyle);
    console.log('%c⚠️ AVISO DE PROTEÇÃO DE PROPRIEDADE INTELECTUAL:', warningStyle);
    console.log(
      '%cEste software, seus algoritmos, interfaces e mecanismos de IA (Raven) são de propriedade exclusiva da Heimdall Security.\n' +
      'Qualquer tentativa de engenharia reversa, clonagem, descompilação ou extração de código é estritamente proibida e monitorada.\n' +
      'Todos os direitos reservados © 2026 Heimdall Security.',
      descStyle
    );
  } catch (e) {}

  // 2. Anti-Frame / Anti-Clickjacking defense
  try {
    if (window.top && window.self !== window.top) {
      window.top.location.href = window.self.location.href;
    }
  } catch (e) {}

  // 3. Prevent DevTools shortcuts & Source Inspection in Production
  const handleKeyDown = (e: KeyboardEvent) => {
    if (process.env.NODE_ENV !== 'production') return;

    // F12
    if (e.key === 'F12') {
      e.preventDefault();
      return false;
    }
    // Ctrl+Shift+I / Ctrl+Shift+J / Ctrl+Shift+C (DevTools)
    if (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'i' || e.key === 'J' || e.key === 'j' || e.key === 'C' || e.key === 'c')) {
      e.preventDefault();
      return false;
    }
    // Ctrl+U (View Source)
    if (e.ctrlKey && (e.key === 'U' || e.key === 'u')) {
      e.preventDefault();
      return false;
    }
    // Ctrl+S (Save Page)
    if (e.ctrlKey && (e.key === 'S' || e.key === 's')) {
      e.preventDefault();
      return false;
    }
  };

  const handleContextMenu = (e: MouseEvent) => {
    if (process.env.NODE_ENV === 'production') {
      // Prevent context menu inspection in production
      e.preventDefault();
    }
  };

  window.addEventListener('keydown', handleKeyDown);
  window.addEventListener('contextmenu', handleContextMenu);

  return () => {
    window.removeEventListener('keydown', handleKeyDown);
    window.removeEventListener('contextmenu', handleContextMenu);
  };
}
