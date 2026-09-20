'use client';

import { useEffect } from 'react';
import { initAntiTamperProtection } from '@/lib/anti-tamper';

export default function AntiTamperProvider({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    const cleanup = initAntiTamperProtection();
    return () => {
      cleanup();
    };
  }, []);

  return <>{children}</>;
}
