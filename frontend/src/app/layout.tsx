import ReactQueryProvider from '@/lib/react-query-provider';
import AntiTamperProvider from '@/components/AntiTamperProvider';
import { LanguageProvider } from '@/context/LanguageContext';
import './globals.css';
import { Toaster } from 'react-hot-toast';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Heimdall Security — Enterprise Cyber Defense & Fraud Intelligence',
  description: 'Heimdall Security Enterprise Platform · Offensive Pentest, Brand Protection, Fraud Intelligence & Raven AI',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="pt">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
      </head>
      <body>
        <ReactQueryProvider>
          <LanguageProvider>
            <AntiTamperProvider>
              {children}
            </AntiTamperProvider>
            <Toaster position="top-right" toastOptions={{
              style: { background: '#111827', color: '#f1f5f9', border: '1px solid #1e2d45' },
              success: { iconTheme: { primary: '#00e676', secondary: '#111827' } },
              error: { iconTheme: { primary: '#ff4757', secondary: '#111827' } },
            }} />
          </LanguageProvider>
        </ReactQueryProvider>
      </body>
    </html>
  );
}
