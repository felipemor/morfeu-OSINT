import ReactQueryProvider from '@/lib/react-query-provider';
import './globals.css';
import { Toaster } from 'react-hot-toast';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'morfeusec OSINT — Enterprise Recon & Mobile Pentest Platform',
  description: 'Enterprise Offensive Intelligence, Perimeter OSINT & Autonomous Mobile Pentesting Platform',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
      </head>
      <body>
        <ReactQueryProvider>
          {children}
          <Toaster position="top-right" toastOptions={{
            style: { background: '#111827', color: '#f1f5f9', border: '1px solid #1e2d45' },
            success: { iconTheme: { primary: '#00e676', secondary: '#111827' } },
            error: { iconTheme: { primary: '#ff4757', secondary: '#111827' } },
          }} />
        </ReactQueryProvider>
      </body>
    </html>
  );
}
