import Sidebar from '@/components/layout/Sidebar';
import FelipinhoFloatingWidget from '@/components/assistant/FelipinhoFloatingWidget';

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen relative">
      <Sidebar />
      <main className="flex-1 overflow-auto p-6 md:p-8">
        {children}
      </main>
      <FelipinhoFloatingWidget />
    </div>
  );
}


