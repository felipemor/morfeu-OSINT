import Sidebar from '@/components/layout/Sidebar';
import FelipinhoFloatingWidget from '@/components/assistant/FelipinhoFloatingWidget';
import GlobalActionsBar from '@/components/GlobalActionsBar';

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen relative">
      <Sidebar />
      <GlobalActionsBar />
      <main className="flex-1 overflow-auto p-6 md:p-8 pt-16">
        {children}
      </main>
      <FelipinhoFloatingWidget />
    </div>
  );
}


