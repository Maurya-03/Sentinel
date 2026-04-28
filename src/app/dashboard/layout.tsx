import { Suspense } from "react";
import { Loader2 } from "lucide-react";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-void flex items-center justify-center">
          <div className="flex items-center gap-3 text-dim">
            <Loader2 size={16} className="animate-spin" />
            <span className="font-mono text-sm">Loading…</span>
          </div>
        </div>
      }
    >
      {children}
    </Suspense>
  );
}
