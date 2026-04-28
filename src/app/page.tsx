"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Search, AlertTriangle, Cpu, Globe, Lock } from "lucide-react";
import { api, pollJob } from "@/lib/api";
import { ScanJob } from "@/types/scan";

export default function HomePage() {
  const router   = useRouter();
  const [url, setUrl]         = useState("");
  const [skipPorts, setSkip]  = useState(false);
  const [loading, setLoading] = useState(false);
  const [status, setStatus]   = useState("");
  const [progress, setProgress] = useState(0);
  const [error, setError]     = useState("");

  const handleScan = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setError("");
    setProgress(0);
    setStatus("Initialising scan…");

    try {
      const job = await api.startScan(url.trim(), skipPorts);

      if (job.status === "done" && job.report) {
        // Mock or instant result
        sessionStorage.setItem(`report:${job.job_id}`, JSON.stringify(job.report));
        router.push(`/dashboard?job=${job.job_id}`);
        return;
      }

      await pollJob(
        job.job_id,
        (updated: ScanJob) => {
          setProgress(updated.progress);
          setStatus(updated.message);
        },
        1500
      );

      const final = await api.getJob(job.job_id);
      if (final.report) {
        sessionStorage.setItem(`report:${job.job_id}`, JSON.stringify(final.report));
      }
      router.push(`/dashboard?job=${job.job_id}`);
    } catch (e: any) {
      setError(e.message ?? "Scan failed");
      setLoading(false);
    }
  };

  const handleDemo = () => {
    sessionStorage.setItem("report:demo", "__mock__");
    router.push("/dashboard?job=demo");
  };

  return (
    <main className="min-h-screen bg-void scan-grid flex flex-col">
      {/* ── Ambient glows ─────────────────────────────────────── */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 w-96 h-96 bg-volt/5 rounded-full blur-3xl" />
        <div className="absolute top-1/3 -right-40 w-96 h-96 bg-pulse/5 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 left-1/2 w-96 h-96 bg-breach/5 rounded-full blur-3xl" />
      </div>

      {/* ── Nav ──────────────────────────────────────────────── */}
      <nav className="relative z-10 flex items-center justify-between px-8 py-5 border-b border-border/50">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-volt/10 border border-volt/30 flex items-center justify-center shadow-glow-volt">
            <Shield size={14} className="text-volt" />
          </div>
          <span className="font-display font-700 text-white tracking-wide">SENTINEL</span>
          <span className="font-mono text-xs text-dim px-2 py-0.5 bg-surface border border-border rounded">v1.0</span>
        </div>
        <div className="flex items-center gap-6">
          <button onClick={handleDemo} className="font-mono text-xs text-dim hover:text-volt transition-colors">
            Load Demo
          </button>
          <a href="https://owasp.org/www-project-top-ten/" target="_blank"
             className="font-mono text-xs text-dim hover:text-bright transition-colors">
            OWASP Top 10 ↗
          </a>
        </div>
      </nav>

      {/* ── Hero ─────────────────────────────────────────────── */}
      <div className="relative z-10 flex-1 flex flex-col items-center justify-center px-4 py-20">
        <div className="w-full max-w-2xl mx-auto text-center">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-volt/10 border border-volt/20 mb-8">
            <span className="w-1.5 h-1.5 rounded-full bg-volt animate-pulse" />
            <span className="font-mono text-xs text-volt tracking-wider">AUTOMATED VAPT · EXPLAINABLE AI</span>
          </div>

          {/* Heading */}
          <h1 className="font-display text-5xl font-800 text-white leading-tight mb-4 tracking-tight">
            Scan.<br />
            <span className="text-volt">Detect.</span>{" "}
            <span className="text-soft">Understand.</span>
          </h1>

          <p className="font-body text-dim text-lg max-w-md mx-auto mb-12 leading-relaxed">
            Automated vulnerability scanning with an Explainable AI engine that tells you
            not just <em className="text-soft not-italic">what</em> was found,
            but <em className="text-volt not-italic">why</em> it exists and how to fix it.
          </p>

          {/* ── Scan Form ──────────────────────────────────────── */}
          <div className="glass rounded-2xl p-6 text-left shadow-glow-volt/10">
            <label className="section-label block mb-3">Target URL</label>

            <div className="flex gap-3">
              <div className="relative flex-1">
                <Globe size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-dim" />
                <input
                  type="text"
                  value={url}
                  onChange={e => setUrl(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !loading && handleScan()}
                  placeholder="http://target.example.com"
                  className="w-full pl-9 pr-4 py-3 bg-abyss border border-border rounded-lg
                             font-mono text-sm text-bright placeholder:text-ghost
                             focus:outline-none focus:border-volt/50 focus:bg-surface
                             transition-all"
                />
              </div>
              <button
                onClick={handleScan}
                disabled={loading || !url.trim()}
                className="px-6 py-3 bg-volt text-void font-display font-700 text-sm rounded-lg
                           hover:bg-volt/90 disabled:opacity-40 disabled:cursor-not-allowed
                           transition-all shadow-glow-volt flex items-center gap-2"
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                    </svg>
                    Scanning
                  </span>
                ) : (
                  <>
                    <Search size={14} />
                    Scan
                  </>
                )}
              </button>
            </div>

            {/* Options row */}
            <div className="flex items-center gap-6 mt-4">
              <label className="flex items-center gap-2 cursor-pointer group">
                <input
                  type="checkbox"
                  checked={skipPorts}
                  onChange={e => setSkip(e.target.checked)}
                  className="w-3.5 h-3.5 accent-volt rounded"
                />
                <span className="font-mono text-xs text-dim group-hover:text-soft transition-colors">
                  Skip port scan
                </span>
              </label>
              <span className="font-mono text-xs text-ghost">
                Scans: SQLi · XSS · Headers · Ports
              </span>
            </div>

            {/* Progress bar */}
            {loading && (
              <div className="mt-5">
                <div className="flex justify-between mb-2">
                  <span className="font-mono text-xs text-dim">{status}</span>
                  <span className="font-mono text-xs text-volt">{progress}%</span>
                </div>
                <div className="h-1 bg-abyss rounded-full overflow-hidden">
                  <div
                    className="h-full bg-volt rounded-full transition-all duration-500"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </div>
            )}

            {/* Error */}
            {error && (
              <div className="mt-4 flex items-center gap-2 text-flaw font-mono text-xs">
                <AlertTriangle size={12} />
                {error}
              </div>
            )}
          </div>

          {/* Feature chips */}
          <div className="flex items-center justify-center gap-3 mt-8 flex-wrap">
            {[
              { icon: <Cpu size={11}/>,   label: "XAI Engine"         },
              { icon: <Lock size={11}/>,  label: "OWASP Coverage"     },
              { icon: <Shield size={11}/>,label: "CVSS Scoring"       },
              { icon: <Globe size={11}/>, label: "Local LLM Support"  },
            ].map(f => (
              <div key={f.label}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-full
                           bg-surface border border-border text-dim font-mono text-xs">
                {f.icon}
                {f.label}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Footer ───────────────────────────────────────────── */}
      <footer className="relative z-10 flex items-center justify-between px-8 py-4 border-t border-border/30">
        <span className="font-mono text-xs text-ghost">
          Only scan targets you own or have explicit permission to test.
        </span>
        <span className="font-mono text-xs text-ghost">SENTINEL · 2025</span>
      </footer>
    </main>
  );
}
