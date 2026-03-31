"use client";

// src/app/dashboard/page.tsx — Main scan results dashboard

import { useEffect, useState, useMemo } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { AlertCircle, Loader2 } from "lucide-react";
import { ScanReport, Vulnerability, Severity } from "@/types/scan";
import { api } from "@/lib/api";
import { MOCK_REPORT } from "@/lib/mock-data";

import Navbar      from "@/components/dashboard/Navbar";
import SummaryBar  from "@/components/dashboard/SummaryBar";
import ChartsPanel from "@/components/dashboard/ChartsPanel";
import OWASPMap    from "@/components/dashboard/OWASPMap";
import FilterBar   from "@/components/dashboard/FilterBar";
import VulnCard    from "@/components/dashboard/VulnCard";

export default function DashboardPage() {
  const params  = useSearchParams();
  const router  = useRouter();
  const jobId   = params.get("job") ?? "";

  const [report, setReport]   = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState("");

  // Filter state
  const [search,         setSearch]         = useState("");
  const [activeSeverity, setActiveSeverity] = useState<Severity | "ALL">("ALL");
  const [activeType,     setActiveType]     = useState("ALL");

  // ── Load report ─────────────────────────────────────────────────────────
  useEffect(() => {
    if (!jobId) { router.replace("/"); return; }

    async function load() {
      setLoading(true);
      try {
        // Check sessionStorage first (set by scan page)
        const cached = sessionStorage.getItem(`report:${jobId}`);
        if (cached === "__mock__") {
          setReport(MOCK_REPORT); setLoading(false); return;
        }
        if (cached) {
          setReport(JSON.parse(cached)); setLoading(false); return;
        }

        if (jobId === "demo") {
          // Fetch from API mock endpoint
          const r = await api.getMockReport().catch(() => MOCK_REPORT);
          setReport(r); setLoading(false); return;
        }

        const job = await api.getJob(jobId);
        if (job.report) { setReport(job.report); }
        else { setError("Report not ready — scan may have failed."); }
      } catch (e: any) {
        // Gracefully fall back to mock
        setReport(MOCK_REPORT);
      } finally {
        setLoading(false);
      }
    }

    load();
  }, [jobId, router]);

  // ── Unique vuln types for filter ────────────────────────────────────────
  const vulnTypes = useMemo(() => {
    if (!report) return [];
    return Array.from(new Set(report.vulnerabilities.map(v => v.type)));
  }, [report]);

  // ── Filtered vulns ──────────────────────────────────────────────────────
  const filtered: Vulnerability[] = useMemo(() => {
    if (!report) return [];
    return report.vulnerabilities.filter(v => {
      const matchSev  = activeSeverity === "ALL" || v.severity === activeSeverity;
      const matchType = activeType     === "ALL" || v.type     === activeType;
      const matchSearch = !search ||
        v.type.toLowerCase().includes(search.toLowerCase()) ||
        v.url.toLowerCase().includes(search.toLowerCase())  ||
        v.evidence?.toLowerCase().includes(search.toLowerCase());
      return matchSev && matchType && matchSearch;
    });
  }, [report, activeSeverity, activeType, search]);

  // ── Loading ──────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="min-h-screen bg-void scan-grid flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-volt/10 border border-volt/30 flex items-center justify-center">
            <Loader2 size={20} className="text-volt animate-spin" />
          </div>
          <span className="font-mono text-sm text-dim">Loading report…</span>
        </div>
      </div>
    );
  }

  // ── Error ────────────────────────────────────────────────────────────────
  if (error || !report) {
    return (
      <div className="min-h-screen bg-void flex items-center justify-center">
        <div className="glass rounded-xl p-8 max-w-md text-center flex flex-col gap-4">
          <AlertCircle size={32} className="text-flaw mx-auto" />
          <p className="font-mono text-sm text-soft">{error || "No report data found."}</p>
          <button
            onClick={() => router.push("/")}
            className="px-4 py-2 bg-volt/10 border border-volt/30 text-volt font-mono text-xs rounded-lg hover:bg-volt/20 transition-all"
          >
            ← Start New Scan
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-void scan-grid">
      {/* Ambient glow */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute top-0 left-1/4 w-96 h-64 bg-flaw/4 rounded-full blur-3xl" />
        <div className="absolute bottom-0 right-1/4 w-96 h-64 bg-volt/3 rounded-full blur-3xl" />
      </div>

      <Navbar report={report} onRefresh={() => router.push("/")} />

      <main className="relative z-10 max-w-7xl mx-auto px-6 py-8 flex flex-col gap-6">

        {/* ── Summary strip ─────────────────────────────────────────────── */}
        <SummaryBar report={report} />

        {/* ── Charts row ────────────────────────────────────────────────── */}
        <ChartsPanel report={report} />

        {/* ── OWASP map ─────────────────────────────────────────────────── */}
        <OWASPMap vulnerabilities={report.vulnerabilities} />

        {/* ── Vulnerability list ────────────────────────────────────────── */}
        <section className="flex flex-col gap-4">
          <div className="flex items-center gap-3">
            <h2 className="font-display font-700 text-white text-lg">Findings</h2>
            <span className="font-mono text-xs text-ghost">
              {report.vulnerabilities.length} total
            </span>
          </div>

          <FilterBar
            search={search}               onSearch={setSearch}
            activeSeverity={activeSeverity} onSeverity={setActiveSeverity}
            activeType={activeType}         onType={setActiveType}
            types={vulnTypes}
            totalShown={filtered.length}
            totalAll={report.vulnerabilities.length}
          />

          <div className="flex flex-col gap-3">
            {filtered.length === 0 ? (
              <div className="glass rounded-xl p-10 text-center">
                <p className="font-mono text-sm text-ghost">
                  No vulnerabilities match the current filters.
                </p>
              </div>
            ) : (
              filtered.map((v, i) => (
                <VulnCard key={`${v.type}-${v.url}-${i}`} vuln={v} index={i} />
              ))
            )}
          </div>
        </section>

        {/* ── Footer ────────────────────────────────────────────────────── */}
        <footer className="flex items-center justify-between pt-4 border-t border-border/30">
          <span className="font-mono text-xs text-ghost">
            SENTINEL v{report.sentinel_version} · XAI-powered security analysis
          </span>
          <span className="font-mono text-xs text-ghost">
            Scan completed {new Date(report.scan_timestamp).toLocaleDateString()}
          </span>
        </footer>
      </main>
    </div>
  );
}
