"use client";

// src/components/dashboard/Navbar.tsx

import Link from "next/link";
import { Shield, Download, ArrowLeft, RefreshCw } from "lucide-react";
import { ScanReport } from "@/types/scan";

interface Props {
  report: ScanReport;
  onRefresh?: () => void;
}

export default function Navbar({ report, onRefresh }: Props) {
  const handleExport = () => {
    const json = JSON.stringify(report, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `sentinel-${new URL(report.target).hostname}-report.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border/50 bg-void/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-6 h-14 flex items-center gap-4">
        {/* Logo */}
        <div className="flex items-center gap-2.5 mr-4">
          <div className="w-7 h-7 rounded-lg bg-volt/10 border border-volt/30 flex items-center justify-center">
            <Shield size={13} className="text-volt" />
          </div>
          <span className="font-display font-700 text-white text-sm tracking-wide">SENTINEL</span>
        </div>

        {/* Breadcrumb */}
        <Link href="/" className="flex items-center gap-1.5 text-dim hover:text-bright transition-colors">
          <ArrowLeft size={12} />
          <span className="font-mono text-xs">New Scan</span>
        </Link>

        <span className="text-border">/</span>

        <span className="font-mono text-xs text-bright truncate max-w-xs">
          {report.target}
        </span>

        {/* Risk badge */}
        <div className="ml-2 flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-flaw/10 border border-flaw/20">
          <span className="w-1.5 h-1.5 rounded-full bg-flaw animate-pulse" />
          <span className="font-mono text-xs text-flaw">
            {report.summary.risk_rating} RISK
          </span>
        </div>

        {/* Right actions */}
        <div className="ml-auto flex items-center gap-2">
          {onRefresh && (
            <button
              onClick={onRefresh}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg
                         border border-border text-dim hover:text-bright hover:border-muted
                         font-mono text-xs transition-all"
            >
              <RefreshCw size={11} />
              Rescan
            </button>
          )}
          <button
            onClick={handleExport}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg
                       bg-volt/10 border border-volt/30 text-volt hover:bg-volt/20
                       font-mono text-xs transition-all"
          >
            <Download size={11} />
            Export JSON
          </button>
        </div>
      </div>
    </header>
  );
}
