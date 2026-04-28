"use client";

// src/components/dashboard/FilterBar.tsx

import { Search, SlidersHorizontal } from "lucide-react";
import { Severity } from "@/types/scan";
import { cn, SEVERITY_CONFIG } from "@/lib/utils";

interface Props {
  search:         string;
  onSearch:       (v: string) => void;
  activeSeverity: Severity | "ALL";
  onSeverity:     (v: Severity | "ALL") => void;
  activeType:     string;
  onType:         (v: string) => void;
  types:          string[];
  totalShown:     number;
  totalAll:       number;
}

const SEVERITIES: (Severity | "ALL")[] = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function FilterBar({
  search, onSearch,
  activeSeverity, onSeverity,
  activeType, onType,
  types, totalShown, totalAll,
}: Props) {
  return (
    <div className="flex flex-col gap-3">
      {/* ── Top row: search + count ───────────────────────────── */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-dim" />
          <input
            type="text"
            value={search}
            onChange={e => onSearch(e.target.value)}
            placeholder="Search vulnerabilities…"
            className="w-full pl-8 pr-4 py-2 bg-abyss border border-border rounded-lg
                       font-mono text-xs text-bright placeholder:text-ghost
                       focus:outline-none focus:border-volt/40 transition-all"
          />
        </div>

        <span className="font-mono text-xs text-ghost ml-auto">
          Showing{" "}
          <span className="text-bright">{totalShown}</span>
          {" "}of{" "}
          <span className="text-bright">{totalAll}</span>
        </span>
      </div>

      {/* ── Filter chips ─────────────────────────────────────── */}
      <div className="flex items-center gap-2 flex-wrap">
        <SlidersHorizontal size={11} className="text-ghost shrink-0" />

        {/* Severity filters */}
        {SEVERITIES.map((sev) => {
          const active = activeSeverity === sev;
          const cfg    = sev !== "ALL" ? SEVERITY_CONFIG[sev] : null;
          return (
            <button
              key={sev}
              onClick={() => onSeverity(sev)}
              className={cn(
                "font-mono text-[10px] tracking-wide uppercase px-2.5 py-1 rounded border transition-all",
                active
                  ? cfg
                    ? `${cfg.color} ${cfg.bg} ${cfg.border}`
                    : "text-volt bg-volt/10 border-volt/30"
                  : "text-ghost bg-transparent border-border hover:border-muted"
              )}
            >
              {sev}
            </button>
          );
        })}

        {/* Divider */}
        <span className="w-px h-4 bg-border" />

        {/* Type filters */}
        {types.map((t) => (
          <button
            key={t}
            onClick={() => onType(activeType === t ? "ALL" : t)}
            className={cn(
              "font-mono text-[10px] tracking-wide px-2.5 py-1 rounded border transition-all",
              activeType === t
                ? "text-pulse bg-pulse/10 border-pulse/30"
                : "text-ghost bg-transparent border-border hover:border-muted"
            )}
          >
            {t}
          </button>
        ))}
      </div>
    </div>
  );
}
