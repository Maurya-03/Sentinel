// src/lib/utils.ts — Shared helpers

import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { Severity } from "@/types/scan";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const SEVERITY_CONFIG: Record<
  Severity,
  { label: string; color: string; bg: string; border: string; glow: string; dot: string }
> = {
  CRITICAL: {
    label:  "Critical",
    color:  "text-critical",
    bg:     "bg-critical/10",
    border: "border-critical/30",
    glow:   "shadow-glow-flaw",
    dot:    "bg-critical",
  },
  HIGH: {
    label:  "High",
    color:  "text-high",
    bg:     "bg-high/10",
    border: "border-high/30",
    glow:   "shadow-glow-breach",
    dot:    "bg-high",
  },
  MEDIUM: {
    label:  "Medium",
    color:  "text-medium",
    bg:     "bg-medium/10",
    border: "border-medium/30",
    glow:   "shadow-glow-breach",
    dot:    "bg-medium",
  },
  LOW: {
    label:  "Low",
    color:  "text-low",
    bg:     "bg-low/10",
    border: "border-low/30",
    glow:   "",
    dot:    "bg-low",
  },
  INFO: {
    label:  "Info",
    color:  "text-info",
    bg:     "bg-info/10",
    border: "border-info/30",
    glow:   "",
    dot:    "bg-info",
  },
};

export function formatTimestamp(iso: string): string {
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(iso));
}

export function scoreToRiskLabel(score: number): string {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0.0)  return "LOW";
  return "NONE";
}

export function getVulnIcon(type: string): string {
  if (type.includes("SQL"))     return "🛢";
  if (type.includes("XSS"))     return "⚡";
  if (type.includes("Port"))    return "🔌";
  if (type.includes("Header"))  return "🔒";
  if (type.includes("Info"))    return "📡";
  return "⚠";
}
