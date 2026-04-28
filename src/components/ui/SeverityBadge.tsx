// src/components/ui/SeverityBadge.tsx

import { Severity } from "@/types/scan";
import { SEVERITY_CONFIG, cn } from "@/lib/utils";

interface Props {
  severity: Severity;
  size?:    "sm" | "md";
  dot?:     boolean;
}

export default function SeverityBadge({ severity, size = "md", dot = true }: Props) {
  const cfg = SEVERITY_CONFIG[severity] ?? SEVERITY_CONFIG.INFO;

  return (
    <span
      className={cn(
        "badge-severity",
        cfg.color, cfg.bg, "border", cfg.border,
        size === "sm" && "text-[10px] px-2 py-0.5"
      )}
    >
      {dot && <span className={cn("w-1.5 h-1.5 rounded-full", cfg.dot)} />}
      {cfg.label}
    </span>
  );
}
