// src/components/ui/ScoreRing.tsx — Circular risk score display

import { cn } from "@/lib/utils";

interface Props {
  score:   number;   // 0–10
  size?:   number;
  label?:  string;
}

function scoreColor(s: number): string {
  if (s >= 9.0) return "#ef4444";
  if (s >= 7.0) return "#f97316";
  if (s >= 4.0) return "#f59e0b";
  if (s > 0.0)  return "#3b82f6";
  return "#334155";
}

export default function ScoreRing({ score, size = 100, label = "Risk Score" }: Props) {
  const r      = 40;
  const circ   = 2 * Math.PI * r;
  const fill   = circ * (score / 10);
  const gap    = circ - fill;
  const color  = scoreColor(score);

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={size} height={size} viewBox="0 0 100 100">
        {/* Track */}
        <circle cx="50" cy="50" r={r} fill="none"
          stroke="#1a2236" strokeWidth="8" />
        {/* Fill */}
        <circle cx="50" cy="50" r={r} fill="none"
          stroke={color} strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={`${fill} ${gap}`}
          strokeDashoffset={circ * 0.25}
          style={{ transition: "stroke-dasharray 1s ease", filter: `drop-shadow(0 0 6px ${color}50)` }}
        />
        {/* Score text */}
        <text x="50" y="47" textAnchor="middle" dominantBaseline="middle"
          fill={color} fontFamily="JetBrains Mono, monospace"
          fontSize="20" fontWeight="600">
          {score.toFixed(1)}
        </text>
        <text x="50" y="63" textAnchor="middle" dominantBaseline="middle"
          fill="#64748b" fontFamily="JetBrains Mono, monospace"
          fontSize="9">
          /10
        </text>
      </svg>
      <span className="font-mono text-xs text-dim">{label}</span>
    </div>
  );
}
