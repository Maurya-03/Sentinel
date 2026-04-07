"use client";

// src/components/dashboard/ChartsPanel.tsx

import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from "recharts";
import { ScanReport, Severity } from "@/types/scan";

interface Props { report: ScanReport }

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#f59e0b",
  LOW:      "#3b82f6",
  INFO:     "#6366f1",
};

export default function ChartsPanel({ report }: Props) {
  const { vulnerabilities, summary } = report;

  // ── Donut data ──────────────────────────────────────────────────────────
  const donutData = Object.entries(summary.severity_breakdown)
    .filter(([, count]) => count > 0)
    .map(([name, value]) => ({ name, value }));

  // ── Score distribution (bar chart) ──────────────────────────────────────
  const barData = vulnerabilities.map((v, i) => ({
    name:  v.type.replace("Cross-Site Scripting (XSS)", "XSS")
                  .replace("Missing Security Header", "Header")
                  .replace("Information Disclosure", "Info Disclosure")
                  .replace("Open Port", "Port")
                  .substring(0, 16),
    score: v.numeric_score,
    fill:  SEV_COLORS[v.severity] ?? "#334155",
  }));

  const CustomTooltip = ({ active, payload }: any) => {
    if (!active || !payload?.length) return null;
    return (
      <div className="glass rounded-lg px-3 py-2">
        <p className="font-mono text-xs text-bright">{payload[0].name}</p>
        <p className="font-mono text-xs text-volt">{payload[0].value}</p>
      </div>
    );
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* ── Severity Donut ─────────────────────────────────── */}
      <div className="stat-card">
        <span className="section-label">Severity Distribution</span>
        <div className="flex items-center gap-6 mt-2">
          <ResponsiveContainer width={140} height={140}>
            <PieChart>
              <Pie
                data={donutData}
                cx="50%" cy="50%"
                innerRadius={42} outerRadius={62}
                paddingAngle={3}
                dataKey="value"
                strokeWidth={0}
              >
                {donutData.map((entry) => (
                  <Cell key={entry.name} fill={SEV_COLORS[entry.name]} opacity={0.9} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>

          <div className="flex flex-col gap-2">
            {donutData.map((d) => (
              <div key={d.name} className="flex items-center gap-2">
                <span
                  className="w-2 h-2 rounded-full shrink-0"
                  style={{ background: SEV_COLORS[d.name] }}
                />
                <span className="font-mono text-xs text-dim">{d.name}</span>
                <span className="font-mono text-xs text-bright ml-auto pl-4">{d.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── CVSS Score Bars ────────────────────────────────── */}
      <div className="stat-card">
        <span className="section-label">CVSS Score by Finding</span>
        <div className="mt-3" style={{ height: 140 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={barData} barSize={16}
              margin={{ top: 0, right: 0, bottom: 0, left: -24 }}>
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#1a2236"
                vertical={false}
              />
              <XAxis
                dataKey="name"
                tick={{ fill: "#64748b", fontSize: 9, fontFamily: "JetBrains Mono" }}
                tickLine={false}
                axisLine={false}
                interval={0}
                angle={-25}
                textAnchor="end"
                height={40}
              />
              <YAxis
                domain={[0, 10]}
                tick={{ fill: "#64748b", fontSize: 9, fontFamily: "JetBrains Mono" }}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.02)" }} />
              <Bar dataKey="score" radius={[3, 3, 0, 0]}>
                {barData.map((entry, i) => (
                  <Cell key={i} fill={entry.fill} opacity={0.85} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
