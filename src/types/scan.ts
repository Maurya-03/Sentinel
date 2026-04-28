// src/types/scan.ts — Core domain types for SENTINEL

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type ScanStatus = "queued" | "running" | "done" | "error";

export interface AiAnalysis {
  explanation: string;
  impact:      string;
  mitigation:  string[];
  confidence:  string;
  source:      "rule_based" | "llm+kb";
}

export interface Vulnerability {
  type:          string;
  subtype?:      string;
  url:           string;
  method?:       string;
  param?:        string;
  payload?:      string;
  severity:      Severity;
  numeric_score: number;
  cwe:           string;
  owasp:         string;
  evidence:      string;
  header?:       string;
  port?:         number;
  service?:      string;
  host?:         string;
  ai_analysis:   AiAnalysis;
}

export interface SeverityBreakdown {
  CRITICAL: number;
  HIGH:     number;
  MEDIUM:   number;
  LOW:      number;
  INFO:     number;
}

export interface ScanSummary {
  total_vulnerabilities: number;
  severity_breakdown:    SeverityBreakdown;
  overall_risk_score:    number;
  risk_rating:           Severity | "NONE";
}

export interface ScanReport {
  sentinel_version: string;
  scan_timestamp:   string;
  target:           string;
  summary:          ScanSummary;
  vulnerabilities:  Vulnerability[];
}

export interface ScanJob {
  job_id:   string;
  status:   ScanStatus;
  progress: number;
  message:  string;
  report?:  ScanReport;
  error?:   string;
  target?:  string;
  created?: string;
}
