// src/lib/api.ts — Typed API client for SENTINEL backend

import { ScanJob, ScanReport } from "@/types/scan";
import { MOCK_REPORT } from "./mock-data";

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "";
const USE_MOCK = process.env.NEXT_PUBLIC_USE_MOCK === "true";

async function req<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(err || `HTTP ${res.status}`);
  }
  return res.json();
}

export const api = {
  /** Start a new scan and return the job. */
  startScan: async (target: string, skipPorts = false): Promise<ScanJob> => {
    if (USE_MOCK) {
      return {
        job_id: "mock-" + Date.now(),
        status: "done",
        progress: 100,
        message: "Mock scan complete",
        report: MOCK_REPORT,
      };
    }
    return req<ScanJob>("/api/scan", {
      method: "POST",
      body: JSON.stringify({ target, skip_ports: skipPorts }),
    });
  },

  /** Poll a job by ID. */
  getJob: async (jobId: string): Promise<ScanJob> => {
    if (jobId.startsWith("mock-")) {
      return {
        job_id:   jobId,
        status:   "done",
        progress: 100,
        message:  "Mock scan complete",
        report:   MOCK_REPORT,
      };
    }
    return req<ScanJob>(`/api/scan/${jobId}`);
  },

  /** Get mock report directly. */
  getMockReport: async (): Promise<ScanReport> => {
    return req<ScanReport>("/api/mock");
  },

  /** List all past scans. */
  listScans: async (): Promise<ScanJob[]> => {
    return req<ScanJob[]>("/api/scans");
  },

  /** Delete a scan job. */
  deleteScan: async (jobId: string): Promise<void> => {
    await req(`/api/scan/${jobId}`, { method: "DELETE" });
  },
};

/** Poll a job until done or error, calling onProgress each tick. */
export async function pollJob(
  jobId:      string,
  onProgress: (job: ScanJob) => void,
  intervalMs  = 1500
): Promise<ScanJob> {
  return new Promise((resolve, reject) => {
    const timer = setInterval(async () => {
      try {
        const job = await api.getJob(jobId);
        onProgress(job);
        if (job.status === "done" || job.status === "error") {
          clearInterval(timer);
          job.status === "done" ? resolve(job) : reject(new Error(job.error ?? "Scan failed"));
        }
      } catch (e) {
        clearInterval(timer);
        reject(e);
      }
    }, intervalMs);
  });
}
