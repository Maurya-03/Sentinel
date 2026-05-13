# Implemented Performance and Scalability Features

This document summarizes the performance, concurrency, and stability upgrades implemented in the SENTINEL backend.

## Latest Backend Optimizations

- **Single shared HTTP client per scan:** The CLI pipeline and FastAPI job runner now reuse one `AsyncHTTPClient` across crawling, form extraction, SQLi, XSS, and header analysis.
- **One-pass form extraction:** Forms are collected once per crawled URL and shared between SQLi and XSS scanners, avoiding duplicate page fetches.
- **Duplicate queue prevention:** The async crawler tracks queued URLs as well as visited URLs, reducing repeated queue entries on link-heavy pages.
- **Unbounded crawler queue with explicit page cap:** The crawler no longer risks stalling on a full queue; `MAX_PAGES` is enforced by queue admission logic.
- **Clear fetch diagnostics:** HTTP fetch failures are preserved and surfaced, so unreachable targets no longer look like clean scans with zero findings.
- **Reachability finding:** If the crawler cannot fetch the initial target, the report includes a `Target Unreachable` INFO result with remediation guidance.
- **Cached Ollama availability checks:** The XAI layer checks local Ollama availability once and reuses the result, avoiding repeated timeout delays.

## 1) Network and I/O Optimizations

- **Async HTTP stack:** Introduced `aiohttp` with a pooled `ClientSession` for non-blocking requests.
- **Connection pooling:** Persistent sessions reuse connections (keep-alive) and reduce TCP/TLS setup.
- **Per-scan client reuse:** One pooled async client is shared across scan phases instead of creating separate sessions per module.
- **Timeouts + retries:** Configurable retries with exponential backoff and jitter for transient failures.
- **DNS caching:** TTL-based DNS cache via `aiohttp` connector and `aiodns`.
- **Rate limiting:** Per-target RPS limiter to avoid overwhelming hosts.
- **Failure visibility:** The async HTTP client records the latest fetch error for diagnostics and reporting.

## 2) Concurrency and Parallelism

- **Concurrent vulnerability modules:** SQLi and XSS run in parallel using `asyncio.gather`.
- **Concurrent HTTP requests:** High-volume probes execute concurrently with a semaphore limit.
- **Async port scan bridging:** Port scan executes in a background thread to avoid blocking the event loop.

## 3) Task Queue and Orchestration

- **Async job queue:** API server uses an `asyncio.Queue` to decouple request submission and execution.
- **Worker pool:** Configurable worker count for concurrent scan jobs (`SCAN_WORKERS`).
- **Job state tracking:** Jobs report `queued`, `running`, `done`, or `error` with progress updates.

## 4) Crawling Optimizations

- **BFS with worker pool:** Async crawl uses a queue and workers for breadth-first traversal.
- **Visited set:** Deduplicates URLs and avoids reprocessing.
- **Queued set:** Prevents duplicate URLs from entering the crawl queue before they are visited.
- **Scope enforcement:** Same-domain restriction + fragment stripping.
- **Static asset filtering:** Skips common static file extensions to reduce noise.
- **Queue admission cap:** `MAX_PAGES` is enforced before enqueueing links, keeping crawl memory bounded without blocking workers.

## 5) Vulnerability Scanning Optimizations

- **Early-stop per param/field:** Stops on first confirmed finding for a param/field.
- **Concurrent request execution:** GET/POST probes run concurrently per endpoint.
- **Form-aware targeting:** Only performs injection tests when parameters/inputs exist.
- **Shared form cache:** SQLi and XSS reuse one extracted form map instead of independently refetching every crawled page.
- **Injected HTTP client:** Scanner modules can reuse the scan-level HTTP client while retaining standalone operation for direct module use.

## 6) Data Handling and Processing

- **Evidence truncation:** Keeps response snippets short to reduce memory and report size.
- **Deduplication:** SQLi/XSS findings are deduped by URL and parameter.
- **Reachability classification:** Unreachable targets are represented as INFO diagnostics rather than silently producing empty reports.

## 7) Explainable AI (XAI) Optimization

- **Rule-based fast path:** Keeps lightweight KB-based explanations; LLM optional.
- **Deferred enrichment:** Enrichment runs after scan results are collected.
- **Cached LLM availability:** Ollama reachability is checked once per process path and reused to avoid repeated connection timeouts.

## 8) Storage Optimization

- **Report batching:** Report is written once per scan (single JSON write).

## 9) Real-Time Communication Optimization

- **SSE streaming:** Existing server-sent events endpoint provides incremental status updates.

## 10) Rate Limiting and Stability

- **RPS limiter + backoff:** Prevents request bursts and handles transient faults gracefully.
- **Connection reuse + bounded concurrency:** Protects CPU/memory by avoiding unbounded task growth.

## 11) System-Level Optimizations

- **Optional uvloop:** API server attempts to enable `uvloop` if available.

---

## Configuration Reference

All new performance controls are in [vapt-scanner/config.py](vapt-scanner/config.py):

- `HTTP_MAX_CONCURRENCY`
- `HTTP_RATE_LIMIT_RPS`
- `HTTP_RETRIES`
- `HTTP_BACKOFF_BASE`
- `DNS_CACHE_TTL`
- `TASK_QUEUE_SIZE`
- `SCAN_WORKERS`
- `EXCLUDED_EXTENSIONS`
