# SENTINEL: Intelligent VAPT Platform

### 1. Title & Abstract
**SENTINEL** is a next-generation, automated Vulnerability Assessment and Penetration Testing (VAPT) platform designed for modern web applications. It combines high-performance asynchronous scanning engines with **Explainable AI (XAI)** to provide not just detection, but deep context and remediation guidance. By leveraging **Local LLMs (via Ollama)**, SENTINEL transforms raw vulnerability data into human-readable insights, bridge the gap between automated tools and expert manual analysis.

---

### 2. Problem Statement
Traditional VAPT tools often suffer from:
*   **High Latency:** Sequential scanning becomes a bottleneck for large modern sites.
*   **Context Vacuum:** Generic vulnerability descriptions lack site-specific context (why *this* parameter is vulnerable).
*   **Data Overload:** Security teams are overwhelmed by raw JSON reports without clear prioritization or fix-actions.
*   **Privacy Risks:** Cloud-based AI analysis often requires sending sensitive scan data to external third-party providers.

---

### 3. Core Concept & Innovation
SENTINEL introduces three key innovations:
1.  **Local XAI Integration:** Uses local LLMs to generate high-fidelity, context-aware explanations and mitigation strategies without data leaving the infrastructure.
2.  **Fully Asynchronous Pipeline:** Utilizes Python's `asyncio` and `aiohttp` for non-blocking I/O across crawling, detection, and analysis.
3.  **Confidence-Weighted Scoring:** A proprietary risk algorithm that scores findings based on detection vector reliability (e.g., Error-based SQLi vs. Time-based).

---

### 4. High-Level Architecture
The system follows a decoupled, service-oriented architecture:
*   **Frontend (Next.js):** A React-based real-time dashboard for scan management and visualization.
*   **REST API (FastAPI):** Orchestration layer handling scan requests, SSE updates, and report persistence.
*   **Scanner Engine (Python/Async):** Modular detection cores (Crawler, SQLi, XSS, Port, Headers).
*   **XAI Engine (Ollama):** Local inference engine for generating qualitative security analysis.

---

### 5. Modular Breakdown
*   **Backend (FastAPI):** Manages the scan lifecycle, task queuing, and provides a structured JSON/SSE API for the UI.
*   **Crawler (BFS):** An asynchronous `BeautifulSoup4` powered crawler that builds a site map, extracts forms, and maps attack surfaces.
*   **Detection Engine:**
    *   **SQLi Scanner:** Implements error-based and time-based boolean inference.
    *   **XSS Scanner:** Context-aware payload reflection testing.
    *   **Port Scanner:** High-speed TCP handshake probe.
*   **AI Engine:** Interfaces with `Ollama` to perform prompt-engineered analysis of raw detection evidence.
*   **Frontend (Tailwind/Lucide):** Responsive UI with categorical breakdowns of vulnerabilities and interactive logs.

---

### 6. Features
*   **Multi-Vector Crawler:** Deep-link discovery with configurable exclusion lists (`.css`, `.jpg`, etc.).
*   **Automated Detection:** Simultaneous SQLi, XSS, and Header security misconfiguration scans.
*   **AI Analysis:** Dynamic generation of "Why", "Impact", and "How to Fix" for every finding.
*   **Interactive Dashboard:** Real-time progress tracking, severity distribution charts, and expanded evidence views.
*   **One-Click Reports:** Structured JSON reports with built-in CVSS-informed scoring.

---

### 7. Technologies & Tools Used
*   **Backend:** FastAPI, Python 3.10+, `asyncio`, `uvicorn`.
*   **HTTP Client:** `aiohttp` (Asynchronous HTTP requests), `requests` (Synchronous Fallbacks).
*   **Parsing:** `BeautifulSoup4`, `lxml`.
*   **AI:** Ollama (Mistral/Llama3), Python `requests` for local inference.
*   **Frontend:** Next.js 14, TypeScript, Tailwind CSS, Lucide React, Framer Motion.
*   **Storage:** JSON-based report persistence with UUID indexing.

---

### 8. Algorithms & Techniques
*   **BFS Crawling:** A Breadth-First Search algorithm with configurable depth and page limits to ensure exhaustive site mapping.
*   **Risk Scoring Algorithm:**
    $$Score = \text{BaseSeverity} \times \text{ConfidenceFactor} + \text{ContextAdjustment}$$
    *   Uses a `SEVERITY_BASE_SCORES` map (0.0 to 10.0).
    *   Adjusts confidence based on the detection vector (e.g., `error_based` = 92%, `reflected_xss` = 95%).
*   **Parallel Scanning:** Uses `asyncio.gather` and `asyncio.TaskGroup` to run independent scanners concurrently across discovered URLs.

---

### 9. Data Handling & Flow
1.  **Inputs:** User provides URL $\rightarrow$ Validated via Pydantic model.
2.  **Crawl:** `AsyncHTTPClient` fetches pages $\rightarrow$ Yields list of URLs and Forms.
3.  **Scan:** Forms and URLs are put into specialized scanner pipelines $\rightarrow$ Yields `RawFinding` objects.
4.  **Enrichment:** `analyzer.py` maps findings to `VULN_KB_FILE` $\rightarrow$ Queries Ollama for dynamic text.
5.  **Output:** Enriched JSON report formatted for persistence and UI consumption.

---

### 10. System Workflow
1.  **Request:** UI sends scan POST request to `/api/scan`.
2.  **Initialize:** Backend starts `async_run_scan` in the background.
3.  **Explore:** Crawler builds the attack surface.
4.  **Attack:** Scanners execute payloads against inputs.
5.  **Think:** AI engine evaluates the findings.
6.  **Report:** Results are saved and updated via SSE or polling.

---

### 11. Advanced Layer: LLM Integration
SENTINEL uses **Ollama** as its primary reasoning engine.
*   **Prompt Engineering:** Custom templates translate raw server responses and payloads into security narratives.
*   **Fallback Mechanism:** If Ollama is offline, the system falls back to a deterministic **Knowledge Base (KB)** of known CWEs.
*   **Contextual Awareness:** The AI receives the specific parameter, URL, and evidence string to ensure responses are not hallucinated generic definitions.

---

### 12. Security Considerations
*   **Rate Limiting:** Configurable `HTTP_RATE_LIMIT_RPS` to avoid inadvertently DOSing targets.
*   **Isolation:** Local AI ensures no sensitive PII or internal URL structures are leaked to public API LLMs.
*   **Safe Payloads:** Uses non-destructive payloads (e.g., `sleep(5)`, `alert(1)`) for detection without impact.

---

### 13. Performance Optimization
*   **Non-Blocking I/O:** The entire scanner core uses `async/await` patterns, allowing the system to handle hundreds of requests simultaneously where synchronous scanners would hang.
*   **Deduplication:** URL normalization prevents scanning the same page multiple times (e.g., `?id=1` and `?id=1&ref=home`).
*   **DNS Caching:** Implements `AioProtocol` DNS caching to reduce lookup overhead.

---

### 14. Challenges & Solutions
*   **Large Site Crawls:** Solved by implementing `MAX_PAGES` and `MAX_CRAWL_DEPTH` guards.
*   **AI Hallucinations:** Mitigated by using a Hybrid Approachâ€”combining static KB metadata (CWE/OWASP) with AI-generated text.
*   **Process Hanging:** Solved via `asyncio.to_thread` for blocking legacy code (like port scanning) and strict timeout management.

---

### 15. Testing & Validation
*   **Functional Testing:** Validated against `testphp.vulnweb.com` and `example.com`.
*   **Unit Tests:** Coverage for `risk_scoring.py` and `utils.py` logic.
*   **Payload Validation:** Rigorous testing of regex-based signature matching for SQLi and XSS reflections.

---

### 16. Output Format & Results
The scanner generates a structured JSON object containing:
*   **Target Metadata:** URLs crawled, scan duration, timestamp.
*   **Categorized Findings:** Grouped by severity (Critical to Info).
*   **Evidence Blocks:** Raw HTTP request/response snippets showing exactly how the vulnerability was identified.

---

### 17. Presentation Enhancements
*   **Visual Indicators:** Color-coded severity badges (Red for Critical, Green for Info).
*   **Progress Visualization:** Step-by-step UI updates (Crawling $\rightarrow$ Scanning $\rightarrow$ Analyzing).
*   **Interactive Mitigation:** Expandable code blocks showing "Before vs. After" code fixes.

---

### 18. Future Enhancements
*   **Authentication Support:** Login recording to scan behind authenticated portals.
*   **Custom Payloads:** A plug-and-play UI for adding custom signatures.
*   **Actionable Export:** Generation of PDF and CSV reports for stakeholders.
*   **Live Attack Map:** Visualization of the crawler's path in real-time.

---

### 19. Conclusion
**SENTINEL** represents a shift in VAPT methodology, moving from mere "alert generators" to "security advisors." By combining the speed of modern asynchronous programming with the reasoning capabilities of local Large Language Models, it provides a comprehensive, private, and highly efficient security auditing solution.