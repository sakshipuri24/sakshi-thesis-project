# SWG-AI & Latency Tools

This repo contains two small, self-contained programs used in an MTU MSc Cybersecurity research project on Secure Web Gateway (SWG) evaluation.

- `swg-ai/` — a **mitmproxy addon** that categorizes domains using **Google Gemini** and enforces allow/block policies (acts like a lightweight SWG).
- `latency/` — a **simple latency tester** that measures round-trip time to a list of popular domains (optionally via a proxy).

## Quick Start

### 1) SWG-AI (mitmproxy addon)
- Install deps: `pip install -r swg-ai/requirements.txt`
- Set your Gemini API key: `export GOOGLE_API_KEY="YOUR_KEY"` (Windows PowerShell: `$Env:GOOGLE_API_KEY="YOUR_KEY"`)
- Start mitmproxy with the addon:
  ```bash
  mitmproxy -s swg-ai/SWG-AI.py
  ```
- Point your system/browser to use the proxy `127.0.0.1:8080` and install the mitmproxy cert from **http://mitm.it** (follow on-screen steps).
- Browse the web. New categories are added to `swg-ai/categories.json` as **allowed** by default. Mark any category as `"blocked"` to enforce.

### 2) Latency tester
- Install deps: `pip install -r latency/requirements.txt`
- Run:
  ```bash
  python latency/latency_tester.py
  ```

## Repo Structure

```
SWG-AI-and-Latency-Repo/
├─ swg-ai/
│  ├─ SWG-AI.py
│  ├─ requirements.txt
│  ├─ README.md
│  ├─ categories.json         # policy (edit to block/allow categories)
│  ├─ block_page.html         # shown when a blocked category is hit
│  ├─ .env.example            # GOOGLE_API_KEY placeholder
│  └─ .gitignore
├─ latency/
│  ├─ latency_tester.py
│  ├─ requirements.txt
└─ README.md   # (this file)
```

---

> Tip: Keep commit messages small and focused. Include before/after examples when changing policy or latency test lists.
