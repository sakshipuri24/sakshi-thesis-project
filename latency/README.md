# Latency tester

A simple script that measures HTTP(S) latency to a set of popular domains.  
You can optionally route requests via a proxy (e.g., the `swg-ai` mitmproxy), to compare **direct** vs **proxied** latency.

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
python latency_tester_proxy.py
```

The script prints per-request timings and an overall summary (average, min, max, std dev).

## Test via a proxy (optional)

macOS/Linux:
```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
python latency_tester_proxy.py
```

Windows PowerShell:
```powershell
$Env:HTTP_PROXY="http://127.0.0.1:8080"
$Env:HTTPS_PROXY="http://127.0.0.1:8080"
python latency_tester_proxy.py
```

> Note: Some corporate proxies require auth or block certain domains; errors are reported per-domain and the script continues.
