# SWG-AI (mitmproxy addon)

This addon turns **mitmproxy** into a simple Secure Web Gateway (SWG):
- Categorizes domains with **Google Gemini**
- Caches results in `domain_cache.json`
- Updates `categories.json` with new categories (default: `allowed`)
- Enforces block/allow based on `categories.json`
- Serves a friendly block page from `block_page.html`
- Logs activity and latency to `logs.txt`

## Install

```bash
pip install -r requirements.txt
```

You also need a Google Gemini API key:

- Create or retrieve an API key
- Export it as an environment variable named `GOOGLE_API_KEY`

macOS/Linux:
```bash
export GOOGLE_API_KEY="YOUR_KEY"
```

Windows PowerShell:
```powershell
$Env:GOOGLE_API_KEY="YOUR_KEY"
```

## Run

```bash
mitmproxy -s SWG-AI.py
```

Then:
1. Set your OS/browser proxy to `127.0.0.1:8080`
2. Open **http://mitm.it** and install the mitmproxy root certificate
3. Browse normally

## Policy file

- `categories.json` maps **category → policy** with values `"allowed"` or `"blocked"`.
- New categories found by Gemini are added as `"allowed"`.
- To block a class of sites, edit the file and set the category to `"blocked"`.

Example:
```json
{
  "Social Media": "blocked",
  "News": "allowed"
}
```

## Files created at runtime

- `domain_cache.json` — caches domain → category to reduce API calls
- `logs.txt` — activity and latency logs

## Custom block page

Edit `block_page.html` to change the message/style. A simple default is included.

## Troubleshooting

- **TLS interception not working**: Ensure the mitmproxy certificate is installed (visit `http://mitm.it`). Some apps pin certificates and won’t proxy.
- **No categories appearing**: Confirm `GOOGLE_API_KEY` is set, and outbound network access is allowed.
- **mitmproxy port**: Default is `8080`. If you change it (e.g., `-p 9090`), update your proxy settings accordingly.
- **Cache/policy resets**: This repo’s `.gitignore` excludes runtime files to keep commits clean.
