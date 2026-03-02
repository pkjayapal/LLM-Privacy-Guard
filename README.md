# LLM-Privacy-Guard
A lightweight browser extension that detects sensitive data **before it is sent to an LLM** (e.g., ChatGPT), warns the user, and optionally redacts it — all locally, with zero network calls.

---

## What This Does

Before a prompt is sent to ChatGPT, the extension:

- Scans for high-signal secrets (API keys, private keys, tokens)
- Warns on sensitive PII (SSNs, credit cards, JWTs)
- Blocks the send until the user decides
- Offers **Redact & Continue**
- Sends nothing to any external service (fully local)

---

## Detection Coverage (MVP)

### BLOCK (High Signal)
- Private key blocks (`-----BEGIN PRIVATE KEY-----`)
- OpenAI-style `sk-...` API keys
- AWS Access Key IDs (`AKIA...`)
- GitHub tokens (`ghp_...`, etc.)

### WARN
- US SSNs
- Credit cards (validated with Luhn check)
- JWT tokens

---

## Architecture (Lightweight by Design)

- Chrome / Edge **Manifest V3**
- TypeScript content script
- No background server
- No external API calls
- No telemetry
- ~300 LOC

All scanning runs inside the browser tab.

---

# Setup Instructions (Windows + VS Code + Edge)

## Install Node.js

Download and install **Node.js LTS**:

https://nodejs.org/

During install:
- Ensure "Add to PATH" is checked

Verify installation in PowerShell:

```powershell
node -v
npm -v
