# LLM Privacy Guard — Test Plan (Edge + chatgpt.com)

This test plan validates a lightweight browser extension that detects sensitive data in prompts, warns the user, optionally redacts, and ensures **nothing is sent to the LLM before the user responds**.

---

## 0) Test Environment

- Browser: **Microsoft Edge** (latest)
- Site: **https://chatgpt.com/**
- Extension: **LLM Privacy Guard (MVP)**
- Build: `content.ts` compiled to `content.js`
- Extension loaded via: `edge://extensions` → **Developer mode** → **Load unpacked**
- After any code change:
  1) `npx tsc`
  2) `edge://extensions` → **Reload**
  3) ChatGPT tab → **Hard refresh** (`Ctrl + Shift + R`)

---

## 1) Pre-Checks

### [ ] 1.1 Script injection 확인 (sanity)
**Steps**
1. Open `https://chatgpt.com`
2. Open DevTools → Console

**Expected**
- Console shows an injection log (e.g., `LLM Privacy Guard injected: ...`)

---

## 2) Core Safety Requirement

### [ ] 2.1 Nothing is sent before modal decision (Enter)
**Input**
- `Here is my key: sk-1234567890abcdef1234567890abcdef`

**Steps**
1. Paste input
2. Press **Enter**
3. Do **not** click anything in the modal for 3–5 seconds

**Expected**
- No message appears in chat
- No assistant response begins
- Only after choosing **Redact & Continue** or **Proceed Anyway** does it send

### [ ] 2.2 Nothing is sent before modal decision (Send button click)
**Input**
- Same as above

**Steps**
1. Paste input
2. Click the **Send** button
3. Wait 3–5 seconds without responding to modal

**Expected**
- Same as 2.1

---

## 3) Detection Tests (Ruleset Correctness)

> Goal: High-signal secrets should trigger reliably, low-noise behavior.

### BLOCK Findings (should trigger modal)

#### [ ] 3.1 API key (sk-…)
**Input**
- `Here is my key: sk-1234567890abcdef1234567890abcdef`

**Expected**
- Modal appears, lists `API_KEY` (BLOCK)

#### [ ] 3.2 GitHub token
**Input**
- `Token: ghp_abcdefghijklmnopqrstuvwxyz123456`

**Expected**
- Modal appears, lists `GITHUB_TOKEN` (BLOCK)

#### [ ] 3.3 AWS Access Key ID
**Input**
- `AWS key: AKIA1234567890ABCDEF`

**Expected**
- Modal appears, lists `AWS_ACCESS_KEY` (BLOCK)

#### [ ] 3.4 Private key block
**Input**
```text
-----BEGIN PRIVATE KEY-----
abc
-----END PRIVATE KEY-----