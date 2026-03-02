// content.ts — MV3 content script (lightweight pre-send DLP)
// Goal: On chatgpt.com (and similar), detect high-signal secrets/PII *before send*,
// show a modal, optionally redact, then continue sending.
//
// Key fixes included:
// - Reliable ChatGPT selectors (#prompt-textarea, send button data-testid)
// - Guard + modal single-flight lock (prevents "hung" dialog from re-entrancy)
// - Do NOT break normal send path when there are no findings
// - After user chooses Redact/Proceed, send by clicking the real send button
//   (more reliable than re-dispatching Enter)

console.log("LLM Privacy Guard injected:", location.href);

type Severity = "BLOCK" | "WARN";
type Finding = { id: string; label: string; severity: Severity };
type ScanResult = { findings: Finding[]; redactedText?: string };

type ModalChoice = "CANCEL" | "REDACT" | "PROCEED";

const EXT_NS = "llm-privacy-guard";
const MODAL_ID = `${EXT_NS}-modal`;

// Single-flight state to prevent multiple concurrent dialogs / promises
let guardInFlight = false;
let modalOpen = false;
let bypassOnce = false;

// ---- Compact ruleset (low false positives) ----
const RE = {
  privateKeyBlock:
    /-----BEGIN (?:RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----/g,

  // generic sk- token (kept strict-ish by length)
  apiKeySk: /\bsk-[A-Za-z0-9]{16,}\b/g,

  // AWS access key id (AKIA / ASIA)
  awsAccessKeyId: /\bA(?:KI|SI)A[0-9A-Z]{16}\b/g,

  // GitHub tokens
  githubToken: /\bgh[pous]_[A-Za-z0-9]{20,}\b/g,

  // JWT (can have false positives; warn level)
  jwt: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,

  // US SSN basic constraints
  ssn: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,

  // CC candidates (validated with Luhn)
  ccCandidate: /\b(?:\d[ -]*?){13,19}\b/g,
};

function luhnOk(num: string): boolean {
  const digits = num.replace(/[^\d]/g, "");
  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

function scan(text: string): ScanResult {
  const findings: Finding[] = [];
  let redacted = text;

  const add = (id: string, label: string, severity: Severity, regex?: RegExp) => {
    findings.push({ id, label, severity });
    if (regex) redacted = redacted.replace(regex, `[REDACTED:${label}]`);
  };

  // BLOCK: very high signal
  if (RE.privateKeyBlock.test(text)) add("private_key", "PRIVATE_KEY", "BLOCK", RE.privateKeyBlock);
  if (RE.apiKeySk.test(text)) add("api_key", "API_KEY", "BLOCK", RE.apiKeySk);
  if (RE.awsAccessKeyId.test(text)) add("aws_key", "AWS_ACCESS_KEY", "BLOCK", RE.awsAccessKeyId);
  if (RE.githubToken.test(text)) add("gh_token", "GITHUB_TOKEN", "BLOCK", RE.githubToken);

  // WARN: moderate signal
  if (RE.ssn.test(text)) add("ssn", "SSN", "WARN", RE.ssn);

  // CC only if Luhn passes
  const ccMatches = text.match(RE.ccCandidate) || [];
  let ccHit = false;
  for (const m of ccMatches) {
    const digits = m.replace(/[^\d]/g, "");
    if (luhnOk(digits)) {
      ccHit = true;
      const esc = m.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      redacted = redacted.replace(new RegExp(esc, "g"), `[REDACTED:CREDIT_CARD]`);
    }
  }
  if (ccHit) findings.push({ id: "cc", label: "CREDIT_CARD", severity: "WARN" });

  if (RE.jwt.test(text)) add("jwt", "JWT", "WARN", RE.jwt);

  return { findings, redactedText: findings.length ? redacted : undefined };
}

// ---- UI: modal ----
function ensureModal(): HTMLDivElement {
  let modal = document.getElementById(MODAL_ID) as HTMLDivElement | null;
  if (modal) return modal;

  modal = document.createElement("div");
  modal.id = MODAL_ID;
  modal.style.cssText = `
    position: fixed; inset: 0; z-index: 2147483647;
    display: none; align-items: center; justify-content: center;
    background: rgba(0,0,0,0.35); font-family: ui-sans-serif, system-ui, -apple-system;
  `;

  modal.innerHTML = `
    <div style="
      width: min(560px, 92vw);
      background: white; border-radius: 14px;
      box-shadow: 0 16px 48px rgba(0,0,0,.25);
      padding: 16px 16px 12px 16px;
    ">
      <div style="display:flex; align-items:center; justify-content:space-between; gap:12px;">
        <div style="font-size:16px; font-weight:700;">LLM Privacy Guard: Potential sensitive data detected</div>
        <button data-x style="border:none; background:transparent; font-size:18px; cursor:pointer;">✕</button>
      </div>

      <div data-body style="margin-top:10px; font-size:13px; line-height:1.35; color:#111;"></div>

      <div style="margin-top:12px; display:flex; gap:8px; justify-content:flex-end; flex-wrap:wrap;">
        <button data-cancel style="padding:8px 10px; border-radius:10px; border:1px solid #ddd; background:#fff; cursor:pointer;">
          Cancel
        </button>
        <button data-redact style="padding:8px 10px; border-radius:10px; border:none; background:#111; color:#fff; cursor:pointer;">
          Redact & Continue
        </button>
        <button data-proceed style="padding:8px 10px; border-radius:10px; border:1px solid #ddd; background:#fff; cursor:pointer;">
          Proceed Anyway
        </button>
      </div>

      <div style="margin-top:10px; font-size:11px; color:#666;">
        Runs locally. No prompt content is stored or sent out.
      </div>
    </div>
  `;

  modal.addEventListener("click", (e) => {
    if (e.target === modal) hideModal();
  });

  document.documentElement.appendChild(modal);
  return modal;
}

let modalResolve: ((c: ModalChoice) => void) | null = null;

function hideModal() {
  const modal = document.getElementById(MODAL_ID) as HTMLDivElement | null;
  if (modal) modal.style.display = "none";
  modalOpen = false;
}

function showModal(findings: Finding[]): Promise<ModalChoice> {
  const modal = ensureModal();
  const body = modal.querySelector("[data-body]") as HTMLDivElement;

  const blocks = findings.filter((f) => f.severity === "BLOCK");
  const warns = findings.filter((f) => f.severity === "WARN");

  const mkList = (items: Finding[]) =>
    items.length
      ? `<ul style="margin:6px 0 0 18px;">${items.map((i) => `<li><b>${i.label}</b></li>`).join("")}</ul>`
      : "";

  body.innerHTML = `
    <div>
      ${blocks.length ? `<div style="color:#b00020; font-weight:700;">Blocked items:</div>${mkList(blocks)}` : ""}
      ${warns.length ? `<div style="margin-top:8px; color:#a15c00; font-weight:700;">Warnings:</div>${mkList(warns)}` : ""}
      <div style="margin-top:10px;">You can redact detected items before continuing.</div>
    </div>
  `;

  const btnX = modal.querySelector("[data-x]") as HTMLButtonElement;
  const btnCancel = modal.querySelector("[data-cancel]") as HTMLButtonElement;
  const btnRedact = modal.querySelector("[data-redact]") as HTMLButtonElement;
  const btnProceed = modal.querySelector("[data-proceed]") as HTMLButtonElement;

  const finish = (c: ModalChoice) => {
    hideModal();
    modalResolve?.(c);
    modalResolve = null;
  };

  btnX.onclick = () => finish("CANCEL");
  btnCancel.onclick = () => finish("CANCEL");
  btnRedact.onclick = () => finish("REDACT");
  btnProceed.onclick = () => finish("PROCEED");

  modalOpen = true;
  modal.style.display = "flex";

  return new Promise((resolve) => (modalResolve = resolve));
}

// ---- ChatGPT integration helpers ----
function findPromptElement(): HTMLTextAreaElement | HTMLDivElement | null {
  const promptTA =
    (document.querySelector("#prompt-textarea") as HTMLTextAreaElement | null) ??
    (document.querySelector('textarea[id*="prompt"]') as HTMLTextAreaElement | null) ??
    (document.querySelector("textarea") as HTMLTextAreaElement | null);

  if (promptTA) return promptTA;

  return document.querySelector('[contenteditable="true"]') as HTMLDivElement | null;
}

function getPromptText(el: HTMLTextAreaElement | HTMLDivElement): string {
  return el instanceof HTMLTextAreaElement ? el.value || "" : el.innerText || "";
}

// Use native setter so React-controlled textarea updates correctly
function setTextareaValueNative(el: HTMLTextAreaElement, value: string) {
  const proto = Object.getPrototypeOf(el);
  const desc = Object.getOwnPropertyDescriptor(proto, "value");
  const setter = desc?.set;
  if (setter) setter.call(el, value);
  else el.value = value;
}

function setPromptText(el: HTMLTextAreaElement | HTMLDivElement, text: string) {
  if (el instanceof HTMLTextAreaElement) {
    setTextareaValueNative(el, text);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    return;
  }
  el.innerText = text;
  el.dispatchEvent(new Event("input", { bubbles: true }));
}

function findSendButton(): HTMLButtonElement | null {
  return (
    (document.querySelector('button[data-testid="send-button"]') as HTMLButtonElement | null) ??
    (document.querySelector('button[aria-label*="Send"]') as HTMLButtonElement | null) ??
    null
  );
}

function clickSendButton(): boolean {
  const btn = findSendButton();
  if (!btn) return false;
  bypassOnce = true;
  btn.click();
  return true;
}

// ---- Guard core ----
async function guardAndMaybeRedact(trigger: "enter" | "click"): Promise<{ allow: boolean; hadFindings: boolean }> {
  // prevent re-entrancy / hung promises
  if (modalOpen) return { allow: false, hadFindings: true }; // keep as cancel while modal shown
  if (guardInFlight) return { allow: false, hadFindings: true };
  guardInFlight = true;

  try {
    if (bypassOnce) {
      bypassOnce = false;
      return { allow: true, hadFindings: false };
    }

    const promptEl = findPromptElement();
    if (!promptEl) return { allow: true, hadFindings: false };

    const text = getPromptText(promptEl).trim();
    if (!text) return { allow: true, hadFindings: false };

    const res = scan(text);

    // Useful debug; remove later if you want
    console.log("Guard invoked. trigger=", trigger, "len=", text.length, "findings=", res.findings.map(f => `${f.severity}:${f.label}`));

    if (!res.findings.length) return { allow: true, hadFindings: false };

    const choice = await showModal(res.findings);
    if (choice === "CANCEL") return { allow: false, hadFindings: true };

    if (choice === "REDACT" && res.redactedText) {
      setPromptText(promptEl, res.redactedText);
    }

    return { allow: true, hadFindings: true };
  } finally {
    guardInFlight = false;
  }
}

// ---- Event hooks ----
// Strategy:
// - For Enter: only intercept when findings exist. If allowed, send via clicking send button.
// - For click: intercept send button click when findings exist. If allowed, optionally redact then re-click programmatically.
// - Normal sends without findings are not affected.

function hookEnterKey() {
  document.addEventListener(
    "keydown",
    async (e) => {
      if (e.key !== "Enter") return;
      if (e.shiftKey) return;
      if (modalOpen) return;

      const promptEl = findPromptElement();
      if (!promptEl) return;

      const target = e.target as Element | null;
      const active = document.activeElement as Element | null;

      const inPrompt =
        active === promptEl ||
        target === promptEl ||
        (!!target?.closest && target.closest("#prompt-textarea") === promptEl) ||
        (!!active?.closest && active.closest("#prompt-textarea") === promptEl);

      if (!inPrompt) return;

      // ✅ CRITICAL: stop ChatGPT from sending BEFORE we show modal
      e.preventDefault();
      e.stopPropagation();

      const res = await guardAndMaybeRedact("enter");

      if (!res.allow) return; // Cancel or blocked by lock

      // If allowed (with or without findings), send ourselves
      if (clickSendButton()) return;

      // Fallback: dispatch Enter on prompt (less reliable)
      bypassOnce = true;
      const evt = new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true });
      (promptEl as any).dispatchEvent(evt);
    },
    true
  );
}

function hookSendClicks() {
  document.addEventListener(
    "click",
    async (e) => {
      if (modalOpen) return;

      const btn = (e.target as Element | null)?.closest("button") as HTMLButtonElement | null;
      if (!btn) return;

      const sendBtn = findSendButton();
      if (!sendBtn) return;

      // Only intercept the real send button
      if (btn !== sendBtn && !sendBtn.contains(btn) && !btn.contains(sendBtn)) return;

      // If this click was triggered by us, let it pass
      if (bypassOnce) {
        bypassOnce = false;
        return;
      }

      // ✅ CRITICAL: stop the real click BEFORE we show modal
      e.preventDefault();
      e.stopPropagation();

      const res = await guardAndMaybeRedact("click");
      if (!res.allow) return;

      // Re-click send once (or click the send button)
      bypassOnce = true;
      sendBtn.click();
    },
    true
  );
}

function init() {
  if ((window as any)[`${EXT_NS}_inited`]) return;
  (window as any)[`${EXT_NS}_inited`] = true;

  hookEnterKey();
  hookSendClicks();
}

init();