/*
 * DNS Sentinel — browser telemetry collector (Manifest V3)
 * Captures Chrome-visible HTTP(S) requests. Metadata only: no cookies,
 * request/response bodies, form fields, query strings or URL fragments.
 */
const API = "http://127.0.0.1:8765";
const EVENTS_ENDPOINT = `${API}/api/events`;
const QUEUE_KEY = "pendingEvents";
const MAX_QUEUE = 1000;
const FLUSH_ALARM = "dns-sentinel-flush";
const requestStartedAt = new Map();
let flushInProgress = false;

function isWebRequest(value) {
  try {
    const u = new URL(value);
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    if ((u.hostname === "127.0.0.1" || u.hostname === "localhost") && u.port === "8765") return false;
    return true;
  } catch { return false; }
}
function safePath(value) {
  try { return (new URL(value).pathname || "/").slice(0, 2048); }
  catch { return "/"; }
}
function makeEvent(d, outcome, extra = {}) {
  let u;
  try { u = new URL(d.url); } catch { return null; }
  const started = requestStartedAt.get(d.requestId);
  return {
    event_id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    source: "browser",
    hostname: u.hostname.toLowerCase(),
    path: safePath(d.url),
    scheme: u.protocol.slice(0, -1),
    method: String(d.method || "GET").slice(0, 16),
    type: String(d.type || "other").slice(0, 40),
    initiator: String(d.initiator || "").slice(0, 512),
    tab_id: Number.isInteger(d.tabId) ? d.tabId : -1,
    frame_id: Number.isInteger(d.frameId) ? d.frameId : -1,
    parent_frame_id: Number.isInteger(d.parentFrameId) ? d.parentFrameId : -1,
    request_id: String(d.requestId || "").slice(0, 128),
    outcome,
    severity: "info",
    ...(started ? { duration_ms: Math.max(0, Date.now() - started) } : {}),
    ...extra
  };
}
async function enqueue(event) {
  if (!event) return;
  try {
    const data = await chrome.storage.local.get(QUEUE_KEY);
    const q = Array.isArray(data[QUEUE_KEY]) ? data[QUEUE_KEY] : [];
    q.push(event);
    await chrome.storage.local.set({ [QUEUE_KEY]: q.slice(-MAX_QUEUE) });
  } catch (e) { console.warn("[DNS Sentinel] Queue write failed:", e); }
}
async function postEvent(event) {
  const r = await fetch(EVENTS_ENDPOINT, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(event), cache: "no-store"
  });
  if (!r.ok) throw new Error(`Agent HTTP ${r.status}`);
}
async function flushPending() {
  if (flushInProgress) return;
  flushInProgress = true;
  try {
    const data = await chrome.storage.local.get(QUEUE_KEY);
    const q = Array.isArray(data[QUEUE_KEY]) ? data[QUEUE_KEY] : [];
    let sent = 0;
    for (const event of q) {
      try { await postEvent(event); sent++; }
      catch { break; }
    }
    if (sent) {
      const latest = await chrome.storage.local.get(QUEUE_KEY);
      const latestQ = Array.isArray(latest[QUEUE_KEY]) ? latest[QUEUE_KEY] : [];
      await chrome.storage.local.set({ [QUEUE_KEY]: latestQ.slice(sent) });
    }
  } catch (e) { console.warn("[DNS Sentinel] Flush failed:", e); }
  finally { flushInProgress = false; }
}
function onBeforeRequest(d) {
  if (isWebRequest(d.url)) requestStartedAt.set(d.requestId, Date.now());
}
function onCompleted(d) {
  if (!isWebRequest(d.url)) return;
  const event = makeEvent(d, "completed", { status_code: Number.isInteger(d.statusCode) ? d.statusCode : 0 });
  requestStartedAt.delete(d.requestId);
  void enqueue(event).then(flushPending);
}
function onErrorOccurred(d) {
  if (!isWebRequest(d.url)) return;
  const event = makeEvent(d, "failed", { error: String(d.error || "Request failed").slice(0, 256) });
  requestStartedAt.delete(d.requestId);
  void enqueue(event).then(flushPending);
}

// Register listeners at service-worker top level.
chrome.webRequest.onBeforeRequest.addListener(onBeforeRequest, { urls: ["http://*/*", "https://*/*"] });
chrome.webRequest.onCompleted.addListener(onCompleted, { urls: ["http://*/*", "https://*/*"] });
chrome.webRequest.onErrorOccurred.addListener(onErrorOccurred, { urls: ["http://*/*", "https://*/*"] });

chrome.alarms.create(FLUSH_ALARM, { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener(a => { if (a.name === FLUSH_ALARM) void flushPending(); });
chrome.runtime.onStartup.addListener(() => void flushPending());
chrome.runtime.onInstalled.addListener(() => void flushPending());

// Preserve the existing popup's GET_TAB message contract.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "GET_TAB") {
    chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
      let parsed = {};
      try { parsed = new URL(tab?.url || ""); } catch (_) {}
      sendResponse({ url: tab?.url || "", hostname: parsed.hostname || "", title: tab?.title || "" });
    }).catch(() => sendResponse({ url: "", hostname: "", title: "" }));
    return true;
  }
  if (message?.type === "GET_TELEMETRY_STATUS") {
    chrome.storage.local.get(QUEUE_KEY).then(d => sendResponse({ queued: (d[QUEUE_KEY] || []).length }))
      .catch(() => sendResponse({ queued: 0 }));
    return true;
  }
});
