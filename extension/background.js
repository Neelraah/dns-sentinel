const API = "http://127.0.0.1:8765";
const suspiciousPatterns = [
  /\/wp-admin/i, /\/wp-login/i, /\.env(?:$|\?)/i, /\/phpmyadmin/i,
  /\/admin(?:\/|$)/i, /\.(?:exe|dll|ps1|bat)(?:$|\?)/i,
  /(?:\.\.\/){2,}/, /\/\.git(?:\/|$)/i
];

chrome.webRequest.onCompleted.addListener(async (details) => {
  if (!details.url.startsWith("http")) return;
  let url;
  try { url = new URL(details.url); } catch { return; }
  const hit = suspiciousPatterns.some((p) => p.test(url.pathname + url.search));
  if (!hit) return;
  const event = {
    timestamp: new Date().toISOString(),
    hostname: url.hostname,
    path: url.pathname,
    method: details.method,
    type: details.type,
    tabId: details.tabId,
    source: "browser-observer",
    severity: "medium"
  };
  try {
    await fetch(`${API}/api/events`, {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify(event)
    });
  } catch (_) {
    const { pendingEvents = [] } = await chrome.storage.local.get("pendingEvents");
    pendingEvents.push(event);
    await chrome.storage.local.set({pendingEvents: pendingEvents.slice(-100)});
  }
}, {urls: ["<all_urls>"]});

chrome.runtime.onStartup.addListener(flushPending);
chrome.runtime.onInstalled.addListener(flushPending);

async function flushPending() {
  const {pendingEvents = []} = await chrome.storage.local.get("pendingEvents");
  if (!pendingEvents.length) return;
  try {
    for (const event of pendingEvents) {
      await fetch(`${API}/api/events`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body:JSON.stringify(event)
      });
    }
    await chrome.storage.local.set({pendingEvents: []});
  } catch (_) {}
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_TAB") {
    chrome.tabs.query({active:true, currentWindow:true}).then(([tab]) => {
      let parsed = {};
      try { parsed = new URL(tab.url); } catch (_) {}
      sendResponse({url: tab.url || "", hostname: parsed.hostname || "", title: tab.title || ""});
    });
    return true;
  }
});