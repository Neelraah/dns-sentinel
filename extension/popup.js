const API = "http://127.0.0.1:8765";
const $ = (id) => document.getElementById(id);
chrome.runtime.sendMessage({type:"GET_TAB"}, (tab) => {
  $("site").textContent = tab?.hostname || "No website detected";
  $("url").textContent = tab?.url || "Browser internal page";
});
async function refresh() {
  try {
    const r = await fetch(`${API}/api/status`);
    if (!r.ok) throw new Error();
    const d = await r.json();
    $("serviceStatus").textContent = "Local agent connected";
    $("serviceStatus").classList.add("good");
    $("events").textContent = d.total_events;
    $("dns").textContent = d.dns_queries;
  } catch {
    $("serviceStatus").textContent = "Agent offline";
    $("events").textContent = "—"; $("dns").textContent = "—";
  }
}
$("dashboard").onclick = () => chrome.tabs.create({url:chrome.runtime.getURL("dashboard.html")});
$("diagnostics").onclick = async () => {
  $("feedback").textContent = "Running nslookup and curl checks…";
  try {
    const r = await fetch(`${API}/api/diagnostics`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain:$("site").textContent})});
    const d = await r.json();
    $("feedback").textContent = d.message || "Diagnostics completed.";
  } catch { $("feedback").textContent = "Start the local agent to run diagnostics."; }
};
refresh();