const API="http://127.0.0.1:8765"; const $=id=>document.getElementById(id);
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function classify(e){const p=(e.path||"").toLowerCase();if(/login|admin|wp-admin/.test(p))return "Credential probing";if(/\.env|\.git|phpmyadmin/.test(p))return "Sensitive file discovery";if(/\.(exe|dll|ps1|bat)/.test(p))return "Malware path probe";if(/\.\.\//.test(p))return "Path traversal probe";return e.category||"Unclassified";}
function severity(e){return e.severity||(classify(e)!=="Unclassified"?"medium":"low");}
async function load(){
 try{
  const [s,e]=await Promise.all([fetch(API+"/api/status"),fetch(API+"/api/events")]);
  if(!s.ok||!e.ok)throw Error(); const status=await s.json(),data=await e.json(),events=data.events||[];
  $("agentLabel").textContent="Agent connected";$("protection").textContent="Monitoring active";$("protectionText").textContent="Local telemetry service is responding. DNS sinkhole state is reported separately.";
  $("total").textContent=status.total_events;$("ips").textContent=status.unique_ips;$("queries").textContent=status.dns_queries;$("high").textContent=status.high_signal;
  $("eventRows").innerHTML=events.slice(-30).reverse().map(x=>`<tr><td>${esc(new Date(x.timestamp).toLocaleTimeString())}</td><td><b>${esc(x.hostname||x.ip||"Local client")}</b><small>${esc(x.source||"honeypot")}</small></td><td>${esc((x.method||"DNS")+" "+(x.path||x.domain||"—"))}</td><td>${esc(classify(x))}</td><td><span class="severity ${esc(severity(x))}">${esc(severity(x).toUpperCase())}</span></td></tr>`).join("")||'<tr><td colspan="5" class="empty">No events captured yet. Use the test command in README to generate safe sample traffic.</td></tr>';
  renderCharts(events);
 }catch{$("agentLabel").textContent="Agent offline";$("protection").textContent="Local agent unavailable";$("protectionText").textContent="Start the Python service and refresh this page."; }
}
function renderCharts(events){
 const counts=Array(12).fill(0);events.forEach(e=>{const h=new Date(e.timestamp).getHours();counts[Math.floor(h/2)]++});
 const max=Math.max(1,...counts);$("timeline").innerHTML=counts.map((n,i)=>`<div class="bar-col"><div class="bar-value">${n||""}</div><div class="bar" style="height:${Math.max(3,n/max*100)}%"></div><small>${String(i*2).padStart(2,"0")}</small></div>`).join("");
 const cats={};events.forEach(e=>{const c=classify(e);cats[c]=(cats[c]||0)+1});
 $("categories").innerHTML=Object.entries(cats).sort((a,b)=>b[1]-a[1]).slice(0,6).map(([k,v])=>`<div class="category"><span>${esc(k)}</span><b>${v}</b></div>`).join("")||'<div class="empty">Waiting for events</div>';
}
$("refresh").onclick=load;setInterval(load,5000);load();
$("runDiag").onclick=async()=>{const domain=$("domainInput").value.trim();$("diagOutput").textContent="Running diagnostics…";try{const r=await fetch(API+"/api/diagnostics",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain})});const d=await r.json();$("diagOutput").textContent=d.output||d.message||"No output";}catch{$("diagOutput").textContent="Cannot reach local agent. Start it with: python app.py";}};