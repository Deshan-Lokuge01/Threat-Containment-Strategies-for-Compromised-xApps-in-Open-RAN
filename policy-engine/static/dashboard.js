/* ZTX_CPU_4_DECIMAL_UI_V2 */
/* ZTX_SCENARIO_TARGET_DEFAULT_FIX_V1 */
/* ZTX_FINAL_UI_BACKEND_TRUTH_V2 */

const ZTX_NS = "ricxapp";
const ZTX_REFRESH_MS = 3000;

const $ = (id) => document.getElementById(id);
const XAPPS = ["telemetry-monitor","qos-optimizer","traffic-analyzer","resource-optimizer","security-observer"];

function esc(v){return String(v??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;");}
function arr(v){return Array.isArray(v)?v:[];}
function obj(v){return v&&typeof v==="object"&&!Array.isArray(v)?v:{};}
function num(v){const n=Number(v);return Number.isFinite(n)?n:null;}
function setText(id,v){const el=$(id);if(el)el.textContent=v??0;}
function pill(t,c){return `<span class="pill ${c||"unknown"}">${esc(t)}</span>`;}
function stateClass(s){s=String(s||"NORMAL").toUpperCase();if(s==="NORMAL")return"healthy";if(s==="OBSERVED")return"observed";if(s==="SUSPICIOUS")return"degraded";if(s==="COMPROMISED")return"compromised";return"unknown";}
function score(v){const n=num(v);return n===null?"N/A":String(Math.round(n));}
function mem(r){const b=num(r?.memory_working_set_bytes??r?.memory_usage_bytes);return b===null?"N/A":`${(b/1024/1024).toFixed(1)} MiB`;}
function cpu(r){const v=num(r?.cpu_percent_1core??r?.cpu_percent_1core_2m);return v===null?"N/A":`${v.toFixed(1)}%`;}
async function apiJson(url,opts={}){const r=await fetch(url,opts);const t=await r.text();try{return JSON.parse(t);}catch{return{ok:false,status:r.status,body:t.slice(0,300)}}}

function hideSelfNav(){
  const path=location.pathname.toLowerCase();
  document.querySelectorAll("a,button").forEach(el=>{
    const text=String(el.textContent||"").trim().toLowerCase();
    if((path==="/"||path.includes("dashboard"))&&text==="runtime dashboard")el.style.display="none";
    if((path.includes("scenario")||path.includes("attack")||path.includes("evaluation"))&&(text==="attack simulation"||text==="scenario + evaluation"))el.style.display="none";
  });
}

let busy=false,lastRows="";
function bodyEl(){return $("runtimeTableBody")||$("runtimeBody")||document.querySelector("#runtimeTable tbody")||document.querySelector("table tbody");}

function mergeRows(statePayload,runtimePayload){
  const m={}; arr(statePayload?.xapps).forEach(x=>{if(x?.xapp)m[x.xapp]=x;});
  return arr(runtimePayload?.rows).map(r=>({runtime:r,state:m[r.xapp]||{}}));
}

function renderSummary(p){
  const s=obj(p?.summary);
  setText("trustedCount",s.NORMAL??s.TRUSTED??0);
  setText("normalCount",s.NORMAL??s.TRUSTED??0);
  setText("observedCount",s.OBSERVED??0);
  setText("suspiciousCount",s.SUSPICIOUS??0);
  setText("compromisedCount",s.COMPROMISED??0);
  setText("quarantinedCount",0);
  const overall=String(p?.overall_state||"NORMAL").toUpperCase();
  setText("overallState",overall);
  const el=$("overallState"); if(el)el.className=`overall ${stateClass(overall)}`;
}

function renderRows(rows){
  const tb=bodyEl(); if(!tb)return;
  if(!rows.length){if(!lastRows)tb.innerHTML=`<tr><td colspan="11">Waiting for runtime data...</td></tr>`;return;}

  const html=rows.map(({runtime,state})=>{
    const r=obj(runtime), s=obj(state), pod=obj(r.pod), svc=obj(r.service), res=obj(r.resources), c=obj(r.containment);
    const xapp=r.xapp||"unknown";
    const st=String(s.state||r.trust_state||"NORMAL").toUpperCase();
    const endpointCount=svc.endpoint_count??"N/A";
    const contained=Boolean(c.contained===true||c.service_isolated===true||num(endpointCount)===0||svc.has_endpoints===false);
    const podName=pod.name||"N/A";
    const ready=pod.ready_text||(pod.ready?"1/1":"0/1");

    return `<tr>
	<td><strong>${esc(xapp)}</strong></td>
        <td>${pill(st, stateClass(st))}</td>
        <td>${score(s.risk_score)}</td>
        <td>${score(s.trust_score)}</td>
        <td>${cpu(res)}</td>
        <td>${mem(res)}</td>
        <td class="mono">${esc(podName)}</td>
        <td>${pill(ready, pod.ready ? "healthy" : "bad")}</td>
        <td>${pill(endpointCount, num(endpointCount) === 0 ? "bad" : "healthy")}</td>
        <td>${contained ? pill("YES", "compromised") : pill("NO", "healthy")}</td>
        <td>
          <button class="btn secondary" style="padding:4px 10px;font-size:.75rem" 
            onclick="window.location.href='/analyze?xapp=${encodeURIComponent(xapp)}&pod=${encodeURIComponent(podName)}'">
            Analyze
          </button>
        </td>
    </tr>`;
  }).join("");

  lastRows=html; tb.innerHTML=html;
  const up=$("updatedAt")||$("runtimeUpdatedAt")||$("lastUpdated"); if(up)up.textContent="Updated "+new Date().toLocaleTimeString();
}

function barHtml(pct,color,label){
  const p=Math.max(0,Math.min(100,pct));
  return `<div class="bar-track"><div class="bar-fill" style="width:${p}%;background:${color}"></div></div>${label?`<div class="bar-label">${label}</div>`:""}`;
}

function gateBadge(flag,onLabel,offLabel){
  if(flag===null||flag===undefined)return `<span class="badge">n/a</span>`;
  return flag?`<span class="badge gate-on">${esc(onLabel)}</span>`:`<span class="badge gate-off">${esc(offLabel)}</span>`;
}

function renderT2(t2){
  const body=$("t2Body"); if(!body)return;
  t2=obj(t2);
  if(!t2.available){
    body.innerHTML=`<div class="empty">T2 state unavailable - ztx_t2_collector.py may not be running, or this pod's /var/lib/ztx-t2-state mount is missing.${t2.error?` (${esc(t2.error)})`:""}</div>`;
    return;
  }

  const ready=t2.ready;
  const scoreVal=num(t2.t2_pressure_score);
  const wl=num(t2.warning_limit), ucl=num(t2.upper_limit);
  const confirmed=t2.confirmed_upper_6of8, cpuGate=t2.cpu_gate_hit;
  const publicState=String(t2.public_state||"NORMAL").toUpperCase();
  let policyState="NORMAL",pClass="healthy";
  if(publicState==="SUSPICIOUS"){policyState="COMPROMISED";pClass="compromised";}
  else if(wl!==null&&scoreVal!==null&&scoreVal>wl){policyState="SUSPICIOUS";pClass="degraded";}

  let scoreHtml;
  if(!ready){
    scoreHtml=`<div class="small-muted">Warming up - ${esc(t2.sample_quality||"?")} (elapsed ${num(t2.elapsed_s)?.toFixed(0)??"?"}s). The frozen model needs a full 30s memory-slope window + MEWMA warmup before scoring starts; this is a real requirement of the multivariate statistic, not a stall.</div>`;
  }else if(scoreVal===null){
    scoreHtml=`<div class="small-muted">No score yet.</div>`;
  }else{
    const pct=ucl?(scoreVal/ucl)*100:0;
    const color=pClass==="compromised"?"var(--red)":pClass==="degraded"?"var(--yellow)":"var(--green)";
    scoreHtml=`
      <div class="t2-score-row">
        <div class="t2-score-num" style="color:${color}">${scoreVal.toFixed(3)}</div>
        ${pill(policyState,pClass)}
        <span class="small-muted">raw model verdict: ${esc(publicState)}</span>
      </div>
      ${barHtml(pct,color)}
      <div class="card-row"><span>WL ${wl!==null?wl.toFixed(3):"N/A"}</span><span>UCL ${ucl!==null?ucl.toFixed(3):"N/A"}</span></div>
      <div class="t2-gates">
        ${gateBadge(confirmed,"6-of-8 CONFIRMED","6-of-8 not yet")}
        ${gateBadge(cpuGate,"CPU GATE HIT","CPU gate: below rate")}
      </div>`;
  }

  const remaining=num(t2.isolation_dwell_seconds_remaining);
  const throttled=t2.throttled===true;
  let dwellHtml="";
  if(throttled||remaining!==null){
    let inner="";
    if(throttled){
      inner+=`<div class="card-row"><span class="badge gate-on">CPU THROTTLE ACTIVE</span><span class="small-muted">immediate, cgroup-level - no dwell</span></div>`;
    }
    if(remaining===null){
      inner+=`<div class="small-muted">dwell: n/a (isolated, or awaiting next poll)</div>`;
    }else{
      const total=num(t2.dwell_seconds_total)||30;
      const elapsed=Math.max(0,total-remaining);
      const pct=total?(elapsed/total)*100:0;
      const color=remaining<=5?"var(--red)":"var(--yellow)";
      inner+=`
        <div class="card-row"><span>dwell elapsed ${elapsed.toFixed(1)}s / ${total.toFixed(0)}s</span><span style="color:${color};font-weight:800">isolates in ${remaining.toFixed(1)}s</span></div>
        ${barHtml(pct,color)}`;
    }
    dwellHtml=`<div class="t2-dwell"><div class="label">Isolation dwell (COMPROMISED &rarr; ISOLATED, 30s policy window)</div>${inner}</div>`;
  }else{
    dwellHtml=`<div class="t2-dwell"><div class="small-muted">No pending dwell - xapp not currently COMPROMISED.</div></div>`;
  }

  body.innerHTML=scoreHtml+dwellHtml;
  const up=$("t2Updated"); if(up)up.textContent="Updated "+new Date().toLocaleTimeString()+(t2.time?` (collector: ${t2.time})`:"");
}

async function refreshDashboard(){
  if(busy)return; busy=true;
  try{
    const [s,r,t2]=await Promise.all([apiJson("/csm/state"),apiJson(`/csm/xapps/runtime-lite?namespace=${encodeURIComponent(ZTX_NS)}`),apiJson("/csm/t2/state")]);
    renderSummary(s); renderRows(mergeRows(s,r)); renderT2(t2);
  }finally{busy=false;}
}

async function primeNormal(){
  await Promise.allSettled(XAPPS.map(xapp=>apiJson("/csm/intent/ingest",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({xapp,signal:"clean_baseline",source:"dashboard_prime_normal"})})));
  await refreshDashboard();
}

/* Scenario console */
function scenarioGrid(){return $("scenarioGrid");}
function scenarioBox(){return $("scenarioBox");}
function evaluationBox(){return $("evaluationBox");}
function recentResults(){return $("recentResults");}
function xappSelect(){return $("xappSelect");}
function containmentBox(){return $("containmentBox");}

function scenarioList(p){return Array.isArray(p)?p:arr(p?.scenarios);}
function sid(s){return s.id||s.scenario_id||s.name||"unknown";}

function renderScenarios(list){
  const g=scenarioGrid(); if(!g)return;
  if(!list.length){g.innerHTML=`<div class="empty">No scenarios returned from API.</div>`;return;}
  g.innerHTML=list.map(s=>{
    const id=sid(s), target=s.target_xapp||s.default_xapp||"telemetry-monitor";
    return `<div class="scenario-card">
      <div class="scenario-meta">${esc(s.category||(s.malicious?"attack":"benign_control"))}</div>
      <h3>${esc(id)} — ${esc(s.name||s.title||id)}</h3>
      <p>${esc(s.description||"")}</p>
      <div class="small-muted">Default target: <b>${esc(target)}</b></div>
      <button class="btn run-scenario-btn" data-scenario-id="${esc(id)}" data-xapp="${esc(target)}">Run Scenario</button>
    </div>`;
  }).join("");
}

function renderEval(s){
  s=obj(s);
  setText("tpCount",s.TP??0); setText("tnCount",s.TN??0); setText("fpCount",s.FP??0); setText("fnCount",s.FN??0); setText("totalRuns",s.total_runs??0);
  const box=evaluationBox(); if(box)box.textContent=JSON.stringify(s,null,2);
  const rr=recentResults(); if(rr){
    const results=arr(s.recent_results);
    rr.innerHTML=results.length?results.map(r=>`<div class="event-card">${pill(r.classification||"RESULT",r.pass?"healthy":"bad")} <b>${esc(r.scenario_id||"")}</b> ${esc(r.xapp||"")} ${esc(r.actual_state||"")} containment=${esc(r.actual_containment)}</div>`).join(""):`<div class="empty">No scenario results yet.</div>`;
  }
}

async function refreshScenario(){
  const g=scenarioGrid(); if(g)g.innerHTML=`<div class="empty">Loading scenarios...</div>`;
  const [sc,ev]=await Promise.all([apiJson("/csm/scenarios"),apiJson("/csm/evaluation/summary")]);
  renderScenarios(scenarioList(sc)); renderEval(ev);
  const sel=xappSelect(); if(sel&&!sel.options.length)sel.innerHTML=XAPPS.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join("");
}

async function runScenario(id,def,btn){
  const target=def||xappSelect()?.value||"telemetry-monitor";
  if(btn){btn.disabled=true;btn.textContent="Running...";}
  const res=await apiJson(`/csm/scenarios/${encodeURIComponent(id)}/run`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({xapp:target,target_xapp:target,namespace:ZTX_NS})});
  const box=scenarioBox(); if(box)box.textContent=JSON.stringify(res,null,2);
  await refreshScenario();
  if(btn){btn.disabled=false;btn.textContent="Run Scenario";}
}

document.addEventListener("click",ev=>{
  const rb=ev.target.closest(".run-scenario-btn");
  if(rb){ev.preventDefault();runScenario(rb.dataset.scenarioId,rb.dataset.xapp,rb);return;}
  const id=ev.target?.id;
  if(id==="refreshBtn"){ev.preventDefault();scenarioGrid()?refreshScenario():refreshDashboard();}
  if(id==="primeAuditBtn"){ev.preventDefault();scenarioGrid()?primeNormal().then(refreshScenario):primeNormal();}
  if(id==="clearEvalBtn"){ev.preventDefault();apiJson("/csm/evaluation/clear",{method:"POST"}).then(refreshScenario);}
  if(id==="verifyBtn"){ev.preventDefault();apiJson("/csm/containment/verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({xapp:xappSelect()?.value||"telemetry-monitor",namespace:ZTX_NS})}).then(r=>{const b=containmentBox();if(b)b.textContent=JSON.stringify(r,null,2);});}
  if(id==="restoreBtn"){ev.preventDefault();apiJson("/csm/containment/restore",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({xapp:xappSelect()?.value||"telemetry-monitor",namespace:ZTX_NS})}).then(r=>{const b=containmentBox();if(b)b.textContent=JSON.stringify(r,null,2);refreshScenario();});}
});

document.addEventListener("DOMContentLoaded",()=>{
  hideSelfNav();
  const page=String(document.body?.dataset?.page||"").toLowerCase();
  const path=location.pathname.toLowerCase();
  if(page.includes("scenario")||path.includes("scenario")||path.includes("attack")||scenarioGrid()){refreshScenario();return;}
  if(path==="/"||path.includes("dashboard")){refreshDashboard();setInterval(refreshDashboard,ZTX_REFRESH_MS);}
});
