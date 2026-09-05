/* ZT-XGuard SOC dashboard — live. States from /trust-state (1s), metrics from
   /csm/xapps/metrics (1s), RAN/E2 from /csm/ran/status (3s). Attacks are launched
   from the external attack console (:30520). */
(function(){
"use strict";
/* force fresh polls — server sends no cache-control, so browsers cache GETs */
var NO={cache:'no-store',headers:{'Cache-Control':'no-cache'}};
function nc(){return (('/x').indexOf('?')>=0?'&':'?')+'_='+Date.now();}

var NODES=[
  {id:'falco',label:'falco',cat:'ctrl',hx:0.15,hy:0.145},{id:'policy-engine',label:'policy-engine',cat:'ctrl',hx:0.40,hy:0.145},
  {id:'canal',label:'canal',cat:'ctrl',hx:0.63,hy:0.145},{id:'spire',label:'spire-server',cat:'ctrl',hx:0.86,hy:0.145},
  {id:'ricxapp-kpimon-go',label:'kpimon-go',cat:'xapp',hx:0.18,hy:0.35},{id:'ricxapp-trafficxapp',label:'trafficxapp',cat:'xapp',hx:0.42,hy:0.35},
  {id:'ricxapp-hw-go',label:'hw-go',cat:'xapp',hx:0.64,hy:0.35},{id:'ricxapp-hw-python',label:'hw-python',cat:'xapp',hx:0.85,hy:0.35},
  {id:'e2term',label:'e2term',cat:'ricplt',hx:0.09,hy:0.56},{id:'e2mgr',label:'e2mgr',cat:'ricplt',hx:0.245,hy:0.56},
  {id:'submgr',label:'submgr',cat:'ricplt',hx:0.40,hy:0.56},{id:'rtmgr',label:'rtmgr',cat:'ricplt',hx:0.555,hy:0.56},
  {id:'appmgr',label:'appmgr',cat:'ricplt',hx:0.71,hy:0.56},{id:'a1mediator',label:'a1mediator',cat:'ricplt',hx:0.87,hy:0.56},
  {id:'dbaas',label:'dbaas · SDL',cat:'ricplt',hx:0.40,hy:0.74},{id:'influxdb',label:'influxdb',cat:'ricplt',hx:0.555,hy:0.74},
  {id:'vespamgr',label:'vespamgr',cat:'ricplt',hx:0.71,hy:0.74},{id:'alarmmanager',label:'alarmmanager',cat:'ricplt',hx:0.87,hy:0.74},
  {id:'o1mediator',label:'o1mediator',cat:'ricplt',hx:0.245,hy:0.74},
  {id:'gnb',label:'gNB',cat:'ran',tag:'E2 node',hx:0.15,hy:0.80},{id:'open5gs',label:'open5GS · 5GC',cat:'ran',tag:'core',hx:0.055,hy:0.905},{id:'ue',label:'UE',cat:'ran',tag:'sim',hx:0.25,hy:0.905}
];
var XAPP_IDS=NODES.filter(function(n){return n.cat==='xapp';}).map(function(n){return n.id;});
var RAN_IDS=['ue','gnb','open5gs'];
var byId={}; NODES.forEach(function(n){byId[n.id]=n;});
var CONNS={
  'ricxapp-kpimon-go':[['submgr','E2 sub · RIC_SUB_REQ/RESP'],['e2term','RIC_INDICATION'],['rtmgr','RMR routing'],['dbaas','SDL'],['influxdb','KPI write'],['appmgr','lifecycle']],
  'ricxapp-trafficxapp':[['a1mediator','A1 policy · 20008'],['rtmgr','RMR · TS_*'],['dbaas','SDL'],['appmgr','lifecycle']],
  'ricxapp-hw-go':[['submgr','E2 sub'],['e2term','RIC_INDICATION'],['rtmgr','RMR'],['a1mediator','A1 · type 1'],['dbaas','SDL'],['appmgr','lifecycle']],
  'ricxapp-hw-python':[['submgr','E2 sub'],['e2term','RIC_INDICATION'],['rtmgr','RMR'],['a1mediator','A1 · type 1'],['dbaas','SDL'],['appmgr','lifecycle']]
};
var ZT=['falco','policy-engine','canal','spire'];
var DATA_EDGES=[]; XAPP_IDS.forEach(function(x){CONNS[x].forEach(function(c){DATA_EDGES.push([x,c[0]]);});});
var BACKBONE=[['e2term','e2mgr'],['e2mgr','rtmgr'],['e2term','submgr'],['submgr','rtmgr'],['a1mediator','rtmgr'],['appmgr','rtmgr'],['appmgr','dbaas'],['rtmgr','dbaas'],['vespamgr','influxdb'],['alarmmanager','vespamgr'],['o1mediator','appmgr']];
var CTRL_EDGES=[['falco','policy-engine'],['policy-engine','canal'],['policy-engine','spire']];
var ZT_EDGES=[]; XAPP_IDS.forEach(function(x){ZT.forEach(function(s){ZT_EDGES.push([s,x]);});});
var RAN_EDGES=[['gnb','e2term'],['ue','gnb'],['open5gs','gnb']];  // E2 / Uu / N2

var STATE={}; XAPP_IDS.forEach(function(id){STATE[id]={state:'NORMAL'};});
var selected='ricxapp-kpimon-go', focusId=null, ranUp=false, incidentActive=false;
var ueUp=false, RANPREV={}, XPREV={};   // live-animation transition tracking
var ranFirst=true, stateFirst=true, PULSE_PREV={svid:{},kpm:null};
var XVISISO={};                          // per-xApp VISUAL isolation (corner+sever), decoupled from logical state so signals play first
/* Attack-Console-anchored detection timing. When an attack is launched from
   the console we record the launch instant (ATK_LAUNCH). When that xApp is first
   declared COMPROMISED we freeze the real launch->compromised latency (ATK_DET)
   and the compromised instant (ATK_COMPR_AT, used to guarantee ISOLATED is never
   displayed before the real 30s dwell elapses). Persisted so a page reload during
   the ~1min detection window doesn't lose the measurement. */
var ATK_LAUNCH={}, ATK_DET={}, ATK_COMPR_AT={};
try{ATK_LAUNCH=JSON.parse(localStorage.getItem('ztx_atk_launch')||'{}')||{};}catch(e){}
try{ATK_DET=JSON.parse(localStorage.getItem('ztx_atk_det')||'{}')||{};}catch(e){}
try{ATK_COMPR_AT=JSON.parse(localStorage.getItem('ztx_atk_compr')||'{}')||{};}catch(e){}
function atkTimeSave(){try{localStorage.setItem('ztx_atk_launch',JSON.stringify(ATK_LAUNCH));localStorage.setItem('ztx_atk_det',JSON.stringify(ATK_DET));localStorage.setItem('ztx_atk_compr',JSON.stringify(ATK_COMPR_AT));}catch(e){}}
var ZTX_DWELL_MS=30000;                   // matches backend DWELL_SECONDS=30.0 (resource attacks)
XAPP_IDS.forEach(function(id){XVISISO[id]=false;});

var stage=document.getElementById('stage'), nodesEl=document.getElementById('nodes'), edgeG=document.getElementById('edgeG');
var P={},dom={},W=1,H=1;
function sizeStage(){var w=stage.clientWidth,h=stage.clientHeight;if(w>4&&h>4){W=w;H=h;}}   // ignore zero reads while the stage is hidden (prevents pod lump-in-corner on view switch)
function home(n){var iso=!!XVISISO[n.id];var hy=iso?0.35:n.hy;if(n.cat==='ran'&&incidentActive)hy-=0.17;return {x:(iso?n.qx:n.hx)*W,y:hy*H};}
function initP(){NODES.forEach(function(n){n.qx=n.hx<0.5?0.05:0.95;n._hx=n.hx;n._hy=n.hy;P[n.id]={x:n.hx*W,y:n.hy*H,vx:0,vy:0,fx:null,fy:null};});}
function resetLayout(){NODES.forEach(function(n){n.hx=n._hx;n.hy=n._hy;P[n.id].fx=null;P[n.id].fy=null;});}
function hs(a,b){var s=0,x=a+b;for(var i=0;i<x.length;i++)s=(s*31+x.charCodeAt(i))&0xffff;return s%7-3;}
function ePath(a,b,c){var A=P[a],B=P[b];var mx=(A.x+B.x)/2,my=(A.y+B.y)/2;var dx=B.x-A.x,dy=B.y-A.y;var L=Math.sqrt(dx*dx+dy*dy)||1;var o=c*L;return 'M'+A.x+' '+A.y+' Q'+(mx-dy/L*o)+' '+(my+dx/L*o)+' '+B.x+' '+B.y;}

function buildTopo(){
  function mk(cls,a,b,t,c){var p=document.createElementNS('http://www.w3.org/2000/svg','path');p.setAttribute('class',cls);p.dataset.a=a;p.dataset.b=b;if(t)p.dataset.type=t;p.dataset.c=c;edgeG.appendChild(p);}
  RAN_EDGES.forEach(function(e){mk('edge raninactive',e[0],e[1],'ran',0.03);mk('ranflow',e[0],e[1],'ranf',0.03);});
  BACKBONE.forEach(function(e){mk('edge backbone',e[0],e[1],'bb',hs(e[0],e[1])*0.03);});
  ZT_EDGES.forEach(function(e){mk('ztedge'+(e[0]==='spire'?' spire':''),e[0],e[1],'zt',hs(e[0],e[1])*0.05);});
  CTRL_EDGES.forEach(function(e){mk('ctrledge',e[0],e[1],'ctrl',hs(e[0],e[1])*0.06);});
  DATA_EDGES.forEach(function(e){var c=hs(e[0],e[1])*0.06;mk('edge',e[0],e[1],'data',c);mk('flow',e[0],e[1],'data',c);});
  XAPP_IDS.forEach(function(x){['canal','policy-engine','spire'].forEach(function(s){mk('enforce',s,x,'enforce',hs(s,x)*0.04);});});
  NODES.forEach(function(n){
    var el=document.createElement('div'); el.className='node '+n.cat; el.dataset.id=n.id; el.tabIndex=0;
    if(n.cat==='xapp') el.dataset.state='NORMAL';
    var h='<div class="disc"><div class="core"></div><div class="halo"></div>';
    if(n.cat==='xapp') h+='<svg class="lock" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="4" y="11" width="16" height="10" rx="2"></rect><path d="M8 11V8a4 4 0 0 1 8 0v3"></path></svg>';
    h+='</div><div class="name">'+n.label+'</div>'; if(n.tag) h+='<div class="tag">'+n.tag+'</div>';
    el.innerHTML=h; nodesEl.appendChild(el); dom[n.id]=el; drag(el,n.id);
    el.addEventListener('keydown',function(id){return function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();focusNode(id);}};}(n.id));
    if(n.cat==='xapp'){ el.addEventListener('dblclick',function(id){return function(e){e.preventDefault();e.stopPropagation();xdOpen(id);};}(n.id)); }
  });
  stage.addEventListener('pointerdown',function(e){if(e.target===stage||e.target.classList.contains('grid-bg'))clearFocus();});
}
var dId=null,dOff={x:0,y:0},moved=false;
function drag(el,id){
  el.addEventListener('pointerdown',function(e){e.stopPropagation();dId=id;moved=false;el.setPointerCapture(e.pointerId);el.classList.add('dragging');var r=stage.getBoundingClientRect();dOff.x=(e.clientX-r.left)-P[id].x;dOff.y=(e.clientY-r.top)-P[id].y;P[id].fx=P[id].x;P[id].fy=P[id].y;});
  el.addEventListener('pointermove',function(e){if(dId!==id)return;moved=true;var r=stage.getBoundingClientRect();P[id].fx=Math.max(24,Math.min(W-24,(e.clientX-r.left)-dOff.x));P[id].fy=Math.max(30,Math.min(H-24,(e.clientY-r.top)-dOff.y));});
  function end(){if(dId!==id)return;el.classList.remove('dragging');if(moved){byId[id].hx=P[id].fx/W;byId[id].hy=P[id].fy/H;}P[id].fx=null;P[id].fy=null;if(!moved)focusNode(id);dId=null;}
  el.addEventListener('pointerup',end); el.addEventListener('pointercancel',end);
}
function topoTick(){
  for(var i=0;i<NODES.length;i++)for(var j=i+1;j<NODES.length;j++){var a=NODES[i].id,b=NODES[j].id,pa=P[a],pb=P[b];var dx=pa.x-pb.x,dy=pa.y-pb.y,d2=dx*dx+dy*dy||1;var d=Math.sqrt(d2),f=Math.min(4000/d2,1.5),ux=dx/d,uy=dy/d;pa.vx+=ux*f;pa.vy+=uy*f;pb.vx-=ux*f;pb.vy-=uy*f;}
  NODES.forEach(function(n){var p=P[n.id],h=home(n);p.vx+=(h.x-p.x)*0.055;p.vy+=(h.y-p.y)*0.055;var no=0.30;if(STATE[n.id]){var s=STATE[n.id].state;if(s==='SUSPICIOUS')no=0.95;else if(s==='COMPROMISED')no=2.4;else if(s==='ISOLATED')no=0;}if(n.cat==='ran')no=ranUp?0.55:0.08;p.vx+=(Math.random()-.5)*no;p.vy+=(Math.random()-.5)*no;});
  NODES.forEach(function(n){var p=P[n.id];if(p.fx!=null){p.x=p.fx;p.y=p.fy;p.vx=0;p.vy=0;}else{p.vx*=0.8;p.vy*=0.8;p.x+=p.vx;p.y+=p.vy;p.x=Math.max(24,Math.min(W-24,p.x));p.y=Math.max(30,Math.min(H-22,p.y));}dom[n.id].style.left=p.x+'px';dom[n.id].style.top=p.y+'px';});
  edgeG.querySelectorAll('path').forEach(function(e){var A=P[e.dataset.a],B=P[e.dataset.b];if(A&&B)e.setAttribute('d',ePath(e.dataset.a,e.dataset.b,parseFloat(e.dataset.c)||0));});
  requestAnimationFrame(topoTick);
}
function applyEdges(id){var st=STATE[id].state; var vi=!!XVISISO[id];
  // edges only SEVER once the xApp is VISUALLY isolated (after the signal
  // animation); until then they stay red so the sequence reads correctly.
  edgeG.querySelectorAll('.edge[data-a="'+id+'"][data-type="data"]').forEach(function(e){e.classList.remove('suspicious','compromised','severing');
    if(vi)e.classList.add('severing');
    else if(st==='SUSPICIOUS')e.classList.add('suspicious');
    else if(st==='COMPROMISED'||st==='ISOLATED')e.classList.add('compromised');});
  edgeG.querySelectorAll('.ztedge[data-b="'+id+'"]').forEach(function(e){e.classList.toggle('severing',vi);});
  edgeG.querySelectorAll('.flow[data-a="'+id+'"]').forEach(function(f){f.style.opacity=(st==='NORMAL'&&!vi)?'':'0';f.style.stroke=st==='SUSPICIOUS'?'var(--suspicious)':(st==='COMPROMISED'||st==='ISOLATED')?'var(--compromised)':'var(--normal)';});
  if(focusId)focusEdges(focusId);
}
function enf(s,x,on){var e=edgeG.querySelector('.enforce[data-a="'+s+'"][data-b="'+x+'"]');if(e)e.classList.toggle('on',on);}
function ranEdge(a,b,on){
  edgeG.querySelectorAll('.edge[data-a="'+a+'"][data-b="'+b+'"][data-type="ran"]').forEach(function(e){e.classList.toggle('raninactive',!on);e.classList.toggle('ranactive',on);});
  edgeG.querySelectorAll('.ranflow[data-a="'+a+'"][data-b="'+b+'"]').forEach(function(e){e.classList.toggle('on',on);});
}
function setRan(d){ d=d||{}; ranUp=!!d.connected; ueUp=!!d.ue;
  var up={gnb:!!d.gnb, open5gs:!!d.core, ue:!!d.ue};
  // staged bring-up: on the down->up transition, light open5GS first, then
  // the gNB ~0.6s later, then flow open5GS->gNB and gNB->e2term end to end.
  var coreJustUp=(!ranFirst && !RANPREV.open5gs && up.open5gs);
  var gnbJustUp=(!ranFirst && !RANPREV.gnb && up.gnb);
  RAN_IDS.forEach(function(id){
    if(gnbJustUp && id==='gnb'){ setTimeout(function(){if(dom.gnb)dom.gnb.classList.toggle('up',up.gnb);},600); }
    else dom[id].classList.toggle('up',!!up[id]);
  });
  ranEdge('open5gs','gnb', !!d.core && !!d.gnb);   // N2/N3 core link
  ranEdge('gnb','e2term', !!d.e2);                 // E2 link to the RIC
  ranEdge('ue','gnb', !!d.ue);                     // Uu radio
  if(coreJustUp||gnbJustUp){
    setTimeout(function(){pulseEdgeAB('open5gs','gnb',1600);},350);
    setTimeout(function(){pulseEdgeAB('gnb','e2term',1600);lightNode('e2term',1600);},1150);
  }
  RANPREV={open5gs:up.open5gs,gnb:up.gnb,ue:up.ue,e2:!!d.e2}; ranFirst=false;
  renderRanCard(d);
  if(selected&&byId[selected].cat==='ran')renderChip();
}
function renderRanCard(d){
  d=d||{};
  var upmap={open5gs:!!d.core,gnb:!!d.gnb,e2:!!d.e2,ue:!!d.ue};
  var rows=[
    ['open5gs','5G Core · open5GS', d.core?'up':'offline'],
    ['gnb','gNB'+(d.gnb_name?' · '+String(d.gnb_name).slice(0,14):''), d.gnb?(d.status||'up'):'offline'],
    ['e2','E2 Link · SCTP→e2term', d.e2?'CONNECTED':'—'],
    ['ue','UE session', d.ue?'attached':'—']
  ];
  var h=''; rows.forEach(function(r){h+='<div class="ranrow'+(upmap[r[0]]?' up':'')+'"><span class="dot"></span><span class="rl">'+r[1]+'</span><span class="rv">'+r[2]+'</span></div>';});
  var el=document.getElementById('ranRows'); if(el)el.innerHTML=h;
  var pl=document.getElementById('ranPlmn'); if(pl)pl.textContent=d.plmn?('PLMN '+d.plmn):(d.connected?'live':'no gNB');
}
var ADJ={};NODES.forEach(function(n){ADJ[n.id]=new Set();});
DATA_EDGES.concat(ZT_EDGES,CTRL_EDGES,BACKBONE,RAN_EDGES).forEach(function(e){ADJ[e[0]].add(e[1]);ADJ[e[1]].add(e[0]);});
function focusEdges(id){edgeG.querySelectorAll('path').forEach(function(e){if(e.classList.contains('enforce'))return;var t=e.dataset.a===id||e.dataset.b===id;e.classList.toggle('dim',!t);e.classList.toggle('hot',t);});NODES.forEach(function(n){dom[n.id].classList.toggle('faded',!(n.id===id||ADJ[id].has(n.id)));});}
function clearFocus(){focusId=null;edgeG.querySelectorAll('path').forEach(function(e){e.classList.remove('dim','hot');});NODES.forEach(function(n){dom[n.id].classList.remove('faded');});}
function focusNode(id){focusId=id;selectNode(id);focusEdges(id);}

var CVAR={NORMAL:'--normal',SUSPICIOUS:'--suspicious',COMPROMISED:'--compromised',ISOLATED:'--isolated'};
function pub(s){s=(s||'NORMAL').toUpperCase();if(s==='QUARANTINED')return 'ISOLATED';if(['NORMAL','SUSPICIOUS','COMPROMISED','ISOLATED'].indexOf(s)<0)return 'NORMAL';return s;}
function setState(id,s){if(!STATE[id])return;s=pub(s);STATE[id].state=s;if(dom[id].dataset.state!==s){dom[id].dataset.state=s;applyEdges(id);}if(id===selected)renderChip();}
function selectNode(id){selected=id;document.querySelectorAll('.node').forEach(function(n){n.classList.remove('sel');});dom[id].classList.add('sel');window._focusSeries=(XAPP_IDS.indexOf(id)>=0)?id:null;syncLegendFocus();renderChip();}
function syncLegendFocus(){var fs=window._focusSeries;document.querySelectorAll('.chart-legend .cl').forEach(function(c){if(!fs){c.classList.remove('foc');c.classList.remove('off');}else{c.classList.toggle('foc',c.dataset.key===fs);c.classList.toggle('off',c.dataset.key!==fs);}});}
function clearFocusSeries(){window._focusSeries=null;syncLegendFocus();}
function renderChip(){var n=byId[selected];var isX=n.cat==='xapp';var ranu=(n.cat==='ran'&&dom[selected].classList.contains('up'));var st=isX?STATE[selected].state:(n.cat==='ran'?(ranu?'up':'offline'):'infra');var cv=isX?'var('+CVAR[st]+')':(ranu?'var(--ran)':'var(--muted)');
  document.getElementById('chipName').textContent=n.label;var sd=document.querySelector('.selchip .sd');sd.style.background=cv;sd.style.boxShadow=(isX||(n.cat==='ran'&&ranUp))?'0 0 8px '+cv:'none';
  document.getElementById('chipState').textContent=st;
  var m=METRICS[selected];
  document.getElementById('chipMetrics').textContent=(isX&&m)?('cpu '+Math.round(m.cpu_millicores)+'mC · mem '+Math.round(m.mem_mb)+'MB · rx '+Math.round(m.rx_kbps)+' tx '+Math.round(m.tx_kbps)+' KB/s'):(n.cat+' · '+ADJ[selected].size+' links');}
var RANK={NORMAL:0,SUSPICIOUS:1,COMPROMISED:2,ISOLATED:3};
function renderCounts(){var c={NORMAL:0,SUSPICIOUS:0,COMPROMISED:0,ISOLATED:0};XAPP_IDS.forEach(function(id){c[STATE[id].state]++;});
  for(var k in c)document.getElementById('cnt-'+k).textContent=c[k];
  var w='NORMAL';XAPP_IDS.forEach(function(id){if(RANK[STATE[id].state]>RANK[w])w=STATE[id].state;});
  var cv='var('+CVAR[w]+')';var o=document.getElementById('overall');o.querySelector('.dot').style.background=cv;o.querySelector('.dot').style.boxShadow='0 0 10px '+cv;
  document.getElementById('overallTxt').textContent=w==='NORMAL'?'All Normal':w.charAt(0)+w.slice(1).toLowerCase()+' active';
  var bm=document.getElementById('brandMark');bm.style.background=cv;bm.style.boxShadow='0 0 12px '+cv;}

/* charts — bright, thin-but-visible lines with glow */
var N=300;
var SERIES=[{key:'ricxapp-kpimon-go',label:'kpimon-go',color:'--x1'},{key:'ricxapp-trafficxapp',label:'trafficxapp',color:'--x2'},{key:'ricxapp-hw-go',label:'hw-go',color:'--x3'},{key:'ricxapp-hw-python',label:'hw-python',color:'--x4'}];
function cssv(v){return getComputedStyle(document.documentElement).getPropertyValue(v).trim();}
function Chart(canvasId,legId,unit){
  var cv=document.getElementById(canvasId),ctx=cv.getContext('2d');
  var buf={};SERIES.forEach(function(s){buf[s.key]=new Array(N).fill(0);});
  var on={};SERIES.forEach(function(s){on[s.key]=true;});
  var leg=document.getElementById(legId);
  SERIES.forEach(function(s){var d=document.createElement('div');d.className='cl';d.dataset.key=s.key;d.innerHTML='<i style="background:'+cssv(s.color)+'"></i>'+s.label;d.onclick=function(){selectNode(s.key);};leg.appendChild(d);});
  function resize(){var r=cv.getBoundingClientRect();if(r.width<2||r.height<2)return;var dpr=window.devicePixelRatio||1;cv.width=Math.max(1,r.width*dpr);cv.height=Math.max(1,r.height*dpr);ctx.setTransform(dpr,0,0,dpr,0,0);}
  function push(vals){SERIES.forEach(function(s){var a=buf[s.key];a.push(vals[s.key]||0);a.shift();});}
  function draw(){
    var r=cv.getBoundingClientRect();var w=r.width,h=r.height;if(w<2||h<2)return;ctx.clearRect(0,0,w,h);
    var fs=window._focusSeries;  // null => show all 4 xApps; set => only that xApp
    function vis(k){return fs?k===fs:true;}
    var mx=1;SERIES.forEach(function(s){if(vis(s.key))for(var i=0;i<N;i++)if(buf[s.key][i]>mx)mx=buf[s.key][i];});mx*=1.25;
    ctx.strokeStyle='rgba(129,140,248,.07)';ctx.lineWidth=1;ctx.beginPath();for(var g=1;g<4;g++){var y=h*g/4;ctx.moveTo(0,y);ctx.lineTo(w,y);}ctx.stroke();
    ctx.fillStyle=cssv('--faint');ctx.font='9px '+(cssv('--mono')||'monospace');ctx.textAlign='left';ctx.fillText(Math.round(mx)+' '+unit,4,11);
    SERIES.forEach(function(s){ if(!vis(s.key))return; var a=buf[s.key]; var col=cssv(s.color);
      ctx.strokeStyle=col; ctx.lineWidth=1.3; ctx.globalAlpha=1;
      ctx.beginPath();for(var i=0;i<N;i++){var x=i/(N-1)*w,y=h-(a[i]/mx)*(h-8)-4;i?ctx.lineTo(x,y):ctx.moveTo(x,y);}ctx.stroke();
      var lv=a[N-1],ly=h-(lv/mx)*(h-8)-4;ctx.fillStyle=col;ctx.beginPath();ctx.arc(w-2,ly,1.8,0,7);ctx.fill();
    });
  }
  window.addEventListener('resize',function(){resize();draw();});resize();
  return {push:push,draw:draw};
}
var chCpu,chMem,chRx,chTx;

/* metrics */
var METRICS={};
function pollMetrics(){
  fetch('/csm/xapps/metrics'+nc(),NO).then(function(r){return r.json();}).then(function(d){
    METRICS=d.metrics||{};
    var cpu={},mem={},rx={},tx={};
    XAPP_IDS.forEach(function(id){var m=METRICS[id]||{};cpu[id]=m.cpu_millicores||0;mem[id]=m.mem_mb||0;rx[id]=m.rx_kbps||0;tx[id]=m.tx_kbps||0;});
    chCpu.push(cpu);chMem.push(mem);chRx.push(rx);chTx.push(tx);renderChip();
  }).catch(function(){});
}
function drawAll(){chCpu.draw();chMem.draw();chRx.draw();chTx.draw();requestAnimationFrame(drawAll);}

/* containment latency — REAL per-mechanism ms from /csm/incident/timing */
var MECHS=[{k:'netpol',label:'Calico CNI Network Policy',tk:'netpol_ms'},{k:'svc',label:'Service Isolation',tk:'svc_ms'},{k:'ipt',label:'Node iptables Block',tk:'ipt_ms'},{k:'svid',label:'SVID Revoke',tk:'svid_revoke_ms'}];
var LAT_SCALE=6000;
function fmtMs(ms){return ms>=1000?(ms/1000).toFixed(2)+'s':Math.round(ms)+'ms';}
/* the four locks fire in PARALLEL — wall-clock containment = the SLOWEST mechanism
   (SVID revoke), not the sum. This is the real parallel-containment latency. */
function parallelMs(t){if(!t)return 0;var mx=0;MECHS.forEach(function(m){var v=t[m.tk];if(v!=null&&v>mx)mx=v;});return mx;}
function buildLat(){var c=document.getElementById('latList');c.innerHTML='';MECHS.forEach(function(m){var d=document.createElement('div');d.className='lrow pending';d.id='lat-'+m.k;d.innerHTML='<div class="lh"><span class="lname"><i></i>'+m.label+'</span><span class="lval">—</span></div><div class="lbar"><i style="width:0%"></i></div>';c.appendChild(d);});}
function updateLat(t){
  var lv=document.getElementById('latVerify');
  if(!t){MECHS.forEach(function(m){var d=document.getElementById('lat-'+m.k);d.className='lrow pending';d.querySelector('.lval').textContent='—';d.querySelector('.lbar i').style.width='0%';});document.getElementById('latFoot').textContent='no active containment · awaiting incident';if(lv)lv.textContent='';return;}
  var total=0;
  MECHS.forEach(function(m){var d=document.getElementById('lat-'+m.k);var ms=t[m.tk];
    if(ms!=null){d.className='lrow done';d.querySelector('.lval').textContent=fmtMs(ms);d.querySelector('.lbar i').style.width=Math.min(100,ms/LAT_SCALE*100)+'%';total+=ms;}
    else if(m.k==='svid' && t.svid_signal_ms!=null){   // full withdrawal still being confirmed at the SPIRE server
      d.className='lrow active';d.querySelector('.lval').textContent='withdrawing…';d.querySelector('.lbar i').style.width='35%';}
    else{d.className='lrow pending';d.querySelector('.lval').textContent='—';d.querySelector('.lbar i').style.width='0%';}
  });
  var tot=parallelMs(t)||total;
  document.getElementById('latFoot').textContent='Parallel Containment Orchestration · '+fmtMs(tot);
  if(lv)lv.textContent='';
}
/* detection latency widget — dual channel (Behaviour runtime, Resource runtime) */
function buildDet(){var c=document.getElementById('detRows');if(!c)return;c.innerHTML='<div class="detrow falco" id="det-falco"><span class="dl"><i></i>Behavior · runtime</span><span class="dv">idle</span></div><div class="detrow t2" id="det-t2"><span class="dl"><i></i>Resource · runtime</span><span class="dv">idle</span></div>';}
function _setDet(id,cls,d){
  var el=document.getElementById(id);if(!el)return;
  var level=(d&&d.level)||'idle';  // idle | suspicious(yellow) | compromised(red)
  el.className='detrow '+cls+(level==='suspicious'?' susp':level==='compromised'?' active':'');
  el.querySelector('.dv').textContent=(d&&d.ms!=null&&level!=='idle')?fmtMs(d.ms):'idle';
}
function updateDet(falco,t2){ _setDet('det-falco','falco',falco); _setDet('det-t2','t2',t2); }

/* incident flow overlay (bottom of topology, only when active) */
var PIPE=[['detect','Detect'],['decide','Decide'],['enforce','Contain'],['verify','Verify']];
var TECH={unexpected_shell:['Unexpected Shell','T1059'],sensitive_file_access:['Sensitive File Access','T1552'],serviceaccount_token_access:['SA Token Access','T1552.007'],external_egress:['External Egress','T1048'],svid_material_access:['SVID Material Access','T1552'],xapp_profile_or_config_tamper:['Config Tamper','T1565'],privileged_container_escape_attempt:['Container Escape','T1611'],resource_anomaly_t2:['Resource Abuse (T²)','T1499'],resource_anomaly_t2_elevated:['Resource Abuse (T²)','T1499']};
function buildPflow(){var c=document.getElementById('pflow');c.innerHTML='';PIPE.forEach(function(s,i){var d=document.createElement('div');d.className='pf';d.id='pf-'+s[0];d.innerHTML='<div class="pd">'+(i+1)+'</div><div class="pl">'+s[1]+'<span class="pms" id="pms-'+s[0]+'"></span></div><div class="pc"></div>';c.appendChild(d);});}
function setpms(id,ms){var e=document.getElementById('pms-'+id);if(e)e.textContent=(ms!=null&&ms>0)?(' '+fmtMs(ms)):'';}
/* the pipeline stages reveal SEQUENTIALLY (Detect -> Decide -> Contain -> Verify)
   the first time a given incident appears, each stamped with its real ms.
   Re-polls of the same incident don't re-animate. */
var INC_KEY=null, INC_SIG='', INC_TIMERS=[];
var INC_ORDER=['detect','decide','enforce','verify'];
function _incClearTimers(){INC_TIMERS.forEach(clearTimeout);INC_TIMERS=[];}
function _pfReset(){PIPE.forEach(function(s,i){var e=document.getElementById('pf-'+s[0]);if(!e)return;e.classList.remove('active','done');e.querySelector('.pd').textContent=i+1;var p=document.getElementById('pms-'+s[0]);if(p)p.textContent='';});}
function _pfDone(id){var e=document.getElementById('pf-'+id);if(e){e.classList.remove('active');e.classList.add('done');e.querySelector('.pd').textContent='✓';}}
function _pfActive(id){var e=document.getElementById('pf-'+id);if(e){e.classList.remove('done');e.classList.add('active');var i=INC_ORDER.indexOf(id);e.querySelector('.pd').textContent=(i+1);}}
function _pfPending(id){var e=document.getElementById('pf-'+id);if(e){e.classList.remove('active','done');var i=INC_ORDER.indexOf(id);e.querySelector('.pd').textContent=(i+1);}}
/* how far the pipeline has progressed — driven by REAL containment/verify timing,
   NOT just the ISOLATED state (T2 attacks contain while state is COMPROMISED). */
function _incApply(inc, done, active, animate){
  var ms={detect:inc.detect_ms,decide:inc.decision_ms,enforce:inc.contain_ms,verify:inc.verify_ms};
  for(var i=0;i<4;i++){ (function(i){
    var id=INC_ORDER[i];
    var fn=function(){ if(i<done){_pfDone(id);} else if(id===active){_pfActive(id);} else {_pfPending(id);} setpms(id, ms[id]); };
    if(animate){ INC_TIMERS.push(setTimeout(fn, i*700)); } else { fn(); }
  })(i); }
}
var INC_XAPP=null;
function incShow(inc){
  incidentActive=true; document.getElementById('incbar').classList.add('show');
  INC_XAPP=inc.xapp||null;
  var sev=document.getElementById('incSev');sev.textContent=inc.state;sev.classList.toggle('iso',inc.state==='ISOLATED');
  document.getElementById('incName').textContent=inc.name;
  document.getElementById('incMeta').textContent=inc.tech+' · '+inc.rule+' · '+inc.ts;
  var ib=document.getElementById('incIsolate');   // operator's manual override — offered while awaiting isolation
  if(ib){ if(inc.state==='COMPROMISED'){ ib.removeAttribute('hidden'); ib.disabled=false; } else { ib.setAttribute('hidden',''); } }
  var contained=(inc.contain_ms!=null)||inc.state==='ISOLATED';
  var verified =(inc.verify_ms!=null)||inc.state==='ISOLATED';
  var done=2+(contained?1:0)+(verified?1:0);            // detect+decide always done
  var active=!contained?'enforce':(!verified?'verify':null);
  var key=inc.name+'|'+inc.ts;
  // include the stamped latencies so the bar RE-RENDERS when real containment
  // timing lands a moment after isolation (was frozen on the first render before)
  var sig=key+'|'+done+'|'+active+'|'+(inc.detect_ms||'')+'|'+(inc.contain_ms||'')+'|'+(inc.verify_ms||'');
  if(sig===INC_SIG) return;                             // nothing changed
  var fresh=(key!==INC_KEY); INC_KEY=key; INC_SIG=sig;
  _incClearTimers(); if(fresh)_pfReset();
  _incApply(inc, done, active, fresh);                  // animate on a new incident; apply instantly on progress
}
function incHide(){incidentActive=false; INC_KEY=null; INC_SIG=''; _incClearTimers(); document.getElementById('incbar').classList.remove('show');}

/* ===== T2 dwell countdown (resource attacks) =====
   Resource incidents use the SAME bottom incident bar as behaviour attacks.
   The only extra element is a small 30->0 countdown pill in the map's top-left
   free space, shown ONLY during the COMPROMISED dwell window (before the
   automatic isolation). It disappears the moment the xApp is isolated. */
var DCNT={key:null,start:0,secs:30,timer:null};
function countTick(){
  var el=document.getElementById('dcNum'); if(!el)return;
  var left=Math.max(0,DCNT.secs-Math.floor((Date.now()-DCNT.start)/1000));
  el.textContent=left;
  var w=document.getElementById('dwellCount'); if(w)w.classList.toggle('urgent',left<=8);
}
function countShow(xapp,inc){
  var w=document.getElementById('dwellCount'); if(!w)return;
  if(inc.state!=='COMPROMISED'){ countHide(); return; }   // dwell only; gone once ISOLATED
  var key=xapp+'|'+inc.ts;
  if(key===DCNT.key) return;
  DCNT.key=key; DCNT.start=Date.now();
  document.getElementById('dcName').textContent=(byId[xapp]&&byId[xapp].label)||String(xapp).replace('ricxapp-','');
  w.removeAttribute('hidden'); w.classList.add('show');
  clearInterval(DCNT.timer); DCNT.timer=setInterval(countTick,500); countTick();
}
function countHide(){
  var w=document.getElementById('dwellCount'); if(!w)return;
  w.classList.remove('show','urgent'); w.setAttribute('hidden','');
  clearInterval(DCNT.timer); DCNT.timer=null; DCNT.key=null;
}
/* all live timestamps render in Sri Lanka time (Asia/Colombo) as HH:MM:SS */
function lkTime(d){try{return d.toLocaleTimeString('en-GB',{hour12:false,timeZone:'Asia/Colombo'});}catch(e){return d.toTimeString().slice(0,8);}}
function shortTs(t){if(t==null||t==='')return '—';var d=new Date(t);if(!isNaN(d.getTime()))return lkTime(d);var m=(''+t).match(/T(\d{2}:\d{2}:\d{2})/);return m?m[1]:(''+t).slice(0,8);}
/* REAL T² (resource) detection latency. The statistical detector accumulates
   evidence across many samples (MEWMA + 6-of-8 corroboration), so its meaningful
   detection time is the wall-clock from the FIRST resource anomaly (SUSPICIOUS) to
   CONFIRMATION (COMPROMISED) — seconds — NOT the per-event ms processing time.
   Computed live from real event timestamps; returns null if it cannot be measured
   (caller then keeps the real per-event ms — never a hardcoded value). */
function t2DetectMs(events){
  // collect T² events, time-sorted oldest->newest
  var t2=[];
  (events||[]).forEach(function(e){
    if(!e||!e.time)return;
    var isT2=(''+(e.source||'')).indexOf('t2')>=0||(''+(e.signal||'')).indexOf('resource_anomaly')>=0;
    if(!isT2)return;
    var tt=new Date(e.time).getTime(); if(isNaN(tt))return;
    t2.push({t:tt,st:pub(e.state)||''});
  });
  if(!t2.length)return null;
  t2.sort(function(a,b){return a.t-b.t;});
  // confirmation = the MOST RECENT COMPROMISED (the current episode's confirmation)
  var confIdx=-1; for(var i=t2.length-1;i>=0;i--){ if(t2[i].st==='COMPROMISED'){confIdx=i;break;} }
  if(confIdx<0)return null;
  // walk back through CONTIGUOUS anomaly samples (gap<=45s) to this episode's onset,
  // so older, separate anomaly episodes don't inflate the latency
  var GAP=45000, confT=t2[confIdx].t, startT=confT;
  for(var j=confIdx;j>=1;j--){
    var cur=t2[j], prev=t2[j-1];
    var curA=(cur.st==='SUSPICIOUS'||cur.st==='COMPROMISED'), prevA=(prev.st==='SUSPICIOUS'||prev.st==='COMPROMISED');
    if(curA&&prevA&&(cur.t-prev.t)<=GAP){ startT=prev.t; } else break;
  }
  var d=confT-startT;
  return (d>0)?d:null;
}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}

/* state poll — /trust-state @1s, always fresh */
/* ===== live animation layer: flyers, packets, node/edge pulses ===== */
var LOGO={
  cert:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M6 8h7M6 11h5"/></svg>x.509',
  kpi:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 16l5-5 4 4 8-9"/><path d="M3 21h18"/></svg>',
  falcon:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l2.6 5.6L21 8.6l-4.5 4 1.1 6.4L12 16l-5.6 3 1.1-6.4L3 8.6l6.4-1z"/></svg>',
  ind:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12a7 7 0 0 1 7-7M8 12a4 4 0 0 1 4-4"/><circle cx="12" cy="12" r="1.8" fill="currentColor"/></svg>',
  shield:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/><path d="M9 12l2 2 4-4"/></svg>'
};
function flyLogo(fromId,toId,cls,opt){
  opt=opt||{}; var a=P[fromId],b=P[toId]; if(!a||!b||!dom[fromId]||!dom[toId])return;
  var el=document.createElement('div'); el.className='flyer '+(cls||'');
  el.innerHTML=opt.text?opt.text:(LOGO[cls]||'');
  if(opt.size)el.style.setProperty('--fsz',opt.size+'px');
  el.style.left=a.x+'px'; el.style.top=a.y+'px'; el.style.opacity='1';
  nodesEl.appendChild(el);
  var dur=opt.dur||2400;   // slow, comprehensible motion
  el.style.transition='left '+dur+'ms cubic-bezier(.35,.05,.5,1),top '+dur+'ms cubic-bezier(.35,.05,.5,1),opacity .3s';
  requestAnimationFrame(function(){el.style.left=b.x+'px'; el.style.top=b.y+'px';});
  setTimeout(function(){el.style.opacity='0';},dur-260);
  setTimeout(function(){el.remove();},dur+120);
}
function firePkt(fromId,toId,cls,dur){
  var a=P[fromId],b=P[toId]; if(!a||!b)return;
  var el=document.createElement('div'); el.className='pkt '+(cls||'');
  el.style.left=a.x+'px'; el.style.top=a.y+'px';
  nodesEl.appendChild(el); dur=dur||850;
  el.style.transition='left '+dur+'ms linear,top '+dur+'ms linear';
  requestAnimationFrame(function(){el.style.left=b.x+'px'; el.style.top=b.y+'px';});
  setTimeout(function(){el.remove();},dur+60);
}
function lightNode(id,ms){var el=dom[id];if(!el)return;el.classList.add('acting');clearTimeout(el._lt);el._lt=setTimeout(function(){el.classList.remove('acting');},ms||1500);}
function pulseZt(a,b,cls,ms){var e=edgeG.querySelector('.ztedge[data-a="'+a+'"][data-b="'+b+'"]');if(!e)return;e.classList.add(cls);clearTimeout(e['_'+cls]);e['_'+cls]=setTimeout(function(){e.classList.remove(cls);},ms||1500);}
function pulseEdgeAB(a,b,ms){edgeG.querySelectorAll('path[data-a="'+a+'"][data-b="'+b+'"],path[data-a="'+b+'"][data-b="'+a+'"]').forEach(function(e){if(e.classList.contains('flow')||e.classList.contains('ranflow'))return;e.classList.add('pulsing');clearTimeout(e._pe);e._pe=setTimeout(function(){e.classList.remove('pulsing');},ms||900);});}

/* REAL SVID renewal (per xApp) - fired when /csm/live/pulses reports a new
   'Writing SVID' line in that xApp's renew-svid sidecar log. */
function svidRenewFor(x){
  if(!STATE[x]||STATE[x].state==='ISOLATED')return;      // revoked identity is not renewed
  lightNode('spire',2800); pulseZt('spire',x,'pulse-cert',2800); flyLogo('spire',x,'cert',{size:22,dur:2600});
}
/* REAL KPM path - fired when kpimon's work-units counter actually advances:
   gNB->e2term indication, e2term->kpimon deliver, kpimon->influxDB write. */
function kpmFlow(){
  if(!ranUp)return;                                      // needs a live E2 link
  var k='ricxapp-kpimon-go'; if(!STATE[k]||STATE[k].state==='ISOLATED')return;
  pulseEdgeAB('gnb','e2term',2400);
  flyLogo('e2term',k,'ind',{size:18,dur:2200});
  setTimeout(function(){pulseEdgeAB(k,'influxdb',2400);flyLogo(k,'influxdb','kpi',{size:20,dur:2400});},2100);
}
function pollPulses(){
  fetch('/csm/live/pulses'+nc(),NO).then(function(r){return r.json();}).then(function(d){
    if(d.svid){ Object.keys(d.svid).forEach(function(x){
      var ts=d.svid[x];
      if(PULSE_PREV.svid[x]===undefined){PULSE_PREV.svid[x]=ts;return;}   // seed, don't fire on load
      if(ts!==PULSE_PREV.svid[x]){PULSE_PREV.svid[x]=ts;svidRenewFor(x);}
    });}
    if(d.kpm&&d.kpm.work_units!=null){
      if(PULSE_PREV.kpm===null){PULSE_PREV.kpm=d.kpm.work_units;}
      else if(d.kpm.work_units>PULSE_PREV.kpm){PULSE_PREV.kpm=d.kpm.work_units;kpmFlow();}
    }
  }).catch(function(){});
}
/* continuous, SLOW UE->gNB traffic (letter packets) while the UE session is up */
function pingCycle(){ if(ueUp) firePkt('ue','gnb','ping',2600); }

/* xApp state transition -> Falco / policy-engine / canal choreography.
   On isolation the SIGNALS play first; only afterward does the node sever
   its connections and move to the corner. On restore the node returns to
   its place first, then its connections are re-established. */
/* after a restore we briefly ignore re-escalation so trailing T2 events (the
   collector keeps posting for ~1-2s) can't re-sever the freshly-created pod. */
var RESTORE_GRACE={};
/* definitively reconnect an xApp: clear visual isolation, un-sever EVERY edge
   touching it (data + zero-trust, both directions), and re-pulse its links. */
function reconnectXapp(x){
  XVISISO[x]=false;
  edgeG.querySelectorAll('.edge[data-a="'+x+'"],.edge[data-b="'+x+'"]').forEach(function(e){e.classList.remove('severing','suspicious','compromised');});
  edgeG.querySelectorAll('.ztedge[data-a="'+x+'"],.ztedge[data-b="'+x+'"]').forEach(function(e){e.classList.remove('severing');});
  applyEdges(x);
  (CONNS[x]||[]).forEach(function(c,i){setTimeout(function(){pulseEdgeAB(x,c[0],1700);},i*200);});
  XD_CONNS_ZT.forEach(function(s){pulseZt(s,x,'pulse-restore',2000);});
}
function onXappTransition(it, prev, st){
  var x=it.xapp;
  var isT2=(''+(it.last_source||'')).indexOf('t2')>=0 || (''+(it.last_signal||'')).indexOf('resource_anomaly_t2')>=0;
  var esc={NORMAL:0,SUSPICIOUS:1,COMPROMISED:2,ISOLATED:3};
  if(esc[st]>esc[prev] && RESTORE_GRACE[x] && Date.now()<RESTORE_GRACE[x]) return;   // ignore trailing re-escalation right after a restore
  if(st==='COMPROMISED' && esc[st]>esc[prev]){           // first entry into COMPROMISED
    ATK_COMPR_AT[x]=Date.now();
    if(ATK_LAUNCH[x]!=null && ATK_DET[x]==null){ ATK_DET[x]=Date.now()-ATK_LAUNCH[x]; }   // real launch->compromised latency
    atkTimeSave();
  }
  if(esc[st]>esc[prev]){                                 // escalation
    if(!isT2 && prev==='NORMAL'){                         // behaviour (Falco) detection - once, at onset
      lightNode('falco',2600); pulseZt('falco',x,'pulse-falco',2600); flyLogo('falco',x,'falcon',{size:24,dur:2400});
    }
    lightNode('policy-engine',2600);
    pulseZt('policy-engine',x, st==='SUSPICIOUS'?'pulse-susp':st==='COMPROMISED'?'pulse-comp':'pulse-iso', 3000);
    if(st==='ISOLATED'){
      lightNode('canal',2800); pulseZt('canal',x,'pulse-canal',3000); flyLogo('canal',x,'shield',{size:24,dur:2400});
      // signals play first; THEN the node severs + moves to the corner
      setTimeout(function(){ XVISISO[x]=true; applyEdges(x); }, 2600);
    }
  } else if(st==='NORMAL' && esc[prev]>=2){              // recovery from compromised/isolated
    if(prev==='ISOLATED'){ vaultRestore(x); }            // old circle -> vault; a fresh one enters + reconnects
    else {                                               // soft recovery (never severed): return + reconnect in place
      RESTORE_GRACE[x]=Date.now()+7000;
      reconnectXapp(x);
      setTimeout(function(){ reconnectXapp(x); lightNode('spire',2200); flyLogo('spire',x,'cert',{size:22,dur:2400}); }, 1200);
    }
  }
}

/* ===== Restore choreography with the forensic Evidence Vault =====
   The severed (isolated) circle slides into the vault at the stage's
   bottom-right and disappears (its forensic record is now sealed).
   A fresh identity enters from the side, homes to its place, and its
   connections + SVID are re-established. Vault only shows during restore. */
function vaultPos(){
  var v=document.getElementById('vault'); var sr=stage.getBoundingClientRect(); var r=v.getBoundingClientRect();
  return {x:(r.left-sr.left)+r.width/2, y:(r.top-sr.top)+r.height/2};
}
function vaultRestore(x){
  var v=document.getElementById('vault'), node=dom[x]; if(!v||!node){XVISISO[x]=false;applyEdges(x);return;}
  v.classList.add('show');
  var cur={x:P[x].x,y:P[x].y}, dur=3200;   // slow, demo-clear travel into the briefcase
  setTimeout(function(){                                 // let the vault ease in before the circle travels
    var vp=vaultPos();
    var ghost=document.createElement('div'); ghost.className='node xapp vghost';
    ghost.innerHTML=node.innerHTML;
    ghost.style.left=cur.x+'px'; ghost.style.top=cur.y+'px'; ghost.style.opacity='1';
    nodesEl.appendChild(ghost);
    ghost.style.transition='left '+dur+'ms cubic-bezier(.5,.05,.5,1),top '+dur+'ms cubic-bezier(.5,.05,.5,1),opacity .45s,transform '+dur+'ms ease-in';
    requestAnimationFrame(function(){ ghost.style.left=vp.x+'px'; ghost.style.top=vp.y+'px'; ghost.style.transform='scale(.32)'; });
    setTimeout(function(){ v.classList.add('absorb'); },dur-260);
    setTimeout(function(){ ghost.style.opacity='0'; },dur-120);
    setTimeout(function(){ ghost.remove(); v.classList.remove('absorb'); refreshInvCount(); },dur+260);

    // --- a FRESH pod is created from the image, enters from the side, travels
    // slowly to its place, and only then reconnects to the RIC platform ---
    XVISISO[x]=false; var h=home(byId[x]);
    P[x].fx=h.x; P[x].fy=h.y;                            // pin the real node at home while hidden (no drift)
    node.style.transition='opacity .3s'; node.style.opacity='0';
    var ENT=2900;                                        // slow, demo-clear entrance
    setTimeout(function(){                               // after the old circle is absorbed, spawn the new one
      var side=(h.x<W/2)? -64 : W+64;
      var np=document.createElement('div'); np.className='node xapp newpod'; np.innerHTML=node.innerHTML;
      np.style.left=side+'px'; np.style.top=h.y+'px'; np.style.opacity='0';
      nodesEl.appendChild(np);
      requestAnimationFrame(function(){
        np.style.transition='left '+ENT+'ms cubic-bezier(.4,.1,.35,1),top '+ENT+'ms cubic-bezier(.4,.1,.35,1),opacity .6s';
        np.style.opacity='1'; np.style.left=h.x+'px'; np.style.top=h.y+'px';
      });
      setTimeout(function(){                             // arrived home: swap flyer -> real node, then connect
        np.remove();
        node.style.opacity='1'; P[x].fx=null; P[x].fy=null;
        RESTORE_GRACE[x]=Date.now()+7000;                // shield the fresh pod from trailing T2 re-escalation
        reconnectXapp(x);                                // definitively wire the new pod to ricplt + ZT plane
        lightNode('spire',2400); flyLogo('spire',x,'cert',{size:22,dur:2600});   // SVID re-issued to the new pod
        setTimeout(function(){reconnectXapp(x);},1200);  // re-assert (survive any transient re-sever)
        setTimeout(function(){reconnectXapp(x);},2800);
      }, ENT+140);
      setTimeout(function(){ v.classList.remove('show'); }, ENT+2800);
    }, dur-300);
  }, 480);
}

function pollState(){
  fetch('/trust-state'+nc(),NO).then(function(r){return r.json();}).then(function(d){
    (d.xapps||[]).forEach(function(it){
      if(!STATE[it.xapp])return;
      var st=pub(it.state);
      if(stateFirst){                                    // seed on first poll - no animation for pre-existing state
        XVISISO[it.xapp]=(st==='ISOLATED'); setState(it.xapp,it.state); XPREV[it.xapp]=st; return;
      }
      var prev=XPREV[it.xapp]||'NORMAL';
      setState(it.xapp,it.state);
      if(st!==prev)onXappTransition(it,prev,st);
      XPREV[it.xapp]=st;
    });
    stateFirst=false;
    renderCounts();
    buildThreatFeed(d.recent_events);
    var le=(d.recent_events||[])[0]; window._lastAction=le?{ts:le.time,xapp:le.xapp,signal:le.signal,state:pub(le.state)}:null;
    if(window._posture)buildPolicy(window._posture);   // refresh live bits at 1s cadence
    // dual-channel detection latency (latest event per source, for the ms)
    // reliable detector attribution: an event is T2 (resource) iff its source is
    // the T2 collector OR its signal is a resource_anomaly. Anything else is Falco.
    var falcoEv=null,t2Ev=null, chanByX={};
    (d.recent_events||[]).forEach(function(e){ if(!e.state)return; var isT2=(''+(e.source||'')).indexOf('t2')>=0 || (''+(e.signal||'')).indexOf('resource_anomaly')>=0;
      if(isT2){if(!t2Ev)t2Ev=e;}else{if(!falcoEv)falcoEv=e;}
      if(e.xapp&&chanByX[e.xapp]===undefined)chanByX[e.xapp]=isT2?'t2':'falco'; });   // newest event per xApp wins
    // per-channel level from each xApp's CURRENT state + which detector drives it.
    // idle when the incident is cleared -> the card resets (no stale latency).
    var LR={idle:0,suspicious:1,compromised:2};
    var falcoLevel='idle',t2Level='idle';
    (d.xapps||[]).forEach(function(it){
      if(XAPP_IDS.indexOf(it.xapp)<0)return;
      var st=pub(it.state);
      var lvl=(st==='COMPROMISED'||st==='ISOLATED')?'compromised':(st==='SUSPICIOUS')?'suspicious':'idle';
      if(lvl==='idle')return;
      var isT2;
      if(chanByX[it.xapp]!==undefined) isT2=(chanByX[it.xapp]==='t2');   // trust the real event channel first
      else isT2=(''+(it.last_source||'')).indexOf('t2')>=0 || (''+(it.last_signal||'')).indexOf('resource_anomaly')>=0;
      if(isT2){ if(LR[lvl]>LR[t2Level])t2Level=lvl; } else { if(LR[lvl]>LR[falcoLevel])falcoLevel=lvl; }
    });
    // Falco is a fast kernel-event detector (ms). For T²: while only SUSPICIOUS,
    // show the fast per-event processing ms; ONLY once COMPROMISED show the REAL
    // elapsed attack->confirmation latency (seconds), computed from event stamps.
    var x2='ricxapp-kpimon-go';
    var t2DetMs=null;
    var launchFresh=(ATK_LAUNCH[x2]!=null)&&((Date.now()-ATK_LAUNCH[x2])<600000);   // ignore stale launch stamps
    if(t2Level==='suspicious'){
      // live count-up from the Attack-Console launch until COMPROMISED is declared
      t2DetMs=launchFresh?(Date.now()-ATK_LAUNCH[x2]):(t2Ev?t2Ev.decision_ms:null);
    } else if(t2Level==='compromised'){
      // frozen REAL launch->compromised latency (falls back to event-derived elapsed)
      t2DetMs=(ATK_DET[x2]!=null)?ATK_DET[x2]:(t2DetectMs(d.recent_events)||(t2Ev?t2Ev.decision_ms:null));
    }
    updateDet(
      {ms:(falcoLevel!=='idle'&&falcoEv)?falcoEv.decision_ms:null, level:falcoLevel},
      {ms:t2DetMs, level:t2Level}
    );
    // MOST RECENT incident (recent_events is newest-first) whose xApp is still contained
    var incTarget=null,incEv=null;
    (d.recent_events||[]).some(function(e){ if(STATE[e.xapp]&&(pub(e.state)==='COMPROMISED'||pub(e.state)==='ISOLATED')&&e.action!=='EVIDENCE_ONLY'&&(STATE[e.xapp].state==='COMPROMISED'||STATE[e.xapp].state==='ISOLATED')){incTarget=e.xapp;incEv=e;return true;}return false; });
    if(incTarget){
      var sig=(incEv&&incEv.signal)||'';var t=TECH[sig]||[sig||'Runtime Anomaly','—'];
      var tim=(window._timing||{})[incTarget]||null;
      // REAL parallel-containment latency only (seconds, SVID-dominated). Never the
      // ms label-write time — if timing isn't captured yet, leave it blank and let a
      // later poll stamp the real value (the incident signature now tracks it).
      var contain=(tim&&parallelMs(tim)>0)?parallelMs(tim):null;
      var isT2inc=(chanByX[incTarget]==='t2');
      // Detect = REAL detection latency. T²: launch->compromised (Attack-Console
      // anchored, falls back to event-derived elapsed). Falco: fast kernel decision.
      var incDetect=isT2inc?((ATK_DET[incTarget]!=null)?ATK_DET[incTarget]:(t2DetectMs(d.recent_events)||null)):(incEv&&incEv.decision_ms);
      // Never display ISOLATED before the real 30s dwell elapses (resource attacks).
      var rawSt=STATE[incTarget].state, dispSt=rawSt;
      if(isT2inc && rawSt==='ISOLATED' && ATK_COMPR_AT[incTarget]!=null && (Date.now()-ATK_COMPR_AT[incTarget])<ZTX_DWELL_MS){ dispSt='COMPROMISED'; }
      var incObj={xapp:incTarget,name:byId[incTarget].label,state:dispSt,tech:t[0]+' ('+t[1]+')',rule:(incEv&&incEv.rule_ids&&incEv.rule_ids.join(', '))||'—',ts:shortTs(incEv&&incEv.time),detect_ms:incDetect,decision_ms:null,contain_ms:contain,verify_ms:(tim&&tim.verify_ms)};
      incidentActive=true;
      incShow(incObj);                                   // same bottom incident bar for behaviour AND resource attacks
      if(chanByX[incTarget]==='t2'){ countShow(incTarget, incObj); }   // + small top-left dwell countdown (COMPROMISED only)
      else { countHide(); }
      updateLat(tim);
    } else { incHide(); countHide(); updateLat(null); }
  }).catch(function(){});
}
/* per-mechanism containment timing poll */
function pollTiming(){ fetch('/csm/incident/timing'+nc(),NO).then(function(r){return r.json();}).then(function(d){ window._timing=d.timing||{}; }).catch(function(){}); }
/* RAN/E2 poll */
function pollRan(){ fetch('/csm/ran/status'+nc(),NO).then(function(r){return r.json();}).then(function(d){ setRan(d); }).catch(function(){}); }

/* marquee removed (replaced by live threat feed) — guard for any stale caller */
function buildMarquee(){ var m=document.getElementById('marqTrack'); if(m)m.innerHTML=''; }

/* ===== Live Threat Feed (centre, below the map) ===== */
/* ===== Live Threat Feed — 24h episode history =====
   One row per THREAT EPISODE, stamped at its ONSET (the first time an xApp
   enters a given state+signal). A continuous run (e.g. SUSPICIOUS 12:15:45 ->
   12:15:51) is a single record at 12:15:45; it is NOT updated as it continues.
   History persists in localStorage and is pruned to the last 24 hours, so past
   events stay visible across refreshes. */
var TF_SIG='', TF_LOG=[], TF_CUR={}, TF_LAST_TIME='', TF_STORE='ztx_threatfeed_v2';
function tfClass(s){s=pub(s);return (s==='SUSPICIOUS'||s==='COMPROMISED'||s==='ISOLATED'||s==='NORMAL')?s:'NORMAL';}
function tfPrune(){ var cut=Date.now()-24*3600*1000; TF_LOG=TF_LOG.filter(function(r){var t=Date.parse(r.t); return isNaN(t)||t>=cut;}); if(TF_LOG.length>400)TF_LOG.length=400; }
function tfLoad(){ try{ var o=JSON.parse(localStorage.getItem(TF_STORE)||'{}'); TF_LOG=o.log||[]; TF_CUR=o.cur||{}; TF_LAST_TIME=o.last||''; }catch(e){ TF_LOG=[];TF_CUR={};TF_LAST_TIME=''; } tfPrune(); }
function tfSave(){ try{ localStorage.setItem(TF_STORE, JSON.stringify({log:TF_LOG,cur:TF_CUR,last:TF_LAST_TIME})); }catch(e){} }
function buildThreatFeed(events){
  var body=document.getElementById('tfBody'); if(!body)return;
  // when an xApp is back to NORMAL, close its episode so a later same-type
  // threat is recorded as a fresh onset (recovery events may not be in the feed)
  XAPP_IDS.forEach(function(x){ if(STATE[x]&&pub(STATE[x].state)==='NORMAL' && TF_CUR[x] && TF_CUR[x].indexOf('NORMAL')!==0){ TF_CUR[x]='NORMAL|'; } });
  var src=(events||[]).filter(function(e){return e.state&&e.xapp;});
  var fresh=src.filter(function(e){return (''+e.time)>TF_LAST_TIME;});   // only events newer than what we've seen
  fresh.sort(function(a,b){return (''+a.time<''+b.time)?-1:1;});         // oldest-first so onsets are recorded in order
  var changed=false;
  fresh.forEach(function(e){
    var isT2=(''+(e.source||'')).indexOf('t2')>=0||(''+(e.signal||'')).indexOf('resource_anomaly')>=0;
    var sig=e.signal||(e.rule_ids&&e.rule_ids.join(', '))||'runtime anomaly';
    var st=pub(e.state);
    var key=st+'|'+sig;
    if(TF_CUR[e.xapp]===key) return;         // same ongoing episode -> ignore continuous repeats
    TF_CUR[e.xapp]=key;                       // a NEW episode for this xApp
    if(st==='NORMAL') return;                 // recovery ends an episode but isn't a threat row itself
    TF_LOG.unshift({t:e.time,st:st,isT2:isT2,xapp:e.xapp,sig:sig});   // record ONSET only
    changed=true;
  });
  if(src.length){ var mx=src.reduce(function(m,e){return (''+e.time>m)?(''+e.time):m;},TF_LAST_TIME); if(mx!==TF_LAST_TIME){TF_LAST_TIME=mx; changed=true;} }
  if(changed){ tfPrune(); tfSave(); }
  var rows=TF_LOG.slice(0,120);
  var sig=rows.map(function(r){return r.t+r.st;}).join(',');
  if(sig===TF_SIG)return;  // nothing changed -> don't touch the DOM
  TF_SIG=sig;
  if(!rows.length){ body.innerHTML='<span class="tfempty">no events · monitoring</span>'; return; }
  body.innerHTML=rows.map(function(r){
    var lbl=(byId[r.xapp]&&byId[r.xapp].label)||String(r.xapp).replace('ricxapp-','');
    return '<div class="tfrow '+tfClass(r.st)+'">'
      +'<span class="tft">'+shortTs(r.t)+'</span>'
      +'<span class="tfsrc '+(r.isT2?'t2':'falco')+'">'+(r.isT2?'T2':'FALCO')+'</span>'
      +'<span class="tfx">'+esc(lbl)+'</span>'
      +'<span class="tfmsg">'+esc(r.sig)+'</span>'
      +'<span class="tfst">'+r.st+'</span></div>';
  }).join('');
}

/* ===== Policy Engine posture + Identity / SVID Health widgets ===== */
function pollPosture(){
  fetch('/csm/policy/posture'+nc(),NO).then(function(r){return r.json();}).then(function(d){window._posture=d;buildPolicy(d);buildSvid(d);}).catch(function(){});
}
/* Policy Engine = the fleet-wide decision + enforcement brain. This widget
   shows what it is enforcing RIGHT NOW: live fleet posture, how many pods it
   is actively containing, which locks are armed, and its most recent action. */
function buildPolicy(d){
  var w=document.getElementById('polWrap'); if(!w)return;
  var enf=d.enforcement||{}, ident=d.identity||{};
  var total=Object.keys(ident).length;
  // live, STATE-derived — an identity is trusted unless the xApp is currently
  // compromised/isolated. Uses live state (not the svid-enabled pod label, which
  // lags on restore) so the count returns to full once an xApp recovers.
  var managed=0, active=0, worst=0, RANK={NORMAL:0,SUSPICIOUS:1,COMPROMISED:2,ISOLATED:3};
  XAPP_IDS.forEach(function(x){ if(!ident[x])return; var st=(STATE[x]&&pub(STATE[x].state))||'NORMAL'; if(RANK[st]>=2)active++; if(RANK[st]>worst)worst=RANK[st];
    if(st!=='COMPROMISED'&&st!=='ISOLATED') managed++; });
  var postureTxt=worst>=2?'UNDER ATTACK':worst===1?'ELEVATED':'STEADY';
  var postureCls=worst>=2?'bad':worst===1?'warn':'ok';
  var locks=[['Falco',enf.auto_quarantine],['T2',enf.t2_auto_contain],['SVID',enf.revoke_spire],['Destruct',enf.allow_destructive]];
  var armed=locks.filter(function(l){return !!l[1];}).length;
  var la=window._lastAction;
  var laTxt=la?(shortTs(la.ts)+' · '+((byId[la.xapp]&&byId[la.xapp].label)||String(la.xapp||'').replace('ricxapp-',''))+' → '+la.state):'—';
  var html='';
  html+='<div class="polhdr"><span class="pplabel">fleet posture</span><span class="pposture '+postureCls+'">'+postureTxt+'</span></div>';
  html+='<div class="polbig"><div class="pbig '+(active?'hot':'')+'"><b>'+active+'</b><span>pods contained</span></div>'
    +'<div class="pbig"><b>'+managed+'/'+Object.keys(ident).length+'</b><span>SVID identities</span></div></div>';
  html+='<div class="pollocks">';
  locks.forEach(function(l){ html+='<span class="plock'+(l[1]?' on':'')+'">'+esc(l[0])+'</span>'; });
  html+='</div>';
  html+='<div class="polrow"><span class="pl">Enforcement locks</span><span class="pv">'+armed+' / 4 armed · '+esc(enf.containment_mode||'service')+'</span></div>';
  var itot=(d.incidents_total!=null?d.incidents_total:'—'), i24=(d.incidents_24h!=null?d.incidents_24h:'—');
  html+='<div class="polrow"><span class="pl">Incidents sealed</span><span class="pv">'+itot+' total · '+i24+' /24h</span></div>';
  html+='<div class="polrow"><span class="pl">Last policy action</span><span class="pv">'+esc(laTxt)+'</span></div>';
  w.innerHTML=html;
}
function svidClock(ts){
  if(ts==null||ts==='')return null;
  var dt;
  if(typeof ts==='number'){ dt=new Date(ts*1000); }             // epoch seconds
  else{                                                          // RFC3339 from kubectl --timestamps (may carry nanoseconds)
    var s=String(ts).replace(/(\.\d{3})\d+/, '$1');             // trim ns -> ms so Date can parse it
    dt=new Date(s);
    if(isNaN(dt.getTime())){ var n=parseFloat(ts); if(!isNaN(n))dt=new Date(n*1000); }  // fallback: numeric string
  }
  if(isNaN(dt.getTime()))return null;
  return lkTime(dt);
}
/* Identity Health: real SPIFFE/SVID state per xApp. Shows the timestamp of the
   latest issued SVID (from the real 'Writing SVID' sidecar events). After
   isolation the identity is revoked -> the SVID can no longer be bound. */
function buildSvid(d){
  var w=document.getElementById('svidWrap'); if(!w)return;
  var ident=d.identity||{}; var xs=XAPP_IDS.filter(function(x){return ident[x];});
  if(!xs.length)xs=Object.keys(ident);
  if(!xs.length){ w.innerHTML='<div class="svidrow"><span class="sdot"></span><span class="sname">no identities</span></div>'; return; }
  w.innerHTML=xs.map(function(x){
    var lbl=(byId[x]&&byId[x].label)||String(x).replace('ricxapp-','');
    var st=(STATE[x]&&pub(STATE[x].state))||'NORMAL';   // live state drives this; label lags on restore
    var clk=svidClock(PULSE_PREV.svid&&PULSE_PREV.svid[x]);
    var cls, tail;
    if(st==='ISOLATED'){ cls='revoked'; tail='<span class="stag bad">REVOKED</span><span class="sx">SVID unbound</span>'; }
    else if(st==='COMPROMISED'){ cls='warn'; tail='<span class="stag warn">BIND FAIL</span><span class="sx">contained</span>'; }
    else { cls='ok'; tail='<span class="stag ok">VALID</span><span class="sx">'+(clk?('issued '+clk):'SVID bound')+'</span>'; }
    return '<div class="svidrow '+cls+'"><span class="sdot"></span>'
      +'<span class="sname">'+esc(lbl)+'</span>'
      +'<span class="sright">'+tail+'</span></div>';
  }).join('');
}

/* ===== Investigation Center (dedicated forensic page) ===== */
var INV={rows:[],sel:null,filter:'',fileCache:{}};
function fmtBytes(b){ if(b==null)return '—'; if(b<1024)return b+' B'; if(b<1048576)return (b/1024).toFixed(1)+' KB'; return (b/1048576).toFixed(1)+' MB'; }
function refreshInvCount(){
  fetch('/csm/incidents?limit=1'+('&_='+Date.now()),NO).then(function(r){return r.json();}).then(function(d){
    var badge=document.getElementById('navInvCount'); if(badge)badge.textContent=(d.count!=null?d.count:'');
  }).catch(function(){});
}
function invOpen(){
  document.body.classList.add('invcenter');
  document.getElementById('invView').removeAttribute('hidden');
  document.getElementById('navInvestigate').classList.add('on');
  document.getElementById('navOverview').classList.remove('on');
  invLoad();
}
function invClose(){
  document.body.classList.remove('invcenter');
  document.getElementById('invView').setAttribute('hidden','');
  document.getElementById('navInvestigate').classList.remove('on');
  document.getElementById('navOverview').classList.add('on');
  homeRelayout();
}
function invLoad(){
  fetch('/csm/incidents?limit=300'+('&_='+Date.now()),NO).then(function(r){return r.json();}).then(function(d){
    INV.rows=d.incidents||[];
    var meta=document.getElementById('invMeta');
    if(meta)meta.textContent=INV.rows.length+' sealed incidents · vault '+(d.vault||'/forensic-vault');
    var badge=document.getElementById('navInvCount'); if(badge)badge.textContent=INV.rows.length;
    invRenderList();
  }).catch(function(){
    document.getElementById('invRows').innerHTML='<div class="invempty">vault unavailable</div>';
  });
}
function invRenderList(){
  var box=document.getElementById('invRows'); if(!box)return;
  var f=INV.filter.toLowerCase();
  var rows=INV.rows.filter(function(r){
    if(!f)return true;
    return [r.id,r.xapp,r.signal,r.falco_rule,r.state].join(' ').toLowerCase().indexOf(f)>=0;
  });
  if(!rows.length){ box.innerHTML='<div class="invempty">no matching incidents</div>'; return; }
  box.innerHTML=rows.map(function(r){
    var st=pub(r.state); var lbl=(byId[r.xapp]&&byId[r.xapp].label)||String(r.xapp||'—').replace('ricxapp-','');
    return '<div class="invrow '+st+(r.id===INV.sel?' sel':'')+'" data-id="'+esc(r.id)+'">'
      +'<div class="irtop"><span class="irx">'+esc(lbl)+'</span><span class="irsig">'+esc(r.signal||r.falco_rule||'runtime anomaly')+'</span>'
      +'<span class="irsrc">'+esc((r.source||'').indexOf('t2')>=0?'T2':'FALCO')+'</span></div>'
      +'<div class="irbot"><span>'+esc(r.captured_utc||r.id)+'</span>'
      +'<span>'+st+'</span>'
      +(r.sealed?'<span class="sealed">✔ sealed · '+(r.artifacts||0)+' files</span>':'<span>unsealed</span>')+'</div></div>';
  }).join('');
  box.querySelectorAll('.invrow').forEach(function(el){ el.onclick=function(){ invSelect(el.dataset.id); }; });
}
function invSelect(id){
  INV.sel=id; invRenderList();
  document.getElementById('invEmpty').setAttribute('hidden','');
  var body=document.getElementById('invBody'); body.removeAttribute('hidden');
  body.innerHTML='<div class="invempty">loading forensic record…</div>';
  fetch('/csm/incidents/'+encodeURIComponent(id)+('?_='+Date.now()),NO).then(function(r){return r.json();}).then(invRenderDetail).catch(function(){
    body.innerHTML='<div class="invempty">failed to load '+esc(id)+'</div>';
  });
}
function kv(k,v,cls){ return '<div class="k">'+esc(k)+'</div><div class="v'+(cls?' '+cls:'')+'">'+esc(v==null||v===''?'—':v)+'</div>'; }
function invRenderDetail(d){
  var body=document.getElementById('invBody'); if(!body)return;
  if(!d.ok){ body.innerHTML='<div class="invempty">'+esc(d.error||'not found')+'</div>'; return; }
  var s=d.summary||{}, m=d.manifest||{}, tr=(m.trigger||{}), dec=(m.decision||{});
  var lbl=(byId[s.xapp]&&byId[s.xapp].label)||String(s.xapp||'—').replace('ricxapp-','');
  var st=pub(s.state);
  var h='';
  // Case
  h+='<div class="invsec"><h4>Case</h4><div class="invkv">'
    +kv('Incident ID',d.id)+kv('Asset (xApp)',lbl)+kv('Pod',s.pod)
    +kv('Captured (UTC)',s.captured_utc)+kv('Sealed (UTC)',s.sealed_utc||'not sealed')
    +kv('Final state',st,'st-'+st)+kv('Severity',s.severity)
    +'</div></div>';
  // Trigger
  h+='<div class="invsec"><h4>Detection trigger</h4><div class="invkv">'
    +kv('Detector',(s.source||'').indexOf('t2')>=0?'T2 resource detector':'Falco (kernel)')
    +kv('Signal',s.signal)+kv('Falco rule',s.falco_rule||tr.falco_rule)
    +kv('Priority',s.priority||tr.priority)
    +kv('Rule IDs',(s.rule_ids&&s.rule_ids.join)?s.rule_ids.join(', '):s.rule_ids)
    +'</div>';
  var alert=tr.alert;
  if(alert)h+='<div class="invalert">'+esc(alert)+'</div>';
  h+='</div>';
  // Response
  h+='<div class="invsec"><h4>Automated response</h4><div class="invkv">'
    +kv('Containment required',dec.containment_required)+kv('Action',dec.containment_action)
    +kv('Score',dec.score)+kv('Confidence',dec.confidence);
  var it=dec.isolation_timing||{};
  if(it&&(it.total_ms!=null||it.total_seconds!=null)){
    h+=kv('Isolation total',(it.total_ms!=null?it.total_ms+' ms':(it.total_seconds+' s')));
  }
  h+='</div></div>';
  // Evidence artifacts (with hashes + view/download)
  var arts=m.artifacts||d.files||[];
  h+='<div class="invsec"><h4>Sealed evidence · integrity '+esc(m.integrity||'sha256')+'</h4><div class="invfiles">';
  (d.files||[]).forEach(function(f){
    var a=arts.filter&&arts.filter(function(x){return x.name===f.name;})[0];
    var hash=a&&a.sha256?a.sha256:null;
    h+='<div class="invfile"><span class="fn">'+esc(f.name)+'</span>'
      +'<span>'+esc(fmtBytes(f.bytes))+'</span>'
      +'<button class="fbtn" data-v="'+esc(d.id)+'|'+esc(f.name)+'">view</button>'
      +'<a class="fbtn" href="/csm/incidents/'+encodeURIComponent(d.id)+'/file/'+encodeURIComponent(f.name)+'?download=1">download</a>'
      +(hash?'<span class="fh">sha256:'+esc(hash.slice(0,24))+'…</span>':'')+'</div>';
  });
  h+='</div><div class="invviewer" id="invViewer" hidden></div></div>';
  // Chain of custody
  var coc=m.chain_of_custody||[];
  if(coc.length){
    h+='<div class="invsec"><h4>Chain of custody</h4><div class="invcustody">';
    coc.forEach(function(c){ h+='<div class="cc"><span class="cca">'+esc(c.action)+'</span><span>'+esc(c.actor)+'</span><span class="cct">'+esc(c.utc||'')+'</span></div>'; });
    h+='</div><div class="invkv" style="margin-top:8px">'+kv('Vault path',d.vault_path)+kv('Schema',m.schema)+'</div></div>';
  }
  body.innerHTML=h;
  body.querySelectorAll('.fbtn[data-v]').forEach(function(b){ b.onclick=function(){ var p=b.dataset.v.split('|'); invViewFile(p[0],p[1]); }; });
}
function invViewFile(id,name){
  var v=document.getElementById('invViewer'); if(!v)return;
  v.removeAttribute('hidden'); v.textContent='loading '+name+'…';
  fetch('/csm/incidents/'+encodeURIComponent(id)+'/file/'+encodeURIComponent(name)+('?_='+Date.now()),NO).then(function(r){return r.text();}).then(function(t){
    v.textContent='── '+name+' ──\n\n'+t;
  }).catch(function(){ v.textContent='failed to load '+name; });
}

/* ===== Attack Console (embedded view; real exec via /csm/attack/launch) ===== */
var ATK={attacks:[],xapps:null,target:null,log:[],lastState:{}};
var ATK_RANK={NORMAL:0,SUSPICIOUS:1,COMPROMISED:2,ISOLATED:3};
function atkShortLabel(id){return (byId[id]&&byId[id].label)||String(id).replace('ricxapp-','');}
function atkFetchCatalog(){
  fetch('/csm/attack/catalog'+nc(),NO).then(function(r){return r.json();}).then(function(d){
    ATK.attacks=d.attacks||[]; ATK.xapps=(d.xapps||XAPP_IDS).filter(function(x){return XAPP_IDS.indexOf(x)>=0;});
    if(!ATK.target||ATK.xapps.indexOf(ATK.target)<0)ATK.target=ATK.xapps[0];
    atkBuildTargets(); atkBuildAttacks();
  }).catch(function(){});
}
/* ===== per-xApp Falco capability profile (frontend policy view) =====
   Falco rules are fleet-wide, but each xApp has a distinct legitimate role, so
   its allowed vs denied runtime capabilities differ. This is the "capability
   profile" a SOC analyst reads before emulating an attack: what this workload
   is permitted to touch, and what would trip a rule. Paths are the REAL ones
   from ztx-xapp-rules.yaml. */
var CAPS={
  'ricxapp-kpimon-go':{role:'E2 KPI Monitor — subscribes to KPM indications, writes metrics to InfluxDB',
    peers:['e2term (RMR)','e2mgr','submgr','influxdb','prometheus','a1mediator'],
    allow:[['Read E2 KPM indications','RMR :4560/4561'],['Write time-series','influxdb.ricplt:8086'],['Read own config','/opt/ric/config (ro)'],['Scratch I/O','/tmp']],
    deny:[['Interactive shell','/bin/sh · /bin/bash'],['Credential files','/etc/shadow · /etc/passwd'],['SPIFFE SVID material','/run/spire · /etc/svid'],['Config tamper','/etc/xapp-profile · /opt/ric/config (rw)'],['SA token','/var/run/secrets/…/token'],['External egress','non-ricplt destinations']]},
  'ricxapp-trafficxapp':{role:'Traffic Steering — reads E2 metrics, issues A1 policy / control',
    peers:['e2term (RMR)','submgr','a1mediator','rtmgr'],
    allow:[['Read E2 metrics','RMR :4560/4561'],['A1 policy control','a1mediator-rmr'],['Read own config','/opt/ric/config (ro)'],['Scratch I/O','/tmp']],
    deny:[['Interactive shell','/bin/sh · /bin/bash'],['Credential files','/etc/shadow · /etc/passwd'],['SPIFFE SVID material','/run/spire · /etc/svid'],['InfluxDB write','influxdb (not in profile)'],['Config tamper','/etc/xapp-profile'],['External egress','non-ricplt destinations']]},
  'ricxapp-hw-go':{role:'HelloWorld (Go) — minimal RMR echo sample xApp',
    peers:['e2term (RMR)','rtmgr'],
    allow:[['RMR send/receive','RMR :4560/4561'],['Route updates','rtmgr'],['Scratch I/O','/tmp']],
    deny:[['Interactive shell','/bin/sh · /bin/bash'],['Credential files','/etc/shadow'],['SPIFFE SVID material','/run/spire · /etc/svid'],['Config tamper','/etc/xapp-profile'],['SA token','/var/run/secrets/…/token'],['External egress','non-ricplt destinations']]},
  'ricxapp-hw-python':{role:'HelloWorld (Python) — RMR sample; python3 runtime permitted',
    peers:['e2term (RMR)','rtmgr'],
    allow:[['RMR send/receive','RMR :4560/4561'],['python3 runtime','proc python3 (profiled)'],['Route updates','rtmgr'],['Scratch I/O','/tmp']],
    deny:[['Interactive shell','/bin/sh · /bin/bash'],['Credential files','/etc/shadow'],['SPIFFE SVID material','/run/spire · /etc/svid'],['Config tamper','/etc/xapp-profile'],['SA token','/var/run/secrets/…/token'],['External egress','non-ricplt destinations']]}
};
/* attack signal -> which capability/path it violates (for the analyst view + incidents) */
var SIGVIOL={
  unexpected_shell:['Interactive shell execution','/bin/sh · /bin/bash'],
  sensitive_file_access:['Sensitive credential file read','/etc/shadow'],
  serviceaccount_token_access:['K8s ServiceAccount token read','/var/run/secrets/kubernetes.io/serviceaccount/token'],
  external_egress:['Egress outside the RIC mesh','non-ricplt destination'],
  svid_material_access:['SPIFFE SVID / SPIRE material access','/run/spire · /etc/svid'],
  xapp_profile_or_config_tamper:['xApp profile / config tamper','/etc/xapp-profile · /opt/ric/config'],
  permission_tamper:['File permission tamper','chmod/chown on protected paths'],
  privileged_container_escape_attempt:['Privileged container escape','/proc · host mounts'],
  resource_anomaly_t2:['CPU budget exceeded','cgroup cpu.max'],
  resource_anomaly_t2_elevated:['CPU budget elevated','cgroup cpu.max']
};
function atkBuildCaps(){
  var c=document.getElementById('atkCaps'); if(!c)return;
  var id=ATK.target; var cap=CAPS[id];
  if(!cap){ c.innerHTML=''; return; }
  var allow=cap.allow.map(function(a){return '<div class="capr ok"><span class="capk">'+esc(a[0])+'</span><span class="capp">'+esc(a[1])+'</span></div>';}).join('');
  var deny=cap.deny.map(function(a){return '<div class="capr no"><span class="capk">'+esc(a[0])+'</span><span class="capp">'+esc(a[1])+'</span></div>';}).join('');
  c.innerHTML='<div class="caphdr">Capability profile · '+esc(atkShortLabel(id))+'</div>'
    +'<div class="caprole">'+esc(cap.role)+'</div>'
    +'<div class="cappeers"><b>Allowed peers</b> '+cap.peers.map(function(p){return '<span class="cappeer">'+esc(p)+'</span>';}).join('')+'</div>'
    +'<div class="capcols"><div class="capcol"><div class="capch ok">PERMITTED</div>'+allow+'</div>'
    +'<div class="capcol"><div class="capch no">DENIED · trips Falco</div>'+deny+'</div></div>';
}
function atkBuildTargets(){
  var c=document.getElementById('atkXapps');if(!c)return;c.innerHTML='';
  (ATK.xapps||XAPP_IDS).forEach(function(id){
    var st=(STATE[id]&&STATE[id].state)||'NORMAL';
    var d=document.createElement('div');d.className='atk-xapp'+(id===ATK.target?' sel':'');d.dataset.state=st;d.dataset.id=id;
    d.innerHTML='<div class="axn"><i></i>'+atkShortLabel(id)+'</div><div class="axs">'+st+'</div>';
    d.onclick=function(){ATK.target=id;atkBuildTargets();atkBuildAttacks();atkBuildCaps();};
    c.appendChild(d);
  });
  atkBuildCaps();
}
/* map an attack (by id / label keyword) to the capability it violates */
function atkViolFor(a){
  var byId={'ZTX-A1':'unexpected_shell','ZTX-A2':'sensitive_file_access','ZTX-A3':'serviceaccount_token_access','ZTX-A8':'external_egress','ZTX-A11':'svid_material_access'};
  var sig=byId[a.id]; var lbl=(a.label||'').toLowerCase();
  if(!sig){
    if(lbl.indexOf('shell')>=0)sig='unexpected_shell';
    else if(lbl.indexOf('token')>=0)sig='serviceaccount_token_access';
    else if(lbl.indexOf('sensitive')>=0||lbl.indexOf('file access')>=0)sig='sensitive_file_access';
    else if(lbl.indexOf('egress')>=0)sig='external_egress';
    else if(lbl.indexOf('svid')>=0)sig='svid_material_access';
    else if(lbl.indexOf('config')>=0||lbl.indexOf('profile')>=0||lbl.indexOf('tamper')>=0)sig='xapp_profile_or_config_tamper';
    else if(lbl.indexOf('escape')>=0)sig='privileged_container_escape_attempt';
    else if(lbl.indexOf('permission')>=0)sig='permission_tamper';
  }
  return sig?SIGVIOL[sig]:null;
}
function atkScopeOK(a,tgt){
  if(a.scope==='python')return tgt.indexOf('hw-python')>=0;
  if(a.scope==='kpimon')return tgt.indexOf('kpimon')>=0;
  return true;
}
function atkScopeNote(a){
  if(a.scope==='python')return 'hw-python only';
  if(a.scope==='kpimon')return 'kpimon-go only';
  return '';
}
function atkBuildAttacks(){
  var c=document.getElementById('atkAttacks');if(!c)return;c.innerHTML='';
  var tgt=ATK.target||'';
  function group(title){var h=document.createElement('div');h.className='atk-group';h.textContent=title;c.appendChild(h);}
  function render(a){
    var ok=atkScopeOK(a,tgt);var dis=!ok;var note=atkScopeNote(a);var kind=a.kind||'falco';
    var d=document.createElement('div');d.className='atk-atk '+kind+(dis?' disabled':'');
    var meta=a.id+' · '+a.rule+(a.tech&&a.tech!=='-'?' · '+a.tech:'')+(note?' · '+note:'');
    var v=atkViolFor(a);
    var vline=(v&&kind==='falco')?'<div class="aa-v">violates <b>'+esc(v[0])+'</b> · <span>'+esc(v[1])+'</span></div>':'';
    d.innerHTML='<div><div class="aa-l">'+a.label+'</div><div class="aa-m">'+meta+'</div>'+(a.desc?'<div class="aa-d">'+a.desc+'</div>':'')+vline+'</div><div class="aa-go">'+(kind==='control'?'Stop':'Launch')+'</div>';
    if(!dis)d.onclick=function(){atkLaunch(tgt,a);};
    c.appendChild(d);
  }
  var falco=ATK.attacks.filter(function(a){return (a.kind||'falco')==='falco';});
  var res=ATK.attacks.filter(function(a){return a.kind==='resource'||a.kind==='control';});
  if(falco.length){group('Falco runtime attacks · any xApp');falco.forEach(render);}
  if(res.length){group('T² resource attacks · kpimon-go only');res.forEach(render);}
  var sel=document.getElementById('atkSel');if(sel)sel.textContent='target · '+atkShortLabel(tgt);
}
function atkLog(cls,msg){
  ATK.log.unshift({cls:cls,msg:msg,t:new Date().toTimeString().slice(0,8)});
  ATK.log=ATK.log.slice(0,60); atkRenderLog();
}
function atkRenderLog(){
  var c=document.getElementById('atkLog');if(!c)return;
  var n=document.getElementById('atkLogN');
  if(!ATK.log.length){c.innerHTML='<div class="empty">no attacks launched yet · pick a target and an attack</div>';if(n)n.textContent='';return;}
  if(n)n.textContent=ATK.log.length+' events';
  c.innerHTML=ATK.log.map(function(e){return '<div class="alr '+e.cls+'"><span class="alt">'+e.t+'</span><span class="alm">'+e.msg+'</span></div>';}).join('');
}
/* ===== Attack Execution playback (right panel of the Attack Console) =====
   When an attack is launched, replay its real kill-chain so anyone can see WHAT
   ran, HOW ZT-XGuard detects it, and the containment it triggers. Stages 1-4
   (operator -> kubectl exec -> command runs -> syscall) are the real, immediate
   execution; stages 5-8 (Falco -> policy -> containment -> verify) are driven by
   the ACTUAL live state + timing of the targeted xApp. */
var ATK_WHAT={
  'ZTX-A1':'Spawns an unexpected shell inside the xApp container — the classic hands-on-keyboard foothold.',
  'ZTX-A2':'Reads /etc/passwd — local account enumeration, a recon step before escalation.',
  'ZTX-A3':'Reads the mounted Kubernetes ServiceAccount token — steals the pod API credential for lateral movement.',
  'ZTX-A8':'Opens a raw TCP socket to an external host (8.8.8.8:53) — data exfiltration / C2 beacon out of the RIC mesh.',
  'ZTX-A6':'Executes a foreign interpreter/tool not in the xApp profile — tool drop / staging.',
  'ZTX-A11':'Reads the SPIFFE SVID key / SPIRE socket — attempts to clone the workload cryptographic identity.',
  'ZTX-A12':'chmod 777 on a protected config file — tampers with the xApp profile / config.',
  'ZTX-LM-03':'Touches the container-runtime socket (containerd/docker/crio) — a container-escape attempt to the node.'
};
var AXE={active:false,xapp:null,kind:null,rule:null,tech:null,t0:0,done:{},key:null};
/* ===== attack scene (animated, map-style demonstration of each attack) ===== */
var AXI={
  bug:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><ellipse cx="12" cy="13" rx="5" ry="6"/><path d="M12 7V4M8.5 9 5.5 6M15.5 9l3-3M7 13H3M17 13h4M8 18l-3 3M16 18l3 3"/></svg>',
  pod:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M8 9h8M8 13h5"/></svg>',
  falco:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  policy:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z"/><path d="M9 12l2 2 4-4"/></svg>',
  canal:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>',
  file:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M6 2h8l4 4v16H6z"/><path d="M14 2v4h4M8 12h8M8 16h6"/></svg>',
  key:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="8" cy="8" r="4"/><path d="M11 11l8 8M16 16l2-2"/></svg>',
  cloud:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M6 17a4 4 0 0 1 .5-8 6 6 0 0 1 11 1.5A3.5 3.5 0 0 1 17 17z"/></svg>',
  cert:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3" y="4" width="18" height="11" rx="2"/><path d="M7 9h7M7 12h4"/><circle cx="17.5" cy="16.5" r="3"/><path d="M15.7 18.6 15 22l2.5-1.4L20 22l-.7-3.4"/></svg>',
  gear:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/></svg>',
  server:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><circle cx="7" cy="7.5" r=".9" fill="currentColor"/><circle cx="7" cy="16.5" r=".9" fill="currentColor"/></svg>',
  cpu:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="6" y="6" width="12" height="12" rx="1.5"/><path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/></svg>',
  tool:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M14 6a4 4 0 0 0-5.5 5.5L3 17l4 4 5.5-5.5A4 4 0 0 0 18 10l-3 1-2-2z"/></svg>'
};
var AXE_SCENE_CFG={
  'ZTX-A1':  {action:'shell', cap:'Adversary spawns an interactive SHELL inside the container — a hands-on-keyboard foothold.'},
  'ZTX-A2':  {asset:'file', alabel:'/etc/passwd', action:'steal', cap:'Reads /etc/passwd — enumerating local accounts before escalation.'},
  'ZTX-A3':  {asset:'key', alabel:'SA token', action:'steal', cap:'Steals the Kubernetes ServiceAccount token — the pod’s API credential for lateral movement.'},
  'ZTX-A6':  {asset:'tool', alabel:'foreign tool', action:'drop', cap:'Drops and runs a tool not in the xApp profile — staging.'},
  'ZTX-A8':  {asset:'cloud', alabel:'8.8.8.8', action:'exfil', cap:'Opens a socket OUT of the RIC mesh — exfiltration / C2 beacon.'},
  'ZTX-A11': {asset:'cert', alabel:'SPIFFE SVID', action:'steal', cap:'Reads the SVID private key — cloning the workload’s cryptographic identity.'},
  'ZTX-A12': {asset:'gear', alabel:'xApp config', action:'tamper', cap:'chmod 777 on a protected config file — tampering with the xApp profile.'},
  'ZTX-LM-03':{asset:'server', alabel:'node runtime', action:'escape', cap:'Touches the container-runtime socket — escaping the container to the host node.'},
  '_resource':{action:'flood', cap:'Floods the CPU under a capped cgroup — resource exhaustion the T² detector catches statistically.'}
};
/* ===== live RIC mini-map for the attack panel (echoes the home map) ===== */
var RIC_ICON='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="4" y="7" width="16" height="10" rx="2"/><circle cx="8" cy="12" r="1" fill="currentColor"/><path d="M12 12h5"/></svg>';
var MAP_NODES=[
  {id:'falco',x:16,y:16,cls:'zt',icon:'falco',label:'Falco'},
  {id:'policy',x:50,y:11,cls:'zt',icon:'policy',label:'Policy'},
  {id:'canal',x:84,y:16,cls:'zt',icon:'canal',label:'Canal'},
  {id:'kpimon',x:20,y:47,cls:'xapp',real:'ricxapp-kpimon-go',label:'kpimon-go'},
  {id:'traffic',x:40,y:47,cls:'xapp',real:'ricxapp-trafficxapp',label:'trafficxapp'},
  {id:'hwgo',x:60,y:47,cls:'xapp',real:'ricxapp-hw-go',label:'hw-go'},
  {id:'hwpy',x:80,y:47,cls:'xapp',real:'ricxapp-hw-python',label:'hw-python'},
  {id:'e2term',x:24,y:83,cls:'ric',label:'e2term'},
  {id:'submgr',x:44,y:83,cls:'ric',label:'submgr'},
  {id:'rtmgr',x:62,y:83,cls:'ric',label:'rtmgr'},
  {id:'influx',x:80,y:83,cls:'ric',label:'influxdb'}
];
var MAP_EDGES=[['kpimon','e2term'],['kpimon','influx'],['traffic','submgr'],['traffic','rtmgr'],['hwgo','e2term'],['hwgo','submgr'],['hwpy','rtmgr'],['hwpy','influx']];
var MAP_XREAL={'ricxapp-kpimon-go':'kpimon','ricxapp-trafficxapp':'traffic','ricxapp-hw-go':'hwgo','ricxapp-hw-python':'hwpy'};
var MAP_XAPPIDS=['kpimon','traffic','hwgo','hwpy'];
var ASC={scene:null,nodes:{},edges:[],raf:null,t:0,target:null,attacking:false,flowTimer:null,built:false};
function ascXY(id){var n=ASC.nodes[id]; return n?{x:n.x,y:n.y}:{x:0,y:0};}
function ascCap(txt,cls){var c=document.getElementById('ascCap'); if(c){c.className='asc-cap '+(cls||''); c.innerHTML=txt;}}
function ascHit(id,cls){var n=ASC.nodes[id]; if(n&&n.el)n.el.classList.add(cls||'act');}
function ascPkt(a,b,cls,dur){
  var pa=ascXY(a), pb=ascXY(b); if((!pa.x&&!pa.y)||(!pb.x&&!pb.y))return;
  var p=document.createElement('div'); p.className='asc-pkt '+(cls||'');
  p.style.left=pa.x+'px'; p.style.top=pa.y+'px'; ASC.scene.appendChild(p); dur=dur||900;
  p.style.transition='left '+dur+'ms cubic-bezier(.4,.1,.35,1),top '+dur+'ms cubic-bezier(.4,.1,.35,1)';
  requestAnimationFrame(function(){p.style.left=pb.x+'px';p.style.top=pb.y+'px';});
  setTimeout(function(){p.remove();},dur+80);
}
function ascFly(a,b,icon,cls,dur){
  var pa=ascXY(a), pb=ascXY(b); var f=document.createElement('div'); f.className='asc-fly '+(cls||'');
  f.innerHTML=icon; f.style.left=pa.x+'px'; f.style.top=pa.y+'px'; ASC.scene.appendChild(f); dur=dur||1400;
  f.style.transition='left '+dur+'ms cubic-bezier(.4,.1,.35,1),top '+dur+'ms cubic-bezier(.4,.1,.35,1),opacity .3s';
  requestAnimationFrame(function(){f.style.left=pb.x+'px';f.style.top=pb.y+'px';});
  setTimeout(function(){f.style.opacity='0';},dur-200); setTimeout(function(){f.remove();},dur+120);
}
function ascAddNode(n){
  var el=document.createElement('div'); el.className='asc-node '+n.cls; el.id='ascn-'+n.id;
  var icon=n.cls==='xapp'?AXI.pod:(n.cls==='ric'?RIC_ICON:(n.cls==='adv'?AXI.bug:(AXI[n.icon]||AXI.pod)));
  el.innerHTML='<span class="asc-i">'+icon+'</span><span class="asc-l">'+esc(n.label)+'</span>';
  ASC.scene.appendChild(el);
  var W=ASC.scene.clientWidth||600,H=ASC.scene.clientHeight||250;
  ASC.nodes[n.id]={el:el,hx:n.x,hy:n.y,phase:Math.random()*6.28,cls:n.cls,real:n.real,x:n.x/100*W,y:n.y/100*H,amp:n.cls==='xapp'?2.6:1.6};
  el.style.left=ASC.nodes[n.id].x+'px'; el.style.top=ASC.nodes[n.id].y+'px'; return n.id;
}
function ascRemove(id){var n=ASC.nodes[id]; if(n){if(n.el)n.el.remove(); delete ASC.nodes[id];} ASC.edges=ASC.edges.filter(function(e){return e.a!==id&&e.b!==id;});}
function ascAddEdge(a,b,cls){var svg=document.getElementById('asc-links'); var ln=document.createElementNS('http://www.w3.org/2000/svg','line'); ln.setAttribute('class','asc-edge'+(cls?(' '+cls):'')); svg.appendChild(ln); ASC.edges.push({a:a,b:b,ln:ln});}
function ascFlowEdge(a,b,cls){ASC.edges.forEach(function(e){ if((e.a===a&&e.b===b)||(e.a===b&&e.b===a)){e.ln.classList.add('flow'); if(cls)e.ln.classList.add(cls);} });}
function ascSeverTarget(t){ASC.edges.forEach(function(e){ if((e.a===t||e.b===t)&&e.ln.classList.contains('data')){e.ln.classList.remove('flow','atk','det','con');e.ln.classList.add('severed');} });}
function ascLoop(){
  var s=ASC.scene; if(!s){ASC.raf=null;return;} var W=s.clientWidth,H=s.clientHeight; ASC.t+=16;
  Object.keys(ASC.nodes).forEach(function(id){var n=ASC.nodes[id]; if(!n.el)return;
    var amp=n.amp; if(id===ASC.target&&ASC.attacking)amp=6.5;
    n.x=n.hx/100*W+Math.sin(ASC.t*0.0016+n.phase)*amp;
    n.y=n.hy/100*H+Math.cos(ASC.t*0.0013+n.phase*1.3)*amp;
    n.el.style.left=n.x+'px'; n.el.style.top=n.y+'px';
  });
  ASC.edges.forEach(function(e){var a=ASC.nodes[e.a],b=ASC.nodes[e.b]; if(a&&b){e.ln.setAttribute('x1',a.x);e.ln.setAttribute('y1',a.y);e.ln.setAttribute('x2',b.x);e.ln.setAttribute('y2',b.y);}});
  ASC.raf=requestAnimationFrame(ascLoop);
}
function ascFlowTick(){
  // colour each xApp by its REAL state, sever+stop flow when contained, flow when healthy
  MAP_NODES.forEach(function(n){ if(n.cls!=='xapp')return; var nn=ASC.nodes[n.id]; if(!nn||!nn.el)return;
    var st=(STATE[n.real]&&pub(STATE[n.real].state))||'NORMAL'; nn.el.setAttribute('data-st',st);
  });
  MAP_EDGES.forEach(function(e){ var mn=MAP_NODES.filter(function(n){return n.id===e[0];})[0]; var st=(STATE[mn.real]&&pub(STATE[mn.real].state))||'NORMAL';
    var edge=ASC.edges.filter(function(x){return x.a===e[0]&&x.b===e[1];})[0]; if(!edge)return;
    if(st==='COMPROMISED'||st==='ISOLATED'){ edge.ln.classList.add('severed'); }
    else { edge.ln.classList.remove('severed'); if(Math.random()<0.55)ascPkt(e[0],e[1],'ok',1100); }
  });
}
function ascBuildMap(){
  var s=document.getElementById('axeScene'); if(!s)return; ASC.scene=s; ASC.nodes={}; ASC.edges=[]; ASC.target=null; ASC.attacking=false;
  s.innerHTML='<svg class="asc-links" id="asc-links"></svg><div class="asc-cap" id="ascCap"></div>';
  MAP_NODES.forEach(ascAddNode);
  MAP_EDGES.forEach(function(e){ascAddEdge(e[0],e[1],'data');});
  ['falco','policy','canal'].forEach(function(z){ MAP_XAPPIDS.forEach(function(x){ ascAddEdge(z,x,'zt'); }); });
  ASC.built=true;
  if(ASC.raf)cancelAnimationFrame(ASC.raf); ASC.raf=requestAnimationFrame(ascLoop);
  clearInterval(ASC.flowTimer); ASC.flowTimer=setInterval(ascFlowTick,1300); ascFlowTick();
  ascCap('Live RIC map · pick a target and <b>Launch</b> an attack to watch it play out.','');
}
function ascBadge(id,html){var n=ASC.nodes[id]; if(!n)return; var b=document.createElement('div'); b.className='asc-badge'; b.innerHTML=html; b.style.left=(n.x+22)+'px'; b.style.top=(n.y-20)+'px'; ASC.scene.appendChild(b); setTimeout(function(){b.remove();},3200);}
function ascWaves(id){var n=ASC.nodes[id]; if(!n)return; for(var i=0;i<4;i++){(function(i){setTimeout(function(){if(!ASC.nodes[id])return; var w=document.createElement('div'); w.className='asc-wave'; w.style.left=n.x+'px'; w.style.top=n.y+'px'; ASC.scene.appendChild(w); setTimeout(function(){w.remove();},1500);},i*420);})(i);} }
function axeSceneBuild(a,xapp){
  if(!ASC.built||!document.getElementById('ascn-falco'))ascBuildMap();
  AXE.cfg=AXE_SCENE_CFG[a.id]||(AXE.kind==='resource'?AXE_SCENE_CFG._resource:{action:'shell',cap:(ATK_WHAT[a.id]||'Runs an operation the xApp profile forbids.')});
  ASC.target=MAP_XREAL[xapp]||'kpimon';
}
/* play the attack action ON the target xApp of the live map */
function axeSceneAttack(){
  var cfg=AXE.cfg||{}, tid=ASC.target, tn=ASC.nodes[tid]; if(!tn)return; ASC.attacking=true; var act=cfg.action;
  ascCap('<b>Adversary</b> exec’s into <b>'+atkShortLabel(AXE.xapp)+'</b> and runs the payload.','warn');
  var advId='_adv'; if(ASC.nodes[advId])ascRemove(advId);
  ascAddNode({id:advId,x:Math.max(5,tn.hx-15),y:tn.hy,cls:'adv',label:'adversary'});
  ascPkt(advId,tid,'atk',900);
  setTimeout(function(){
    ascCap(cfg.cap||'','warn');
    var ax=(tn.hx<50?tn.hx+15:tn.hx-15), ay=Math.max(30,tn.hy-20);
    if(act==='steal'){ var s1=ascAddNode({id:'_ast',x:ax,y:ay,cls:'asset',icon:cfg.asset,label:cfg.alabel}); ascFly(s1,tid,AXI[cfg.asset]||AXI.file,'steal',1400); ascHit('_ast','lost'); setTimeout(function(){ascRemove(s1);},1700); }
    else if(act==='drop'){ var s2=ascAddNode({id:'_ast',x:ax,y:ay,cls:'asset',icon:cfg.asset,label:cfg.alabel}); ascFly(advId,tid,AXI[cfg.asset]||AXI.tool,'atk',1300); setTimeout(function(){ascRemove(s2);},1700); }
    else if(act==='tamper'){ var s3=ascAddNode({id:'_ast',x:ax,y:ay,cls:'asset',icon:cfg.asset,label:cfg.alabel}); ascFly(tid,s3,AXI.tool,'atk',1300); ascHit('_ast','lost'); setTimeout(function(){ascRemove(s3);},1800); }
    else if(act==='exfil'){ var s4=ascAddNode({id:'_ast',x:95,y:24,cls:'asset',icon:'cloud',label:cfg.alabel}); ascFly(tid,s4,'<span class="asc-doc">DATA</span>','exfil',1500); setTimeout(function(){ascRemove(s4);},2000); }
    else if(act==='escape'){ var s5=ascAddNode({id:'_ast',x:tn.hx,y:96,cls:'asset',icon:'server',label:cfg.alabel}); ascFly(tid,s5,'<span class="asc-doc">ESC</span>','atk',1400); setTimeout(function(){ascRemove(s5);},1900); }
    else if(act==='shell'){ ascBadge(tid,'&gt;_'); }
    else if(act==='flood'){ ascWaves(tid); }
    setTimeout(function(){ascRemove(advId);},1600);
  },1050);
}
function axeStep(txt,cls){var c=document.getElementById('axeSteps');if(!c)return;var t=lkTime(new Date());var d=document.createElement('div');d.className='axe-step '+(cls||'');d.innerHTML='<span class="axs-t">'+t+'</span><span class="axs-x">'+txt+'</span>';c.appendChild(d);c.scrollTop=c.scrollHeight;}
function atkExecReset(){
  AXE.active=false;AXE.done={};
  var b=document.getElementById('axeBody'),i=document.getElementById('axeIdle');
  if(b)b.removeAttribute('hidden'); if(i)i.style.display='none';   // the live map IS the idle view
  ascBuildMap();
  var s=document.getElementById('axeSub');if(s)s.textContent='live map · awaiting launch';
  var rb=document.getElementById('axeReplay'); if(rb)rb.setAttribute('hidden','');
}
var AXE_LAST=null;
/* replay the last attack on the map, on a scripted timeline (demo playback) */
function axeReplay(){
  if(!AXE_LAST)return; var a=AXE_LAST.a, xapp=AXE_LAST.xapp;
  AXE={active:false,xapp:xapp,kind:a.kind||'falco',rule:a.rule,tech:a.tech,t0:Date.now(),done:{},key:null,cfg:null};
  document.getElementById('axeSub').textContent='replay · '+atkShortLabel(xapp);
  axeSceneBuild(a,xapp); axeSceneAttack(); var tid=ASC.target;
  var det=(a.kind==='resource')?3400:2600;
  setTimeout(function(){ ascHit('falco','act'); ascFlowEdge('falco',tid,'det'); ascPkt('falco',tid,'det',800); ascCap((a.kind==='resource'?'<b>T² detector</b>':'<b>Falco</b>')+' catches it at the kernel — rule <b>'+esc(a.rule||'')+'</b>.','det'); },det);
  setTimeout(function(){ ascHit('policy','act'); ascFlowEdge('policy',tid,'det'); ascPkt('policy',tid,'det',800); ascCap('<b>Policy Engine</b> decides: COMPROMISED — containment required.','det'); },det+1300);
  setTimeout(function(){ ascHit('canal','act'); ascFlowEdge('canal',tid,'con'); ascPkt('canal',tid,'con',800); ascSeverTarget(tid); ascCap('<b>Containment</b> applied — NetworkPolicy · service isolation · node iptables · SVID revoke.','con'); ASC.attacking=false; },det+2800);
}
function atkExecStart(xapp,a){
  var body=document.getElementById('axeBody'),idle=document.getElementById('axeIdle'); if(!body)return;
  idle.style.display='none'; body.removeAttribute('hidden');
  AXE_LAST={a:a,xapp:xapp,tim:null};
  var rb=document.getElementById('axeReplay'); if(rb)rb.removeAttribute('hidden');
  AXE={active:true,xapp:xapp,kind:a.kind||'falco',rule:a.rule,tech:a.tech,t0:Date.now(),done:{},key:xapp+'|'+a.id+'|'+Date.now()};
  // anchor detection timing at this launch instant; clear any prior measurement
  ATK_LAUNCH[xapp]=AXE.t0; delete ATK_DET[xapp]; delete ATK_COMPR_AT[xapp]; atkTimeSave();
  document.getElementById('axeSub').textContent='live · '+atkShortLabel(xapp);
  document.getElementById('axeName').textContent=a.label;
  document.getElementById('axeTech').textContent=(a.id+' · '+a.rule+(a.tech&&a.tech!=='-'?' · '+a.tech:''));
  document.getElementById('axeTarget').textContent='pod exec · '+atkShortLabel(xapp);
  document.getElementById('axeCmd').textContent=(a.command||'(command)');
  document.getElementById('axeSteps').innerHTML='';
  var v=atkViolFor(a); var what=ATK_WHAT[a.id]||(AXE.kind==='resource'?'Floods CPU with stress-ng under a capped cgroup — resource-exhaustion the T² detector catches statistically.':'Runs a command the xApp profile forbids.');
  document.getElementById('axeImpact').innerHTML='<b>What it does</b> '+esc(what)+(v?('<br><b>Violates</b> '+esc(v[0])+' · <span class="axe-path">'+esc(v[1])+'</span>'):'');
  // build + play the animated attack scene
  axeSceneBuild(a,xapp);
  axeSceneAttack();
  axeStep('Operator launched <b>'+esc(a.label)+'</b> against <b>'+esc(atkShortLabel(xapp))+'</b>','ok');
  setTimeout(function(){ axeStep('Kubernetes <b>pods/exec</b> → <code>'+esc(a.command||'')+'</code>','cmd'); },600);
  setTimeout(function(){ axeStep(AXE.kind==='resource'?'CPU load builds under the cgroup quota':'Syscall reaches the kernel — visible to Falco','ok'); },1600);
  setTimeout(function(){ axeStep(AXE.kind==='resource'?'T² detector scoring resource metrics (MEWMA + 6-of-8)…':'awaiting kernel-level detection…','wait'); },2400);
}
function atkExecTick(){
  if(!AXE.active)return;
  var x=AXE.xapp; var st=(STATE[x]&&pub(STATE[x].state))||'NORMAL';
  var tim=(window._timing||{})[x]||null;
  var isT2=AXE.kind==='resource';
  var tid=ASC.target;
  if(!AXE.done.falco && (st==='SUSPICIOUS'||st==='COMPROMISED'||st==='ISOLATED')){
    AXE.done.falco=1; ascHit('falco','act'); ascFlowEdge('falco',tid,'det'); ascPkt('falco',tid,'det',800);
    ascCap((isT2?'<b>T² detector</b>':'<b>Falco</b>')+' catches it at the kernel — rule <b>'+esc(AXE.rule||'')+'</b> → '+st,'det');
    axeStep((isT2?'T² detector':'Falco')+' matched <b>'+esc(AXE.rule||'rule')+'</b>'+(AXE.tech&&AXE.tech!=='-'?(' ('+esc(AXE.tech)+')'):'')+' → <b>'+st+'</b>','det');
  }
  if(!AXE.done.policy && (st==='COMPROMISED'||st==='ISOLATED')){
    AXE.done.policy=1; ascHit('policy','act'); ascFlowEdge('policy',tid,'det'); ascPkt('policy',tid,'det',800);
    ascCap('<b>Policy Engine</b> decides: <b>'+st+'</b> — containment required.','det');
    axeStep('Policy Engine decision: <b>'+st+'</b> · containment required','det');
  }
  var contained=(tim&&(tim.total_ms!=null))||st==='ISOLATED';
  if(!AXE.done.contain && contained){
    AXE.done.contain=1; if(AXE_LAST)AXE_LAST.tim=tim;
    ascHit('canal','act'); ascFlowEdge('canal',tid,'con'); ascPkt('canal',tid,'con',800); ascSeverTarget(tid);
    var parts=[]; if(tim){ if(tim.netpol_ms!=null)parts.push('NetPol '+fmtMs(tim.netpol_ms)); if(tim.svc_ms!=null)parts.push('SvcIso '+fmtMs(tim.svc_ms)); if(tim.ipt_ms!=null)parts.push('iptables '+fmtMs(tim.ipt_ms)); if(tim.svid_revoke_ms!=null)parts.push('SVID '+fmtMs(tim.svid_revoke_ms)); }
    ascCap('<b>Containment</b> applied — NetworkPolicy · service isolation · node iptables · SVID revoke.','con');
    axeStep('Containment applied — '+(parts.length?parts.join(' · '):'4 locks')+'','con');
    document.getElementById('axeSub').textContent='contained · '+atkShortLabel(x);
    ASC.attacking=false; AXE.active=false;   // kill-chain shown; the map now follows real state
  }
}
function atkLaunch(xapp,a){
  var kind=a.kind||'falco';
  if(kind!=='control') atkExecStart(xapp,a);   // begin the execution playback
  if(kind==='control'){atkLog('ok','<b>'+atkShortLabel(xapp)+'</b> · '+a.label+'…');}
  else if(kind==='resource'){atkLog('ok','<b>'+atkShortLabel(xapp)+'</b> ← starting <b>'+a.label+'</b> ('+a.rule+') — T² detects in ~25s, isolates after a 30s dwell');}
  else{atkLog('ok','<b>'+atkShortLabel(xapp)+'</b> ← launching <b>'+a.label+'</b> ('+a.id+' · '+a.rule+')');}
  fetch('/csm/attack/launch'+nc(),{method:'POST',headers:{'Content-Type':'application/json','Cache-Control':'no-cache'},cache:'no-store',body:JSON.stringify({xapp:xapp,attack:a.id})})
    .then(function(r){return r.json();}).then(function(d){
      if(d.launched){
        if(d.command&&AXE.active&&AXE.xapp===xapp){var cc=document.getElementById('axeCmd');if(cc)cc.textContent=d.command; var tt=document.getElementById('axeTarget');if(tt&&d.pod)tt.textContent='exec · '+d.pod+' / '+(d.container||'');}
        atkLog('ok', kind==='resource'?('load running in <b>'+(d.container||'?')+'</b> — watch the T² detection card + fleet'):(kind==='control'?'stress-ng stopped in <b>'+(d.container||'?')+'</b>':'exec ok in <b>'+(d.container||'?')+'</b> · '+(d.pod||'')+' — watching for detection…'));}
      else{atkLog('err','launch failed: '+(d.error||'unknown')); if(AXE.active&&AXE.xapp===xapp)axeStep('launch failed: '+esc(d.error||'unknown'),'err');}
    }).catch(function(){atkLog('err','launch request failed (network)');});
}
function atkOnState(){
  atkExecTick();
  var c=document.getElementById('atkFleet');
  if(c){c.innerHTML=(ATK.xapps||XAPP_IDS).map(function(id){var st=(STATE[id]&&STATE[id].state)||'NORMAL';return '<div class="afx" data-state="'+st+'"><b>'+atkShortLabel(id)+'</b><span style="color:var('+(CVAR[st]||'--muted')+')">'+st+'</span></div>';}).join('');}
  (ATK.xapps||XAPP_IDS).forEach(function(id){
    var st=(STATE[id]&&STATE[id].state)||'NORMAL';var prev=ATK.lastState[id];
    if(prev&&prev!==st){
      var cls='ok',word='';
      if(st==='SUSPICIOUS'&&prev==='NORMAL'){cls='det';word='detected · anomaly';}
      else if(st==='COMPROMISED'){cls='det';word='detected · compromise';}
      else if(st==='ISOLATED'){cls='con';word='contained · isolated';}
      else if(st==='NORMAL'&&(prev==='COMPROMISED'||prev==='ISOLATED')){cls='ok';word='restored';}
      else{word=null;}
      if(word!==null)atkLog(cls,'<b>'+atkShortLabel(id)+'</b> '+prev+' → <b>'+st+'</b> · '+word);
    }
    ATK.lastState[id]=st;
  });
  document.querySelectorAll('#atkXapps .atk-xapp').forEach(function(el){var st=(STATE[el.dataset.id]&&STATE[el.dataset.id].state)||'NORMAL';el.dataset.state=st;var s=el.querySelector('.axs');if(s)s.textContent=st;});
}
/* re-measure the stage + un-collapse any pods that got clamped into the corner
   while the map was hidden, and refresh the charts. Called on return to Overview. */
function homeRelayout(){
  requestAnimationFrame(function(){
    sizeStage();
    if(W>4&&H>4){ NODES.forEach(function(n){ var p=P[n.id]; if(p&&p.fx==null&&p.x<48&&p.y<58){ var h=home(n); p.x=h.x; p.y=h.y; p.vx=0; p.vy=0; } }); }
    if(typeof chCpu!=='undefined'&&chCpu){ [chCpu,chMem,chRx,chTx].forEach(function(c){ if(c&&c.draw)c.draw(); }); }
  });
}
function atkShowView(on){
  document.body.classList.toggle('atk',on);
  var v=document.getElementById('atkView');if(v){if(on)v.removeAttribute('hidden');else v.setAttribute('hidden','');}
  document.getElementById('navAttack').classList.toggle('on',on);
  document.getElementById('navOverview').classList.toggle('on',!on);
  if(on){atkFetchCatalog();atkRenderLog();atkOnState(); if(!AXE.active)atkExecReset();}
  else {homeRelayout(); if(ASC.raf){cancelAnimationFrame(ASC.raf);ASC.raf=null;} clearInterval(ASC.flowTimer); ASC.flowTimer=null; ASC.built=false;}
}

/* ===== xApp detail view (double-click an xApp circle) ===== */
var XD={xid:null,detailTimer:null,logTimer:null,graphTimer:null,range:1800,charts:{},mapPos:{},pktSeq:0,anomalyStart:null,lastCpuActual:null,mapIds:[],mapP:{},mapHome:{},mapEdges:[],mapDom:{},mapRaf:null,mapW:0,mapH:0};
var XD_CONNS_ZT=['falco','policy-engine','canal','spire'];

function xdShortLabel(id){return (byId[id]&&byId[id].label)||String(id).replace('ricxapp-','');}

function xdOpen(id){
  XD.xid=id; XD.anomalyStart=null; XD.lastCpuActual=null; XD.charts={};
  document.body.classList.add('xdetail');
  document.getElementById('xdView').removeAttribute('hidden');
  document.getElementById('xdName').textContent=xdShortLabel(id);
  document.getElementById('xdMapSub').textContent=xdShortLabel(id)+' · connected components';
  xdBuildMap(id);
  xdResetTerm();
  var ci=document.getElementById('xdCmdInput'); if(ci)ci.value='';   // show the command hints placeholder
  var tt=document.getElementById('xdTermTarget'); if(tt)tt.textContent='· '+xdShortLabel(id);
  XDV.res=null; XDV.hist=[]; XDV.hi=0;
  xdPollDetail(); xdPollLogs(); xdPollGraphs();
  clearInterval(XD.detailTimer); clearInterval(XD.logTimer); clearInterval(XD.graphTimer);
  XD.detailTimer=setInterval(xdPollDetail,2000);
  XD.logTimer=setInterval(xdPollLogs,5000);
  XD.graphTimer=setInterval(xdPollGraphs,15000);
}
function xdClose(){
  document.body.classList.remove('xdetail');
  document.getElementById('xdView').setAttribute('hidden','');
  clearInterval(XD.detailTimer); clearInterval(XD.logTimer); clearInterval(XD.graphTimer);
  if(XD.mapRaf){cancelAnimationFrame(XD.mapRaf);XD.mapRaf=null;}
  XD.xid=null;
  homeRelayout();
}

/* ---- row1: T2 gauges, detection, latency, event log ---- */
function xdPollDetail(){
  if(!XD.xid)return;
  fetch('/csm/xapp/'+XD.xid+'/detail'+nc(),NO).then(function(r){return r.json();}).then(function(d){
    if(!d||!d.ok)return;
    var st=pub(d.state);
    var sd=document.getElementById('xdSd');sd.style.color='var('+(CVAR[st]||'--muted')+')';sd.style.background='currentColor';
    var se=document.getElementById('xdState');se.textContent=st;se.className='xdstate '+st;
    document.getElementById('xdUpd').textContent='updated '+new Date().toTimeString().slice(0,8);
    xdUpdateMapState(st);

    // active-attack window: shade graphs from when this xApp last left NORMAL
    if(st==='NORMAL'){ XD.anomalyStart=null; }
    else if(XD.anomalyStart==null){ XD.anomalyStart=Date.now()/1000; }
    Object.keys(XD.charts).forEach(function(k){XD.charts[k].setAttackWindow(XD.anomalyStart);});

    xdBuildT2Gauges(d.t2);
    xdBuildThrottle(d.t2);
    xdBuildDetRows(d, st);
    xdBuildLat(d.containment);
    xdBuildEvents(d.events||[]);

    var isoBtn=document.getElementById('xdBtnIsolate');
    isoBtn.disabled=(st!=='COMPROMISED');
    isoBtn.title=(st==='COMPROMISED')?'Force isolation now, skipping the remaining dwell':'Only available while COMPROMISED (mid-dwell)';
  }).catch(function(){});
}

function xdBuildT2Gauges(t2){
  var c=document.getElementById('xdT2Gauges');
  var sub=document.getElementById('xdT2Sub');
  if(!t2){
    sub.textContent='';
    c.innerHTML='<div class="xdt2empty">T² resource detector only monitors kpimon-go (the RIC-KPI processing xApp). Other xApps are covered by Falco runtime detection only.</div>';
    return;
  }
  sub.textContent=t2.sample_quality||'';
  var s=t2.score||{}, cg=t2.cpu_rate_gate||{}, cf=t2.confirmation||{};
  var scoreMax=(s.upper_limit||15)*1.4;
  var scorePct=Math.min(100,((s.value||0)/scoreMax)*100);
  var wlPct=Math.min(100,((s.warning_limit||0)/scoreMax)*100);
  var ulPct=Math.min(100,((s.upper_limit||0)/scoreMax)*100);
  var scoreCls=(s.value>=s.upper_limit)?'crit':(s.value>=s.warning_limit)?'warn':'';
  var cgPct=cg.window?Math.min(100,(cg.hits/cg.window)*100):0;
  var cgCls=cg.hit?'crit':(cgPct>50?'warn':'');
  var h='';
  h+='<div class="xdg"><div class="xdgl"><span>T² Pressure Score</span><b>'+(s.value!=null?s.value.toFixed(2):'—')+' / UCL '+(s.upper_limit!=null?s.upper_limit.toFixed(1):'—')+'</b></div>'
    +'<div class="xdg-track"><div class="xdg-zone" style="left:'+wlPct+'%; width:'+(ulPct-wlPct)+'%; background:var(--suspicious)"></div>'
    +'<div class="xdg-zone" style="left:'+ulPct+'%; width:'+(100-ulPct)+'%; background:var(--compromised)"></div>'
    +'<div class="xdg-fill '+scoreCls+'" style="width:'+scorePct+'%"></div>'
    +'<div class="xdg-mark" style="left:'+wlPct+'%"></div><div class="xdg-mark" style="left:'+ulPct+'%"></div></div></div>';
  h+='<div class="xdg"><div class="xdgl"><span>CPU-rate Gate</span><b>'+(cg.hits!=null?cg.hits:'—')+' / '+(cg.window||60)+' samples over '+(cg.floor_millicores?Math.round(cg.floor_millicores):'—')+'mC</b></div>'
    +'<div class="xdg-track"><div class="xdg-fill '+cgCls+'" style="width:'+cgPct+'%"></div>'
    +'<div class="xdg-mark" style="left:'+((cg.rate_threshold||0.15)*100)+'%"></div></div></div>';
  var hits=cf.hits||0, win=cf.window||8;
  var dots='';
  for(var i=0;i<win;i++){dots+='<i'+(i<hits?' class="hit"':'')+'></i>';}
  h+='<div class="xdg"><div class="xdgl"><span>6-of-8 Confirmation</span><b>'+hits+' / '+win+(cf.confirmed?' · confirmed':'')+'</b></div>'
    +'<div class="xd8'+(cf.confirmed?' confirmed':'')+'">'+dots+'</div></div>';
  if(t2.resource_label && t2.resource_label!=='—'){
    h+='<div class="xdg"><div class="xdgl"><span>Likely resource</span><b>'+t2.resource_label+'</b></div></div>';
  }
  c.innerHTML=h;
}

function xdBuildDetRows(d,st){
  var c=document.getElementById('xdDetRows');
  var isT2=(''+(d.last_source||'')).indexOf('t2')>=0 || (''+(d.last_signal||'')).indexOf('resource_anomaly_t2')>=0;
  var level=(st==='COMPROMISED'||st==='ISOLATED')?'compromised':(st==='SUSPICIOUS')?'suspicious':'idle';
  var falcoLevel=isT2?'idle':level, t2Level=isT2?level:'idle';
  var sig=d.last_signal||'';
  var falcoLabel=isT2?'idle':((TECH[sig]&&TECH[sig][0])||(falcoLevel!=='idle'?'Runtime anomaly':'idle'));
  var t2=d.t2;
  var t2Label=isT2?((t2&&t2.resource_label!=='—'&&t2.resource_label)||'Resource anomaly'):'idle';
  function row(cls,label,val,level){
    return '<div class="detrow '+cls+(level==='suspicious'?' susp':level==='compromised'?' active':'')+'">'
      +'<span class="dl"><i></i>'+label+'</span><span class="dv">'+val+'</span></div>';
  }
  c.innerHTML=row('falco','Behavior',falcoLabel,falcoLevel)+row('t2','Resource',t2Label,t2Level);
}

function xdBuildLat(t){
  var lv=document.getElementById('xdLatVerify');
  var list=document.getElementById('xdLatList'), foot=document.getElementById('xdLatFoot');
  if(!t||!t.applied){
    list.innerHTML=MECHS.map(function(m){return '<div class="lrow pending"><div class="lh"><span class="lname"><i></i>'+m.label+'</span><span class="lval">—</span></div><div class="lbar"><i style="width:0%"></i></div></div>';}).join('');
    foot.textContent='no active containment'; lv.textContent=''; return;
  }
  var total=0;
  list.innerHTML=MECHS.map(function(m){
    var ms=t[m.tk];
    if(ms!=null){total+=ms; return '<div class="lrow done"><div class="lh"><span class="lname"><i></i>'+m.label+'</span><span class="lval">'+fmtMs(ms)+'</span></div><div class="lbar"><i style="width:'+Math.min(100,ms/LAT_SCALE*100)+'%"></i></div></div>';}
    return '<div class="lrow pending"><div class="lh"><span class="lname"><i></i>'+m.label+'</span><span class="lval">—</span></div><div class="lbar"><i style="width:0%"></i></div></div>';
  }).join('');
  var tot=parallelMs(t)||total;
  foot.textContent='parallel · slowest mechanism '+fmtMs(tot);
  lv.textContent=(t.verify_ms!=null)?('verify '+fmtMs(t.verify_ms)):'';
}

function xdBuildEvents(events){
  var c=document.getElementById('xdEvents'), n=document.getElementById('xdEvN');
  n.textContent=events.length?events.length+' events':'';
  if(!events.length){c.innerHTML='<div class="empty">no recent events</div>';return;}
  c.innerHTML=events.map(function(e){
    var isT2=(''+(e.source||'')).indexOf('t2')>=0;
    var cls=(pub(e.state)==='ISOLATED')?'con':(pub(e.state)==='COMPROMISED')?'det':(pub(e.state)==='SUSPICIOUS')?'':'ok';
    var label=(TECH[e.signal]&&TECH[e.signal][0])||e.signal||'—';
    return '<div class="alr '+cls+'"><span class="alt">'+shortTs(e.time)+'</span><span class="alm">'+(isT2?'T² · ':'Falco · ')+'<b>'+label+'</b> · '+pub(e.state)+'</span></div>';
  }).join('');
}

/* ---- row2: container logs, graphs ---- */
/* Semantic log syntax-highlighting. Industry-standard severity coloring
   (error=red, warn=amber, ok=green) plus domain-aware highlights so an
   operator can eyeball an xApp's behaviour at a glance: RIC/E2 protocol
   traffic, KPM/cell metrics, InfluxDB writes, and SPIFFE/SVID identity
   material each get their own colour. Uses a private-use-area token pass
   so an earlier match is never re-scanned by a later rule. */
var XD_LOG_RULES={
  main:[
    {re:/\b(error|errors|failed|failure|fatal|panic|exception|refused|timed?\s?out|timeout|unreachable|not ready|unready|registration fail\w*|deregister\w*|cannot|unable|denied|dropped|disconnect\w*|lost)\b/gi, cls:'lg-err'},
    {re:/\b(warn(ing)?|retry|retrying|degraded|stale|reconnect\w*|backoff)\b/gi, cls:'lg-warn'},
    {re:/\b(connected|established|registered|subscription\s+success\w*|subscribed|success(ful)?|ready|healthy|active|running|started)\b/gi, cls:'lg-ok'},
    {re:/\b(RIC_INDICATION|RIC_SUB\w*|RIC_CONTROL\w*|E2AP|E2SM(?:-KPM)?|E2\s?node|RMR|ric indication|indication\s+message|subscription)\b/gi, cls:'lg-proto'},
    {re:/\b(cell\s+metrics|no\.?\s*of\s*cells|number\s+of\s+cells|cell[-\s]?id|cells?|PRB\w*|RSRP|RSRQ|SINR|throughput|MeasReport|measurement\w*|KPM|KPI(?!mon)\b|CQI|DRB\w*)\b/gi, cls:'lg-metric'},
    {re:/\b(influx\w*|writing\s+to\s+\w+|write\s+point|inserted|persist\w*|SDL|RNIB|redis)\b/gi, cls:'lg-store'},
    {re:/\b(parsing|decoding|encoding|processing|building)\b/gi, cls:'lg-verb'},
    {re:/([:=]\s*)(\d+(?:\.\d+)?)/g, cls:'lg-num', grp:2}
  ],
  svid:[
    {re:/\b(error|failed|fail\w*|denied|unavailable|expired|invalid|no\s+svid|no\s+identity|not\s+found|permission\s+denied|revoked|missing)\b/gi, cls:'lg-err'},
    {re:/\b(writing\s+svid|wrote|renewed|renewal|fetched|received|valid|success\w*|updated|rotated|READY|OK)\b/gi, cls:'lg-ok'},
    {re:/(spiffe:\/\/[^\s"'<]+)/gi, cls:'lg-id'},
    {re:/\b(SVID\s*#?\d*|svid\.\d+\.pem|svid\.\d+\.key|X509[-\s]?SVID|JWT[-\s]?SVID|bundle)\b/gi, cls:'lg-material'},
    {re:/\b(CYCLE|RENEW_INTERVAL\w*|NEXT_CHECK\w*|WORKLOAD_API_SOCKET|TIMESTAMP_UTC|POD_HOSTNAME|EXPECTED_SPIFFE_ID|RENEWAL\s+REPORT)\b/gi, cls:'lg-meta'}
  ]
};
/* Benign lines whose wording trips the error highlighter but are NOT failures -
   e.g. kpimon-go's RMR "Constraints failed for encoding subscription request,
   Cannot allocate memory" (a routine RMR encoding-buffer message). For these the
   'failed'/'Cannot' words are NOT reddened and no red line accent is applied. */
var XD_LOG_BENIGN=[
  /constraints failed for encoding subscription request/i,
  /cannot allocate memory/i
];
function xdIsBenignLog(raw){ for(var i=0;i<XD_LOG_BENIGN.length;i++){ if(XD_LOG_BENIGN[i].test(raw))return true; } return false; }
function xdColorLog(raw, kind){
  var benign=xdIsBenignLog(raw);
  var s=raw.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  var store=[]; var tok=function(html){store.push(html);return ''+(store.length-1)+'';};
  (XD_LOG_RULES[kind]||[]).forEach(function(r){
    if(benign && r.cls==='lg-err') return;   // skip red error-word highlighting for benign lines
    s=s.replace(r.re,function(){
      var whole=arguments[0];
      if(r.grp){var pre=arguments[1]||'',val=arguments[r.grp]||'';return pre+tok('<span class="'+r.cls+'">'+val+'</span>');}
      return tok('<span class="'+r.cls+'">'+whole+'</span>');
    });
  });
  s=s.replace(/(\d+)/g,function(_,i){return store[+i];});
  // line-level severity accent
  var lvl='';
  if(!benign && /\b(error|fatal|panic|failed|failure|refused|denied|not ready|registration fail)/i.test(raw))lvl='err';
  else if(!benign && /\b(warn|retry|degraded|stale)/i.test(raw))lvl='warn';
  return {html:s, lvl:lvl};
}
function xdRenderLog(elId,lines,kind){
  var el=document.getElementById(elId);
  var atBottom=(el.scrollTop+el.clientHeight)>=(el.scrollHeight-16);
  el.innerHTML=(lines||[]).map(function(l){
    var m=l.match(/^(\S+)\s([\s\S]*)$/);
    var ts=m?m[1].slice(11,19):''; var body=m?m[2]:l;
    var c=xdColorLog(body,kind);
    return '<span class="ln'+(c.lvl?(' lvl-'+c.lvl):'')+'">'+(ts?('<span class="ts">'+ts+'</span>'):'')+c.html+'</span>';
  }).join('');
  if(atBottom)el.scrollTop=el.scrollHeight;
}
function xdPollLogs(){
  if(!XD.xid)return;
  fetch('/csm/xapp/'+XD.xid+'/logs?container=renew-svid&tail=200'+('&_='+Date.now()),NO).then(function(r){return r.json();}).then(function(d){
    if(d&&d.ok)xdRenderLog('xdLogSvid',d.lines,'svid');
  }).catch(function(){});
  fetch('/csm/xapp/'+XD.xid+'/logs?container=main&tail=200'+('&_='+Date.now()),NO).then(function(r){return r.json();}).then(function(d){
    if(d&&d.ok){document.getElementById('xdLogMainSub').textContent=d.container||'';xdRenderLog('xdLogMain',d.lines,'main');}
  }).catch(function(){});
}

/* Same visual language as the homepage Chart(): thin line, minimal grid,
   glowing last-point dot, per-xApp series color for continuity. Adds a
   soft area fill under the line and real axis labels (peak value, time
   range) since this detail page's graphs are meant to be more detailed
   than the homepage's rolling minis. Also supports a translucent shaded
   band marking an active-attack time window (setAttackWindow). */
function XDChart(canvasId,unit,color){
  var cv=document.getElementById(canvasId),ctx=cv.getContext('2d');
  var pts=[], attackStart=null;
  function resize(){var r=cv.getBoundingClientRect();if(r.width<2||r.height<2)return;var dpr=window.devicePixelRatio||1;cv.width=Math.max(1,r.width*dpr);cv.height=Math.max(1,r.height*dpr);ctx.setTransform(dpr,0,0,dpr,0,0);}
  function set(points){pts=points||[];draw();}
  function setAttackWindow(startEpoch){attackStart=startEpoch;draw();}
  function draw(){
    var r=cv.getBoundingClientRect();var w=r.width,h=r.height;if(w<2||h<2)return;ctx.clearRect(0,0,w,h);
    var PAD_L=30,PAD_B=13,PAD_T=8;
    if(!pts.length){ctx.fillStyle=cssv('--faint');ctx.font='9.5px '+(cssv('--mono')||'monospace');ctx.textAlign='center';ctx.fillText('no data yet',w/2,h/2);return;}
    var vs=pts.map(function(p){return p.v;});
    var mx=Math.max.apply(null,vs)*1.18||1, mn=0;
    var t0=pts[0].t, t1=pts[pts.length-1].t, span=(t1-t0)||1;
    var col=color||cssv('--ctrl');
    function X(t){return PAD_L+((t-t0)/span)*(w-PAD_L-4);}
    function Y(v){return h-((v-mn)/(mx-mn||1))*(h-PAD_T-PAD_B)-PAD_B;}
    // attack-window shaded band (drawn first, under everything)
    if(attackStart!=null && attackStart<=t1){
      var bx=Math.max(PAD_L,X(Math.max(attackStart,t0)));
      ctx.fillStyle='rgba(239,68,68,.10)';
      ctx.fillRect(bx,PAD_T,w-bx,h-PAD_T-PAD_B);
      ctx.strokeStyle='rgba(239,68,68,.35)';ctx.lineWidth=1;ctx.setLineDash([2,3]);
      ctx.beginPath();ctx.moveTo(bx,PAD_T);ctx.lineTo(bx,h-PAD_B);ctx.stroke();ctx.setLineDash([]);
    }
    // grid
    ctx.strokeStyle='rgba(129,140,248,.07)';ctx.lineWidth=1;ctx.beginPath();
    for(var g=1;g<4;g++){var gy=PAD_T+(h-PAD_T-PAD_B)*g/4;ctx.moveTo(PAD_L,gy);ctx.lineTo(w,gy);}
    ctx.stroke();
    // area fill under the line
    ctx.beginPath();
    pts.forEach(function(p,i){var x=X(p.t),y=Y(p.v); i?ctx.lineTo(x,y):ctx.moveTo(x,y);});
    ctx.lineTo(X(t1),h-PAD_B); ctx.lineTo(X(t0),h-PAD_B); ctx.closePath();
    var grad=ctx.createLinearGradient(0,PAD_T,0,h-PAD_B);
    grad.addColorStop(0,col+'33'); grad.addColorStop(1,col+'00');
    ctx.fillStyle=grad; ctx.fill();
    // line
    ctx.strokeStyle=col; ctx.lineWidth=1.4; ctx.lineJoin='round'; ctx.beginPath();
    pts.forEach(function(p,i){var x=X(p.t),y=Y(p.v); i?ctx.lineTo(x,y):ctx.moveTo(x,y);});
    ctx.stroke();
    // last-point glow dot
    var lx=X(t1), ly=Y(vs[vs.length-1]);
    ctx.fillStyle=col; ctx.shadowColor=col; ctx.shadowBlur=6;
    ctx.beginPath(); ctx.arc(lx,ly,2.2,0,7); ctx.fill(); ctx.shadowBlur=0;
    // axis labels
    ctx.fillStyle=cssv('--faint');ctx.font='9px '+(cssv('--mono')||'monospace');
    ctx.textAlign='right'; ctx.fillText(Math.round(mx)+' '+unit,PAD_L-4,PAD_T+8); ctx.fillText('0',PAD_L-4,h-PAD_B+3);
    ctx.textAlign='left'; ctx.fillText(xdAgo(span),PAD_L,h-2);
    ctx.textAlign='right'; ctx.fillText('now',w,h-2);
  }
  window.addEventListener('resize',function(){resize();draw();});resize();
  return {set:set,draw:draw,setAttackWindow:setAttackWindow};
}
function xdAgo(sec){var m=Math.round(sec/60);return m<1?Math.round(sec)+'s ago':'-'+m+'m'}

function xdPollGraphs(){
  if(!XD.xid)return;
  // fixed per-metric colours (homepage palette --x1..--x4), one per graph -
  // NOT tied to which xApp is selected, per explicit correction.
  if(!XD.charts.cpu){
    XD.charts.cpu=XDChart('xdCCpu','mC',cssv('--x1')); XD.charts.mem=XDChart('xdCMem','MB',cssv('--x2'));
    XD.charts.rx=XDChart('xdCRx','KB/s',cssv('--x3')); XD.charts.tx=XDChart('xdCTx','KB/s',cssv('--x4'));
  }
  [['cpu','xdCpuNow','mC'],['mem','xdMemNow','MB'],['rx','xdRxNow','KB/s'],['tx','xdTxNow','KB/s']].forEach(function(m){
    var metric=m[0];
    fetch('/csm/xapp/'+XD.xid+'/metrics_range?metric='+metric+'&range_s='+XD.range+'&step_s='+Math.max(5,Math.round(XD.range/120))+nc(),NO)
      .then(function(r){return r.json();}).then(function(d){
        if(!d||!d.ok)return;
        XD.charts[metric].set(d.points);
        XD.charts[metric].setAttackWindow(XD.anomalyStart);
        var last=d.points&&d.points.length?d.points[d.points.length-1].v:null;
        document.getElementById(m[1]).textContent=last!=null?(last.toFixed(1)+' '+m[2]):'';
        if(metric==='cpu'){XD.lastCpuActual=last; XD.cpuPoints=d.points; xdDrawThrSpark();}
      }).catch(function(){});
  });
}

/* ---- row3: CPU throttle, xApp map, isolation verification ---- */
function xdBuildThrottle(t2){
  var c=document.getElementById('xdThrottle');
  if(XD.xid!=='ricxapp-kpimon-go'){
    c.innerHTML='<div class="xdt-off">CPU throttling is applied to the resource-monitored xApp (kpimon-go) only. Other xApps are contained by network isolation + identity revocation.</div>';
    return;
  }
  if(!t2){c.innerHTML='<div class="xdt-off">T² collector state unavailable.</div>';return;}
  XD.lastT2=t2;
  var th=t2.throttle||{};
  var normalLimit=200, quota=th.quota_millicores||40;
  var active=!!th.active;
  var ceiling=active?quota:normalLimit;
  var actual=XD.lastCpuActual; // real, live Prometheus cAdvisor value (same fetch as the CPU graph)
  var actualPct=actual!=null?Math.min(100,(actual/normalLimit)*100):0;
  var ceilPct=Math.min(100,(ceiling/normalLimit)*100);
  c.innerHTML=
    '<div class="xdt-desc">On a confirmed resource anomaly the T² engine caps kpimon-go\'s CPU cgroup (<b>cpu.max</b>) to starve the abuse while it is contained.</div>'
    +'<div class="xdt-big"><span class="xdt-bignum'+(active?' on':'')+'">'+ceiling+'</span><span class="xdt-bigunit">mC ceiling</span></div>'
    +'<div class="xdt-signame">CPU signature <span>'+(active?'capped':'live')+'</span></div>'
    +'<canvas id="xdThrSpark" class="xdt-spark"></canvas>'
    +'<div class="xdt-kv"><span>live usage</span><b>'+(actual!=null?actual.toFixed(1)+' mC':'—')+'</b></div>'
    +(active?'<span class="xdt-badge on"><i></i>THROTTLED to '+quota+' mC</span>':'<span class="xdt-badge"><i></i>not throttled</span>');
  xdDrawThrSpark();
}
function xdDrawThrSpark(){
  var cv=document.getElementById('xdThrSpark'); if(!cv)return;
  var pts=XD.cpuPoints||[]; var normalLimit=200;
  var t2=XD.lastT2||{}; var th=(t2.throttle||{}); var ceiling=th.active?(th.quota_millicores||40):normalLimit;
  var r=cv.getBoundingClientRect(); var dpr=window.devicePixelRatio||1;
  cv.width=Math.max(1,r.width*dpr); cv.height=Math.max(1,r.height*dpr);
  var ctx=cv.getContext('2d'); ctx.setTransform(dpr,0,0,dpr,0,0);
  var w=r.width,h=r.height; ctx.clearRect(0,0,w,h);
  if(!pts.length){ctx.fillStyle=cssv('--faint');ctx.font='9px '+(cssv('--mono')||'monospace');ctx.textAlign='center';ctx.fillText('no data',w/2,h/2);return;}
  var vs=pts.map(function(p){return p.v;});
  var mx=Math.max(Math.max.apply(null,vs),ceiling)*1.15||1;
  var t0=pts[0].t,t1=pts[pts.length-1].t,span=(t1-t0)||1;
  function Y(v){return h-(v/mx)*(h-4)-2;}
  // ceiling line
  var cy=Y(ceiling);
  ctx.strokeStyle=th.active?cssv('--compromised'):'rgba(129,140,248,.35)'; ctx.lineWidth=1; ctx.setLineDash([3,3]);
  ctx.beginPath();ctx.moveTo(0,cy);ctx.lineTo(w,cy);ctx.stroke();ctx.setLineDash([]);
  // attack shading
  if(XD.anomalyStart!=null&&XD.anomalyStart<=t1){var bx=Math.max(0,((XD.anomalyStart-t0)/span)*w);ctx.fillStyle='rgba(239,68,68,.09)';ctx.fillRect(bx,0,w-bx,h);}
  // area + line (x1 cyan, matching the CPU graph)
  var col=cssv('--x1');
  ctx.beginPath();pts.forEach(function(p,i){var x=(p.t-t0)/span*w,y=Y(p.v);i?ctx.lineTo(x,y):ctx.moveTo(x,y);});
  ctx.lineTo(w,h);ctx.lineTo(0,h);ctx.closePath();
  var g=ctx.createLinearGradient(0,0,0,h);g.addColorStop(0,col+'33');g.addColorStop(1,col+'00');ctx.fillStyle=g;ctx.fill();
  ctx.strokeStyle=col;ctx.lineWidth=1.4;ctx.beginPath();pts.forEach(function(p,i){var x=(p.t-t0)/span*w,y=Y(p.v);i?ctx.lineTo(x,y):ctx.moveTo(x,y);});ctx.stroke();
}

var XD_MAP_BUILT=null;
function xdEdgePath(a,b,bow){
  var mx=(a.x+b.x)/2,my=(a.y+b.y)/2;var dx=b.x-a.x,dy=b.y-a.y;var L=Math.sqrt(dx*dx+dy*dy)||1;var o=(bow||0)*L;
  return 'M'+a.x+' '+a.y+' Q'+(mx-dy/L*o)+' '+(my+dx/L*o)+' '+b.x+' '+b.y;
}
function xdBuildMap(id){
  // Same node/edge markup + CSS classes as the homepage topology AND the same
  // force-directed physics (repulsion between all pairs + spring to a home
  // anchor + per-state jitter + damping), so nodes drift and spread to fill
  // the widget exactly like the homepage - just scoped to this xApp's node
  // set: the xApp (centre), the 4 ZT-plane enforcers, and its real RIC peers.
  var conns=(CONNS[id]||[]).map(function(c){return c[0];});
  var ids=[id].concat(XD_CONNS_ZT).concat(conns);
  var seen={};ids=ids.filter(function(x){if(seen[x])return false;seen[x]=1;return true;});
  var wrap=document.getElementById('xdMapNodes'), g=document.getElementById('xdMapEdgeG');
  wrap.innerHTML=''; g.innerHTML='';
  var W=wrap.parentElement.clientWidth||460, H=wrap.parentElement.clientHeight||300;
  XD.mapIds=ids; XD.mapW=W; XD.mapH=H; XD.mapP={}; XD.mapHome={}; XD.mapDom={}; XD.mapEdges=[];
  var cx=W*0.5, cy=H*0.5;
  // home anchors: xApp at centre; ZT enforcers on an inner ring above,
  // RIC peers on a wider outer ring - spread to use the whole widget.
  var zt=ids.filter(function(x){return XD_CONNS_ZT.indexOf(x)>=0;});
  var peers=ids.filter(function(x){return x!==id && XD_CONNS_ZT.indexOf(x)<0;});
  XD.mapHome[id]={x:cx,y:cy};
  zt.forEach(function(z,i){var a=(i/Math.max(1,zt.length))*Math.PI - Math.PI; XD.mapHome[z]={x:cx+Math.cos(a)*W*0.30,y:cy+Math.sin(a)*H*0.30-H*0.06};});
  peers.forEach(function(pn,i){var a=(i/Math.max(1,peers.length))*Math.PI*2 - Math.PI/2; XD.mapHome[pn]={x:cx+Math.cos(a)*W*0.40,y:cy+Math.sin(a)*H*0.40};});
  ids.forEach(function(nid){
    var hm=XD.mapHome[nid]||{x:cx,y:cy};
    XD.mapP[nid]={x:hm.x+(Math.random()-.5)*24,y:hm.y+(Math.random()-.5)*24,vx:0,vy:0};
    var n=byId[nid]||{label:nid,cat:'ricplt'};
    var el=document.createElement('div');
    el.className='node '+n.cat+(nid===id?' xdcenter':''); el.dataset.id=nid;
    if(n.cat==='xapp')el.dataset.state='NORMAL';
    var h='<div class="disc"><div class="core"></div><div class="halo"></div>';
    if(n.cat==='xapp')h+='<svg class="lock" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="4" y="11" width="16" height="10" rx="2"></rect><path d="M8 11V8a4 4 0 0 1 8 0v3"></path></svg>';
    h+='</div><div class="name">'+n.label+'</div>';
    el.innerHTML=h; wrap.appendChild(el); XD.mapDom[nid]=el;
  });
  // edges: all fan out from the xApp centre to each peer/enforcer
  ids.filter(function(x){return x!==id;}).forEach(function(oid){
    var isZt=XD_CONNS_ZT.indexOf(oid)>=0;
    if(isZt){
      var z=document.createElementNS('http://www.w3.org/2000/svg','path');
      z.setAttribute('class','ztedge'+(oid==='spire'?' spire':'')); XD.mapEdges.push({el:z,a:id,b:oid,bow:0.04}); g.appendChild(z);
      var en=document.createElementNS('http://www.w3.org/2000/svg','path');
      en.setAttribute('class','enforce'); en.dataset.enforce='1'; XD.mapEdges.push({el:en,a:id,b:oid,bow:-0.04}); g.appendChild(en);
    } else {
      var e=document.createElementNS('http://www.w3.org/2000/svg','path');
      e.setAttribute('class','edge'); XD.mapEdges.push({el:e,a:id,b:oid,bow:0.05}); g.appendChild(e);
      var f=document.createElementNS('http://www.w3.org/2000/svg','path');
      f.setAttribute('class','flow'); XD.mapEdges.push({el:f,a:id,b:oid,bow:0.05}); g.appendChild(f);
    }
  });
  XD_MAP_BUILT=id;
  if(XD.mapRaf)cancelAnimationFrame(XD.mapRaf);
  xdMapTick();
}
function xdMapTick(){
  if(!XD.xid){XD.mapRaf=null;return;}
  var ids=XD.mapIds, P=XD.mapP, W=XD.mapW, H=XD.mapH;
  // refresh dims if the card resized
  var wrapEl=document.getElementById('xdMapNodes');
  if(wrapEl&&wrapEl.parentElement){W=XD.mapW=wrapEl.parentElement.clientWidth||W;H=XD.mapH=wrapEl.parentElement.clientHeight||H;}
  // pairwise repulsion
  for(var i=0;i<ids.length;i++)for(var j=i+1;j<ids.length;j++){
    var pa=P[ids[i]],pb=P[ids[j]];if(!pa||!pb)continue;
    var dx=pa.x-pb.x,dy=pa.y-pb.y,d2=dx*dx+dy*dy||1,d=Math.sqrt(d2);
    var f=Math.min(5200/d2,1.6),ux=dx/d,uy=dy/d;
    pa.vx+=ux*f;pa.vy+=uy*f;pb.vx-=ux*f;pb.vy-=uy*f;
  }
  // spring to home + state jitter
  var xst=(STATE[XD.xid]&&STATE[XD.xid].state)||'NORMAL';
  ids.forEach(function(nid){
    var p=P[nid],hm=XD.mapHome[nid];if(!p||!hm)return;
    p.vx+=(hm.x-p.x)*0.05;p.vy+=(hm.y-p.y)*0.05;
    var no=0.13;
    if(nid===XD.xid){if(xst==='SUSPICIOUS')no=0.7;else if(xst==='COMPROMISED')no=2;else if(xst==='ISOLATED')no=0;}
    p.vx+=(Math.random()-.5)*no;p.vy+=(Math.random()-.5)*no;
  });
  // integrate + clamp
  ids.forEach(function(nid){
    var p=P[nid];if(!p)return;
    p.vx*=0.8;p.vy*=0.8;p.x+=p.vx;p.y+=p.vy;
    p.x=Math.max(30,Math.min(W-30,p.x));p.y=Math.max(28,Math.min(H-24,p.y));
    var el=XD.mapDom[nid];if(el){el.style.left=p.x+'px';el.style.top=p.y+'px';}
  });
  // redraw edges
  XD.mapEdges.forEach(function(e){var a=P[e.a],b=P[e.b];if(a&&b)e.el.setAttribute('d',xdEdgePath(a,b,e.bow));});
  XD.mapRaf=requestAnimationFrame(xdMapTick);
}
function xdUpdateMapState(st){
  var el=XD.mapDom[XD.xid];if(el)el.dataset.state=st;
  var iso=(st==='ISOLATED');
  XD.mapEdges.forEach(function(e){
    var cl=e.el.classList;
    if(cl.contains('edge')||cl.contains('flow')){cl.toggle('compromised',iso); if(cl.contains('flow'))e.el.style.opacity=iso?0:'';}
    if(cl.contains('ztedge'))cl.toggle('severing',iso);
    if(cl.contains('enforce'))cl.toggle('on',iso);
  });
}
function xdResetTerm(){
  document.getElementById('xdTermBody').innerHTML='<div class="xdtermline dim">$ interactive verification console — type <b>verify</b> to prove isolation, or <b>help</b> for commands</div>';
  var ch=document.getElementById('xdChecks');
  if(ch)ch.innerHTML=['cp','ingress','egress'].map(function(k){var m=XD_CHECK_META[k];return '<div class="xdchk"><div class="xdchk-ic"></div><div class="xdchk-body"><div class="xdchk-name">'+m.name+'<span class="xdchk-dir">'+m.dir+'</span></div><div class="xdchk-detail">not yet run</div></div><div class="xdchk-badge">—</div></div>';}).join('');
  xdSetHero('','not yet checked');
}
function xdSetHero(cls,text){
  var h=document.getElementById('xdIsoHero');
  h.className='xdisohero'+(cls?(' '+cls):'');
  h.querySelector('.xdisotxt').textContent=text;
}
function xdTermLine(html,delayMs){
  return new Promise(function(res){
    setTimeout(function(){
      var body=document.getElementById('xdTermBody');
      var d=document.createElement('div'); d.className='xdtermline'; d.innerHTML=html;
      body.appendChild(d); body.scrollTop=body.scrollHeight;
      res();
    },delayMs);
  });
}
function xdFirePacket(fromId,toId,blocked){
  var a=XD.mapP[fromId], b=XD.mapP[toId]; if(!a||!b)return;
  var wrap=document.getElementById('xdMapNodes'); if(!wrap)return;
  var el=document.createElement('div'); el.className='xdpkt go'+(blocked?' blocked':' ok');
  var frac=blocked?0.5:0.9;
  var x=a.x+(b.x-a.x)*frac, y=a.y+(b.y-a.y)*frac;
  el.style.left=a.x+'px'; el.style.top=a.y+'px';
  wrap.appendChild(el);
  requestAnimationFrame(function(){el.style.left=x+'px'; el.style.top=y+'px';});
  if(blocked){ // a little "wall" burst where it stops
    setTimeout(function(){var w=document.createElement('div');w.className='xdwall';w.style.left=x+'px';w.style.top=y+'px';wrap.appendChild(w);setTimeout(function(){w.remove();},600);},560);
  }
  setTimeout(function(){el.remove();},1200);
}
function xdBurstPackets(dir,blocked){
  var others=Object.keys(XD.mapP).filter(function(x){return x!==XD.xid;}).slice(0,6);
  others.forEach(function(o,i){setTimeout(function(){
    if(dir==='in')xdFirePacket(o,XD.xid,blocked); else xdFirePacket(XD.xid,o,blocked);
  },i*70);});
}
var XD_CHECK_META={
  cp:{name:'Control-plane rules',dir:'labels + iptables',cmd:'iptables -C ZTX-DIRECT-QUARANTINE -s/-d &lt;ip&gt; DROP'},
  ingress:{name:'Ingress probe',dir:'outside &rarr; xApp',cmd:'nc -z -w3 &lt;podIP&gt; &lt;port&gt; from throwaway pod'},
  egress:{name:'Egress probe',dir:'xApp &rarr; RIC platform',cmd:'nc/wget a RIC platform peer from inside the xApp'}
};
function xdInitChecks(){
  document.getElementById('xdChecks').innerHTML=['cp','ingress','egress'].map(function(k){
    var m=XD_CHECK_META[k];
    return '<div class="xdchk pending" id="xdchk-'+k+'"><div class="xdchk-ic"></div>'
      +'<div class="xdchk-body"><div class="xdchk-name">'+m.name+'<span class="xdchk-dir">'+m.dir+'</span></div>'
      +'<div class="xdchk-detail">'+m.cmd+'</div></div>'
      +'<div class="xdchk-badge">···</div></div>';
  }).join('');
}
function xdSetCheck(k,state,detail,badge){
  var el=document.getElementById('xdchk-'+k);if(!el)return;
  el.className='xdchk '+state;                 // iso (blocked) | open (reachable) | skip | pending
  el.querySelector('.xdchk-detail').innerHTML=detail;
  el.querySelector('.xdchk-badge').textContent=badge;
}
/* ===== interactive verification console ===== */
var XDV={res:null, hist:[], hi:0};
var XD_HELP=[
  'verify      run the full 3-way isolation proof (iptables + ingress + egress)',
  'iptables    node DROP-rule evidence (control-plane)',
  'ingress     external pod -> xApp reachability probe',
  'egress      xApp -> RIC platform reachability probe',
  'labels      the pod security labels',
  'netpol      deny-all NetworkPolicy membership',
  'svid        SPIFFE / SVID identity status',
  'clear       clear the terminal      help    this list'
];
function xdTOut(html,cls){var b=document.getElementById('xdTermBody');if(!b)return;var d=document.createElement('div');d.className='xdtermline';d.innerHTML='<span class="o '+(cls||'')+'">'+html+'</span>';b.appendChild(d);b.scrollTop=b.scrollHeight;}
function xdTEcho(c){var b=document.getElementById('xdTermBody');if(!b)return;var d=document.createElement('div');d.className='xdtermline';d.innerHTML='<span class="p">$</span> '+esc(c);b.appendChild(d);b.scrollTop=b.scrollHeight;}
function xdParseLabels(d){try{return JSON.parse((((d||{}).transcript||[])[0]||{}).out||'{}');}catch(e){return {};}}
function xdShowEvidence(sec,d){
  if(sec==='iptables'){var cp=d.control_plane||{};
    xdTOut('iptables -t raw -C ZTX-DIRECT-QUARANTINE -s/-d '+esc(d.pod_ip)+' -j DROP','');
    xdTOut('egress_blocked='+cp.egress_blocked+'  ingress_blocked='+cp.ingress_blocked+'  ->  '+(cp.blocked?'DROP rules ACTIVE':'no rules'), cp.blocked?'ok':'fail');
  } else if(sec==='ingress'){var ai=d.active_ingress||{};
    xdTOut('[fresh probe pod] nc -z -w3 '+esc(d.pod_ip)+' '+esc(d.port),'');
    xdTOut(ai.reachable?('CONNECTED — reachable ('+(ai.ms||0)+'ms)'):('FAILED / TIMED OUT — blocked ('+(ai.ms||0)+'ms)'), ai.reachable?'fail':'ok');
  } else if(sec==='egress'){var eg=d.active_egress||{};
    if(eg.attempted){ xdTOut('['+esc(XD.xid)+'] '+(eg.tool||'nc')+' -> '+esc(eg.target||''),''); xdTOut(eg.reachable?'CONNECTED — xApp still reached the RIC platform':'FAILED / TIMED OUT — xApp cannot reach the RIC platform', eg.reachable?'fail':'ok'); }
    else { xdTOut('egress probe skipped: '+esc(eg.reason||'target not compromised'),'dim'); }
  } else if(sec==='labels'){var L=xdParseLabels(d);var ks=Object.keys(L); if(!ks.length){xdTOut('(no labels)','dim');} ks.forEach(function(k){xdTOut(esc(k)+'='+esc(L[k]),'');});
  } else if(sec==='netpol'){var L=xdParseLabels(d);var q=(L['zt-xguard.io/quarantine']==='true');
    xdTOut('NetworkPolicy zt-xguard-quarantine-deny-all  selects  zt-xguard.io/quarantine=true','');
    xdTOut('pod matches deny-all: '+(q?'YES — ingress+egress denied by Calico':'no'), q?'ok':'dim');
  } else if(sec==='svid'){var L=xdParseLabels(d);var v=L['zt-xguard.io/svid-enabled'];var revoked=(v==='false');
    xdTOut('zt-xguard.io/svid-enabled='+esc(v||'true'),'');
    xdTOut(revoked?'SVID REVOKED — SPIRE entry withdrawn; no new SVID can be issued':'SVID active — workload identity valid', revoked?'ok':'dim');
  }
}
function xdVerifyCmd(cmd){
  var c=cmd.toLowerCase().replace(/^\.\/|\.sh.*$/g,'').trim();
  if(c==='clear'||c==='cls'){var b=document.getElementById('xdTermBody');if(b)b.innerHTML='';return;}
  xdTEcho(cmd);
  if(c==='help'||c==='?'||c===''){ XD_HELP.forEach(function(l){xdTOut(esc(l),'dim');}); return; }
  if(c==='verify'||c==='v'||c==='verify-isolation'||c.indexOf('verify-isolation')>=0){ xdVerify(cmd); return; }
  if(['iptables','ingress','egress','labels','netpol','svid'].indexOf(c)>=0){
    if(!XDV.res){ xdTOut('no verification data yet — running verify first…','dim'); xdVerify(cmd,c); }
    else { xdShowEvidence(c, XDV.res); }
    return;
  }
  xdTOut('unknown command: '+esc(cmd)+'  — type <b>help</b>','dim');
}
function xdRunCmd(){
  var inp=document.getElementById('xdCmdInput'); if(!inp)return;
  var cmd=(inp.value||'').trim(); if(!cmd)cmd='help';
  if(cmd){XDV.hist.push(cmd);XDV.hi=XDV.hist.length;}
  inp.value='';
  xdVerifyCmd(cmd);
}
function xdCmdHistory(dir){
  var inp=document.getElementById('xdCmdInput'); if(!inp||!XDV.hist.length)return;
  XDV.hi=Math.max(0,Math.min(XDV.hist.length,XDV.hi+dir));
  inp.value=(XDV.hi<XDV.hist.length)?XDV.hist[XDV.hi]:'';
}
async function xdVerify(cmdText, focus){
  if(!XD.xid)return;
  var btn=document.getElementById('xdBtnVerify'); btn.disabled=true;
  xdResetTerm(); xdInitChecks(); xdSetHero('busy','verifying…');
  var reqPromise=fetch('/csm/xapp/'+XD.xid+'/verify-isolation'+nc(),{method:'POST',headers:{'Content-Type':'application/json','Cache-Control':'no-cache'},cache:'no-store',body:'{}'}).then(function(r){return r.json();});
  await xdTermLine('<span class="p">$</span> '+(cmdText?esc(cmdText):('./verify-isolation.sh '+XD.xid)),60);
  xdBurstPackets('in',true); xdBurstPackets('out',true);   // probe both directions while we wait
  var d=await reqPromise;
  if(!d||!d.ok){ await xdTermLine('<span class="fail">verify request failed</span>',150); xdSetHero('','check failed'); btn.disabled=false; return; }

  // 1) control-plane
  await xdTermLine('<span class="p">$</span> kubectl get pod '+d.pod+' -n ricxapp -o labels',220);
  var lbls=(d.transcript[0]||{}).out||'';
  await xdTermLine('<span class="o">'+lbls.replace(/</g,'&lt;')+'</span>',120);
  await xdTermLine('<span class="p">$</span> iptables -t raw -C ZTX-DIRECT-QUARANTINE -s/-d '+d.pod_ip+' -j DROP',300);
  var cp=d.control_plane||{};
  await xdTermLine('<span class="o '+(cp.blocked?'ok':'fail')+'">egress_blocked='+cp.egress_blocked+'  ingress_blocked='+cp.ingress_blocked+'</span>',120);
  xdSetCheck('cp', cp.blocked?'iso':'open',
    cp.blocked?'egress + ingress DROP rules active':'no DROP rules present',
    cp.blocked?'BLOCKED':'OPEN');

  // 2) ingress probe
  await xdTermLine('<span class="p">$</span> [probe pod] nc -z -w3 '+d.pod_ip+' '+d.port,280);
  var ai=d.active_ingress||{};
  await xdTermLine('<span class="o '+(ai.reachable?'fail':'ok')+'">'+(ai.reachable?'CONNECTED &mdash; reachable':'FAILED / TIMED OUT &mdash; blocked')+'  ('+(ai.ms||0)+'ms)</span>',120);
  xdSetCheck('ingress', ai.reachable?'open':'iso',
    ai.reachable?('reachable in '+(ai.ms||0)+'ms'):('timed out ('+(ai.ms||0)+'ms)'),
    ai.reachable?'REACHABLE':'BLOCKED');

  // 3) egress probe
  var eg=d.active_egress||{};
  if(eg.attempted){
    await xdTermLine('<span class="p">$</span> ['+XD.xid+'] '+(eg.tool||'nc')+' &rarr; '+esc(eg.target||'ric-platform'),280);
    await xdTermLine('<span class="o '+(eg.reachable?'fail':'ok')+'">'+(eg.reachable?'CONNECTED &mdash; reachable':'FAILED / TIMED OUT &mdash; blocked')+'</span>',120);
    xdSetCheck('egress', eg.reachable?'open':'iso',
      eg.reachable?'xApp still reached the RIC platform':'xApp could not reach the RIC platform',
      eg.reachable?'REACHABLE':'BLOCKED');
  } else {
    await xdTermLine('<span class="o dim">egress probe skipped: '+(eg.reason||'')+'</span>',120);
    xdSetCheck('egress','skip', (eg.reason||'not attempted'), 'N/A');
  }

  // final verdict + map/packet reaction
  xdBurstPackets('in', d.overall_isolated); xdBurstPackets('out', d.overall_isolated);
  xdSetHero(d.overall_isolated?'iso':'open', d.overall_isolated?'ISOLATED · verified 3 ways':'REACHABLE · not isolated');
  await xdTermLine('<span class="'+(d.overall_isolated?'ok':'fail')+'">'+(d.overall_isolated?'✔ VERDICT: pod is network-isolated (proved 3 ways)':'⚠ VERDICT: pod is still reachable')+'</span>',160);
  await xdTermLine('<span class="o dim">evidence cached · type <b>iptables</b> / <b>ingress</b> / <b>egress</b> / <b>labels</b> / <b>netpol</b> / <b>svid</b> / <b>help</b></span>',80);
  document.querySelectorAll('#xdMap .edge').forEach(function(e){e.classList.toggle('compromised',!!d.overall_isolated);});
  XDV.res=d;                                   // cache for the interactive sub-commands
  if(focus)xdShowEvidence(focus,d);
  btn.disabled=false;
}
function xdIsolateNow(){
  if(!XD.xid)return;
  fetch('/csm/containment/isolate-now'+nc(),{method:'POST',headers:{'Content-Type':'application/json','Cache-Control':'no-cache'},cache:'no-store',body:JSON.stringify({xapp:XD.xid})})
    .then(function(){xdPollDetail();}).catch(function(){});
}
function xdRestore(){
  if(!XD.xid)return;
  var btn=document.getElementById('xdBtnRestore'); btn.disabled=true; btn.textContent='Restoring…';
  fetch('/csm/containment/restore'+nc(),{method:'POST',headers:{'Content-Type':'application/json','Cache-Control':'no-cache'},cache:'no-store',body:JSON.stringify({xapp:XD.xid})})
    .then(function(r){return r.json();}).then(function(){btn.disabled=false;btn.textContent='Restore';xdPollDetail();})
    .catch(function(){btn.disabled=false;btn.textContent='Restore';});
}

/* boot */
function tickClock(){document.getElementById('clock').textContent=lkTime(new Date());}
document.getElementById('navAttack').onclick=function(){atkShowView(true);};
document.getElementById('navOverview').onclick=function(){invClose();atkShowView(false);};
document.getElementById('navInvestigate').onclick=function(){atkShowView(false);invOpen();};
var _atkBack=document.getElementById('atkBack'); if(_atkBack)_atkBack.onclick=function(){atkShowView(false);};
var _axeRp=document.getElementById('axeReplay'); if(_axeRp)_axeRp.onclick=axeReplay;
var _incIso=document.getElementById('incIsolate');
if(_incIso)_incIso.onclick=function(){ if(!INC_XAPP)return; _incIso.disabled=true;
  fetch('/csm/containment/isolate-now'+nc(),{method:'POST',headers:{'Content-Type':'application/json','Cache-Control':'no-cache'},cache:'no-store',body:JSON.stringify({xapp:INC_XAPP})}).then(function(r){return r.json();}).catch(function(){}); };
document.getElementById('invBack').onclick=invClose;
var _invS=document.getElementById('invSearch');
if(_invS)_invS.addEventListener('input',function(){INV.filter=this.value||'';invRenderList();});
document.getElementById('btnReset').onclick=resetLayout;
document.getElementById('btnAll').onclick=clearFocus;
window.addEventListener('resize',sizeStage);
setInterval(tickClock,1000);tickClock();

sizeStage();initP();buildTopo();buildDet();updateDet(null,null);buildLat();updateLat(null);buildPflow();buildMarquee();incHide();tfLoad();
chCpu=Chart('cCpu','legCpu','mC');chMem=Chart('cMem','legMem','MB');chRx=Chart('cRx','legRx','KB/s');chTx=Chart('cTx','legTx','KB/s');
XAPP_IDS.forEach(applyEdges);selectNode(selected);clearFocusSeries();renderCounts();
var _bA=document.getElementById('btnAll');if(_bA)_bA.addEventListener('click',clearFocusSeries);
requestAnimationFrame(topoTick);requestAnimationFrame(drawAll);
pollTiming();pollMetrics();pollState();pollRan();
setInterval(pollMetrics,1000);
setInterval(pollTiming,1000);
setInterval(pollState,1000);
setInterval(pollRan,3000);
setInterval(atkOnState,1000);
/* live-animation loops (event-driven off REAL system signals) */
setInterval(pollPulses,8000);               // real per-xApp SVID renewals + real KPM work-unit advances
setTimeout(pollPulses,3000);
setInterval(pingCycle,2200);                // slow continuous UE->gNB traffic (while UE up)
pollPosture();refreshInvCount();            // policy posture + SVID health widgets, investigation count
setInterval(pollPosture,6000);
setInterval(refreshInvCount,15000);

document.getElementById('xdBack').onclick=xdClose;
document.getElementById('xdBtnVerify').onclick=function(){xdVerify();};
var _xdRun=document.getElementById('xdCmdRun'); if(_xdRun)_xdRun.onclick=xdRunCmd;
var _xdCmd=document.getElementById('xdCmdInput'); if(_xdCmd)_xdCmd.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();xdRunCmd();}else if(e.key==='ArrowUp'){e.preventDefault();xdCmdHistory(-1);}else if(e.key==='ArrowDown'){e.preventDefault();xdCmdHistory(1);}});
document.getElementById('xdBtnIsolate').onclick=xdIsolateNow;
document.getElementById('xdBtnRestore').onclick=xdRestore;
document.querySelectorAll('#xdRanges button').forEach(function(b){
  b.addEventListener('click',function(){
    document.querySelectorAll('#xdRanges button').forEach(function(x){x.classList.remove('on');});
    b.classList.add('on'); XD.range=parseInt(b.dataset.r,10)||1800; xdPollGraphs();
  });
});
document.addEventListener('keydown',function(e){if(e.key==='Escape'&&XD.xid)xdClose();});
})();
