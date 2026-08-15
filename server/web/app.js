'use strict';

const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => [...root.querySelectorAll(s)];
let csrf = '';
let nodes = [];
let currentNode = null;
let listenState = {active:'', desired:'', pending:false};
let latestRelease = '';
let logStream = null;
let pendingConfirm = null;
let certFiles = {cert:'', key:''};

function esc(v=''){return String(v).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
function show(id){const e=$('#'+id);if(e)e.classList.add('show');}
function hide(id){const e=$('#'+id);if(e)e.classList.remove('show');}
function text(id,v){const e=$('#'+id);if(e)e.textContent=v==null?'—':String(v);}
function html(id,v){const e=$('#'+id);if(e)e.innerHTML=v;}
function toast(msg){const t=$('#toast');if(!t)return;t.textContent=msg;t.classList.add('show');clearTimeout(t._timer);t._timer=setTimeout(()=>t.classList.remove('show'),2200);}
function fmtBytes(n){n=Number(n)||0;const u=['B','KiB','MiB','GiB','TiB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++;}return `${n>=10||i===0?n.toFixed(0):n.toFixed(1)} ${u[i]}`;}
function fmtRate(n){return fmtBytes(n)+'/s';}
function fmtAgo(ts){if(!ts)return '—';let d=Math.max(0,Math.floor(Date.now()/1000-ts));if(d<5)return '刚刚';if(d<60)return `${d} 秒前`;if(d<3600)return `${Math.floor(d/60)} 分钟前`;if(d<86400)return `${Math.floor(d/3600)} 小时前`;return `${Math.floor(d/86400)} 天前`;}
function fmtUptime(sec){sec=Number(sec)||0;const d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600),m=Math.floor(sec%3600/60);return d?`${d} 天 ${h} 小时`:h?`${h} 小时 ${m} 分钟`:`${m} 分钟`;}
function passwordStrength(v){if(!v)return {level:0,label:'—'};if(v.length<8)return {level:0,label:'不足 8 位'};let level=1;const kinds=[/[a-z]/.test(v),/[A-Z]/.test(v),/[0-9]/.test(v),/[^A-Za-z0-9]/.test(v)].filter(Boolean).length;if(v.length>=12)level++;if(kinds>=3)level++;if(v.length>=16||kinds===4)level++;return {level:Math.min(4,level),label:['','弱','一般','强','很强'][Math.min(4,level)]};}
function updateStrength(input,box,label){const v=$(input)?.value||'',r=passwordStrength(v),b=$(box);if(b)b.dataset.level=String(r.level);text(label.slice(1),r.label);}

async function api(path, opts={}){
  const method=(opts.method||'GET').toUpperCase();
  const headers=new Headers(opts.headers||{});
  if(opts.json!==undefined){headers.set('Content-Type','application/json');opts.body=JSON.stringify(opts.json);}
  if(!['GET','HEAD'].includes(method)&&csrf)headers.set('X-CSRF-Token',csrf);
  const res=await fetch(path,{...opts,method,headers,credentials:'same-origin'});
  const ct=res.headers.get('content-type')||'';
  let body=ct.includes('json')?await res.json():await res.text();
  if(!res.ok){const e=new Error(body?.reason||body?.error||body?.message||`HTTP ${res.status}`);e.status=res.status;e.code=body?.code||'';e.action=body?.action||'';throw e;}
  return body;
}
function localizeErrorText(v=''){
  const exact={
    'port must be 1-65535':'端口必须在 1–65535 之间',
    'listen address is required':'请输入监听 IP 地址',
    'invalid listen address':'请输入有效的监听 IP 地址',
    'invalid admin path':'管理入口格式无效',
    'new password must be 8-128 characters':'新密码长度必须为 8–128 位',
    'password must be 8-128 characters':'密码长度必须为 8–128 位',
    'unauthorized':'登录状态已失效，请重新登录',
    'bad csrf token':'安全令牌无效，请刷新页面后重试',
    'node is offline':'节点离线',
    'node command queue is busy':'节点命令队列繁忙，请稍后重试',
    'agent command timeout':'等待 Agent 响应超时',
    'process is protected':'该进程受保护',
    'process cannot be safely restarted':'该进程无法安全重启',
    'restart snapshot unavailable':'无法创建进程重启快照',
    'service is protected or invalid':'服务受保护或名称无效',
    'systemd not available':'systemd 不可用',
    'record is not restartable':'该恢复记录不可启动',
    'restart record not found':'未找到恢复记录'
  };
  return exact[v]||v;
}
function errorMessage(e){const msg=localizeErrorText(e?.message||'操作失败'),act=localizeErrorText(e?.action||'');return [msg,act].filter(Boolean).join(' · ');}

function lockUI(){document.body.classList.add('auth-locked');}
function unlockUI(){document.body.classList.remove('auth-locked');hide('setupOverlay');hide('loginOverlay');}
async function bootstrap(){
  lockUI();hide('setupOverlay');hide('loginOverlay');
  try{
    const setup=await api('/api/setup/status');
    if(setup.required){show('setupOverlay');$('#setupPass')?.focus();return;}
    try{const session=await api('/api/session');csrf=session.csrf;unlockUI();await loadAll();}
    catch{show('loginOverlay');$('#loginPass')?.focus();}
  }catch(e){show('loginOverlay');text('loginError','无法连接 NodeLume Server');}
}
function validateSetup(){
  const a=$('#setupPass')?.value||'',b=$('#setupPass2')?.value||'',btn=$('#setupBtn');
  let msg='';if(a&&a.length<8)msg='密码至少 8 位';else if(b&&a!==b)msg='两次密码不一致';
  const valid=a.length>=8&&!!b&&a===b;text('setupError',msg);if(btn)btn.disabled=!valid;return valid;
}
async function setupAdmin(){
  if(!validateSetup())return;
  const password=$('#setupPass').value;
  try{
    await api('/api/setup',{method:'POST',json:{password}});
    const r=await api('/api/login',{method:'POST',json:{password}});
    csrf=r.csrf;$('#setupPass').value='';$('#setupPass2').value='';unlockUI();toast('初始化完成');await loadAll();
  }catch(e){toast(errorMessage(e));}
}
async function login(){const p=$('#loginPass').value;if(!p)return;try{const r=await api('/api/login',{method:'POST',json:{password:p}});csrf=r.csrf;$('#loginError').textContent='';$('#loginPass').value='';unlockUI();await loadAll();}catch(e){text('loginError',localizeErrorText(e.message));lockUI();}}
async function logout(){try{await api('/api/logout',{method:'POST',json:{}});}catch{}csrf='';if(logStream){logStream.close();logStream=null;}lockUI();show('loginOverlay');}

async function loadAll(){await loadSettings().catch(()=>{});await Promise.allSettled([loadNodes(),loadListen(),loadSelf(),loadUpdate(),loadAudit(),loadLogs(),loadCommonEnrollment()]);startLogStream();}
async function loadNodes(){nodes=await api('/api/nodes');renderNodes();renderRecent();}
function renderNodes(){
  const q=($('#searchInput')?.value||'').trim().toLowerCase();const list=nodes.filter(n=>`${n.name} ${n.group} ${n.note} ${n.system?.os||''}`.toLowerCase().includes(q));
  text('totalServers',nodes.length);text('onlineServers',nodes.filter(n=>n.status==='online').length);text('offlineServers',nodes.filter(n=>n.status!=='online').length);
  const grid=$('#serverGrid');if(!grid)return;
  if(!list.length){grid.innerHTML='<div class="server-empty">暂无节点</div>';return;}
  grid.innerHTML=list.map(n=>{const h=n.latest||{},on=n.status==='online',bad=n.status==='incompatible';return `<article class="server ${on?'':'offline'}" data-node="${esc(n.id)}"><div class="server-head"><div class="server-title"><div><div class="name">${esc(n.name)}</div><div class="meta">${esc(n.system?.os||'未注册')} · ${esc(n.system?.arch||'—')}</div></div></div><div class="status"><span class="sdot"></span><span>${bad?'协议不兼容':on?'在线':n.status==='waiting'?'等待接入':'离线'}</span></div></div><div class="metrics">${metric('CPU',h.cpu,on)}${metric('内存',h.memory,on)}${metric('磁盘',h.disk,on)}</div><div class="server-foot"><span>${esc(n.group||'默认分组')}</span><span>${on?`↑ ${fmtRate(h.net_out)} ↓ ${fmtRate(h.net_in)}`:`最后心跳 ${fmtAgo(n.last_seen)}`}</span></div></article>`;}).join('');
  $$('.server[data-node]',grid).forEach(e=>e.onclick=()=>openNode(e.dataset.node));
}
function metric(label,v,on){v=Math.max(0,Math.min(100,Number(v)||0));return `<div class="metric"><div class="row"><span>${label}</span><b>${on?`${v.toFixed(v%1?1:0)}%`:'--'}</b></div><div class="bar"><div class="fill" style="width:${on?v:0}%"></div></div></div>`;}
function renderRecent(){const c=$('#recentJoin');if(!c)return;const recent=[...nodes].sort((a,b)=>(b.created_at||0)-(a.created_at||0)).slice(0,3);c.innerHTML='<h4 style="margin:0 0 6px">最近接入</h4>'+(!recent.length?'<div class="hint">暂无</div>':recent.map(n=>`<div class="recent-join-row"><span><i class="tiny-dot"></i>${esc(n.name)}</span><span class="hint">${fmtAgo(n.created_at)}</span></div>`).join(''));}

async function openNode(id){
  const n=nodes.find(x=>x.id===id);if(!n)return;currentNode=n;resetTabs();
  text('dName',n.name);text('dMeta',`${n.system?.os||'未注册'} · ${n.system?.arch||'—'} · Agent ${n.system?.agent||'—'}`);
  text('detailStatusText',n.status==='online'?'在线':n.status==='waiting'?'等待接入':'离线');
  $('#offlineBanner').style.display=n.status==='online'?'none':'block';
  html('dNodeMeta',`<span class="node-meta-chip">${esc(n.group||'默认分组')}</span>${n.note?`<span class="node-meta-note">${esc(n.note)}</span>`:''}<span class="node-meta-note">最后心跳：${esc(fmtAgo(n.last_seen))}</span>`);
  const h=n.latest||{};
  text('dcpu',`${(Number(h.cpu)||0).toFixed(1)}%`);text('dram',`${(Number(h.memory)||0).toFixed(1)}%`);text('ddisk',`${(Number(h.disk)||0).toFixed(1)}%`);text('dtemp',h.temperature==null?'--':`${Number(h.temperature).toFixed(1)}°C`);
  if($('#dcpuBar'))$('#dcpuBar').style.width=`${Number(h.cpu)||0}%`;if($('#dramBar'))$('#dramBar').style.width=`${Number(h.memory)||0}%`;if($('#ddiskBar'))$('#ddiskBar').style.width=`${Number(h.disk)||0}%`;
  text('procCount',h.processes||0);text('overviewNet',n.status==='online'?`↑ ${fmtRate(h.net_out)}　↓ ${fmtRate(h.net_in)}`:'—');text('overviewLoad',`${Number(h.load1||0).toFixed(2)} / ${Number(h.load5||0).toFixed(2)} / ${Number(h.load15||0).toFixed(2)}`);text('overviewUptime',fmtUptime(h.uptime));
  text('cpuModel',n.system?.cpu_model||'—');text('cpuCores',n.system?.cpu_cores||'—');text('cpuFreq',Number(h.cpu_freq_mhz)>0?`${(Number(h.cpu_freq_mhz)/1000).toFixed(2)} GHz`:'—');text('cpuLoad',`${Number(h.load1||0).toFixed(2)} / ${Number(h.load5||0).toFixed(2)} / ${Number(h.load15||0).toFixed(2)}`);
  text('memTotal',fmtBytes(n.system?.memory_total||0));text('memUsed',fmtBytes(h.memory_used||0));text('memAvail',fmtBytes(h.memory_available||0));text('memSwap',h.swap_total?`${fmtBytes(h.swap_used||0)} / ${fmtBytes(h.swap_total)}`:'0 B');
  renderTopProcesses('cpuProcTable',Array.isArray(h.top_cpu)?h.top_cpu:[]);renderTopProcesses('memProcTable',Array.isArray(h.top_memory)?h.top_memory:[]);
  text('sysHostname',n.system?.hostname||'—');text('sysOS',n.system?.os||'—');text('sysKernel',n.system?.kernel||'—');text('sysArch',n.system?.arch||'—');text('sysAgent',n.system?.agent||'—');text('sysProtocol',`Protocol v${n.system?.protocol||'—'}`);text('sysTransport',location.protocol==='https:'?'HTTPS Long Poll':'HTTP Long Poll');text('sysHeartbeat',fmtAgo(n.last_seen));renderSelf('agent',h.self||{});
  show('detailOverlay');await loadHistory(1);
}
function renderTopProcesses(id,list){
  const rows=list.slice(0,10);html(id,!rows.length?'<div class="hint">暂无进程数据</div>':`<div class="tablewrap"><table><thead><tr><th>PID</th><th>进程</th><th>CPU</th><th>内存</th><th>用户</th></tr></thead><tbody>${rows.map(p=>`<tr class="top-proc-row" data-pid="${p.pid}"><td>${p.pid}</td><td>${esc(p.name)}</td><td>${Number(p.cpu||0).toFixed(1)}%</td><td>${Number(p.memory_mb||0).toFixed(1)} MiB</td><td>${esc(p.user||'—')}</td></tr>`).join('')}</tbody></table></div>`);
  $$(`#${id} .top-proc-row`).forEach(r=>r.onclick=()=>openProcess(Number(r.dataset.pid)));
}
function resetTabs(){$$('#tabs .tab').forEach(x=>x.classList.toggle('active',x.dataset.tab==='overview'));$$('.tabpane').forEach(x=>x.classList.toggle('active',x.id==='pane-overview'));}
async function loadHistory(minutes){if(!currentNode)return;try{const data=await api(`/api/nodes/${encodeURIComponent(currentNode.id)}/history?minutes=${minutes}`);drawChart('overviewChart',data.map(x=>Number(x.cpu)||0));drawChart('cpuChart',data.map(x=>Number(x.cpu)||0));drawChart('memChart',data.map(x=>Number(x.memory)||0));}catch{}}
function drawChart(id,data){const c=$('#'+id);if(!c)return;const r=c.getBoundingClientRect();if(r.width<20)return;const dpr=devicePixelRatio||1,w=r.width,h=190;c.width=w*dpr;c.height=h*dpr;const x=c.getContext('2d');x.scale(dpr,dpr);x.clearRect(0,0,w,h);const css=getComputedStyle(document.documentElement);x.strokeStyle=css.getPropertyValue('--line');x.fillStyle=css.getPropertyValue('--muted');x.lineWidth=1;for(let i=0;i<=4;i++){const y=10+i*40;x.beginPath();x.moveTo(38,y);x.lineTo(w-10,y);x.stroke();}if(!data.length)return;x.strokeStyle=css.getPropertyValue('--green');x.lineWidth=2;x.beginPath();data.forEach((v,i)=>{const px=38+i*(w-50)/Math.max(1,data.length-1),py=170-Math.max(0,Math.min(100,v))*1.6;i?x.lineTo(px,py):x.moveTo(px,py);});x.stroke();}

async function loadProcesses(){if(!currentNode||currentNode.status!=='online'){html('allProcTable','<div class="hint">节点离线</div>');return;}try{const p=await api(`/api/nodes/${encodeURIComponent(currentNode.id)}/processes`);renderProcesses(Array.isArray(p)?p:[]);}catch(e){html('allProcTable',`<div class="server-card-error">${esc(errorMessage(e))}</div>`);}}
function renderProcesses(list){const q=($('#procSearch')?.value||'').toLowerCase();list=list.filter(p=>`${p.name} ${p.pid} ${p.user}`.toLowerCase().includes(q));html('allProcTable',`<div class="tablewrap"><table><thead><tr><th>PID</th><th>进程</th><th>CPU</th><th>内存</th><th>用户</th></tr></thead><tbody>${list.map(p=>`<tr class="proc-row" data-pid="${p.pid}"><td>${p.pid}</td><td>${esc(p.name)}</td><td>${Number(p.cpu||0).toFixed(1)}%</td><td>${Number(p.memory_mb||0).toFixed(1)} MiB</td><td>${esc(p.user||'—')}</td></tr>`).join('')}</tbody></table></div>`);$$('.proc-row').forEach(r=>r.onclick=()=>openProcess(Number(r.dataset.pid)));}
async function openProcess(pid){try{const p=await api(`/api/nodes/${encodeURIComponent(currentNode.id)}/process/${pid}`);text('pName',p.name);text('pPid',p.pid);text('pState',p.state);text('pCpu',`${Number(p.cpu||0).toFixed(1)}%`);text('pMem',`${Number(p.memory_mb||0).toFixed(1)} MiB`);text('pUser',p.user||'—');text('pLaunch',p.launch||'—');text('pService',p.service||'—');text('pParent',p.parent||'—');text('pExe',p.exe||'—');text('pCwd',p.cwd||'—');text('pCmd',p.command||'—');text('pTree',p.tree||'—');const a=[];if(p.can_terminate)a.push(actionBtn('terminate','结束'));if(p.can_kill)a.push(actionBtn('kill','强制结束',true));if(p.can_restart)a.push(actionBtn('restart','重启'));html('procActions',a.join(''));$$('#procActions [data-act]').forEach(b=>b.onclick=()=>confirmAction('进程操作',`确认对 ${esc(p.name)} (${p.pid}) 执行“${b.textContent}”？`,'',()=>processAction(pid,b.dataset.act),b.dataset.act==='kill'));show('procOverlay');}catch(e){toast(errorMessage(e));}}
function actionBtn(a,l,d=false){return `<button class="btn ${d?'danger':''}" data-act="${a}">${l}</button>`;}
async function processAction(pid,action){try{await api(`/api/nodes/${encodeURIComponent(currentNode.id)}/process/${pid}/action`,{method:'POST',json:{action}});hide('procOverlay');toast('操作成功');await loadProcesses();}catch(e){toast(errorMessage(e));}}
async function loadStopped(){if(!currentNode||currentNode.status!=='online'){html('stoppedProcTable','<div class="hint">节点离线</div>');return;}try{const a=await api(`/api/nodes/${encodeURIComponent(currentNode.id)}/stopped`);html('stoppedProcTable',!a?.length?'<div class="hint">暂无已停止项目</div>':`<div class="tablewrap"><table><thead><tr><th>名称</th><th>方式</th><th>停止时间</th><th></th></tr></thead><tbody>${a.map(x=>`<tr><td>${esc(x.name)}</td><td>${esc(x.launch||'—')}</td><td>${fmtAgo(x.stopped_at)}</td><td>${x.can_start?`<button class="btn small start-stopped" data-rid="${esc(x.id)}">启动</button>`:'—'}</td></tr>`).join('')}</tbody></table></div>`);$$('.start-stopped').forEach(b=>b.onclick=()=>startStopped(b.dataset.rid));}catch(e){html('stoppedProcTable',esc(errorMessage(e)));}}
async function startStopped(rid){try{await api(`/api/nodes/${encodeURIComponent(currentNode.id)}/stopped/${encodeURIComponent(rid)}/start`,{method:'POST',json:{}});toast('已启动');await loadStopped();}catch(e){toast(errorMessage(e));}}
async function loadDisks(){if(!currentNode||currentNode.status!=='online'){html('diskTable','<div class="hint">节点离线</div>');return;}try{const a=await api(`/api/nodes/${encodeURIComponent(currentNode.id)}/disks`);const c=$('#diskTable');if(c)c.innerHTML=`<div class="tablewrap"><table><thead><tr><th>设备</th><th>挂载点</th><th>文件系统</th><th>已用</th><th>总计</th><th>使用率</th></tr></thead><tbody>${(a||[]).map(d=>`<tr><td>${esc(d.name||'—')}</td><td>${esc(d.mount)}</td><td>${esc(d.fs_type)}</td><td>${fmtBytes(d.used)}</td><td>${fmtBytes(d.total)}</td><td>${Number(d.percent||0).toFixed(1)}%</td></tr>`).join('')}</tbody></table></div>`;}catch(e){html('diskTable',`<div class="server-card-error">${esc(errorMessage(e))}</div>`);}}

function openEdit(){if(!currentNode)return;textValue('#editNodeName',currentNode.name);textValue('#editNodeGroup',currentNode.group||'');textValue('#editNodeNote',currentNode.note||'');const desired=currentNode.report_interval_sec||2,applied=currentNode.applied_report_interval_sec||currentNode.latest?.report_interval_sec||0;setSelectValue('#editNodeInterval',String(desired));text('editApplyHint',applied?(applied===desired?`当前已应用 ${applied} 秒`:`当前已应用 ${applied} 秒 · 目标 ${desired} 秒 · 等待 Agent 应用`):`当前已应用状态未知 · 目标 ${desired} 秒`);show('nodeEditOverlay');}
function textValue(s,v){const e=$(s);if(e)e.value=v;}
async function saveNode(){if(!currentNode)return;const body={name:$('#editNodeName').value.trim(),group:$('#editNodeGroup').value.trim(),note:$('#editNodeNote').value.trim(),report_interval_sec:Number($('#editNodeInterval').value)};try{const r=await api(`/api/nodes/${encodeURIComponent(currentNode.id)}`,{method:'PATCH',json:body});hide('nodeEditOverlay');toast(r.pending?'已保存，上线后应用':'已保存');await loadNodes();currentNode=nodes.find(n=>n.id===currentNode.id);if(currentNode)await openNode(currentNode.id);}catch(e){toast(errorMessage(e));}}
async function reenroll(){if(!currentNode)return;try{const r=await api(`/api/nodes/${encodeURIComponent(currentNode.id)}/reenroll`,{method:'POST',json:{}});const ok=await copyText(r.install_command);toast(ok?'新的接入命令已复制':'接入命令已生成，请手动复制');}catch(e){toast(errorMessage(e));}}
async function deleteNode(){if(!currentNode)return;try{await api(`/api/nodes/${encodeURIComponent(currentNode.id)}`,{method:'DELETE'});hide('detailOverlay');toast('节点已删除并吊销身份');currentNode=null;await loadNodes();}catch(e){toast(errorMessage(e));}}

async function loadCommonEnrollment(){try{const r=await api('/api/enrollment/common');text('commonTokenState',r.active?'有效':'未生成');$('#commonTokenState')?.classList.toggle('off',!r.active);text('commonJoinedText',`已接入：${r.joined||0} 台`);$('#commonInstallCommand').textContent=r.active?'Token 已存在；为安全起见不重复显示，请重新生成后复制。':'点击“生成 Token”创建通用 Token';$('#revokeCommonToken').style.display=r.active?'':'none';text('regenCommonToken',r.active?'重新生成':'生成 Token');}catch{}}
async function generateCommon(){const days=Number($('#commonTokenExpiry').value),name=$('#commonNodeName').value.trim();try{const r=await api('/api/enrollment/common',{method:'POST',json:{days,name}});$('#commonInstallCommand').textContent=r.install_command;text('commonTokenState','有效');$('#commonTokenState')?.classList.remove('off');$('#revokeCommonToken').style.display='';text('regenCommonToken','重新生成');setHttpWarning(r.install_command);toast('通用 Token 已生成');await loadCommonEnrollmentMetaOnly(r.install_command);}catch(e){toast(errorMessage(e));}}
async function loadCommonEnrollmentMetaOnly(cmd){const r=await api('/api/enrollment/common');text('commonJoinedText',`已接入：${r.joined||0} 台`);if(cmd)$('#commonInstallCommand').textContent=cmd;}
async function revokeCommon(){try{await api('/api/enrollment/common',{method:'DELETE',json:{}});text('commonTokenState','未生成');$('#commonTokenState')?.classList.add('off');$('#commonInstallCommand').textContent='点击“生成 Token”创建通用 Token';$('#revokeCommonToken').style.display='none';text('regenCommonToken','生成 Token');toast('通用 Token 已撤销');}catch(e){toast(errorMessage(e));}}
async function generateSingle(){const name=$('#singleNodeName').value.trim();try{const r=await api('/api/nodes',{method:'POST',json:{name}});$('#singleInstallCommand').textContent=r.install_command;setHttpWarning(r.install_command);toast('一次性接入命令已生成');await loadNodes();}catch(e){toast(errorMessage(e));}}
function setHttpWarning(cmd){const http=/\s-s\s+'?http:\/\//.test(cmd)||location.protocol==='http:';['commonHttpWarning','singleHttpWarning'].forEach(id=>$('#'+id)?.classList.toggle('show',http));}
async function copyText(v){
  if(!v)return false;
  if(navigator.clipboard&&window.isSecureContext){try{await navigator.clipboard.writeText(v);return true;}catch{}}
  const ta=document.createElement('textarea');ta.value=v;ta.setAttribute('readonly','');ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();ta.setSelectionRange(0,v.length);
  let ok=false;try{ok=document.execCommand('copy');}catch{}ta.remove();return ok;
}
async function copyCode(id){const v=$('#'+id)?.textContent||'';if(!v)return;toast(await copyText(v)?'已复制':'请手动复制');}

async function loadSettings(){const r=await api('/api/settings'),s=r.settings||{},c=r.certificate||{};text('serverVersionText',`v${r.server_version}`);text('serverProtocolText',`v${r.protocol_version}`);text('aboutVersion',`v${r.server_version}`);textValue('#securePath',s.admin_path||'/');textValue('#domainInput',s.domain||'');setSelectValue('#logRetention',String(s.log_retention_days||7));setSelectValue('#logCapacity',String(s.log_max_mib||50));renderCert(c);}
function renderCert(c){text('certStatusBadge',({valid:'有效',renewal_due:'待续期',expired:'已过期',missing:'缺失',invalid:'无效'})[c.status]||'未配置');text('certDomainText',c.domain||'—');text('certSourceText',c.source==='acme'?'自动申请':c.source==='manual'?'手动导入':'—');text('certExpiryText',c.not_after?new Date(c.not_after*1000).toLocaleString():'—');text('certRenewText',c.auto_renew?'自动':'—');}
async function loadSelf(){try{renderSelf('server',await api('/api/self/status'));}catch{}}
function renderSelf(prefix,s){const P=prefix==='server'?'serverSelf':'agentSelf';text(P+'CPU',`${Number(s.cpu_percent||0).toFixed(1)}%`);text(P+'Mem',fmtBytes(s.rss_bytes));text(P+'Disk',fmtBytes(s.disk_bytes));text(P+'Inodes',s.inodes||0);text(P+'RX',fmtBytes(s.rx_bytes));text(P+'TX',fmtBytes(s.tx_bytes));text(P+'RXRate',fmtRate(s.rx_rate));text(P+'TXRate',fmtRate(s.tx_rate));}
async function loadListen(){try{listenState=await api('/api/settings/listen');const [a,p]=splitListen(listenState.desired||listenState.active);textValue('#listenAddress',a);textValue('#listenPort',p);text('currentListenText',listenState.active);refreshListenDirty();}catch{}}
function splitListen(v){if(v.startsWith('[')){const i=v.lastIndexOf(']:');return [v.slice(1,i),v.slice(i+2)];}const i=v.lastIndexOf(':');return [v.slice(0,i),v.slice(i+1)];}
function wantedListen(){const a=$('#listenAddress').value.trim(),p=Number($('#listenPort').value);return {a,p,text:(a.includes(':')?`[${a}]`:a)+`:${p}`};}
function validListenAddress(a){if(a==='localhost')return true;if(a.includes(':')){if(!/^[0-9A-Fa-f:]+$/.test(a)||(a.match(/::/g)||[]).length>1)return false;const compressed=a.includes('::'),parts=a.split(':');if(compressed){const nonempty=parts.filter(Boolean);return nonempty.length<=7&&nonempty.every(x=>/^[0-9A-Fa-f]{1,4}$/.test(x));}return parts.length===8&&parts.every(x=>/^[0-9A-Fa-f]{1,4}$/.test(x));}const f=a.split('.');return f.length===4&&f.every(x=>/^\d{1,3}$/.test(x)&&Number(x)>=0&&Number(x)<=255);}
function listenValidation(){const w=wantedListen();if(!w.a)return '请输入监听 IP 地址';if(!validListenAddress(w.a))return '请输入有效的监听 IP 地址';if(!Number.isInteger(w.p)||w.p<1||w.p>65535)return '端口必须在 1–65535 之间';return '';}
function refreshListenDirty(){const w=wantedListen(),changed=w.text!==listenState.desired,pending=listenState.desired!==listenState.active,err=listenValidation();text('listenError',err);$('#saveListenBtn').disabled=!changed||!!err;$('#listenPendingBox').classList.toggle('show',pending);text('restartServerBtn',pending?'重启并应用':'重启 Server');}
async function saveListen(){const w=wantedListen(),v=listenValidation();if(v){toast(v);return;}try{listenState=await api('/api/settings/listen',{method:'PATCH',json:{address:w.a,port:w.p}});refreshListenDirty();toast(listenState.pending?'已保存，重启后生效':'监听配置未发生变化');}catch(e){toast(errorMessage(e));}}
async function restartServer(){const w=wantedListen();if(['127.0.0.1','::1','localhost'].includes(w.a)&&!confirm('重启后公网将无法直接访问。确认继续？'))return;try{const r=await api('/api/server/restart',{method:'POST',json:{}});toast('Server 正在重启…');const target=splitListen(r.target||listenState.desired),port=target[1];let base=`${location.protocol}//${location.hostname}${port&&port!==(location.protocol==='https:'?'443':'80')?':'+port:''}`;await waitServer(base);if(base!==location.origin)location.href=base+location.pathname;else await loadAll();}catch(e){toast(errorMessage(e));}}
async function waitServer(base){await new Promise(r=>setTimeout(r,800));for(let i=0;i<30;i++){try{const x=await fetch(base+'/healthz',{cache:'no-store'});if(x.ok)return;}catch{}await new Promise(r=>setTimeout(r,500));}throw new Error('Server 重启后未恢复');}
function normalizeAdminPath(){let p=$('#securePath').value.trim();if(p&&!p.startsWith('/'))p='/'+p;return p||'/';}
function validateAdminPath(){const p=normalizeAdminPath();const ok=p==='/'||(/^\/[A-Za-z0-9_-]{1,48}$/.test(p)&&!['/api','/assets','/healthz','/install'].some(x=>p.startsWith(x)));const msg=ok?'':'管理入口仅支持字母、数字、短横线和下划线';text('securePathError',msg);$('#saveSecurePath').disabled=!ok;return ok;}
async function saveSecurity(){if(!validateAdminPath())return;const p=normalizeAdminPath();try{await api('/api/settings/security',{method:'POST',json:{admin_path:p}});toast('安全入口已保存');if(location.pathname!==p)setTimeout(()=>location.href=p,500);}catch(e){toast(errorMessage(e));}}
function validateNewPassword(){const n=$('#newPass')?.value||'',n2=$('#newPass2')?.value||'';let msg='';if(n&&n.length<8)msg='新密码至少 8 位';else if(n2&&n!==n2)msg='两次密码不一致';const valid=n.length>=8&&!!n2&&n===n2;text('newPassError',msg);$('#changePassBtn').disabled=!valid;return valid;}
async function changePassword(){if(!validateNewPassword())return;const n=$('#newPass').value;try{await api('/api/settings/password',{method:'POST',json:{new:n}});csrf='';hide('settingsOverlay');lockUI();show('loginOverlay');toast('密码已修改，请重新登录');}catch(e){toast(errorMessage(e));}}

function certLog(line,state='running'){const out=$('#certLogOutput');if(!out)return;if(out.textContent.trim()==='暂无日志')out.innerHTML='';const d=document.createElement('div');d.textContent=`[${new Date().toLocaleTimeString('zh-CN',{hour12:false})}] ${line}`;out.appendChild(d);out.scrollTop=out.scrollHeight;text('certLogState',state==='ok'?'成功':state==='fail'?'失败':'进行中');}
async function activateCertificateResult(r,label){
  const target=r?.access_url||'';
  toast(`${label}，重启后启用 HTTPS`);
  if(!target)return;
  confirmAction('启用 HTTPS',`证书已准备完成。重启 Server 后将切换到 <b>${esc(target)}</b>。`,'',async()=>{
    try{
      await api('/api/server/restart',{method:'POST',json:{}});
      toast('Server 正在重启并切换 HTTPS…');
      await waitServer(target);
      location.href=target+location.pathname;
    }catch(e){toast(errorMessage(e));}
  });
}
async function applyCert(){const domain=$('#domainInput').value.trim();if(!domain){toast('请填写域名');return;}$('#certLogOutput').innerHTML='';certLog('检查域名与 80 端口');try{await api('/api/settings/https/check',{method:'POST',json:{domain}});certLog('开始 ACME HTTP-01 验证');const r=await api('/api/settings/https/apply',{method:'POST',json:{domain}});certLog('证书签发并保存完成','ok');renderCert(r.certificate||{});activateCertificateResult(r,'证书申请成功');}catch(e){certLog(`${e.code||'ERROR'} · ${e.message}${e.action?' · '+e.action:''}`,'fail');toast(errorMessage(e));}}
async function checkCert(){try{const r=await api('/api/settings/certificate/check',{method:'POST',json:{}});renderCert(r);certLog('当前证书检查完成','ok');}catch(e){certLog(errorMessage(e),'fail');}}
async function importCert(){const domain=$('#domainInput').value.trim(),mode=$('#certImportTabs .active')?.dataset.importMode||'file';let certificate='',private_key='';if(mode==='file'){certificate=certFiles.cert;private_key=certFiles.key;}else{certificate=$('#certPem').value;private_key=$('#certKey').value;}if(!domain||!certificate||!private_key){toast('请填写域名并提供证书和私钥');return;}$('#certImportProgress').classList.add('show');text('certImportProgressText','验证证书与私钥');text('certImportProgressPct','35%');$('#certImportProgressBar').style.width='35%';certLog('读取并验证证书 / 私钥');try{const r=await api('/api/settings/certificate/import',{method:'POST',json:{domain,certificate,private_key}});$('#certImportProgressBar').style.width='100%';text('certImportProgressPct','100%');text('certImportProgressText','导入完成');certLog('证书匹配、域名、有效期和证书链验证通过','ok');hide('certImportOverlay');await loadSettings();activateCertificateResult(r,'证书已导入');}catch(e){text('certImportProgressText','导入失败');certLog(errorMessage(e),'fail');toast(errorMessage(e));}}
async function readFile(input,key,label){const f=input.files?.[0];if(!f)return;certFiles[key]=await f.text();text(label,f.name);}

async function saveLogSettings(){try{const retention_days=parseInt($('#logRetention').value,10),max_mib=parseInt($('#logCapacity').value,10);await api('/api/settings/logs',{method:'POST',json:{retention_days,max_mib}});text('logUsageText',`运行日志容量上限 ${max_mib} MiB`);toast('日志设置已保存');}catch(e){toast(errorMessage(e));}}
async function loadLogs(){try{const r=await api('/api/logs/runtime');text('runtimeLog',r.text||'暂无日志');text('logUsageText',`当前运行日志 ${fmtBytes(r.bytes)} / ${$('#logCapacity')?.value||50} MiB`);}catch{}}
function startLogStream(){if(logStream)logStream.close();try{logStream=new EventSource('/api/logs/runtime/stream');logStream.addEventListener('log',e=>{let s='';try{s=JSON.parse(e.data);}catch{s=e.data;}const el=$('#runtimeLog');if(!el)return;if(el.textContent==='暂无日志')el.textContent='';el.textContent+=s;el.scrollTop=el.scrollHeight;});}catch{}}
async function clearLogs(){try{await api('/api/logs/runtime',{method:'DELETE',json:{}});text('runtimeLog','暂无日志');toast('运行日志已清除');}catch(e){toast(errorMessage(e));}}
const auditActionZH={setup_password:'初始化管理员密码',login:'管理员登录',logout:'退出登录',security_settings:'修改安全入口',change_password:'修改管理员密码',create_node:'创建节点',reenroll_node:'重新接入节点',delete_node:'删除节点',edit_node:'编辑节点',agent_register:'Agent 接入',common_enrollment:'通用 Token',log_settings:'修改日志设置',clear_runtime_logs:'清除运行日志',process_terminate:'结束进程',process_kill:'强制结束进程',process_restart:'重启进程',process_start_saved:'启动已停止进程',listen_settings:'修改监听配置',server_restart:'重启 Server',certificate_issue:'申请证书',certificate_check:'检查证书',certificate_import:'导入证书',https_apply:'修改 HTTPS',server_update:'更新 Server',agent_upgrade:'更新 Agent'};
function auditDetailZH(v=''){return v.replace('initial administrator password created','已创建初始管理员密码').replace('administrator login','管理员登录成功').replace('administrator logout','管理员已退出登录').replace('administrator password changed; sessions revoked','管理员密码已修改，会话已失效').replace('one-time enrollment created','已创建一次性接入 Token').replace('new one-time enrollment created; current credential remains valid until successful replacement','已创建新的重新接入 Token；新身份接入成功前旧凭据继续有效').replace('node and credential removed','节点及凭据已删除').replace('common enrollment token generated','已生成通用接入 Token').replace('common enrollment token revoked','已撤销通用接入 Token').replace('server runtime logs cleared','Server 运行日志已清除').replace(/admin path /,'管理入口 ').replace(/failed attempt (\d)\/3/,'密码错误（$1/3）').replace(/report (\d+)s/,'上报 $1 秒').replace(/target v/,'目标 v').replace(/^(\d+) days \/ (\d+) MiB$/,'保留 $1 天 / 容量 $2 MiB');}
function auditResultZH(v=''){if(v==='success')return '成功';if(v==='failed')return '失败';if(v==='requested')return '已请求';if(v==='queued')return '已加入队列';if(v.startsWith('failed: '))return '失败：'+localizeErrorText(v.slice(8));if(v==='installed; awaiting reconnect/health commit')return '已安装，等待重连并确认';return v;}
async function loadAudit(){try{const a=await api('/api/audit');const rows=(a||[]).slice().sort((x,y)=>(y.time||0)-(x.time||0));html('auditList',rows.map(x=>`<div class="audit-item"><div class="time">${new Date(x.time*1000).toLocaleString()}</div>${esc(auditActionZH[x.action]||x.action)}${x.node?' · '+esc(x.node):''}${x.detail?' · '+esc(auditDetailZH(x.detail)):''} · ${esc(auditResultZH(x.result))}</div>`).join('')||'<div class="hint">暂无审计记录</div>');}catch{}}

async function loadUpdate(){try{const r=await api('/api/update/status');latestRelease=r.latest_version||'';const agents=r.agents||[];text('serverVersionMeta',`当前 v${r.server_version} · ${latestRelease?'最新 v'+latestRelease:'无法获取最新版本'} · Protocol v${r.protocol_version}`);const online=agents.filter(a=>a.status==='online').length,count=agents.filter(a=>latestRelease&&a.version&&a.version.replace(/^v/,'')!==latestRelease&&a.status==='online').length;text('agentUpdateMeta',`${online} 在线 · ${count} 台可更新`);text('updateSummary',r.server_update_available||count?`${(r.server_update_available?1:0)+count} 项可更新`:'已是最新');text('updateSummarySub',r.error?'版本源暂不可用':`Server ${r.server_update_available?'可更新':'最新'} · ${count} 个 Agent 可更新`);$('#serverUpdateBtn').disabled=!r.server_update_available||!!r.incompatible_agents;text('serverUpdateText',r.incompatible_agents?`${r.incompatible_agents} 个 Agent 不兼容，暂不能更新 Server`:(r.server_update_available?'Protocol 兼容，可更新':'当前已是最新'));renderAgentUpdates(agents);}catch(e){text('updateSummary','检查失败');text('agentUpdateMeta','检查失败');}}
function renderAgentUpdates(a){const latest=latestRelease;html('agentUpdateRows',a.map(x=>{const cur=(x.version||'').replace(/^v/,'');const can=x.status==='online'&&latest&&cur!==latest;return `<tr><td>${esc(x.name)}</td><td>${esc(x.version||'—')}</td><td>${latest?'v'+esc(latest):'—'}</td><td><span class="badge ${x.status==='online'?'':'off'}">${x.status==='online'?(can?'可更新':'最新'):'离线'}</span></td><td>${can?`<button class="btn small agent-update" data-id="${esc(x.id)}">更新</button>`:'—'}</td></tr>`;}).join(''));$$('.agent-update').forEach(b=>b.onclick=()=>updateAgent(b.dataset.id));}
async function updateAgent(id){if(!latestRelease){toast('未获取到目标版本');return;}try{await api(`/api/nodes/${encodeURIComponent(id)}/update`,{method:'POST',json:{version:latestRelease}});toast('Agent 更新命令执行完成');await loadUpdate();await loadNodes();}catch(e){toast(errorMessage(e));throw e;}}
async function updateAllAgents(){const bs=$$('.agent-update');for(const b of bs){try{await updateAgent(b.dataset.id);}catch{toast('批量更新已暂停');break;}}}
async function updateServer(){if(!latestRelease)return;try{await api('/api/update/server',{method:'POST',json:{version:latestRelease}});toast('Server 更新已进入安全更新队列');}catch(e){toast(errorMessage(e));}}

function prettySelect(select){if(!select||select.dataset.pretty)return;select.dataset.pretty='1';const wrap=document.createElement('div');wrap.className='pretty-select';select.parentNode.insertBefore(wrap,select);wrap.appendChild(select);const btn=document.createElement('button');btn.type='button';btn.className='pretty-select-btn';const menu=document.createElement('div');menu.className='pretty-select-menu';wrap.append(btn,menu);const render=()=>{const o=select.options[select.selectedIndex];btn.innerHTML=`<span>${esc(o?.text||'')}</span><span>⌄</span>`;menu.innerHTML=[...select.options].map((x,i)=>`<button type="button" data-i="${i}" class="${i===select.selectedIndex?'active':''}">${esc(x.text)}</button>`).join('');$$('button',menu).forEach(x=>x.onclick=()=>{select.selectedIndex=Number(x.dataset.i);select.dispatchEvent(new Event('change',{bubbles:true}));wrap.classList.remove('open');render();});};select._prettyRender=render;btn.onclick=e=>{e.stopPropagation();$$('.pretty-select.open').forEach(x=>x!==wrap&&x.classList.remove('open'));wrap.classList.toggle('open');};select.addEventListener('change',render);render();}
function setSelectValue(sel,v){const e=$(sel);if(!e)return;e.value=v;if(typeof e._prettyRender==='function')e._prettyRender();}
function confirmAction(title,body,note,cb,danger=false){text('confirmTitle',title);html('confirmText',body);const n=$('#confirmNote');if(n){n.textContent=note||'';n.style.display=note?'':'none';}const b=$('#confirmActionBtn');b.classList.toggle('danger',danger);pendingConfirm=cb;show('confirmOverlay');}

function resetSettingsNav(){$$('#settingNav button').forEach(x=>x.classList.toggle('active',x.dataset.setting==='general'));$$('.setting-pane').forEach(x=>x.classList.toggle('active',x.id==='setting-general'));}
async function openSettings(){resetSettingsNav();textValue('#newPass','');textValue('#newPass2','');validateNewPassword();show('settingsOverlay');await loadSettings().then(validateAdminPath).catch(()=>{});await Promise.allSettled([loadListen(),loadSelf(),loadUpdate(),loadAudit(),loadLogs()]);}

function bindUI(){
  $$('.close,[data-close]').forEach(b=>b.addEventListener('click',()=>hide(b.dataset.close||b.closest('.overlay')?.id)));
  document.addEventListener('click',()=>$$('.pretty-select.open').forEach(x=>x.classList.remove('open')));
  ['#commonTokenExpiry','#editNodeInterval','#logRetention','#logCapacity'].forEach(s=>prettySelect($(s)));
  $('#setupPass')?.addEventListener('input',()=>{updateStrength('#setupPass','#setupStrength','#setupStrengthText');validateSetup();});$('#setupPass2')?.addEventListener('input',validateSetup);$('#newPass')?.addEventListener('input',()=>{updateStrength('#newPass','#newPassStrength','#newPassStrengthText');validateNewPassword();});$('#newPass2')?.addEventListener('input',validateNewPassword);
  $('#setupBtn').onclick=setupAdmin;$('#loginBtn').onclick=login;$('#loginPass').addEventListener('keydown',e=>{if(e.key==='Enter')login();});$('#logoutBtn').onclick=logout;$('#settingsLogoutBtn').onclick=logout;
  $('#themeBtn').onclick=()=>{const dark=document.documentElement.dataset.theme==='dark';document.documentElement.dataset.theme=dark?'':'dark';localStorage.setItem('nodelume-theme',dark?'light':'dark');};if(localStorage.getItem('nodelume-theme')==='dark')document.documentElement.dataset.theme='dark';
  $('#addBtn').onclick=$('#mobileAddBtn').onclick=()=>{show('addOverlay');loadCommonEnrollment();};$('#settingsBtn').onclick=openSettings;
  $('#searchInput').oninput=renderNodes;$('#refreshBtn').onclick=()=>loadAll().then(()=>toast('已刷新'));$('#procSearch').oninput=loadProcesses;
  $('#addModeTabs').onclick=e=>{const b=e.target.closest('button');if(!b)return;$$('#addModeTabs button').forEach(x=>x.classList.remove('active'));b.classList.add('active');$$('.add-pane').forEach(x=>x.classList.toggle('active',x.id===`add-${b.dataset.addMode}`));};
  $('#regenCommonToken').onclick=generateCommon;$('#revokeCommonToken').onclick=()=>confirmAction('撤销通用 Token','撤销后将不能用于新 Agent 接入，已接入 Agent 不受影响。','',revokeCommon,true);$('#generateSingleToken').onclick=generateSingle;$('#copyCommonCommand').onclick=()=>copyCode('commonInstallCommand');$('#copySingleCommand').onclick=()=>copyCode('singleInstallCommand');
  $('#tabs').onclick=e=>{const b=e.target.closest('.tab');if(!b||b.disabled)return;$$('#tabs .tab').forEach(x=>x.classList.remove('active'));b.classList.add('active');$$('.tabpane').forEach(x=>x.classList.toggle('active',x.id===`pane-${b.dataset.tab}`));if(b.dataset.tab==='process')loadProcesses();if(b.dataset.tab==='stopped')loadStopped();if(b.dataset.tab==='disk')loadDisks();if(['overview','cpu','memory'].includes(b.dataset.tab))loadHistory(1);};
  $$('.ranges').forEach(g=>g.onclick=e=>{const b=e.target.closest('.range');if(!b)return;g.querySelectorAll('.range').forEach(x=>x.classList.remove('active'));b.classList.add('active');loadHistory(Number(b.dataset.range));});
  $('#editNodeBtn').onclick=openEdit;$('#saveNodeEditBtn').onclick=saveNode;$('#reenrollBtn').onclick=reenroll;$('#deleteNodeBtn').onclick=()=>currentNode&&confirmAction('删除节点',`确认删除 <b>${esc(currentNode.name)}</b>？删除后该 Agent 身份立即失效。`,'',deleteNode,true);
  $('#confirmActionBtn').onclick=()=>{const f=pendingConfirm;pendingConfirm=null;hide('confirmOverlay');if(f)f();};
  $('#settingNav').onclick=e=>{const b=e.target.closest('button');if(!b)return;$$('#settingNav button').forEach(x=>x.classList.remove('active'));b.classList.add('active');$$('.setting-pane').forEach(x=>x.classList.toggle('active',x.id===`setting-${b.dataset.setting}`));};
  $('#listenAddress').oninput=$('#listenPort').oninput=refreshListenDirty;$('#saveListenBtn').onclick=saveListen;$('#restartServerBtn').onclick=()=>confirmAction(listenState.pending?'重启并应用':'重启 Server','Server 将短暂断开，页面会自动等待恢复。','',restartServer,true);$('#securePath').oninput=validateAdminPath;$('#saveSecurePath').onclick=saveSecurity;$('#changePassBtn').onclick=changePassword;
  $('#certAutoBtn').onclick=applyCert;$('#certCheckBtn').onclick=checkCert;$('#certImportBtn').onclick=()=>{const d=$('#domainInput').value.trim();if(!d){toast('请先填写域名');return;}text('certImportDomainText',d);show('certImportOverlay');};$('#certFilePickBtn').onclick=()=>$('#certFileInput').click();$('#keyFilePickBtn').onclick=()=>$('#keyFileInput').click();$('#certFileInput').onchange=e=>readFile(e.target,'cert','certFileName');$('#keyFileInput').onchange=e=>readFile(e.target,'key','keyFileName');$('#certImportTabs').onclick=e=>{const b=e.target.closest('[data-import-mode]');if(!b)return;$$('#certImportTabs .cert-import-tab').forEach(x=>x.classList.toggle('active',x===b));$('#certImportFilePane').classList.toggle('active',b.dataset.importMode==='file');$('#certImportPastePane').classList.toggle('active',b.dataset.importMode==='paste');};$('#certImportApplyBtn').onclick=importCert;$('#certLogCopyBtn').onclick=async()=>toast(await copyText($('#certLogOutput').innerText)?'日志已复制':'请手动复制日志');$('#certLogClearBtn').onclick=()=>{html('certLogOutput','<span class="log-muted">暂无日志</span>');text('certLogState','暂无');};
  $('#logRetention').onchange=saveLogSettings;$('#logCapacity').onchange=saveLogSettings;$('#clearRuntimeLogs').onclick=()=>confirmAction('清除运行日志','确认清除 NodeLume Server 运行日志？','',clearLogs,true);
  $('#checkUpdatesBtn').onclick=loadUpdate;$('#serverUpdateBtn').onclick=()=>confirmAction('更新 Server',`确认更新到 <b>v${esc(latestRelease)}</b>？`,'更新失败会由系统更新器回滚。',updateServer,true);$('#allAgentUpdateBtn').onclick=()=>confirmAction('批量更新 Agent','按顺序更新所有可更新在线 Agent；任一失败即暂停后续。','',updateAllAgents,true);
}

document.addEventListener('DOMContentLoaded',()=>{bindUI();validateSetup();validateNewPassword();bootstrap();setInterval(()=>{if(!document.body.classList.contains('auth-locked'))loadNodes().catch(()=>{});},5000);});
