'use strict';
const $=id=>document.getElementById(id);
const labels={wireguard:'WireGuard',openvpn:'OpenVPN',ikev2:'IKEv2 / IPsec'};
const summaries={wireguard:'A fast, minimal VPN built around public-key authentication.',openvpn:'A flexible VPN with username and password authentication.',ikev2:'Native VPN connectivity with EAP-MSCHAPv2 credentials.'};
const short={wireguard:'WG',openvpn:'OV',ikev2:'I2'};
const ipv6Networks={wireguard:'fd66:66::/64',openvpn:'fd67:67::/64',ikev2:'fd68:68::/64'};
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let overview=null,state=null,page='overview',activeService=null,toastTimeout=null,taskWatchSeq=0;
let modalReturnFocus=null,activeTaskId=null,taskWatching=false,pendingTaskResume=false,mutationRequests=0;
const requests=new Map(),disabledControls=new Map();
function health(online){
 $('engineHealth').classList.toggle('offline',!online);
 $('engineHealth').lastElementChild.textContent=online?'ENGINE ONLINE':'ENGINE OFFLINE';
 $('sidebarHealth').classList.toggle('offline',!online);
 $('sidebarHealth').lastElementChild.textContent=online?'Engine online':'Engine offline';
}
async function api(url,opt={}){
 let res;
 try{res=await fetch(url,{credentials:'same-origin',cache:'no-store',...opt,headers:{'Content-Type':'application/json',...(opt.headers||{})}})}
 catch{health(false);const err=new Error('Cannot reach the server. Check your connection and try again.');err.status=0;throw err}
 health(res.status<500);
 let data={};
 try{data=await res.json()}catch{
  if(res.ok){health(false);const err=new Error('The server returned an unexpected response. Try again.');err.status=502;throw err}
 }
 if(!res.ok){const err=new Error(data.error||'Request failed ('+res.status+')');err.status=res.status;throw err}
 return data;
}
const send=(url,body)=>api(url,{method:'POST',body:JSON.stringify(body||{})});
function toast(message,error=false){const e=$('toast');e.textContent=message;e.classList.toggle('error',error);e.classList.remove('hidden');clearTimeout(toastTimeout);toastTimeout=setTimeout(()=>e.classList.add('hidden'),6500)}
function authMessage(message,retry=false){$('authMessage').textContent=message;$('authMessage').classList.toggle('hidden',!message);$('authRetry').classList.toggle('hidden',!retry)}
function clearError(){$('appError').classList.add('hidden');$('appRetry').classList.add('hidden')}
function authScreen(which,message=''){
 closeModal();$('connectionScreen').classList.add('hidden');$('appShell').classList.add('hidden');$('authScreen').classList.remove('hidden');
 $('setupBox').classList.toggle('hidden',which!=='setup');$('loginBox').classList.toggle('hidden',which!=='login');
 $('authHTTPWarning').classList.toggle('hidden',location.protocol==='https:');authMessage(message);
}
function appScreen(){$('connectionScreen').classList.add('hidden');$('authScreen').classList.add('hidden');$('appShell').classList.remove('hidden')}
function endSession(message){
 taskWatchSeq++;taskWatching=false;if(activeTaskId)pendingTaskResume=true;activeTaskId=null;
 $('loginForm').reset();document.querySelectorAll('input[type="password"]').forEach(input=>{input.value=''});
 authScreen('login',message||'Your session ended. Sign in again to continue.');applyLocks();
}
function handleError(err,protectedRequest=true){
 if(protectedRequest&&err.status===401){endSession(pendingTaskResume||activeTaskId?'Your session ended. The server operation continues. Sign in again to check its progress.':'');return}
 if(err.status===409&&err.message==='another operation is running'){toast('Another server operation is running. Checking its progress…');void resumeActiveTask();return}
 const retry=err.status===0||err.status>=500;
 if(!$('appShell').classList.contains('hidden')){$('appErrorMessage').textContent=err.message;$('appError').classList.remove('hidden');$('appRetry').classList.toggle('hidden',!retry);toast(err.message,true)}
 else if(!$('authScreen').classList.contains('hidden'))authMessage(err.message,retry);
 else{$('connectionScreen').classList.remove('hidden');$('connectionMessage').textContent=err.message;$('connectionRetry').classList.remove('hidden')}
}
function applyLocks(){
 // Preserve controls that were disabled before a request, including unavailable IPv6.
 for(const [control,disabled] of disabledControls)control.disabled=disabled;disabledControls.clear();
 function lock(control){if(!disabledControls.has(control))disabledControls.set(control,control.disabled);control.disabled=true}
 for(const {scope} of requests.values()){
  if(!scope?.isConnected)continue;if(scope.matches('button,input,select'))lock(scope);scope.querySelectorAll('button,input,select').forEach(lock);
 }
 if(mutationRequests||taskWatching)document.querySelectorAll('#page form button,#page form input,#page form select,#modalContent form button,#modalContent form input,#page [data-action]').forEach(control=>{
  const kind=(control.dataset.action||'').split(':')[0];
  if(!control.dataset.action||['service','ipv6','toggle','delete','password','add'].includes(kind))lock(control);
 });
}
async function locked(key,scope,action,mutation=false){
 if(requests.has(key)||(mutation&&(mutationRequests||taskWatching)))return;
 requests.set(key,{scope});if(mutation)mutationRequests++;scope?.setAttribute('aria-busy','true');applyLocks();
 try{return await action()}finally{requests.delete(key);if(mutation)mutationRequests--;scope?.removeAttribute('aria-busy');applyLocks()}
}
async function boot(){
 await locked('boot',$('connectionRetry'),async()=>{
  try{state=await api('/api/state');if(!state.setupComplete){authScreen('setup');return}if(await refresh(true))await resumeActiveTask()}
  catch(err){handleError(err,false)}
 });
}
async function refresh(initial=false){
 if(requests.has('refresh'))return false;
 return locked('refresh',$('refreshBtn'),async()=>{
  try{
   const current=await api('/api/overview');overview=current;
   $('lastChecked').textContent='Last checked: '+new Date().toLocaleTimeString();
   $('accountName').textContent=overview.adminUser;$('sidebarVersion').textContent='VPN Engine v'+overview.version;
   $('httpWarning').classList.toggle('hidden',overview.https===true);
   const warnings=Array.isArray(overview.warnings)?overview.warnings:[];
   $('runtimeWarnings').innerHTML=warnings.map(w=>'<div class="note notice-warning">'+esc(w)+'</div>').join('');
   $('runtimeWarnings').classList.toggle('hidden',!warnings.length);clearError();appScreen();render();return true;
  }catch(err){
   if(initial&&err.status===401){authScreen('login');return false}
   handleError(err);return false
  }
 });
}
async function retryConnection(){if(!$('appShell').classList.contains('hidden')){if(await refresh())await resumeActiveTask()}else await boot()}
$('connectionRetry').addEventListener('click',retryConnection);
$('authRetry').addEventListener('click',retryConnection);
$('appRetry').addEventListener('click',retryConnection);
$('refreshBtn').addEventListener('click',async()=>{if(await refresh())await resumeActiveTask()});
$('setupForm').addEventListener('submit',async e=>{
 e.preventDefault();const body=Object.fromEntries(new FormData(e.target));
 await locked('setup',e.target,async()=>{
  try{await send('/api/setup',body);e.target.reset();authScreen('login','Admin account created. Sign in with your new username and password.')}
  catch(err){
   if(err.status===409)authMessage('An administrator already exists. Sign in using that account.',true);
   else if(err.status===429)authMessage('The server is processing another request. Try again shortly.');
   else handleError(err,false);
  }
 });
});
$('loginForm').addEventListener('submit',async e=>{
 e.preventDefault();const body=Object.fromEntries(new FormData(e.target));
 await locked('login',e.target,async()=>{
  try{await send('/api/login',body);e.target.reset();authMessage('');if(await refresh())await resumeActiveTask()}
  catch(err){
   if(err.status===401)authMessage('Username or password was not accepted. Try again.');
   else if(err.status===429)authMessage(err.message.includes('busy')?'The server is processing another sign-in request. Try again shortly.':'Too many sign-in attempts. Wait five minutes, then try again.');
   else handleError(err,false);
  }
 });
});
$('logoutBtn').addEventListener('click',async()=>{await locked('logout',$('logoutBtn'),async()=>{try{await send('/api/logout',{});endSession('You have signed out.')}catch(err){handleError(err)}})});
$('nav').addEventListener('click',e=>{const button=e.target.closest('button[data-page]');if(!button)return;page=button.dataset.page;activeService=null;render()});
function navigate(to,id=null){page=to;activeService=id;render();window.scrollTo({top:0,behavior:'instant'})}
function service(id){return overview.services.find(s=>s.id===id)}
function serviceUsers(id){return overview.users.filter(u=>u.service===id)}
function badge(status){const kind=(status==='running'||status==='enabled')?'running':(status==='stopped'||status==='disabled')?'stopped':'';return `<span class="badge ${kind}">${esc(status)}</span>`}
function button(text,action,cls='',disabled=false){return '<button type="button" class="btn '+cls+'" data-action="'+esc(action)+'"'+(disabled?' disabled':'')+'>'+esc(text)+'</button>'}
function statCard(label,value,note){return `<div class="stat-card"><div class="stat-title">${esc(label)}</div><div class="stat-number">${esc(value)}</div><div class="stat-sub">${esc(note)}</div></div>`}
function heading(title,desc=""){return `<div class="heading-row"><div><h1>${esc(title)}</h1>${desc?`<p class="intro">${esc(desc)}</p>`:""}</div></div>`}
function serviceCard(s){return `<article class="service-card"><div class="service-header"><div class="service-logo ${esc(s.id)}">${esc(short[s.id])}</div>${badge(s.status)}</div><h3>${esc(labels[s.id])}</h3><p class="service-desc">${esc(summaries[s.id])}</p><div class="service-bottom"><span class="service-meta"><strong>${s.installed?(s.id==='ikev2'?'UDP 500/4500':'UDP '+s.config.port):'Not configured'}</strong></span>${button(s.installed?'Manage →':'Install →','open:'+s.id,s.installed?'small':'small primary')}</div></article>`}
function render(){if(!overview)return;const navPage=page==='detail'?'services':page;document.querySelectorAll('#nav button[data-page]').forEach(b=>{const selected=b.dataset.page===navPage;b.classList.toggle('selected',selected);if(selected)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current')});$('breadcrumb').textContent=page==='detail'?labels[activeService]:page.charAt(0).toUpperCase()+page.slice(1);let content='';switch(page){case 'overview':content=renderOverview();break;case 'services':content=renderServices();break;case 'detail':content=renderDetail(activeService);break;case 'users':content=renderUsersPage();break;case 'settings':content=renderSettings();break;}$('page').innerHTML=content;attachActions();applyLocks()}
function renderOverview(){const n=overview.services.filter(s=>s.installed).length,r=overview.services.filter(s=>s.status==='running').length;return heading('Overview')+`<div class="stats-grid">${statCard('Installed protocols',n+' / 3','WireGuard · OpenVPN · IKEv2')}${statCard('Running services',r,'Services reporting active')}${statCard('VPN users',overview.users.length,'Across all protocols')}</div><div class="section-head"><div><h2>VPN services</h2><p>Choose which protocol to run on this server.</p></div>${button('All services →','goto:services','small ghost')}</div><div class="grid-3">${overview.services.map(serviceCard).join('')}</div><div class="panel engine-info"><h2>Engine information</h2><div class="detail-grid"><div class="detail"><small>Control plane</small><strong>${overview.https?'HTTPS / TCP 443':'HTTP / TCP '+esc(overview.panelPort)}</strong></div><div class="detail"><small>Outgoing interface</small><strong>${esc(overview.outgoingInterface||'Not detected')}</strong></div><div class="detail"><small>Server version</small><strong>${esc(overview.version)}</strong></div></div></div>`}
function renderServices(){return heading('VPN services','Each VPN protocol installs and runs separately. Installing the panel does not install any VPN server.')+`<div class="grid-3">${overview.services.map(serviceCard).join('')}</div>`}
function detail(label,value){return `<div class="detail"><small>${esc(label)}</small><strong>${esc(value)}</strong></div>`}
function ipv6Warning(id){
 const native=id==='ikev2'?'<p class="form-help">IPv6 protection depends on your device\'s native VPN implementation. IPv6 traffic may bypass the VPN on some devices when IPv6 tunneling is unavailable.</p>':'';
 return '<p class="form-help">Turning IPv6 off keeps IPv4 working. Supported client profiles help prevent IPv6 traffic from bypassing the VPN. Check protection on your device.</p>'+native;
}
function installIPv6Options(id){
 const available=overview.ipv6Available===true;
 return '<div class="wide"><label class="checkbox-label"><input type="checkbox" name="ipv6"'+(available?' checked':' disabled')+'> IPv6 support</label><p class="form-help">'+(available?'This server supports IPv6. Include it in this VPN service.':'IPv6 internet access was not detected. Check Settings > Server IPv6 connectivity for possible provider or server network causes. IPv4 will work normally.')+'</p>'+ipv6Warning(id)+'</div>';
}
function renderIPv6(id,cfg){
 const enabled=cfg.ipv6===true,unavailable=overview.ipv6Available!==true;
 return '<div class="panel"><h2>IPv6 support</h2><p>IPv6 support is '+(enabled?'On':'Off')+' for this VPN service.</p>'+(unavailable?'<p class="form-help">IPv6 internet access was not detected. Check Settings > Server IPv6 connectivity for possible provider or server network causes. You can keep using IPv4.</p>':'')+ipv6Warning(id)+'<p class="form-help">After a change, reconnect your devices. WireGuard and OpenVPN users should download and import their updated profiles.</p><div class="form-actions">'+button(enabled?'Turn IPv6 off':'Turn IPv6 on','ipv6:'+id+':'+(!enabled),'small ghost',!enabled&&unavailable)+'</div></div>';
}
function renderDetail(id){const s=service(id);if(!s)return '<p>Service not found.</p>';const cfg=s.config;let content=`<button class="back" data-action="goto:services">← Back to services</button><div class="heading-row"><div><div class="eyebrow">PROTOCOL SETTINGS</div><h1>${esc(labels[id])}</h1><p class="intro">${esc(summaries[id])}</p></div>${badge(s.status)}</div>`;
if(!s.installed){content+=`<section class="panel"><h2>Install ${esc(labels[id])}</h2><p class="panel-intro">Only this protocol and its required packages will be installed.</p><form id="installForm" data-service="${esc(id)}"><div class="form-grid"><label>Public IPv4 or domain<input required name="endpoint" value="${esc(location.hostname)}" maxlength="253"></label><label>Outgoing network interface<input required name="interface" value="${esc(overview.outgoingInterface||'')}" maxlength="15"></label><label>VPN subnet (private /24)<input required name="cidr" value="${esc(cfg.cidr)}"></label><label>DNS server<input required name="dns" value="${esc(cfg.dns)}"></label>${id==='ikev2'?'<div class="note wide">IKEv2 uses UDP 500 and 4500. The server certificate authority can be downloaded after installation.</div>':`<label class="wide">VPN UDP port<input type="number" min="1" max="65535" name="port" required value="${esc(cfg.port)}"></label>`}</div><div class="form-actions"><button class="btn primary" type="submit">Install ${esc(labels[id])} →</button></div></form></section>`;content=content.replace('</div><div class="form-actions">',installIPv6Options(id)+'</div><div class="form-actions">');return content}
content+=`<div class="panel"><div class="section-head"><h2>Service information</h2><div class="table-actions">${button('Start','service:'+id+':start','small')}${button('Stop','service:'+id+':stop','small ghost')}${button('Restart','service:'+id+':restart','small ghost')}${button('Logs','logs:'+id,'small ghost')}</div></div><div class="detail-grid">${detail('Server',cfg.endpoint)}${detail('Port',id==='ikev2'?'500, 4500 / UDP':cfg.port+' / UDP')}${detail('Network',cfg.cidr)}${detail('Outgoing interface',cfg.interface)}${detail('DNS',cfg.dns)}${detail('Status',s.status)}</div></div>`;
content+=renderIPv6(id,cfg);
content+=`<div class="panel"><div class="section-head"><div><h2>Access & users</h2><p>Manage accounts and client profiles for ${esc(labels[id])}.</p></div>${button('Add '+(id==='wireguard'?'device':'user'),'add:'+id,'small primary')}</div>${renderUserTable(serviceUsers(id),id)}</div>`;
if(id==='ikev2')content+=`<div class="panel"><h2>Samsung / native IKEv2 setup</h2><p class="panel-intro">Use IKEv2/IPsec MSCHAPv2 in your device's built-in VPN settings. The server authenticates with a certificate; the user authenticates with a username and password.</p><div class="note">Install the generated CA certificate on each device and select it when configuring the VPN. The server identity must match the public hostname or IP address.</div><div class="form-actions"><a class="btn primary" href="/api/services/ikev2/ca" download>Download CA certificate</a></div></div>`;
if(id==='openvpn')content+=`<div class="panel"><h2>OpenVPN connection</h2><p>Download an .ovpn profile for any user. OpenVPN Connect will request the username and password when connecting.</p></div>`;
content+=`<div class="panel"><h2>Remove protocol</h2><p>Stop and remove this protocol's VPN Engine configuration and accounts. Other protocols and the admin panel remain available.</p><div class="form-actions">${button('Remove '+labels[id],'service:'+id+':remove','danger small')}</div></div>`;
return content}
function renderUserTable(users,id){if(!users.length)return `<div class="empty"><h3>No ${id==='wireguard'?'devices':'users'} yet</h3><p>Create the first account to connect a device.</p></div>`;return `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Details</th><th>Status</th><th>Actions</th></tr></thead><tbody>${users.map(u=>`<tr><td><strong>${esc(u.name)}</strong></td><td class="small-text mono">${esc(u.address||labels[u.service])}</td><td>${badge(u.enabled?'enabled':'disabled')}</td><td><div class="table-actions">${button(id==='ikev2'?'Details':'Profile','profile:'+u.id,'small ghost')}${id==='wireguard'?button('QR','qr:'+u.id,'small ghost'):button('Password','password:'+u.id,'small ghost')}${button(u.enabled?'Disable':'Enable','toggle:'+u.id,'small ghost')}${button('Delete','delete:'+u.id,'small danger')}</div></td></tr>`).join('')}</tbody></table></div>`}
function renderUsersPage(){return heading('VPN users','Accounts are separate for each VPN protocol. WireGuard uses cryptographic keys instead of passwords.')+(overview.services.some(s=>s.installed)?overview.services.filter(s=>s.installed).map(s=>`<section class="panel"><div class="section-head"><div><h2>${esc(labels[s.id])}</h2><p>${serviceUsers(s.id).length} account(s)</p></div>${button('Add user','add:'+s.id,'small primary')}</div>${renderUserTable(serviceUsers(s.id),s.id)}</section>`).join(''):'<div class="empty">No VPN protocols installed.</div>')}
function renderIPv6Connectivity(){
 const available=overview.ipv6Available===true;
 const status='<span class="badge '+(available?'running':'stopped')+'">'+(available?'Available':'Unavailable')+'</span>';
 const details=available
  ? '<p class="form-help">A working public IPv6 internet connection was detected on this server. You can enable IPv6 separately for each VPN service.</p>'
  : '<p class="form-help">No usable IPv6 internet connection could be detected on this server.</p><div class="note notice-warning">This does not mean VPN Engine failed to install IPv6. Your ISP or VPS provider may not have assigned IPv6, or the server\'s IPv6 address, default route, or network configuration may be missing or incorrect.</div><p class="form-help">IPv4 VPN services remain available. IPv6 options are disabled until the server has working IPv6 connectivity.</p>';
 return '<section class="panel narrow-panel"><div class="section-head"><h2>Server IPv6 connectivity</h2>'+status+'</div>'+details+'</section>';
}
function renderSettings(){const access=overview.https?`<label>Admin panel<input value="HTTPS / TCP 443" disabled></label><input type="hidden" name="panelPort" value="${esc(overview.panelPort)}">`:`<label>Admin panel port (TCP)<input type="number" min="1" max="65535" name="panelPort" required value="${esc(overview.panelPort)}"></label>`;const note=overview.https?'This connection uses HTTPS. Keep automatic certificate renewal enabled on your server.':'HTTPS is not active. The panel is currently exposed directly over HTTP.';return heading('Engine settings')+`<section class="panel narrow-panel"><h2>Admin account</h2><p class="form-help">Changing your admin username or password signs out all admin sessions. Sign in again with your updated details.</p><form id="settingsForm"><div class="form-grid"><label>Admin username<input required name="username" pattern="[A-Za-z][A-Za-z0-9_.-]{0,31}" value="${esc(overview.adminUser)}"></label>${access}<label class="wide">New password (leave blank to keep current)<input type="password" name="newPassword" minlength="8" maxlength="256" autocomplete="new-password"></label></div><div class="form-actions"><button type="submit" class="btn primary">Save settings</button></div></form></section>${renderIPv6Connectivity()}<div class="note narrow-panel">${note}</div>`}
function showModal(title,body){
 if($('modal').classList.contains('hidden'))modalReturnFocus=document.activeElement;
 $('modalTitle').textContent=title;$('modalContent').innerHTML=body;$('modal').classList.remove('hidden');
 $('appShell').inert=true;$('authScreen').inert=true;applyLocks();
 ($('modalContent').querySelector('input:not(:disabled),button:not(:disabled),a[href]')||$('modalClose')).focus();
}
function closeModal(){
 if($('modal').classList.contains('hidden'))return;
 $('modal').classList.add('hidden');$('modalContent').innerHTML='';$('appShell').inert=false;$('authScreen').inert=false;
 if(modalReturnFocus?.isConnected&&!modalReturnFocus.disabled)modalReturnFocus.focus();modalReturnFocus=null;
}
function taskTitle(t){return (labels[t.service]||t.service)+': '+(t.action==='ipv6'?'IPv6 update':t.action)}
function taskStateText(t){if(t.status==='running')return t.action.charAt(0).toUpperCase()+t.action.slice(1)+' in progress…';return t.status==='done'?'Completed successfully.':'Operation failed.'}
function taskProgressBody(t){
 if(t.action!=='install')return '<p id="taskState" class="task-state" role="status">Working… You can close this window; the operation will continue.</p><pre class="activity" id="taskLog">Preparing…</pre>';
 const progress=Math.max(0,Math.min(100,Number(t.progress)||0));
 return '<div class="task-progress-wrap"><div class="task-progress-head"><strong id="taskStage">'+esc(t.stage||'Preparing installation')+'</strong><span id="taskPercent">'+progress+'%</span></div><progress class="task-progress-bar" id="taskProgress" aria-labelledby="taskStage" max="100" value="'+progress+'"></progress><p class="task-hint" id="taskState" role="status">This may take a few minutes. You can close this window; installation will continue.</p></div><details class="task-details" id="taskDetails"><summary>Technical details</summary><pre class="activity" id="taskLog">Preparing…</pre></details>';
}
function paintTask(t){
 const progress=Math.max(0,Math.min(100,Number(t.progress)||0));
 const p=$('taskProgress');if(p)p.value=t.status==='done'?100:progress;
 const percent=$('taskPercent');if(percent)percent.textContent=(t.status==='done'?100:progress)+'%';
 const stage=$('taskStage');if(stage)stage.textContent=t.stage||taskStateText(t);
 const log=$('taskLog');if(log){const lines=(t.messages||[]).join('\n');log.textContent=lines+(t.error?(lines?'\n\n':'')+'ERROR: '+t.error:'');log.scrollTop=log.scrollHeight}
 const st=$('taskState');if(st){if(t.action!=='install')st.textContent=taskStateText(t);else if(t.status==='done')st.textContent='Installation completed successfully.';else if(t.status==='error')st.textContent='Installation failed. See technical details below.'}
 if($('taskDetails')&&t.status==='error')$('taskDetails').open=true;
}
async function watchTask(initial){
 const seq=++taskWatchSeq;taskWatching=true;pendingTaskResume=true;applyLocks();
 try{
  let t=typeof initial==='string'?await api('/api/tasks/'+encodeURIComponent(initial)):initial;
  activeTaskId=t.id;showModal(taskTitle(t),taskProgressBody(t));
  while(seq===taskWatchSeq){
   paintTask(t);
   if(t.status!=='running'){
    pendingTaskResume=false;activeTaskId=null;await refresh();
    if(t.status==='done')toast((labels[t.service]||t.service)+' '+(t.action==='ipv6'?'IPv6 update':t.action)+' completed.');
    else{const err=new Error(t.error||'Operation failed. Check the service logs.');err.status=400;handleError(err)}
    return;
   }
   await new Promise(resolve=>setTimeout(resolve,700));if(seq!==taskWatchSeq)return;
   t=await api('/api/tasks/'+encodeURIComponent(t.id));
  }
 }catch(err){if(seq===taskWatchSeq){closeModal();handleError(err)}}
 finally{if(seq===taskWatchSeq){taskWatching=false;activeTaskId=null}applyLocks()}
}
async function resumeActiveTask(){
 if(requests.has('resume'))return false;
 return locked('resume',null,async()=>{
  try{
   const d=await api('/api/tasks/active');if(!d.task){pendingTaskResume=false;return false}
   if(taskWatching&&(!activeTaskId||activeTaskId===d.task.id)){
    if($('modal').classList.contains('hidden')){showModal(taskTitle(d.task),taskProgressBody(d.task));paintTask(d.task)}
    return true;
   }
   void watchTask(d.task);return true;
  }catch(err){handleError(err);return false}
 });
}
$('modalClose').addEventListener('click',closeModal);
$('modal').addEventListener('click',e=>{if(e.target===$('modal'))closeModal()});
document.addEventListener('keydown',e=>{
 if($('modal').classList.contains('hidden'))return;
 if(e.key==='Escape'){closeModal();return}
 if(e.key!=='Tab')return;
 const controls=Array.from($('modal').querySelectorAll('button:not(:disabled),input:not(:disabled),select:not(:disabled),a[href],summary,[tabindex="0"]')).filter(el=>el.getClientRects().length);
 const first=controls[0],last=controls[controls.length-1];
 if(e.shiftKey&&(document.activeElement===first||!controls.includes(document.activeElement))){e.preventDefault();last?.focus()}
 else if(!e.shiftKey&&(document.activeElement===last||!controls.includes(document.activeElement))){e.preventDefault();first?.focus()}
});
function attachActions(){
 document.querySelectorAll('#page [data-action]').forEach(el=>el.addEventListener('click',handleAction));
 if($('installForm'))$('installForm').addEventListener('submit',installService);
 if($('settingsForm'))$('settingsForm').addEventListener('submit',saveSettings);
}
async function mutationError(err){
 // A failed disconnect may still have saved the access change. Show that current state.
 if(err.status>=500){const fresh=await refresh();if(!fresh&&$('appShell').classList.contains('hidden'))return}
 handleError(err);
}
async function handleAction(e){
 const target=e.currentTarget,bits=target.dataset.action.split(':'),kind=bits[0];
 if(kind==='goto'){navigate(bits[1]);return}if(kind==='open'){navigate('detail',bits[1]);return}
 if(kind==='add'){addUserDialog(bits[1]);return}if(kind==='password'){passwordDialog(bits[1]);return}
 const mutation=['toggle','delete','service','ipv6'].includes(kind);
 if(kind==='delete'&&!confirm('Delete this account and end its VPN access?'))return;
 if(kind==='service'&&bits[2]==='remove'&&!confirm('Remove '+labels[bits[1]]+' and all its VPN Engine accounts?'))return;
 if(kind==='ipv6'&&!confirm('Change IPv6 support for '+labels[bits[1]]+'? Devices will need to reconnect. WireGuard and OpenVPN profiles should be downloaded and imported again.'))return;
 await locked('action:'+target.dataset.action,target,async()=>{
  try{
   if(kind==='qr'){
    const blob=await download('/api/users/'+encodeURIComponent(bits[1])+'/qr');
    const data=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result);reader.onerror=()=>reject(new Error('Could not display this QR code. Try again.'));reader.readAsDataURL(blob)});
    showModal('WireGuard QR code','<p>Scan with the WireGuard app.</p><img class="qr-image" alt="WireGuard QR code" src="'+esc(data)+'">');
   }else if(kind==='profile'){
    const user=overview.users.find(u=>u.id===bits[1]);
    if(user?.service==='ikev2'){
     const d=await api('/api/users/'+encodeURIComponent(user.id)+'/profile');
     showModal('IKEv2 connection details','<div class="detail-grid single-column">'+detail('VPN type',d.type)+detail('Server / remote ID',d.server)+detail('Username',d.username)+'</div><p class="profile-hint">'+esc(d.hint)+'</p><a class="btn primary" href="/api/services/ikev2/ca" download>Download CA certificate</a>');
    }else{
     const blob=await download('/api/users/'+encodeURIComponent(bits[1])+'/profile'),link=document.createElement('a'),url=URL.createObjectURL(blob);
     link.href=url;link.download=(user?.name||'vpn-engine')+(user?.service==='wireguard'?'.conf':'.ovpn');link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    }
   }else if(kind==='toggle'||kind==='delete'){
    if(kind==='toggle')await send('/api/users/'+encodeURIComponent(bits[1])+'/toggle');
    else await api('/api/users/'+encodeURIComponent(bits[1]),{method:'DELETE'});
    await refresh();toast(kind==='toggle'?'Account updated.':'Account deleted.');
   }else if(kind==='logs'){
    const d=await api('/api/services/'+bits[1]+'/logs');showModal('Service logs','<pre class="activity" id="serviceLog"></pre>');$('serviceLog').textContent=d.logs||'No logs available.';
   }else if(kind==='service')await runServiceTask(bits[1],bits[2],{});
   else if(kind==='ipv6')await runServiceTask(bits[1],'ipv6',{enabled:bits[2]==='true'});
  }catch(err){if(kind==='toggle'||kind==='delete')await mutationError(err);else handleError(err)}
 },mutation);
}
async function download(url){
 let res;
 try{res=await fetch(url,{credentials:'same-origin',cache:'no-store'})}
 catch{health(false);const err=new Error('Cannot reach the server. Try again.');err.status=0;throw err}
 health(res.status<500);
 if(!res.ok){let data={};try{data=await res.json()}catch{}const err=new Error(data.error||'Download failed ('+res.status+')');err.status=res.status;throw err}
 return res.blob();
}
async function installService(e){
 e.preventDefault();const id=e.target.dataset.service,data=Object.fromEntries(new FormData(e.target));
 data.port=id==='ikev2'?500:Number(data.port);data.ipv6=overview.ipv6Available===true&&e.target.elements.ipv6.checked;
 data.ipv6Cidr=service(id).config.ipv6Cidr||ipv6Networks[id];
 await locked('install',e.target,async()=>{try{await runServiceTask(id,'install',data)}catch(err){handleError(err)}},true);
}
async function runServiceTask(id,action,payload){const data=await send('/api/services/'+id+'/'+action,payload);await watchTask(data.taskId)}
function addUserDialog(id){
 const password=id==='wireguard'?'':'<label>Password ('+(id==='ikev2'?'8–72 characters, letters/digits/@ . _ ! + - = # %':'8–256 characters')+')<input type="password" name="password" required minlength="8" maxlength="'+(id==='ikev2'?'72':'256')+'" autocomplete="new-password"></label>';
 showModal('Add '+(id==='wireguard'?'device':'user')+' · '+labels[id],'<form id="addUserForm"><label>'+(id==='wireguard'?'Device name':'Username')+'<input name="name" pattern="[A-Za-z][A-Za-z0-9_.-]{0,31}" required placeholder="'+(id==='wireguard'?'phone':'alice')+'"></label>'+password+'<div class="form-actions"><button class="btn primary" type="submit">Create</button></div></form>');
 $('addUserForm').addEventListener('submit',async e=>{
  e.preventDefault();const b=Object.fromEntries(new FormData(e.target));b.service=id;
  await locked('add-user',e.target,async()=>{try{await send('/api/users',b);closeModal();await refresh();toast('Account created.')}catch(err){handleError(err)}},true);
 });
}
function passwordDialog(id){
 const user=overview.users.find(x=>x.id===id);if(!user)return;
 const hint=user.service==='ikev2'?' (8–72 characters, letters/digits/@ . _ ! + - = # %)':'';
 showModal('Change password · '+user.name,'<form id="changePasswordForm"><label>New VPN password'+hint+'<input type="password" name="password" minlength="8" maxlength="'+(user.service==='ikev2'?'72':'256')+'" required autocomplete="new-password"></label><p class="form-help">This ends the user\'s current VPN connections. They will need the new password to reconnect.</p><div class="form-actions"><button class="btn primary" type="submit">Change password</button></div></form>');
 $('changePasswordForm').addEventListener('submit',async e=>{
  e.preventDefault();const data=Object.fromEntries(new FormData(e.target));
  await locked('password:'+id,e.target,async()=>{try{await send('/api/users/'+encodeURIComponent(id)+'/password',data);closeModal();await refresh();toast('VPN password updated.')}catch(err){await mutationError(err)}},true);
 });
}
async function saveSettings(e){
 e.preventDefault();const req=Object.fromEntries(new FormData(e.target));req.panelPort=Number(req.panelPort);
 const credentialsChanged=req.username.trim()!==overview.adminUser||req.newPassword!=='';
 await locked('settings',e.target,async()=>{
  try{
   const res=await send('/api/settings',req);
   if(credentialsChanged)endSession('Admin details saved. Sign in again with your updated username and password.');else toast('Engine settings saved.');
   if(res.restart)setTimeout(()=>{location.href=overview.https?'https://'+location.hostname+'/':'http://'+location.hostname+':'+res.panelPort+'/'},1700);
   else if(!credentialsChanged)await refresh();
  }catch(err){handleError(err)}
 },true);
}
void boot();
