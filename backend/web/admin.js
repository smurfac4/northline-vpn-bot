"use strict";
const tg=window.Telegram?.WebApp;
const el=id=>document.getElementById(id);
const scopes={device:'Всё устройство',telegram:'Только Telegram'};
const labels={none:'Нет профиля',active:'Активен',creating:'Создаётся',revoking:'Отключается',revoked:'Отключён',expired:'Истёк'};
const titles={overview:'Обзор',servers:'Серверы и скорость',users:'Пользователи',requests:'Запросы',settings:'Настройки'};
let serverEnvironment=null,registry=null,registryLoading=false,registryError='',registryRequest=0,editingServer=null;
const actions={status:'Проверка профиля',issue:'Создание / смена сервера',revoke:'Отключение профиля',connection:'Инструкция / файл',config:'Конфигурация',
  'chat/start':'Команда /start','chat/help':'Команда /help','chat/admin':'Команда /admin',
  'chat/message':'Сообщение боту','chat/id':'Команда /id','chat/servers':'Выбор серверов в чате',
  'chat/status':'Профиль в чате','chat/guide':'Инструкция в чате','chat/select':'Выбор сервера',
  'chat/issue':'Подтверждение профиля','chat/revoke':'Подтверждение отключения',
  'admin/snapshot':'Просмотр админки','admin/server':'Настройка сервера','admin/account':'Настройка аккаунта','admin/revoke':'Отзыв доступа',
  'admin/registry':'Настройка реальных серверов','admin/restart':'Перезапуск сервиса','admin/measure':'Проверка метрик','admin/environment':'Смена режима'};
let data=null,view='overview',busy=false,loading=false,pendingAction=null,lastSuccess=0,revision=0,loadPromise=null,denied=false;
const activeMeasurements=new Set();
const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const number=value=>Number(value||0).toLocaleString('ru-RU');
const date=(value,full=false)=>value?new Date(value*1000).toLocaleString('ru-RU',full?{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}:{hour:'2-digit',minute:'2-digit',second:'2-digit'}):'—';
const userName=user=>[user.first_name,user.last_name].filter(Boolean).join(' ') || (user.username?'@'+user.username:'Аккаунт '+user.user_id);
const locationName=row=>/^[A-Z]{2}$/.test(row.country||'')&&row.country_name?Array.from(row.country,c=>String.fromCodePoint(0x1f1e6+c.charCodeAt(0)-65)).join('')+' '+row.country_name:row.name;
const liveAccess=(user,scope)=>user.live_access?.[scope]||{allowed:false,source:'environment'};
const source=value=>({bot:'Бот',miniapp:'Mini App',local:'Локально'}[value]||value);
tg?.ready();tg?.expand();tg?.setHeaderColor?.('#0b0c10');tg?.setBackgroundColor?.('#0b0c10');
for(const id of ['brand-link','back-app','user-app-link'])el(id).href='/'+(window.location.hash||'');
function goBack(){
  if(busy)return;
  if(el('server-editor').open)el('server-editor').close();
  else if(el('confirm-dialog').open)el('confirm-dialog').close();
  else if(el('user-dialog').open)el('user-dialog').close();
  else if(view!=='overview')showView('overview');
  else window.location.href='/'+(window.location.hash||'');
}
tg?.BackButton?.show();tg?.BackButton?.onClick(goBack);

function message(text='',error=false){el('message').textContent=text;el('message').toggleAttribute('data-error',error);}
async function api(path,body,timeoutMs=25000){
  const headers={};if(tg?.initData)headers['X-Telegram-Init-Data']=tg.initData;
  if(body!==undefined)headers['Content-Type']='application/json';
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),timeoutMs);
  try{
    const response=await fetch('/api/admin/'+path,{headers,cache:'no-store',signal:controller.signal,method:body===undefined?'GET':'POST',body:body===undefined?undefined:JSON.stringify(body)});
    const result=await response.json().catch(()=>{throw new Error('Сервер вернул неполный ответ. Повторите загрузку.');});
    if(!response.ok){const error=new Error(response.status===401?'Откройте админку заново из Telegram-бота.':result.error||'Не удалось выполнить действие.');error.status=response.status;throw error;}
    return result;
  }catch(error){if(error.name==='AbortError')throw new Error('Сервер долго отвечает. Повторите запрос.');if(error instanceof TypeError)throw new Error('Нет связи с сервером. Проверьте интернет.');throw error;}
  finally{clearTimeout(timer);}
}
function lockAdmin(){
  activeMeasurements.clear();
  denied=true;++revision;data=null;registry=null;registryLoading=false;++registryRequest;pendingAction=null;editingServer=null;
  el('content').hidden=true;el('locked').hidden=false;
  for(const id of ['server-editor','user-dialog','confirm-dialog'])if(el(id).open)el(id).close();
}
function showView(next){if(!titles[next])return;view=next;el('page-title').textContent=titles[next];for(const key of Object.keys(titles))el('view-'+key).hidden=key!==next;document.querySelectorAll('#sections button').forEach(button=>{const active=button.dataset.view===next;button.classList.toggle('selected',active);if(active)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');});window.scrollTo(0,0);}
function button(text,action,attrs='',danger=false){return `<button class="secondary ${danger?'danger-button':''}" data-action="${action}" ${attrs}${busy?' disabled':''}>${esc(text)}</button>`;}
function statusTag(status){return `<span class="tag ${status==='active'?'':status==='creating'||status==='revoking'?'warn':''}">${esc(labels[status]||status)}</span>`;}
function profileCell(profile){return profile&&profile.status!=='none'?`${statusTag(profile.status)}<small>${esc(profile.server)}</small>`:'<span class="muted">Нет профиля</span>';}
function recentRows(events){return events.length?events.map(event=>`<div class="event-row"><span class="event-icon">${event.status_code>=400?'!':'↗'}</span><div class="event-description">${esc(actions[event.action]||event.action)}<small>${esc(userName(event))} · ${esc(source(event.source))} · ${event.status_code}</small></div><time class="event-time">${date(event.created)}</time></div>`).join(''):'<p class="empty">Запросов пока нет. Они появятся после обращений к боту или Mini App.</p>';}
function renderOverview(){
  const stats=data.stats;const active=(stats.active.device||0)+(stats.active.telegram||0);
  el('stats').innerHTML=[['Аккаунты',stats.users,'Ограничено: '+stats.blocked],['Активные профили',active,'Два независимых режима'],['Запросы за 24 ч',stats.requests_24h,'Чат и Mini App'],['Ошибки за 24 ч',stats.errors_24h,'Включая отказы доступа']].map(([label,value,note])=>`<article class="stat"><span class="stat-label">${esc(label)}</span><div class="stat-value">${number(value)}</div><small>${esc(note)}</small></article>`).join('');
  const max=Math.max(1,...data.activity.map(row=>row.requests));
  el('activity').innerHTML='<svg class="activity-chart" viewBox="0 0 288 140" preserveAspectRatio="none" aria-hidden="true">'+data.activity.map((row,index)=>{
    const height=Math.max(2,row.requests/max*130);
    return `<rect x="${index*12+1}" y="${140-height}" width="8" height="${height}" rx="2"><title>${esc(date(row.hour,true))}: ${row.requests} запросов</title></rect>`;
  }).join('')+'</svg>';
  el('chart-total').textContent=number(stats.requests_24h)+' всего';
  el('mode-summary').innerHTML=Object.keys(scopes).map(scope=>`<div class="mode-summary-row"><span>${esc(scopes[scope])}<small class="muted"> / ${scope==='device'?'WireGuard / OpenVPN':'MTProto'}</small></span><strong>${number(stats.active[scope])}</strong></div>`).join('');
  el('recent-events').innerHTML=recentRows(data.events.slice(0,6));
}
function renderServers(){
  const sourceRows=realRows(),scope=el('server-scope').value,search=el('server-search').value.trim().toLowerCase();
  const rows=sourceRows.filter(server=>(scope==='all'||scope===server.scope)&&`${server.name} ${server.id}`.toLowerCase().includes(search));
  el('server-list-title').textContent='Серверы';
  el('real-toolbar').hidden=false;
  el('catalog-note').textContent='WireGuard / OpenVPN для устройства · MTProto для Telegram. Публичные серверы проверяются каждый час.';
  el('speed-note').textContent='Свои серверы: текущий трафик. OpenVPN: туннель и HTTPS. MTProto: ответ Telegram.';
  el('refresh-registry').disabled=busy||registryLoading;el('add-real-server').disabled=busy||registryLoading;
  el('registry-message').textContent=registryLoading?'Загрузка серверов…':registryError;
  const errors=registry?Object.entries(registry.catalogs).filter(([scope,item])=>item.error&&(el('server-scope').value==='all'||scope===el('server-scope').value)):[];
  const errorsHtml=errors.map(([scope,item])=>`<div class="registry-error">${esc(scopes[scope])}: ${esc(item.error)}</div>`).join('');
  el('server-grid').innerHTML=errorsHtml+(rows.length?rows.map(realCard).join(''):registryLoading||errors.length||registryError?'':`<div class="real-empty"><strong>${search?'Ничего не найдено по запросу':'Серверы пока не найдены'}</strong>${search?'Измените поисковый запрос.':'Дождитесь автоматической проверки или добавьте свой сервер.'}</div>`);
}
function renderUsers(){
  const search=el('user-search').value.trim().toLowerCase(),filter=el('user-filter').value;
  const rows=data.users.filter(user=>`${userName(user)} ${user.username} ${user.user_id}`.toLowerCase().includes(search)&&(filter!=='blocked'||user.blocked)&&(filter!=='active'||Object.values(user.profiles).some(p=>p.status==='active'))&&(filter!=='live'||(!user.blocked&&Object.keys(scopes).some(scope=>liveAccess(user,scope).allowed))));
  el('user-count').textContent=rows.length+' из '+data.stats.users;
  el('user-rows').innerHTML=rows.length?rows.map(user=>`<tr><td><span class="account-name">${esc(userName(user))}</span>${user.blocked?' <span class="tag warn">Ограничен</span>':''}<small>${user.username?'@'+esc(user.username)+' · ':''}${user.user_id}</small></td><td><span class="access-summary">${liveAccess(user,'device').allowed?'Реальный режим разрешён':'Реальный режим закрыт'}</span>${profileCell(user.profiles.device)}</td><td><span class="access-summary">${liveAccess(user,'telegram').allowed?'Реальный режим разрешён':'Реальный режим закрыт'}</span>${profileCell(user.profiles.telegram)}</td><td>${number(user.requests_24h)}</td><td>${date(user.last_seen,true)}</td><td>${button('Открыть','user',`data-user="${user.user_id}"`)}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">Аккаунты не найдены.</td></tr>';
}
function renderEvents(){
  const search=el('event-search').value.trim().toLowerCase(),filter=el('event-filter').value;
  const rows=data.events.filter(event=>`${userName(event)} ${event.user_id} ${event.node} ${event.action} ${actions[event.action]||''}`.toLowerCase().includes(search)&&
    (filter!=='errors'||event.status_code>=400)&&(filter!=='bot'||event.source==='bot')&&(filter!=='miniapp'||event.source==='miniapp')&&(filter!=='actions'||['issue','revoke'].includes(event.action)));
  el('event-rows').innerHTML=rows.length?rows.map(event=>`<tr><td>${date(event.created)}</td><td>${esc(userName(event))}<small>${event.user_id}</small></td><td>${esc(source(event.source))}</td><td>${esc(actions[event.action]||event.action)}</td><td>${esc(scopes[event.scope]||(event.scope==='admin'?'Админка':event.scope))}<small>${esc(event.node)}</small></td><td><span class="tag ${event.status_code>=400?'error':''}">${event.status_code}</span></td><td>${number(Math.round(event.duration_ms))}</td></tr>`).join(''):'<tr><td colspan="7" class="empty">Запросы не найдены.</td></tr>';
}
function renderSettings(){
  el('current-mode').textContent='Рабочий сервис';
  el('mode-hint').textContent='Серверы проверяются и обновляются каждый час. Доступ бессрочный.';
  el('readiness').innerHTML=data.readiness.checks.map(check=>`<li><span class="${check.ok?'check-ok':'check-no'}">${check.ok?'✓':'○'}</span>${esc(check.label)}</li>`).join('');
  el('proxy-readiness').textContent=data.readiness.telegram_note;
  const auditLabels={live_access_granted:'Разрешён доступ к реальному режиму',live_access_denied:'Закрыт доступ к реальному режиму',server_maintenance:'Сервер отправлен на обслуживание',server_available:'Сервер возвращён в работу',real_server_save:'Сохранён реальный сервер',real_server_delete:'Удалён реальный сервер',account_blocked:'Создание профилей заблокировано',account_allowed:'Создание профилей разрешено',profile_revoked:'Доступ отозван',environment_changed:'Изменён режим',metrics_requested:'Запрошены метрики',service_restart:'Перезапуск бота и приложения'};
  el('audit-list').innerHTML=data.audit.length?data.audit.map(row=>`<div class="event-row"><span class="event-icon">⚙</span><div class="event-description">${esc(auditLabels[row.action]||row.action)}<small>${esc(row.target)} · Администратор ${row.actor}</small></div><time class="event-time">${date(row.created,true)}</time></div>`).join(''):'<p class="empty">Действий администратора пока нет.</p>';
}
function render(){el('environment').textContent='Рабочий сервис';el('admin-id').textContent='Telegram ID '+data.admin_id;el('updated').textContent='Обновлено '+date(data.updated_at);renderOverview();renderServers();renderUsers();renderEvents();renderSettings();}
function reload(silent=false,internal=false){
  if(denied&&silent)return Promise.resolve(false);
  if(loading)return internal?loadPromise.then(()=>reload(silent,true)):loadPromise;
  if(busy&&!internal)return Promise.resolve(false);
  const epoch=revision;loading=true;el('reload').disabled=true;
  loadPromise=(async()=>{
    try{const result=await api('snapshot');if(epoch!==revision)return false;
      if(data&&data.mode!==result.mode)activeMeasurements.clear();
      data=result;denied=false;lastSuccess=Date.now();el('content').hidden=false;el('locked').hidden=true;render();if(!silent)message();finishMeasurements();return true;
    }catch(error){if(epoch!==revision)return false;message(error.message,true);
      if(error.status===401||error.status===403){lockAdmin();}
      return false;
    }finally{loading=false;el('reload').disabled=busy;}
  })();
  return loadPromise;
}

function confirm(title,text,callback,note){pendingAction=callback;el('confirm-title').textContent=title;el('confirm-text').textContent=text;el('note-label').hidden=note===undefined;el('server-note').value=note||'';if(el('user-dialog').open)el('user-dialog').close();el('confirm-dialog').showModal();el('cancel').focus();}
async function change(path,body,success){
  if(busy)return false;busy=true;++revision;el('reload').disabled=true;message('Сохранение…');
  if(data)renderServers();
  try{const result=await api(path,body);
    const measurement=path==='measure'&&result.pending?body.scope+':'+body.node:null;
    if(measurement)activeMeasurements.add(measurement);
    if(result.restart_required){message('Приложение перезапускается. Проверяем новый режим…');return await waitForMode(result.mode,result.previous_runtime_id);}
    else{const refreshed=await reload(true,true);if(!denied&&(!measurement||!refreshed||activeMeasurements.has(measurement)))message(refreshed?(result.external_notice|| (result.pending_revoke?'Доступ закрыт. Отзыв действующего профиля завершается автоматически.':success)):'Изменения сохранены, но состояние не обновилось. Нажмите «Обновить».',!refreshed);return refreshed;}
  }catch(error){if(error.status===401||error.status===403)lockAdmin();message(error.message,true);return false;}finally{busy=false;el('reload').disabled=false;if(data){renderSettings();renderServers();}}
}
function finishMeasurements(){
  for(const key of activeMeasurements){
    const server=data.servers.find(row=>row.scope+':'+row.id===key);
    if(server?.measuring)continue;
    activeMeasurements.delete(key);
    const metric=server?.metric;
    if(server?.metric_kind==='availability'){
      message(metric?.state==='online'?(server.scope==='device'?'Туннель OpenVPN и HTTPS проверены: ':'Публичный прокси отвечает: ')+number(metric.latency_ms)+' мс.':metric?.note||'Сервер не ответил.',metric?.state!=='online');
      continue;
    }
    if(metric?.state==='online'&&metric.download_mbps!=null&&metric.upload_mbps!=null){
      message('Замер завершён · '+scopes[server.scope]+': ↓ '+number(metric.download_mbps)+' Мбит/с · ↑ '+number(metric.upload_mbps)+' Мбит/с.'+(metric.download_mbps===0&&metric.upload_mbps===0?' Сейчас нет передачи данных.':''));
    }else message(metric?.note||'Не удалось завершить замер. Повторите попытку.',true);
  }
}
async function waitForMode(mode,previousRuntime){
  const deadline=Date.now()+45000;
  while(Date.now()<deadline){
    await new Promise(resolve=>setTimeout(resolve,1500));
    const remaining=deadline-Date.now();if(remaining<=0)break;
    try{
      const result=await api('snapshot',undefined,Math.min(4000,remaining));
      if(result.mode===mode&&(!previousRuntime||result.runtime_id!==previousRuntime)){
        data=result;serverEnvironment=mode;lastSuccess=Date.now();render();
        try{window.localStorage?.setItem('northline.environment',JSON.stringify({mode,updated:Date.now()}));}catch(_){}
        message('Сервис перезапущен.');return true;
      }
    }catch(error){
      if(error.status===401||error.status===403){lockAdmin();message(error.message,true);return false;}
    }
  }
  message('Перезапуск ещё не подтверждён. Нажмите «Обновить» и проверьте режим.',true);
  return false;
}



function showUser(id){const user=data.users.find(user=>user.user_id===id);if(!user)return;el('user-title').textContent=userName(user);
  el('user-detail').innerHTML=`<p>Telegram ID: ${user.user_id}<br>${user.username?'@'+esc(user.username)+'<br>':''}Первое наблюдение: ${date(user.first_seen,true)}<br>Последнее: ${date(user.last_seen,true)}<br>Запросов за 24 ч: ${number(user.requests_24h)}</p>`+
    `<p class="footnote">Доступ к реальным серверам выдаётся отдельно для каждого режима. Запрет также отзывает действующий профиль этого режима. Права администратора не меняются.</p>`+
    Object.keys(scopes).map(scope=>{const profile=user.profiles[scope]||{status:'none'},access=liveAccess(user,scope);return `<article class="user-detail-profile"><h3>${scopes[scope]}</h3><div class="account-access"><span class="tag ${access.allowed?'':'warn'}">Реальный режим: ${access.allowed?'разрешён':'закрыт'}</span><small>${access.source==='account'?'Настройка аккаунта':'Настройка сервиса'}</small></div>${user.is_admin?'<p>Администратор · закрытие доступа недоступно.</p>':button(access.allowed?'Закрыть доступ':'Разрешить доступ','live-access',`data-user="${user.user_id}" data-scope="${scope}"`,access.allowed)}<hr>${statusTag(profile.status)}${profile.server?`<p>${esc(profile.server)}</p><p>${profile.expires===0?'Бессрочный доступ':'Доступ до '+date(profile.expires,true)}</p>`:''}${['active','creating','revoking'].includes(profile.status)?button('Отозвать этот профиль','revoke',`data-user="${user.user_id}" data-scope="${scope}"`,true):''}</article>`;}).join('')+
    `<p class="footnote">Ограничение аккаунта запрещает новые профили и смену сервера. Уже выданный доступ отзывается отдельно.</p>${user.is_admin?'<p class="footnote">Администратор · ограничение аккаунта недоступно.</p>':button(user.blocked?'Разрешить новые профили':'Запретить новые профили','block',`data-user="${user.user_id}"`,!user.blocked)}`;
  el('user-dialog').showModal();}
function handleAction(target){if(!data||busy)return;const action=target.dataset.action,id=Number(target.dataset.user),scope=target.dataset.scope,node=target.dataset.node;
  if(action==='edit-real')return openServerEditor(scope,node);
  if(action==='delete-real')return deleteRealServer(scope,node);
  if(action==='user')return showUser(id);
  if(action==='live-access'){
    const user=data.users.find(user=>user.user_id===id);if(!user||user.is_admin||!scopes[scope])return;
    const allowed=!liveAccess(user,scope).allowed;
    confirm(allowed?'Разрешить доступ к реальным серверам?':'Закрыть доступ к режиму?',`${userName(user)} · ${id}\n${scopes[scope]}\n`+(allowed?'Пользователь сможет создать профиль в этом режиме.'+(user.blocked?' Аккаунт также ограничен: разрешите новые профили отдельной кнопкой.':''):'Действующий профиль этого режима будет отозван. Второй режим останется без изменений.'),async()=>{
      if(await change('account',{user_id:id,scope,live_access:allowed},allowed?'Доступ разрешён. Пользователь может подключаться.':'Доступ закрыт.'))showUser(id);
    });
    return;
  }
  if(action==='maintenance'){
    const server=data.servers.find(server=>server.scope===scope&&server.id===node);if(!server)return;
    const next=!server.maintenance;
    confirm(next?'Отправить на обслуживание?':'Вернуть сервер в работу?',`${server.name} · ${scopes[scope]}\n`+(next?'Новые профили на этом сервере создаваться не будут. Текущие сохранятся.':'Сервер снова станет доступен для новых профилей.'),()=>change('server',{scope,node,maintenance:next,note:el('server-note').value},'Настройки сервера сохранены.'),server.note);
  }else if(action==='measure')return change('measure',{scope,node},data.servers.find(row=>row.scope===scope&&row.id===node)?.metric_kind==='availability'?(scope==='device'?'Проверяем туннель OpenVPN и выход в интернет, до 40 секунд…':'Проверяем подключение публичного прокси к Telegram…'):'Идёт замер трафика, около 10 секунд. Результат появится в карточке сервера.');
  else if(action==='block'){
    const user=data.users.find(user=>user.user_id===id);if(!user)return;
    confirm(user.blocked?'Разрешить новые профили?':'Ограничить аккаунт?',`${userName(user)} · ${id}\nУже действующие профили останутся без изменений.`,()=>change('account',{user_id:id,blocked:!user.blocked},'Настройки аккаунта сохранены.'));
  }else if(action==='revoke'){
    const user=data.users.find(user=>user.user_id===id),profile=user?.profiles[scope];if(!profile)return;
    confirm('Отозвать доступ?',`${userName(user)}\n${scopes[scope]} · ${profile.server}\nВторой режим останется без изменений.`+(profile.access_type==='public'?' Публичный ключ внешнего оператора останется рабочим; профиль удалится из бота.':''),()=>change('revoke',{user_id:id,scope,expected_profile:profile.id,expected_status:profile.status},'Профиль отключён.'));
  }
}
document.addEventListener('click',event=>{const viewButton=event.target.closest('[data-view]');if(viewButton)showView(viewButton.dataset.view);const action=event.target.closest('[data-action]');if(action)handleAction(action);});
for(const id of ['server-search','server-scope'])el(id).addEventListener('input',()=>{if(data)renderServers();});
for(const id of ['user-search','user-filter'])el(id).addEventListener('input',()=>{if(data)renderUsers();});
for(const id of ['event-search','event-filter'])el(id).addEventListener('input',()=>{if(data)renderEvents();});
el('restart-service').onclick=()=>{if(data&&!busy)confirm('Перезапустить сервис?','Бот и Mini App будут недоступны несколько секунд. Профили и настройки сохранятся.',()=>change('restart',{confirm:true},'Сервис перезапущен.'));};
el('reload').onclick=()=>{denied=false;reload();};
el('cancel').onclick=()=>el('confirm-dialog').close();el('close-user').onclick=()=>el('user-dialog').close();
el('confirm').onclick=()=>{const action=pendingAction;pendingAction=null;el('confirm-dialog').close();if(action)action();};
el('confirm-dialog').addEventListener('close',()=>{pendingAction=null;});
el('settings-servers-live').onclick=()=>browseServers('live');
el('add-real-server').onclick=()=>openServerEditor(el('server-scope').value==='telegram'?'telegram':'device');
el('refresh-registry').onclick=()=>loadRegistry();
el('editor-close').onclick=()=>{if(!busy)el('server-editor').close();};
el('editor-cancel').onclick=el('editor-close').onclick;
el('editor-scope').onchange=()=>{if(editingServer&&!editingServer.id)openServerEditor(el('editor-scope').value);};
el('server-form').onsubmit=saveRealServer;
el('server-editor').addEventListener('cancel',event=>{if(busy)event.preventDefault();});

reload();setInterval(()=>{if(!document.hidden&&!busy&&!denied&&Date.now()-lastSuccess>(activeMeasurements.size?1500:15000))reload(true);},1000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)reload(true);});

function realRows(){
  if(!registry)return [];
  return Object.entries(registry.catalogs).flatMap(([scope,catalog])=>catalog.rows.map(row=>({...row,scope})))
    .concat((data.servers||[]).filter(row=>row.autodiscovered).map(row=>({...row,enabled:!row.maintenance})));
}
function realCard(row){
  if(row.autodiscovered){
    const metric=row.metric||{},attrs=`data-scope="device" data-node="${esc(row.id)}"`;
    return `<article class="server-card"><div class="server-top"><h3>${esc(row.name)}</h3><span class="tag">${row.maintenance?'Недоступен / обслуживание':metric.state==='online'?'Туннель проверен':'Нужна проверка'}</span></div><p class="server-meta">Всё устройство · OpenVPN · VPN Gate</p><p class="registry-address">${esc(row.endpoint||'')}</p><p>${metric.latency_ms==null?'Нет замера':number(metric.latency_ms)+' мс · HTTPS через VPN'}</p><p class="server-note">Отдельный автоматически обновляемый VPN-каталог. Оператор ведёт журналы подключений. Конфигурация импортируется в OpenVPN Connect.</p><div class="server-actions">${button(row.measuring?'Проверяем туннель…':'Проверить туннель','measure',attrs+(row.measuring?' disabled':''))}${button(row.maintenance?'Вернуть в работу':'Обслуживание','maintenance',attrs)}</div>${metric.note?'<p class="server-note">'+esc(metric.note)+'</p>':''}</article>`;
  }
  const address=row.scope==='device'?row.endpoint:row.host+':'+row.port;
  let status=row.enabled?'Настроен':'Отключён';
  const current=data.mode==='live'?data.servers.find(server=>server.scope===row.scope&&server.id===row.id):null;
  const metric=current?.metric;
  if(row.enabled&&current?.maintenance)status='Обслуживание';
  else if(row.enabled&&metric?.state==='online')status='Отвечает';
  else if(row.enabled&&metric?.state==='unavailable')status=row.scope==='telegram'?'Нет метрик':'Нет ответа';
  else if(row.enabled&&metric?.state==='stale')status='Нужна проверка';
  const external=current?.access_type==='public'||row.has_secret;
  if(external&&row.enabled&&metric?.state==='unavailable')status='Нет ответа';
  const attrs=`data-scope="${esc(row.scope)}" data-node="${esc(row.id)}"`;
  const speed=external?(metric?.latency_ms==null?'Не проверен':number(metric.latency_ms)+' мс · ответ Telegram'):(metric?.download_mbps==null?'Нет замера':number(metric.download_mbps)+' Мбит/с ↓');
  const idle=metric?.state==='online'&&metric.download_mbps===0&&metric.upload_mbps===0;
  const progress=current?.measuring?'Идёт замер · около 10 секунд':idle?'Замер завершён · нет трафика':metric?.state==='stale'?'Замер устарел':metric?.state==='unavailable'?'Замер не удался':metric?.state==='online'&&metric.download_mbps!=null?'Замер завершён':metric?.state==='online'?'Нужен повторный замер':'Ещё не измеряли';
  const progressLabel=external?(current?.measuring?'Проверяем подключение к Telegram…':metric?.state==='online'?'Подключение проверено':metric?.state==='unavailable'?'Нет ответа':metric?.state==='stale'?'Проверка устарела':'Ещё не проверяли'):progress;
  const detail=row.scope==='telegram'
    ? 'Активных соединений: '+(metric?.peer_count==null?'нет замера':number(metric.peer_count))
    : 'Проверка SSH: '+(metric?.latency_ms==null?'нет замера':number(metric.latency_ms)+' мс');
  return `<article class="server-card"><div class="server-top"><h3>${esc(locationName(row))}</h3><span class="tag ${row.enabled?'':'warn'}">${status}</span></div><p class="server-meta">${esc(scopes[row.scope])} · ${esc(row.id)}</p><p class="registry-address">${esc(address)}<br>${row.scope==='device'?'Подсеть: '+esc(row.subnet)+'<br>SSH: '+esc(row.ssh_host):'MTProto · подключение прямо в Telegram'}</p><div class="server-bottom"><span>${row.profiles||0} действующих профилей${metric?.sampled_at?'<br>Замер '+date(metric.sampled_at,true):''}</span><span>${esc(speed)}</span></div><div class="server-actions">${button('Редактировать','edit-real',attrs)}${button('Удалить','delete-real',attrs,true)}</div>${current?`<p class="measurement-state" role="status">${esc(progressLabel)}</p>${external?'<p class="server-note">Публичный прокси · общий ключ. Проверяем доступность; счётчики трафика оператора недоступны.</p>':`<p class="server-note">Трафик ↑: ${metric?.upload_mbps==null?'нет замера':number(metric.upload_mbps)+' Мбит/с'} · ${esc(detail)}</p>`}<div class="server-actions">${button(current.maintenance?'Вернуть в работу':'Обслуживание','maintenance',attrs)}${button(current.measuring?(external?'Проверяем…':'Замеряем…'):current.measurable===false?'Проверка недоступна':external?'Проверить подключение':'Замерить трафик','measure',attrs+(current.measuring||current.measurable===false?' disabled':''))}</div>${metric?.note?'<p class="server-note">'+esc(metric.note)+'</p>':''}`:''}</article>`;
}
async function browseServers(){
  if(!data||busy)return;
  serverEnvironment='live';showView('servers');renderServers();await loadRegistry();
}
async function loadRegistry(){
  const token=++registryRequest;registryLoading=true;registryError='';renderServers();
  try{const result=await api('registry');if(token!==registryRequest)return false;registry=result;return true;}
  catch(error){if(token!==registryRequest)return false;registryError=error.message;
    if(error.status===401||error.status===403){lockAdmin();}
    return false;
  }finally{if(token===registryRequest)registryLoading=false;if(data)renderServers();}
}
function openServerEditor(scope,id){
  if(busy||!registry)return;
  const catalog=registry.catalogs[scope];
  if(!catalog||catalog.error||!catalog.revision){message(catalog?.error||'Обновите список серверов перед редактированием.',true);return;}
  const row=id?catalog.rows.find(row=>row.id===id):null;
  if(id&&!row){message('Сервер больше не найден. Обновите список.',true);return;}
  editingServer={scope,id:id||null,revision:catalog.revision};
  el('editor-title').textContent=id?'Редактировать сервер':'Добавить сервер';
  el('editor-error').textContent='';el('editor-scope').value=scope;el('editor-scope').disabled=!!id;
  el('editor-id').value=row?.id||'';el('editor-id').readOnly=!!id;
  el('editor-name').value=row?.name||'';
  el('editor-location').textContent=row?.country?'Локация: '+locationName(row)+'. При смене адреса страна определится заново.':'Флаг и страна определятся автоматически по IP или домену при сохранении.';
  let host='',port=scope==='device'?51820:8443;
  if(row){if(scope==='device'){const parts=row.endpoint.split(':');host=parts[0];port=parts[1];}else{host=row.host;port=row.port;}}
  el('editor-host').value=host;el('editor-port').value=String(port);
  el('editor-key').value=row?.public_key||'';el('editor-ssh').value=row?.ssh_host||'';
  el('editor-secret').value='';el('editor-secret').placeholder=row?.has_secret?'Сохранён · оставьте пустым, чтобы не менять':'Secret из ссылки прокси';
  el('proxy-secret-label').hidden=scope!=='telegram';
  const used=new Set(catalog.rows.map(node=>node.subnet));let subnet='10.77.0.0/24';
  for(let segment=77;segment<255;segment++){const candidate='10.'+segment+'.0.0/24';if(!used.has(candidate)){subnet=candidate;break;}}
  el('editor-subnet').value=row?.subnet||subnet;
  el('editor-enabled').checked=row?.enabled!==false;
  el('wireguard-fields').hidden=scope!=='device';el('proxy-editor-note').hidden=scope!=='telegram';
  for(const key of ['editor-key','editor-subnet','editor-ssh'])el(key).required=scope==='device';
  if(!el('server-editor').open)el('server-editor').showModal();
}
async function registryChange(body,success,fromEditor=false){
  if(busy)return;busy=true;++revision;el('editor-save').disabled=true;message('Сохранение списка серверов…');
  try{
    const result=await api('registry',body);
    if(fromEditor)el('server-editor').close();
    const catalogRefreshed=await loadRegistry();const stateRefreshed=await reload(true,true);
    if(!denied)message(catalogRefreshed&&stateRefreshed?(result.location_warning||(success+(result.location?' Локация: '+result.location+'.':''))):'Настройки сохранены, но обновить список не удалось. Нажмите «Обновить список».',!!result.location_warning||!(catalogRefreshed&&stateRefreshed));
  }catch(error){
    if(fromEditor)el('editor-error').textContent=error.message;else message(error.message,true);
    if(error.status===401||error.status===403){lockAdmin();}
  }finally{busy=false;el('editor-save').disabled=false;el('reload').disabled=false;if(data){renderSettings();renderServers();}}
}
async function saveRealServer(event){
  event.preventDefault();if(!editingServer||busy)return;
  if(!el('server-form').reportValidity())return;
  const scope=editingServer.scope;
  const server={id:el('editor-id').value.trim(),name:el('editor-name').value.trim(),enabled:el('editor-enabled').checked};
  if(scope==='device')Object.assign(server,{endpoint:el('editor-host').value.trim()+':'+Number(el('editor-port').value),
    public_key:el('editor-key').value.trim(),subnet:el('editor-subnet').value.trim(),ssh_host:el('editor-ssh').value.trim()});
  else {
    Object.assign(server,{host:el('editor-host').value.trim(),port:Number(el('editor-port').value)});
    if(el('editor-secret').value.trim())server.secret=el('editor-secret').value.trim();
  }
  await registryChange({scope,action:'save',original_id:editingServer.id,expected_revision:editingServer.revision,server},
    'Параметры сервера сохранены и применены.',true);
}
function deleteRealServer(scope,id){
  const catalog=registry?.catalogs[scope],server=catalog?.rows.find(row=>row.id===id);
  if(!server)return;
  const version=catalog.revision;
  confirm('Удалить сервер из списка?',server.name+' · '+id+'\nVPS не будет удалён. При наличии действующих профилей операция будет отклонена.',
    ()=>registryChange({scope,action:'delete',original_id:id,expected_revision:version,confirm:true},'Сервер удалён из списка. Резервная копия сохранена.'));
}
