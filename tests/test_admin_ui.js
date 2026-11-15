function runAdminTests(source){
  const elements=new Map();
  function element(){return {value:'',textContent:'',innerHTML:'',hidden:false,disabled:false,open:false,dataset:{},
    classList:{toggle(){}},setAttribute(){},removeAttribute(){},toggleAttribute(){},addEventListener(){},focus(){},
    showModal(){this.open=true;},close(){this.open=false;},reportValidity(){return true;}};}
  const document={hidden:false,getElementById(id){if(!elements.has(id))elements.set(id,element());return elements.get(id);},
    querySelectorAll(){return [];},addEventListener(){}};
  const window={location:{hash:'#test-fragment'},scrollTo(){}};
  const checks=`return (async()=>{
    let count=0;function assert(ok,label){if(!ok)throw new Error(label);count++;}
    for(const id of ['server-scope','user-filter','event-filter'])el(id).value='all';
    const device={id:1,status:'active',server:'Germany',node:'wg-eu',expires:1900000000};
    const telegram={id:2,status:'active',server:'USA',node:'tg-us',expires:1900000000};
    const fixture={mode:'live',admin_id:10,updated_at:1800000000,stats:{users:1,blocked:0,requests_24h:3,errors_24h:1,active:{device:1,telegram:1}},
      readiness:{device_ready:false,checks:[{label:'Configure server',ok:false}],telegram_note:'Not configured'},
      activity:Array.from({length:24},(_,i)=>({hour:1800000000-i*3600,requests:i})),
      users:[{user_id:20,first_name:'<img src=x onerror=bad>',username:'test',last_seen:1800000000,first_seen:1790000000,requests_24h:3,blocked:false,profiles:{device,telegram}}],
      servers:[{id:'wg-eu',scope:'device',name:'Germany',protocol:'WireGuard',profiles:1,maintenance:false,note:'',metric:{state:'online',download_mbps:500,upload_mbps:200,latency_ms:30}},
               {id:'tg-us',scope:'telegram',name:'USA',protocol:'MTProto',profiles:1,maintenance:true,note:'Check',metric:{state:'online',download_mbps:400,upload_mbps:100,latency_ms:20}}],
      events:[{id:1,created:1800000000,user_id:20,first_name:'<b>test</b>',source:'bot',scope:'device',action:'issue',node:'wg-eu',status_code:200,duration_ms:10}],audit:[],speed_note:'Current traffic'};
    data=fixture;registry={catalogs:{device:{rows:[{id:'wg-eu',name:'Germany',endpoint:'vpn.example.com:51820',subnet:'10.77.0.0/24',ssh_host:'fixture',enabled:true}],revision:'initial'},telegram:{rows:[{id:'tg-us',name:'USA',host:'proxy.example.com',port:443,enabled:true}],revision:'initial'}}};render();
    assert(el('user-rows').innerHTML.includes('&lt;img')&&!el('user-rows').innerHTML.includes('<img'),'User names cannot inject HTML');
    assert(el('activity').innerHTML.includes('<svg')&&!el('activity').innerHTML.includes('style='),'Chart works without inline styles forbidden by CSP');
    el('server-scope').value='telegram';renderServers();
    assert(!el('server-grid').innerHTML.includes('Germany')&&el('server-grid').innerHTML.includes('USA'),'Server filter keeps the selected mode');
    el('user-search').value='not-found';renderUsers();assert(el('user-rows').innerHTML.includes('Аккаунты не найдены'),'User search handles no matches');el('user-search').value='';
    showView('settings');assert(el('page-title').textContent==='Настройки'&&!el('view-settings').hidden,'Settings navigation works');
    showUser(20);assert(el('user-dialog').open&&el('user-detail').innerHTML.includes('data-scope="telegram"'),'Account detail includes independent profile controls');
    let mutation;api=async(path,body)=>{if(path==='snapshot')return fixture;mutation={path,body};return {ok:true};};
    fixture.users[0].live_access={device:{allowed:false,source:'environment'},telegram:{allowed:false,source:'environment'}};
    showUser(20);
    assert(el('user-detail').innerHTML.includes('data-action="live-access"')&&el('user-detail').innerHTML.includes('Реальный режим: закрыт'),'Account detail exposes separate permissions for real servers');
    handleAction({dataset:{action:'live-access',user:'20',scope:'telegram'}});
    assert(el('confirm-dialog').open&&el('confirm-text').textContent.includes('Только Telegram'),'Grant confirmation identifies the account and the exact mode');
    const grantAction=pendingAction;pendingAction=null;el('confirm-dialog').close();await grantAction();
    assert(mutation.path==='account'&&mutation.body.live_access===true&&mutation.body.scope==='telegram'&&mutation.body.user_id===20,'Account grant enables only the chosen connection mode');
    fixture.users[0].live_access.telegram={allowed:true,source:'account'};
    showUser(20);
    assert(el('user-detail').innerHTML.includes('Закрыть доступ')&&el('user-detail').innerHTML.includes('Настройка аккаунта'),'Granted permission displays its current state and a revoke action');
    handleAction({dataset:{action:'live-access',user:'20',scope:'telegram'}});
    assert(el('confirm-text').textContent.includes('будет отозван')&&el('confirm-text').textContent.includes('Второй режим'),'Closing access explains immediate scoped profile revocation');
    const denyAction=pendingAction;pendingAction=null;el('confirm-dialog').close();await denyAction();
    assert(mutation.body.live_access===false&&mutation.body.scope==='telegram','Access can be closed independently of the legacy account block');
    el('user-filter').value='live';renderUsers();
    assert(el('user-rows').innerHTML.includes('data-user="20"'),'Account filter finds users with real-server access');
    fixture.users[0].blocked=true;renderUsers();
    assert(el('user-rows').innerHTML.includes('Аккаунты не найдены'),'Blocked accounts do not appear as eligible for real access');
    fixture.users[0].blocked=false;el('user-filter').value='all';
    handleAction({dataset:{action:'revoke',user:'20',scope:'telegram'}});
    assert(el('confirm-dialog').open&&el('confirm-text').textContent.includes('Второй режим'),'Revocation asks for explicit scoped confirmation');
    const revokeAction=pendingAction;pendingAction=null;el('confirm-dialog').close();await revokeAction();
    assert(mutation.path==='revoke'&&mutation.body.scope==='telegram'&&mutation.body.expected_profile===2,'Revocation carries the exact profile and mode');
    handleAction({dataset:{action:'maintenance',scope:'device',node:'wg-eu'}});
    el('server-note').value='Maintenance note';const maintenance=pendingAction;pendingAction=null;await maintenance();
    assert(mutation.path==='server'&&mutation.body.maintenance===true&&mutation.body.note==='Maintenance note','Maintenance request preserves note and server');
    busy=true;mutation=null;handleAction({dataset:{action:'measure',scope:'device',node:'wg-eu'}});assert(mutation===null,'Repeated clicks during a write cannot start another action');busy=false;
    api=async()=>{const error=new Error('Denied');error.status=403;throw error;};await reload();
    assert(el('content').hidden&&!el('locked').hidden&&data===null,'Access denial clears the dashboard state');
    denied=false;data=fixture;
    let resolveOld;let snapshots=0;
    api=(path)=>{
      if(path!=='snapshot')return Promise.resolve({ok:true});
      snapshots++;if(snapshots===1)return new Promise(resolve=>{resolveOld=resolve;});
      return Promise.resolve({...fixture,stats:{...fixture.stats,users:2}});
    };
    const previousRead=reload(true);
    const write=change('account',{user_id:20,blocked:true},'Saved');
    await Promise.resolve();
    assert(busy,'Administrative write stays locked through its refresh');
    resolveOld({...fixture,stats:{...fixture.stats,users:99}});
    await Promise.all([previousRead,write]);
    assert(data.stats.users===2&&snapshots===2&&!busy,'Old snapshot cannot overwrite the result of an administrative action');
    el('server-scope').value='all';el('server-search').value='';
    const realNode={id:'eu-1',name:'Real Germany',endpoint:'vpn.example.com:51820',subnet:'10.77.0.0/24',public_key:'public-key',ssh_host:'northline-eu-1',enabled:true,profiles:0};
    const realCatalog={active_mode:'live',catalogs:{device:{revision:'v1',rows:[realNode],error:null},telegram:{revision:'t1',rows:[],error:null}}};
    let registryWrite=null,environmentWrites=0;
    api=async(path,body)=>{if(path==='snapshot')return fixture;if(path==='registry'&&body){registryWrite=body;return {ok:true,applied:false};}if(path==='registry')return realCatalog;if(path==='environment'){environmentWrites++;return {ok:true};}};
    await el('settings-servers-live').onclick();
    assert(view==='servers'&&serverEnvironment==='live'&&el('server-grid').innerHTML.includes('Real Germany'),'Catalog tab opens the real-server list');
    openServerEditor('device','eu-1');
    assert(el('server-editor').open&&el('editor-id').readOnly&&el('editor-scope').disabled,'Editing keeps server identity and protocol fixed');
    assert(el('editor-host').value==='vpn.example.com'&&el('editor-port').value==='51820','Editor restores endpoint fields');
    el('editor-name').value='Edited real server';
    await saveRealServer({preventDefault(){}});
    assert(registryWrite.expected_revision==='v1'&&registryWrite.original_id==='eu-1'&&registryWrite.server.name==='Edited real server','Save carries captured version and edited values');
    openServerEditor('device','eu-1');
    api=async()=>{const error=new Error('List changed');error.status=409;throw error;};
    await saveRealServer({preventDefault(){}});
    assert(el('server-editor').open&&el('editor-error').textContent==='List changed','Conflict preserves the editing form and shows its error');
    openServerEditor('telegram');
    assert(el('wireguard-fields').hidden&&!el('editor-key').required&&el('editor-port').value==='8443','MTProto form does not require WireGuard fields');
    el('editor-cancel').onclick();assert(!el('server-editor').open,'Cancel closes the editor without saving');
    el('server-search').value='missing';renderServers();
    assert(el('server-grid').innerHTML.includes('Ничего не найдено')&&!el('server-grid').innerHTML.includes('пока не добавлены'),'Search miss is distinct from an empty registry');
    denied=false;data=fixture;
    el('user-dialog').showModal();el('server-editor').showModal();el('confirm-dialog').showModal();pendingAction=()=>{};
    api=async()=>{const error=new Error('Session expired');error.status=401;throw error;};
    await reload();
    assert(data===null&&registry===null&&pendingAction===null,'Expired admin session clears cached data and pending actions');
    assert(!el('user-dialog').open&&!el('server-editor').open&&!el('confirm-dialog').open,'Expired session closes private dialogs');
    denied=false;data=fixture;
    api=async path=>{if(path==='snapshot')throw new Error('Offline');return {ok:true};};
    await change('account',{user_id:20,blocked:true},'Saved');
    assert(el('message').textContent.includes('состояние не обновилось'),'Successful write with failed refresh reports stale state instead of a false full success');
    let restartReads=0;
    api=async()=>{restartReads++;const error=new Error('Reopen Telegram');error.status=401;throw error;};
    await waitForMode('live','before');
    assert(restartReads===1&&denied&&el('message').textContent==='Reopen Telegram','Restart polling stops immediately when authentication expires');
    denied=false;data=fixture;
    let resolveStale;
    api=()=>new Promise(resolve=>{resolveStale=resolve;});
    const staleReload=reload();lockAdmin();resolveStale(fixture);await staleReload;
    assert(denied&&data===null&&el('content').hidden,'A stale successful snapshot cannot restore admin data after another request denies access');
    el('server-editor').showModal();busy=true;goBack();
    assert(el('server-editor').open,'Telegram Back cannot close a server form while it is being saved');
    busy=false;goBack();assert(!el('server-editor').open,'Telegram Back closes the editor after saving finishes');
    denied=false;const live={...fixture,mode:'live',runtime_id:'after'};
    const proxyMetric={state:'online',download_mbps:1.5,upload_mbps:0.3,peer_count:4,note:'Two sample measurement',sampled_at:1800000000};
    data={...live,servers:[{...fixture.servers[1],maintenance:false,metric:proxyMetric,measurable:true}]};
    const proxyRow={id:'tg-us',scope:'telegram',host:'proxy.example.com',port:8443,name:'Telegram proxy',enabled:true};
    const card=realCard(proxyRow);
    assert(card.includes('data-action="measure"')&&card.includes('Замерить трафик'),'Real Telegram server card exposes a measurement button');
    assert(card.includes('Активных соединений: 4')&&card.includes('Мбит/с')&&!card.includes('Проверка SSH'),'Telegram card displays actual traffic and connections without a fake SSH latency');
    let proxyMeasure;
    api=async(path,body)=>{if(path==='snapshot')return data;if(path==='measure'){proxyMeasure=body;return {pending:true};}};
    await handleAction({dataset:{action:'measure',scope:'telegram',node:'tg-us'}});
    assert(proxyMeasure.scope==='telegram'&&proxyMeasure.node==='tg-us','Telegram measurement targets the correct mode and server');
    data.servers[0].metric={state:'unavailable',note:'Counters unavailable'};
    assert(realCard(proxyRow).includes('Нет метрик')&&!realCard(proxyRow).includes('Нет ответа'),'Missing counters do not claim the proxy itself is offline');
    data.servers[0].measurable=false;
    assert(realCard(proxyRow).includes('Проверка недоступна'),'Unmanaged proxies show that their metrics adapter is missing');
    const autoNode={...realNode,country:'LT',country_name:'Литва'};
    const autoCatalog={...realCatalog,catalogs:{...realCatalog.catalogs,device:{...realCatalog.catalogs.device,rows:[autoNode]}}};
    registry=autoCatalog;openServerEditor('device','eu-1');
    assert(locationName(autoNode)==='🇱🇹 Литва'&&el('editor-location').textContent.includes('🇱🇹 Литва'),'Editor displays the automatically detected flag and country');
    assert(el('editor-name').value==='Real Germany','Optional custom server name is retained separately from its detected country');
    let autoWrite;
    api=async(path,body)=>{if(path==='snapshot')return data;if(path==='registry'&&body){autoWrite=body;return {ok:true,location:'🇱🇹 Литва'};}if(path==='registry')return autoCatalog;};
    el('editor-name').value='';await saveRealServer({preventDefault(){}});
    assert(autoWrite.server.name===''&&el('message').textContent.includes('🇱🇹 Литва'),'Empty names are submitted for automatic naming and the detected location is confirmed');
    api=async(path,body)=>{if(path==='snapshot')return data;if(path==='registry'&&body)return {ok:true,location_warning:'Страну определить не удалось'};if(path==='registry')return autoCatalog;};
    await registryChange(autoWrite,'Saved');
    assert(el('message').textContent.includes('Страну определить не удалось'),'Failed country detection is visible even when the server was saved');
    data={...live,servers:[{...fixture.servers[1],measuring:true,measurable:true,metric:{state:'online',download_mbps:0,upload_mbps:0,peer_count:0}}]};
    activeMeasurements.add('telegram:tg-us');
    const runningCard=realCard(proxyRow);
    assert(runningCard.includes('Идёт замер')&&runningCard.includes('Замеряем…'),'Running measurement displays visible progress even when the previous speed is zero');
    finishMeasurements();assert(activeMeasurements.has('telegram:tg-us'),'Measurement remains tracked until the server finishes sampling');
    data.servers[0].measuring=false;finishMeasurements();
    assert(!activeMeasurements.size&&el('message').textContent.includes('Замер завершён')&&el('message').textContent.includes('нет передачи данных'),'Completed zero measurement explicitly reports idle traffic rather than appearing broken');
    assert(realCard(proxyRow).includes('Замер завершён · нет трафика'),'Idle server card clearly labels a valid zero result');
    data.servers[0]={...data.servers[0],access_type:'public',metric_kind:'availability',metric:{state:'online',latency_ms:123,download_mbps:null,upload_mbps:null,note:'Public connection checked'}};
    const publicCard=realCard({...proxyRow,has_secret:true});
    assert(publicCard.includes('Проверить подключение')&&publicCard.includes('123 мс')&&!publicCard.includes('Трафик ↑'),'Public proxy cards offer a connection check and no invented bandwidth counters');
    activeMeasurements.add('telegram:tg-us');finishMeasurements();
    assert(el('message').textContent.includes('Публичный прокси отвечает')&&!el('message').textContent.includes('Мбит/с'),'Public proxy checks report response time rather than a fake zero speed');
    const devicePublic={id:'ovpn-us-test',name:'USA',scope:'device',protocol:'OpenVPN',autodiscovered:true,access_type:'public',metric_kind:'availability',endpoint:'8.8.8.8:443',maintenance:false,metric:{state:'online',latency_ms:120},measurable:true};
    data.servers.push(devicePublic);
    assert(realRows().some(row=>row.id===devicePublic.id),'Admin includes the independent auto-discovered device VPN catalog');
    const deviceCard=realCard(devicePublic);
    assert(deviceCard.includes('OpenVPN')&&deviceCard.includes('Проверить туннель')&&!deviceCard.includes('Редактировать'),'Imported OpenVPN cards offer tunnel checks instead of manual SSH editing');
    activeMeasurements.add('device:'+devicePublic.id);finishMeasurements();
    assert(el('message').textContent.includes('OpenVPN')&&!el('message').textContent.includes('прокси отвечает'),'Device VPN checks report a VPN tunnel rather than a Telegram proxy');
    return 'Admin UI checks: '+count+' passed';
  })();`;
  return new Function('window','document','fetch','setTimeout','clearTimeout','setInterval','AbortController',source.replace('reload();setInterval','setInterval')+'\n'+checks)(
    window,document,()=>new Promise(()=>{}),(callback,delay)=>{if(delay===1500)callback();return 1;},()=>{},()=>1,class {abort(){}},
  );
}
