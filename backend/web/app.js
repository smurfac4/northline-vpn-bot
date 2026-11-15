"use strict";

const tg = window.Telegram?.WebApp;
const el = id => document.getElementById(id);
const pendingStates = ['active', 'creating', 'revoking'];
const scopeNames = {device:'Всё устройство', telegram:'Только Telegram'};
const scopeProtocols = {device:'WireGuard', telegram:'MTProto'};
const stateLabels = {active:'Активен', creating:'Создаётся', revoking:'Отключается', revoked:'Отключён', expired:'Срок истёк'};
const requestedScope = /(?:[?&])scope=(device|telegram)(?:&|$)/.exec(window.location?.search || '')?.[1];
const state = {
  scope:requestedScope || 'device', initialScopeChosen:!!requestedScope, liveAccess:{},
  profiles:{}, selections:{}, connection:null, connectionRequest:null, platform:'other', refreshToken:null,
  nodes: [], profile: {status:'none'}, selected: '', mode:'live', hours:0, personalTest:false,
  loaded:false, available:true, busy:false, refreshing:false, epoch:0, account:false, confirmation:null, noticeKind:null, denied:false,
};

tg?.ready();
tg?.expand();
tg?.setHeaderColor?.('#0b0c10');
tg?.setBackgroundColor?.('#0b0c10');

async function api(path, body, options = {}) {
  const headers = {};
  if (tg?.initData) headers['X-Telegram-Init-Data'] = tg.initData;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const controller = options.controller || new AbortController();
  const timeout = setTimeout(() => controller.abort(), path === 'status' ? 12000 : 45000);
  try {
    const response = await fetch('/api/' + path + (path.includes('?') ? '&' : '?') + 'scope=' + state.scope, {
      headers, signal:controller.signal, cache:'no-store',
      method:body === undefined ? 'GET' : 'POST',
      body:body === undefined ? undefined : JSON.stringify(body),
    });
    const data = await response.json().catch(() => {throw new Error('Сервер временно недоступен. Попробуйте ещё раз.');});
    if (!response.ok) {
      const error = new Error(response.status === 401
      ? 'Сеанс завершён. Закройте приложение и откройте его снова из бота.'
      : data.error || 'Не удалось выполнить действие.');
      error.status = response.status;
      throw error;
    }
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('Сервер долго отвечает. Обновите состояние перед повторной попыткой.');
    if (error instanceof TypeError) throw new Error('Нет связи с сервером. Проверьте интернет и повторите попытку.');
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function notice(message = '', error = false, kind = 'action') {
  state.noticeKind = message ? kind : null;
  el('notice').textContent = message;
  el('notice').toggleAttribute('data-error', error);
  el('retry').hidden = !error || state.denied;
}

function expireSession(error) {
  if (error.status !== 401) return false;
  state.denied = true;
  ++state.epoch;
  state.loaded = false; state.available = false;
  state.nodes = []; state.profiles = {}; state.selections = {}; state.selected = '';
  state.profile = {status:'none',scope:state.scope};
  closeConfirmation(); closeConnection();
  if (el('telegram-session-dialog').open) el('telegram-session-dialog').close();
  if (el('locations').open) el('locations').close();
  el('open-admin').hidden = true;
  renderProfile();
  el('hero-state').textContent = 'Сеанс завершён';
  el('headline').textContent = 'Откройте приложение заново';
  el('subtitle').textContent = 'Вернитесь в бота и нажмите кнопку приложения.';
  el('synced').textContent = 'Требуется вход через Telegram';
  notice(error.message, true, 'connection');
  syncBackButton();
  return true;
}

function syncControls() {
  const scopeDenied = state.mode === 'live' && state.liveAccess[state.scope]?.allowed === false;
  const pending = pendingStates.includes(state.profile.status);
  const openingProxy = state.scope === 'telegram' && state.mode === 'live' && !!state.connectionRequest;
  const switching = pending && state.selected !== state.profile.node;
  const transition = ['creating', 'revoking'].includes(state.profile.status);
  el('activate').textContent = state.busy ? 'Сохранение…' : switching ? 'Сменить сервер' : pending ? 'Текущий сервер' : 'Получить доступ';
  el('activate').hidden = pending && !switching && !transition;
  el('activate').disabled = scopeDenied || state.busy || !state.loaded || !state.available || !state.nodes.length || (pending && !switching) || transition || !!state.nodes.find(node => node.id === state.selected)?.maintenance;
  el('dial-action').disabled = scopeDenied || state.busy || !state.loaded || openingProxy || (state.profile.status !== 'active' && el('activate').disabled);
  if (state.profile.node_retired && el('activate').disabled) el('dial-action').disabled = true;
  el('dial-action').setAttribute('aria-label', state.profile.status === 'active' ? 'Открыть настройку подключения' : 'Создать профиль выбранной локации');
  const session = state.profile.session;
  if (state.scope === 'telegram' && state.mode === 'live' && state.profile.status === 'active') {
    el('dial-action').setAttribute('aria-label', session?.controllable ? session.enabled ? 'Приостановить доступ на сервере' : 'Возобновить доступ на сервере' : 'Включить или выключить прокси в Telegram');
    if (session?.pending) el('dial-action').disabled = true;
  }
  for (const id of ['choose', 'all-locations', 'account-locations']) el(id).disabled = state.busy || !state.loaded || !state.nodes.length;
  for (const id of ['download', 'revoke', 'setup']) el(id).disabled = state.busy || !state.loaded;
  if (scopeDenied) el('setup').disabled = true;
  if (openingProxy) {el('setup').disabled = true;el('setup').textContent = 'Открываем Telegram…';}
  else if (state.scope === 'telegram' && state.mode === 'live') el('setup').textContent = 'Подключить в Telegram';
  if (state.scope === 'telegram' && session?.controllable && !session.enabled) el('setup').textContent = 'Возобновить и подключить';
  if (session?.controllable && session.pending) {el('setup').disabled = true;el('setup').textContent = 'Переключаем доступ…';}
  for (const id of ['scope-device', 'scope-telegram']) el(id).disabled = state.busy;
  el('refresh').disabled = state.busy || state.refreshing;
  el('retry').disabled = state.busy || state.refreshing;
  el('refresh').textContent = state.refreshing ? 'Обновление…' : '↻ Обновить';
  el('trial-help').textContent = state.denied ? 'Откройте приложение через бота' : !state.loaded ? 'Загружаем доступные локации…' : scopeDenied ? 'Администратор ещё не разрешил этот режим вашему аккаунту.' : !state.available ? 'Этот режим пока недоступен. Выберите другой.'
    : !state.nodes.some(node => !node.maintenance) ? 'Доступных серверов пока нет. Попробуйте позже.'
    : pending ? 'Доступ без ограничения по времени' : 'Бессрочный доступ';
  if(state.loaded&&!scopeDenied&&state.mode==='live'&&state.nodes.find(node=>node.id===state.selected)?.access_type==='public')el('trial-help').textContent=state.scope==='device'?'Публичный VPN Gate · подключение через OpenVPN Connect.':'Публичный прокси с общим ключом. Подключение выключается в настройках Telegram.';
  el('server-label').textContent = pending ? 'Сменить локацию' : 'Локация подключения';
  el('platform').disabled = state.busy;
  el('connection-download').disabled = state.busy || !!state.connectionRequest || !state.connection?.download;
  el('connection-connect').disabled = state.busy || !state.loaded || !!state.connectionRequest || !state.connection?.connect_url;
  const clientReady = !state.busy && state.loaded && !state.connectionRequest && !!state.connection?.client;
  el('connection-app').disabled = !clientReady;
  el('client-installed').disabled = !clientReady;
  el('connection-import').disabled = !clientReady || !state.connection?.download;
  el('trial').setAttribute('aria-busy', String(state.busy));
}

function updateRemaining() {
  const {profile} = state;
  if (pendingStates.includes(profile.status) && profile.expires === 0) {
    el('remaining').textContent = 'Безлимит';
    return;
  }
  const seconds = Math.max(0, (profile.expires || 0) - Math.floor(Date.now() / 1000));
  const minutes = Math.ceil(seconds / 60);
  el('remaining').textContent = !pendingStates.includes(profile.status) || !seconds ? '—'
    : minutes < 60 ? `${minutes} мин` : `${Math.floor(minutes / 60)} ч ${minutes % 60} мин`;
}

function renderScope() {
  el('protocol').textContent = state.profile.protocol || state.nodes.find(node=>node.id===state.selected)?.protocol || scopeProtocols[state.scope];
  el('scope-description').textContent = state.scope === 'device' ? 'VPN для приложений и браузера' : 'Прокси для Telegram. Другие приложения работают напрямую.';
  for (const scope of ['device','telegram']) {
    el('scope-' + scope).classList.toggle('active',state.scope === scope);
    el('scope-' + scope).setAttribute('aria-pressed',String(state.scope === scope));
    el(scope + '-profile-state').textContent = state.mode==='live' && state.liveAccess[scope]?.allowed===false ? 'Нет доступа' : stateLabels[state.profiles[scope]?.status] || 'Нет профиля';
  }
}

function serverCount(count) {
  const last=count%100;
  const index=last>=11&&last<=14?2:count%10===1?0:count%10>=2&&count%10<=4?1:2;
  return count+' '+['реальный сервер','реальных сервера','реальных серверов'][index];
}

function renderProfile() {
  const {profile, mode} = state;
  const pending = pendingStates.includes(profile.status);
  const protocol=profile.protocol || scopeProtocols[state.scope];
  el('mode').textContent = protocol;
  el('headline').textContent = {
    none:'Начните с локации', active:'Доступ готов', creating:'Готовим ваш доступ',
    revoking:'Отключение профиля', revoked:'Профиль отключён', expired:'Срок доступа истёк',
  }[profile.status] || 'Состояние профиля';
  el('subtitle').textContent = profile.status === 'creating' ? 'Сервер готовит доступ. Состояние обновится автоматически.'
    : profile.status === 'revoking' ? 'Отзываем доступ. Это может занять несколько секунд.'
    : profile.status === 'active' ? (state.scope === 'device' ? protocol==='OpenVPN'?'Импортируйте .ovpn в OpenVPN Connect.':'Откройте конфигурацию в WireGuard для подключения.' : 'Откройте ссылку прокси в Telegram.')
    : 'Выберите страну — мы подготовим профиль для вашего устройства.';
  el('hero-state').textContent = profile.status === 'active' ? 'Профиль готов' : stateLabels[profile.status] || 'Не настроен';
  el('hero-caption').textContent = state.scope === 'device' ? 'Подключение включается в '+(protocol==='OpenVPN'?'OpenVPN Connect':'WireGuard') : 'Прокси включается в настройках Telegram';
  if(mode==='live'&&profile.access_type==='public')el('hero-caption').textContent=state.scope==='device'?'Публичный VPN Gate · OpenVPN Connect':'Публичный прокси · общий ключ внешнего оператора';
  if (state.scope === 'telegram' && mode === 'live' && profile.status === 'active' && profile.session?.controllable) {
    el('headline').textContent = profile.session.pending ? 'Переключаем доступ' : profile.session.enabled ? 'Доступ на сервере включён' : 'Доступ приостановлен';
    el('hero-state').textContent = profile.session.pending ? 'Ожидаем сервер' : profile.session.enabled ? 'Доступ включён' : 'Пауза';
    el('hero-caption').textContent = 'Кнопка питания приостанавливает доступ. Профиль сохраняется.';
    el('subtitle').textContent = profile.session.enabled ? 'Подключение в Telegram включается отдельно. Его состояние Mini App не видит.' : 'Для прямого подключения выключите «Использовать прокси» в Telegram. Кнопка питания возобновит доступ с тем же профилем.';
  }
  el('profile').hidden = profile.status === 'none';
  el('state').textContent = stateLabels[profile.status] || '—';
  el('state').dataset.state = profile.status;
  el('server').textContent = profile.server || '—';
  el('expires').textContent = profile.expires === 0 ? 'Бессрочно' : profile.expires ? new Date(profile.expires * 1000).toLocaleString('ru-RU', {
    day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit',
  }) : '—';
  renderScope();
  el('setup').hidden = profile.status !== 'active';
  if (profile.node_retired && profile.status === 'active') {
    el('headline').textContent = 'Сервер недоступен';
    el('hero-state').textContent = 'Нужна замена';
    el('subtitle').textContent = profile.replacement ? 'Найден новый сервер: ' + profile.replacement.server + '. Подтвердите смену и обновите подключение.' : 'Рабочую замену пока не нашли. Выберите доступную страну или дождитесь следующей проверки.';
    el('hero-caption').textContent = state.scope === 'device' ? 'После смены сервера импортируйте новый конфиг.' : 'После смены подтвердите новый прокси в Telegram.';
    el('setup').hidden = true;
  }
  el('setup').textContent = state.scope==='telegram'?'Подключить в Telegram':'Настройка подключения';
  el('revoke').textContent=profile.access_type==='public'?'Убрать профиль из бота':'Отключить профиль';
  // The setup sheet is the single place for instructions and downloads.
  el('download').hidden = true;
  el('import-help').hidden = true;
  el('revoke').hidden = !pending || profile.status === 'revoking';
  if (mode==='live' && state.liveAccess[state.scope]?.allowed===false) {
    el('headline').textContent = 'Доступ к режиму закрыт';
    el('subtitle').textContent = 'Доступ к каждому режиму выдаёт администратор. Выберите разрешённый режим подключения.';
    el('hero-state').textContent = 'Нет доступа';
    el('hero-caption').textContent = scopeNames[state.scope] + ' · требуется разрешение';
    el('setup').hidden = true;
  }
  el('server-count').textContent = serverCount(state.nodes.length);
  el('selected').textContent = state.nodes.find(node => node.id === state.selected)?.name || 'Нет доступных серверов';
  document.querySelector('.signal').classList.toggle('is-active', profile.status === 'active' && !profile.node_retired && !(state.scope === 'telegram' && mode === 'live' && (profile.access_type === 'public' || profile.session?.controllable && !profile.session.enabled)));
  updateRemaining();
  syncControls();
}

function applyStatus(data) {
  if ((data.scope && data.scope !== state.scope) || (data.profile?.scope && data.profile.scope !== state.scope)) return false;
  const modeChanged = state.mode !== data.mode;
  const changed = !state.loaded || modeChanged || state.profile.id !== data.profile.id || state.profile.node !== data.profile.node;
  const statusChanged = state.profile.status !== data.profile.status || state.profile.expires !== data.profile.expires
    || state.profile.node_retired !== data.profile.node_retired
    || state.profile.session?.enabled !== data.profile.session?.enabled || state.profile.session?.pending !== data.profile.session?.pending;
  if (changed || statusChanged) {
    if (el('telegram-session-dialog').open) el('telegram-session-dialog').close();
    if (state.confirmation) closeConfirmation();
    closeConnection();
  }
  if (modeChanged) {state.selections={};state.profiles={};state.selected='';}
  if (data.live_access) state.liveAccess = data.live_access;
  else if (modeChanged) state.liveAccess = {};
  state.nodes = data.nodes;
  state.profile = data.profile;
  state.profiles = {...state.profiles, ...data.profiles, [state.scope]:data.profile};
  if (typeof data.is_admin === 'boolean') el('open-admin').hidden = !data.is_admin;
  state.mode = data.mode;
  if (typeof data.personal_test === 'boolean') state.personalTest = data.personal_test;
  state.hours = data.hours;
  if (typeof data.available === 'boolean') state.available = data.available;
  const draft = state.selections[state.scope];
  if (!state.loaded && draft && draft.profileId === data.profile.id && draft.profileStatus === data.profile.status
      && data.nodes.some(node => node.id === draft.node)) state.selected = draft.node;
  else if (changed && pendingStates.includes(data.profile.status)) state.selected = data.profile.node;
  if (!state.nodes.some(node => node.id === state.selected)) state.selected = state.nodes.find(node => node.id === data.profile.replacement?.node && !node.maintenance)?.id || state.nodes.find(node => !node.maintenance)?.id || state.nodes[0]?.id || '';
  state.loaded = true; state.denied = false;
  el('synced').textContent = 'Обновлено ' + new Date().toLocaleTimeString('ru-RU', {hour:'2-digit', minute:'2-digit'});
  renderProfile();
  if (el('locations').open) renderLocations();
  return true;
}

function scopePreferenceKey() {
  const id = tg?.initDataUnsafe?.user?.id;
  return id === undefined ? null : 'northline.scope.' + id;
}

function chooseInitialScope(data) {
  const allowed = scope => data.mode !== 'live' || data.live_access?.[scope]?.allowed !== false;
  let saved;
  try {const key=scopePreferenceKey();if(key) saved=window.localStorage?.getItem(key);} catch (_) {}
  if (scopeNames[saved] && allowed(saved)) return saved;
  const active = Object.keys(scopeNames).find(scope => allowed(scope) && data.profiles?.[scope]?.status === 'active');
  if (active) return active;
  return Object.keys(scopeNames).find(allowed) || state.scope;
}

async function refresh(background = false) {
  if (state.busy || state.refreshing || (background && state.denied)) return;
  const epoch = state.epoch;
  const token = {}; state.refreshToken = token;
  state.refreshing = true;
  syncControls();
  try {
    const data = await api('status');
    // A read started before a mutation cannot overwrite its result.
    if (state.epoch !== epoch) return;
    if (!state.initialScopeChosen) {
      const preferred = chooseInitialScope(data);
      state.initialScopeChosen = true;
      if (preferred !== state.scope) {
        state.profiles = data.profiles || {};
        if (data.live_access) state.liveAccess = data.live_access;
        await switchScope(preferred, false);
        return;
      }
    }
    applyStatus(data);
    if (!background || state.noticeKind === 'connection') notice();
  } catch (error) {
    if (state.epoch !== epoch) return;
    if (expireSession(error)) return;
    el('synced').textContent = 'Не удалось обновить';
    if (!state.loaded) {
      el('headline').textContent = 'Нет связи с сервером';
      el('subtitle').textContent = 'Проверьте интернет и нажмите «Повторить загрузку».';
    }
    notice(error.message, true, 'connection');
  } finally {
    if (state.refreshToken === token) state.refreshing = false;
    syncControls();
  }
}

async function mutate(path, body, success) {
  if (state.busy || !state.loaded) return;
  state.busy = true;
  ++state.epoch;
  syncControls();
  notice('Сохранение…');
  try {
    const profile = await api(path, body);
    applyStatus({scope:state.scope, nodes:state.nodes, mode:state.mode, hours:state.hours, profile});
    notice(success);
    tg?.HapticFeedback?.notificationOccurred('success');
    return profile;
  } catch (error) {
    if (expireSession(error)) return;
    // A lost response does not imply a failed server operation.
    try {applyStatus(await api('status'));} catch (refreshError) {
      if (expireSession(refreshError)) return;
      el('synced').textContent = 'Нет связи с сервером';
    }
    notice(error.message, true);
    tg?.HapticFeedback?.notificationOccurred('error');
  } finally {
    state.busy = false;
    syncControls();
  }
}

function syncBackButton() {
  const visible = state.account || el('locations').open || el('action-dialog').open || el('connection-dialog').open || el('telegram-session-dialog').open;
  if (visible) tg?.BackButton?.show(); else tg?.BackButton?.hide();
  const locationOpen = el('locations').open;
  for (const [id, active] of [['nav-home', !state.account && !locationOpen], ['nav-locations', locationOpen], ['nav-account', state.account && !locationOpen]]) {
    el(id).classList.toggle('active', active);
    if (active) el(id).setAttribute('aria-current', 'page'); else el(id).removeAttribute('aria-current');
  }
}

function renderLocations() {
  const query = el('search').value.trim().toLocaleLowerCase();
  const filtered = state.nodes.filter(node => `${node.location || ''} ${node.server_name || ''} ${node.name} ${node.id}`.toLocaleLowerCase().includes(query));
  el('location-count').textContent = `Найдено: ${filtered.length} из ${state.nodes.length}`;
  el('empty').hidden = filtered.length > 0;
  el('location-list').replaceChildren(...filtered.map(node => {
    const button = document.createElement('button');
    const selected = state.selected === node.id;
    button.className = 'country' + (selected ? ' chosen' : '');
    button.type = 'button';
    button.disabled = !!node.maintenance;
    button.setAttribute('aria-pressed', String(selected));
    const flagMatch = node.name.match(/^([\u{1F1E6}-\u{1F1FF}]{2})\s*/u);
    const flag = document.createElement('span');
    flag.className = 'country-flag';
    flag.textContent = node.flag || (flagMatch ? flagMatch[1] : '◎');
    flag.setAttribute('aria-hidden', 'true');
    const name = document.createElement('span');
    name.className = 'country-copy';
    const title = document.createElement('span');
    title.textContent = node.location || (flagMatch ? node.name.slice(flagMatch[0].length) : node.name);
    const tag = document.createElement('small');
    tag.textContent = node.maintenance ? 'На обслуживании / недоступен' : state.profile.node === node.id && state.profile.status === 'active' ? 'Ваш текущий сервер' : node.protocol || scopeProtocols[state.scope];
    if (node.server_name && node.server_name!==node.name) tag.textContent=node.server_name+' · '+tag.textContent;
    if (node.access_type==='public') tag.textContent=(state.scope==='device'?'Публичный VPN Gate · ':'Публичный прокси · ')+tag.textContent;
    name.append(title, tag);
    const check = document.createElement('span');
    check.className = 'country-check';
    check.textContent = selected ? '✓' : '';
    check.setAttribute('aria-hidden', 'true');
    button.append(flag, name, check);
    button.onclick = () => {
      if (state.busy || node.maintenance) return;
      state.selected = node.id;
      el('selected').textContent = node.name;
      syncControls();
      el('locations').close();
      syncBackButton();
      tg?.HapticFeedback?.selectionChanged();
    };
    return button;
  }));
}

function openLocations() {
  if (state.busy || !state.loaded || !state.nodes.length || el('locations').open) return;
  el('search').value = '';
  renderLocations();
  el('locations').showModal();
  el('close-locations').focus({preventScroll:true});
  syncBackButton();
}

function tab(account) {
  state.account = account;
  el('home').hidden = account;
  el('account').hidden = !account;
  syncBackButton();
  window.scrollTo(0, 0);
}

function closeConfirmation() {
  state.confirmation = null;
  if (el('action-dialog').open) el('action-dialog').close();
}

function confirmAction(path, body, title, description, success) {
  state.confirmation = {path, body, success};
  el('action-title').textContent = title;
  el('action-description').textContent = description;
  el('action-submit').textContent = path === 'revoke' ? (state.profile.access_type==='public'?'Убрать из бота':'Отключить профиль') : 'Сменить сервер';
  el('action-submit').classList.toggle('danger', path === 'revoke');
  el('action-dialog').showModal();
  el('action-cancel').focus({preventScroll:true});
  syncBackButton();
}

el('open-admin').onclick = () => {window.location.href='/admin'+(window.location.hash||'');};
el('choose').onclick = openLocations;
el('all-locations').onclick = openLocations;
el('account-locations').onclick = openLocations;
el('search').oninput = renderLocations;
el('close-locations').onclick = () => el('locations').close();
el('nav-home').onclick = () => tab(false);
el('dial-action').onclick = async () => {
  if (el('dial-action').disabled) return;
  if (state.profile.node_retired) return el('activate').click();
  if (state.scope === 'telegram' && state.mode === 'live' && state.profile.status === 'active') {
    if (state.profile.session?.controllable) return toggleTelegramSession();
    showTelegramSession(); return;
  }
  if (state.profile.status === 'active') el('setup').click();
  else el('activate').click();
};
el('nav-locations').onclick = () => {tab(false); openLocations();};
el('brand-home').onclick = () => tab(false);
el('nav-account').onclick = () => tab(true);
el('refresh').onclick = () => refresh();
el('retry').onclick = () => refresh();
el('account-profile').onclick = () => {
  tab(false);
  (el('profile').hidden ? el('trial') : el('profile')).scrollIntoView({behavior:'smooth'});
};
el('close-app').onclick = () => {if (tg?.initData) tg.close(); else tab(false);};
el('action-cancel').onclick = closeConfirmation;
el('action-submit').onclick = () => {
  const action = state.confirmation;
  if (!action) return;
  closeConfirmation();
  mutate(action.path, action.body, action.success);
};
for (const id of ['locations', 'action-dialog', 'connection-dialog', 'telegram-session-dialog']) {
  el(id).addEventListener('close', () => {
    if (id === 'action-dialog') state.confirmation = null;
    if (id === 'connection-dialog' && !el(id).open) cancelConnection();
    syncBackButton();
  });
}
tg?.BackButton?.onClick(() => {
  if (el('telegram-session-dialog').open) el('telegram-session-dialog').close();
  else if (el('action-dialog').open) closeConfirmation();
  else if (el('locations').open) el('locations').close();
  else if (el('connection-dialog').open) closeConnection();
  else tab(false);
});

const user = tg?.initDataUnsafe?.user;
el('user-name').textContent = user ? [user.first_name, user.last_name].filter(Boolean).join(' ') : 'Пользователь Telegram';
el('user-id').textContent = user ? `ID: ${user.id}` : 'Откройте приложение из Telegram-бота';
el('copy-id').hidden = !user || !navigator.clipboard;
el('copy-id').onclick = async () => {
  try {await navigator.clipboard.writeText(String(user.id)); notice('Telegram ID скопирован.');}
  catch (_) {notice('Не удалось скопировать ID. Его можно получить командой /id в боте.', true);}
};

el('trial').onsubmit = event => {
  event.preventDefault();
  if (el('activate').disabled) return;
  const body = {scope:state.scope, node:state.selected, expected_profile:state.profile.id || 0, expected_status:state.profile.status};
  const name = state.nodes.find(node => node.id === state.selected)?.name || '';
  if (state.profile.status === 'active') {
    confirmAction('issue', body, 'Сменить сервер?', name + '. Доступ останется бессрочным.' +
      (state.mode === 'live' ? state.scope === 'device' ? ' Скачайте новую конфигурацию после смены.' : ' Используйте новую ссылку прокси после смены.' : ''), 'Сервер изменён: ' + name);
  } else mutate('issue', body, 'Профиль создан.');
};
el('revoke').onclick = () => {
  if (state.busy || !state.loaded) return;
  const external=state.profile.access_type==='public';
  confirmAction('revoke', {scope:state.scope, expected_profile:state.profile.id, expected_status:state.profile.status}, external?'Убрать профиль из бота?':'Отключить профиль?',
    external?(state.scope==='device'?'Это публичный VPN. Удаление профиля не отзывает общую конфигурацию. Отключите VPN в OpenVPN Connect.':'Это публичный прокси. Чтобы отключить соединение, выключите его в настройках Telegram. Удаление профиля не отзывает общий ключ.'):'Будет отключён профиль «' + scopeNames[state.scope] + '». Второй режим сохранится.',external?(state.scope==='device'?'Профиль убран из бота. Отключите VPN в OpenVPN Connect.':'Профиль убран из бота. Выключите прокси в настройках Telegram.'):'Профиль отключён.');
};
function saveFile(download) {
  const url = URL.createObjectURL(new Blob([download.content], {type:'text/plain'}));
  const link = document.createElement('a');
  link.href = url; link.download = download.filename;
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

async function switchScope(scope, remember = true) {
  if (state.busy || !scopeNames[scope]) return;
  state.initialScopeChosen = true;
  if (remember) {
    try {const key=scopePreferenceKey();if(key) window.localStorage?.setItem(key,scope);} catch (_) {}
  }
  tab(false);
  if (state.scope === scope) return;
  if (state.loaded) state.selections[state.scope] = {node:state.selected, profileId:state.profile.id, profileStatus:state.profile.status};
  closeConfirmation();
  closeConnection();
  if (el('locations').open) el('locations').close();
  if (el('telegram-session-dialog').open) el('telegram-session-dialog').close();
  ++state.epoch; state.refreshToken = null; state.refreshing = false;
  state.scope = scope; state.loaded = false; state.available = false; state.nodes = []; state.connection = null;
  state.profile = state.profiles[scope] || {status:'none',scope};
  state.selected = state.selections[scope]?.node || '';
  notice(); renderProfile();
  el('headline').textContent = 'Загрузка профиля';
  el('subtitle').textContent = 'Проверяем режим «' + scopeNames[scope] + '»…';
  await refresh();
}

function detectPlatform() {
  const agent = navigator.userAgent || '';
  if (/Android/i.test(agent)) return 'android';
  if (/iPad|iPhone|iPod/i.test(agent) || (/Mac/i.test(agent) && navigator.maxTouchPoints > 1)) return 'ios';
  if (/Windows/i.test(agent)) return 'windows';
  if (/Mac/i.test(agent)) return 'macos';
  if (/Linux/i.test(agent)) return 'linux';
  return 'other';
}
state.platform = detectPlatform();
el('platform').value = state.platform;

function cancelConnection() {
  if (state.connectionRequest) state.connectionRequest.controller.abort();
  state.connectionRequest = null;
  state.connection = null;
  syncControls();
}

function closeConnection() {
  cancelConnection();
  if (el('connection-dialog').open) el('connection-dialog').close();
}

function clientPreferenceKey() {
  return 'northline.client.' + (tg?.initDataUnsafe?.user?.id || 'browser') + '.' + state.platform + '.' + state.connection?.protocol;
}

function clientActionLabel(client, installed) {
  if (installed && client.open_via_store) return state.platform === 'android' ? 'Открыть через Google Play' : 'Открыть через App Store';
  return (installed ? 'Открыть ' : 'Скачать ') + client.name;
}

function renderClient() {
  const client = state.connection?.client;
  el('client-choice').hidden = !client;
  el('connection-app').hidden = !client;
  el('connection-import').hidden = !client;
  if (!client) return;
  let installed = false;
  try {installed = window.localStorage?.getItem(clientPreferenceKey()) === 'installed';} catch (_) {}
  el('client-installed').checked = installed;
  el('client-installed-label').textContent = client.name + ' уже установлено';
  el('connection-app').textContent = clientActionLabel(client, installed);
}

function openExternal(url, options = {}) {
  if (/^https:\/\//.test(url) && tg?.openLink) tg.openLink(url, options);
  else if (state.platform === 'ios' && tg && /^openvpn:\/\//.test(url)) {
    // Telegram iOS sends a new-window navigation to its external URL handler.
    const link = document.createElement('a');
    link.href = url; link.target = '_blank'; link.rel = 'noopener noreferrer';
    document.body.append(link); link.click(); link.remove();
  }
  else window.location.href = url;
}

function downloadConnection(connection) {
  if (connection.download_url && tg?.downloadFile && tg?.isVersionAtLeast?.('8.0')) {
    tg.downloadFile({url:new URL(connection.download_url, window.location.href).href, file_name:connection.download.filename});
  } else saveFile(connection.download);
}

async function toggleTelegramSession(connect = false) {
  if (state.busy || !state.loaded || state.scope !== 'telegram' || !state.profile.session?.controllable || state.profile.session.pending) return;
  const enabled = connect || !state.profile.session.enabled;
  const result = await mutate('session', {scope:'telegram', expected_profile:state.profile.id,
    expected_enabled:state.profile.session.enabled, enabled}, enabled ? 'Доступ на сервере возобновлён. Подключитесь в Telegram.' : 'Доступ на сервере приостановлен. Профиль сохранён.');
  if (result?.session?.enabled && !result.session.pending) await el('setup').onclick();
  else if (result?.session && !result.session.enabled && !result.session.pending) showTelegramSession();
}

function showTelegramSession() {
  const managed = state.profile.session?.controllable;
  el('telegram-session-note').textContent = managed
    ? 'Доступ на сервере приостановлен, профиль сохранён. Чтобы Telegram работал напрямую, выключите «Использовать прокси» в настройках Telegram.'
    : 'Профиль сохранится при отключении. Для публичного сервера переключатель соединения находится в Telegram; Mini App не видит его состояние.';
  el('telegram-session-connect').textContent = managed ? 'Возобновить и подключить' : 'Включить в Telegram';
  el('telegram-session-dialog').showModal(); syncBackButton();
}

async function loadConnection() {
  if (state.busy || !state.loaded || state.profile.status !== 'active') return;
  cancelConnection();
  const request = {controller:new AbortController(), scope:state.scope, platform:state.platform,
    profileId:state.profile.id, profileStatus:state.profile.status};
  state.connectionRequest = request;
  syncControls();
  el('connection-note').textContent = 'Загрузка инструкции…';
  el('connection-connect').hidden = true;
  el('connection-download').hidden = true;
  renderClient();
  el('connection-help').textContent = '';
  el('connection-steps').replaceChildren();
  try {
    const path = 'connection?platform=' + request.platform + '&expected_profile=' + request.profileId
      + '&expected_status=' + request.profileStatus;
    const result = await api(path, undefined, {controller:request.controller});
    if (state.connectionRequest !== request) return;
    if (result.scope !== request.scope || result.platform !== request.platform || result.profile?.id !== request.profileId
        || state.profile.id !== request.profileId || state.profile.status !== request.profileStatus) {
      throw new Error('Профиль изменился. Обновите его и откройте настройку заново.');
    }
    state.connection = result;
    renderClient();
    el('connection-protocol').textContent = result.protocol;
    el('connection-title').textContent = scopeNames[request.scope];
    el('connection-note').textContent = request.scope==='telegram'?'Нажмите кнопку ниже и подтвердите использование прокси в Telegram.':'Профиль готов к настройке на вашем устройстве.';
    el('connection-steps').replaceChildren(...result.steps.map(text => {
      const item = document.createElement('li'); item.textContent = text; return item;
    }));
    el('connection-download').textContent = result.client ? 'Скачать файл вручную' : 'Скачать конфигурацию';
    el('connection-download').hidden = !result.download;
    el('connection-connect').hidden = !result.connect_url;
    el('connection-help').textContent = request.scope==='telegram'?'Прокси работает в приложении Telegram. Сайты, Mini Apps и другие приложения используют обычное подключение.':result.protocol==='OpenVPN'?'Импортируйте файл .ovpn в OpenVPN Connect. Если скачать не удалось, отправьте /config боту.':'Импортируйте файл .conf в WireGuard. Если скачать не удалось, отправьте /config боту.';
    if(result.notice)el('connection-help').textContent=result.notice;
    return result;
  } catch (error) {
    if (state.connectionRequest !== request) return;
    if (expireSession(error)) return;
    el('connection-note').textContent = error.message + ' Закройте инструкцию, обновите профиль и попробуйте снова.';
  } finally {
    if (state.connectionRequest === request) state.connectionRequest = null;
    syncControls();
  }
}
el('scope-device').onclick = () => switchScope('device');
el('scope-telegram').onclick = () => switchScope('telegram');
el('device-profile').onclick = () => switchScope('device');
el('telegram-profile').onclick = () => switchScope('telegram');
function openTelegramProxy() {
  const connection = state.connection;
  if (state.busy || !state.loaded || state.connectionRequest || state.mode !== 'live' || state.scope !== 'telegram'
      || state.profile.status !== 'active' || (state.profile.expires !== 0 && state.profile.expires <= Math.floor(Date.now()/1000))
      || connection?.scope !== state.scope || connection.profile?.id !== state.profile.id
      || !/^https:\/\/t\.me\/proxy\?/.test(connection.connect_url || '')) return false;
  try {
    if (tg?.openTelegramLink) tg.openTelegramLink(connection.connect_url);
    else window.location.href = connection.connect_url;
    return true;
  } catch (_) {
    const message = 'Не удалось открыть окно Telegram. Получите ссылку командой /config в боте.';
    el('connection-note').textContent = message;
    notice(message, true);
    return false;
  }
}
el('setup').onclick = async () => {
  if (state.busy || !state.loaded || state.profile.status !== 'active' || el('setup').disabled) return;
  if (state.scope === 'telegram' && state.mode === 'live') {
    if (state.profile.session?.controllable && !state.profile.session.enabled) return toggleTelegramSession(true);
    const id = state.profile.id;
    const connection = await loadConnection();
    if (state.scope !== 'telegram' || state.mode !== 'live' || state.profile.id !== id || state.profile.status !== 'active' || !state.loaded) return;
    if (connection && state.connection === connection && openTelegramProxy()) return;
    if (!state.connectionRequest) {el('connection-dialog').showModal();syncBackButton();}
    return;
  }
  el('connection-dialog').showModal(); syncBackButton(); loadConnection();
};
el('close-connection').onclick = closeConnection;
el('close-telegram-session').onclick = () => {el('telegram-session-dialog').close();syncBackButton();};
el('telegram-session-connect').onclick = () => {el('telegram-session-dialog').close();syncBackButton();return el('setup').onclick();};
el('telegram-session-settings').onclick = () => {
  notice('В настройках Telegram выключите «Использовать прокси». Профиль останется сохранённым.');
  // An official settings deep link; old clients may open the parent settings page.
};
el('client-installed').onchange = () => {
  try {window.localStorage?.setItem(clientPreferenceKey(), el('client-installed').checked ? 'installed' : 'not-installed');} catch (_) {}
  const client = state.connection?.client;
  if (client) el('connection-app').textContent = clientActionLabel(client, el('client-installed').checked);
};
el('connection-app').onclick = () => {
  if (el('connection-app').disabled) return;
  const client = state.connection?.client;
  if (!client) return;
  const installed = el('client-installed').checked;
  try {
    if (!installed) {
      openExternal(client.install_url);
      el('connection-note').textContent = 'После установки отметьте «' + client.name + ' уже установлено» и нажмите «Импортировать конфиг».';
    } else if (client.open_url) {
      openExternal(client.open_url, state.platform === 'ios' ? {try_browser:'safari'} : {});
      el('connection-note').textContent = client.open_via_store ? 'На странице приложения нажмите «Открыть». Затем вернитесь для импорта конфига.' : 'Подтвердите открытие ' + client.name + '. Если приложение не открылось, запустите его с устройства.';
    } else el('connection-note').textContent = 'Запустите ' + client.name + ' из списка приложений устройства. Затем нажмите «Импортировать конфиг».';
  } catch (_) {el('connection-note').textContent = 'Запустите ' + client.name + ' на устройстве. Для установки снимите отметку «Уже установлено».';}
};
el('connection-import').onclick = async () => {
  if (el('connection-import').disabled) return;
  const connection = state.connection;
  const name = connection.client.name;
  try {
    if (connection.download_expires && connection.download_expires <= Math.floor(Date.now()/1000) + 5) {
      await loadConnection();
      if (state.connection?.client) el('connection-note').textContent = 'Ссылка обновлена. Нажмите «Импортировать конфиг» ещё раз.';
      return;
    }
    if (connection.client.external_import && connection.import_page_url) {
      openExternal(new URL(connection.import_page_url, window.location.href).href, {try_browser:'safari'});
      el('connection-note').textContent = 'В Safari нажмите «Открыть OpenVPN Connect» и подтвердите открытие приложения. Если страница осталась в Telegram, откройте её через меню в Safari.';
      return;
    }
    if (connection.client.native_import && connection.download_url) {
      openExternal('openvpn://import-profile/' + new URL(connection.download_url, window.location.href).href);
      el('connection-note').textContent = 'Подтвердите импорт в ' + name + ', затем включите VPN. Если окно не появилось, нажмите «Скачать файл вручную» и откройте его в приложении.';
      return;
    }
    if (typeof File === 'function' && navigator.share && navigator.canShare) {
      const files = [new File([connection.download.content], connection.download.filename, {type:'application/octet-stream'})];
      if (navigator.canShare({files})) {
        await navigator.share({files});
        if (state.connection === connection) el('connection-note').textContent = 'Выберите ' + name + ' в меню устройства и подтвердите импорт. Затем включите VPN в приложении.';
        return;
      }
    }
    downloadConnection(connection);
    el('connection-note').textContent = 'Откройте файл ' + connection.download.filename + ' в ' + name + ' через «Добавить → Импорт из файла», затем включите VPN.';
  } catch (error) {
    if (state.connection !== connection) return;
    el('connection-note').textContent = error.name === 'AbortError' ? 'Импорт отменён. Можно повторить или скачать файл вручную.' : 'Автоматический импорт недоступен. Нажмите «Скачать файл вручную» и откройте его в ' + name + '.';
  }
};
el('connection-connect').onclick = () => {
  if (!el('connection-connect').disabled) openTelegramProxy();
};
el('platform').onchange = () => {state.platform = el('platform').value; loadConnection();};
el('connection-download').onclick = () => {
  if (state.busy || state.connectionRequest || !state.connection?.download) return;
  try {
    if (state.connection.download_expires && state.connection.download_expires <= Math.floor(Date.now()/1000) + 5) {
      loadConnection().then(() => {if (state.connection) el('connection-note').textContent = 'Ссылка обновлена. Нажмите «Скачать файл вручную» ещё раз.';});
      return;
    }
    downloadConnection(state.connection);
    const message = 'Файл передан на скачивание. Если он не появился, отправьте /config в боте.';
    el('connection-note').textContent = message;
    notice(message);
  } catch (_) {
    el('connection-note').textContent = 'Не удалось скачать файл. Получите его через /config в боте.';
  }
};
el('download').onclick = () => {el('setup').onclick();};

renderScope();
syncControls();
refresh();
setInterval(() => {if (!document.hidden && state.loaded) refresh(true);}, 5000);
setInterval(updateRemaining, 1000);
document.addEventListener('visibilitychange', () => {if (!document.hidden) refresh(true);});
window.addEventListener('online', () => refresh(true));
window.addEventListener('storage', event => {if (event.key === 'northline.environment') refresh(true);});
window.addEventListener('offline', () => {notice('Нет подключения к интернету.', true, 'connection');});
