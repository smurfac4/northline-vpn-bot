import json
import hashlib
import os
import queue
import secrets
import threading
from contextvars import ContextVar
from html import escape
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from urllib.request import Request, urlopen

import settings
from backend.catalog import SCOPES, PLATFORMS, instructions
from backend.admin import is_admin


CURRENT_USER = ContextVar('telegram_sender', default=None)


class RequestFailed(Exception):
    pass


def request(url, payload=None, headers=None, timeout=35):
    headers = dict(headers or {})
    if isinstance(payload, dict):
        payload = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    try:
        with urlopen(Request(url, data=payload, headers=headers), timeout=timeout) as response:
            return json.load(response)
    except HTTPError as error:
        try:
            body = json.load(error)
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        message = body.get("error") or body.get("description") or f"HTTP {error.code}"
        raise RequestFailed(message) from None
    except (OSError, URLError, ValueError):
        raise RequestFailed("Нет связи с сервером. Попробуйте ещё раз через несколько секунд.") from None


def telegram(method, payload=None, headers=None, timeout=35):
    body = request(f"https://api.telegram.org/bot{settings.TOKEN}/{method}", payload, headers, timeout=timeout)
    if not isinstance(body,dict) or (body.get('ok') and 'result' not in body):
        raise RequestFailed('Telegram вернул некорректный ответ. Повторите запрос.')
    if not body.get("ok"):
        raise RequestFailed(body.get("description", "Telegram API error."))
    return body["result"]


def api(user, path, payload=None, scope="device", timeout=45):
    query = urlencode({"scope": scope})
    payload = {**payload, "scope": scope} if payload is not None else None
    headers = {"X-Bot-Key": settings.BOT_KEY, "X-Telegram-User": str(user)}
    identity = CURRENT_USER.get()
    if identity and identity.get('id') == user:
        headers['X-Telegram-Profile'] = json.dumps({key:identity[key] for key in
            ('id','username','first_name','last_name') if key in identity})
    return request(
        f"http://127.0.0.1:{settings.PORT}/api/{path}{'&' if '?' in path else '?'}{query}", payload,
        headers, timeout=timeout,
    )


def upload(method, chat, field, filename, mime, data, timeout=35):
    boundary = uuid.uuid4().hex
    header = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n{chat}\r\n'
        f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        f"Content-Type: {mime}\r\n\r\n"
    ).encode()
    return telegram(method, header + data + f"\r\n--{boundary}--\r\n".encode(),
                    {"Content-Type": f"multipart/form-data; boundary={boundary}"}, timeout=timeout)


class StickerSender:
    """A bounded background queue; Telegram stores the image after the first upload."""
    def __init__(self, cache_path=None):
        self.cache_path = cache_path or settings.ROOT / 'data' / 'sticker-cache.json'
        self.jobs = queue.Queue(maxsize=8)
        self.lock = threading.Lock()
        self.pending = set()
        self.worker = None

    def submit(self, chat):
        with self.lock:
            if chat in self.pending:
                return False
            try:
                self.jobs.put_nowait(chat)
            except queue.Full:
                return False
            self.pending.add(chat)
            if self.worker is None:
                self.worker = threading.Thread(target=self._run, name='sticker-sender', daemon=True)
                self.worker.start()
        return True

    def _run(self):
        while True:
            with self.lock:
                try:
                    chat = self.jobs.get_nowait()
                except queue.Empty:
                    self.worker = None
                    return
            try:
                self._send(chat)
            except Exception:
                # Sticker failures must never stop polling or expose credentials.
                print('Sticker delivery failed; other bot commands remain available.', flush=True)
                try:
                    telegram('sendMessage', {'chat_id': chat, 'text': 'Не удалось отправить стикер. Попробуйте ещё раз.'}, timeout=5)
                except Exception:
                    pass
            finally:
                with self.lock:
                    self.pending.discard(chat)
                self.jobs.task_done()

    def _send(self, chat):
        image = (Path(__file__).parent / 'ready.webp').read_bytes()
        key = hashlib.sha256(settings.TOKEN.encode() + b'\0' + image).hexdigest()
        file_id = None
        try:
            cached = json.loads(self.cache_path.read_text())
            if isinstance(cached, dict) and cached.get('key') == key and isinstance(cached.get('file_id'), str):
                file_id = cached['file_id']
        except (OSError, ValueError):
            pass
        if file_id:
            try:
                telegram('sendSticker', {'chat_id': chat, 'sticker': file_id}, timeout=10)
                return
            except RequestFailed as error:
                if not any(reason in str(error).lower() for reason in
                           ('wrong file identifier', 'file_id', 'wrong remote file', 'invalid file id')):
                    raise
        result = upload('sendSticker', chat, 'sticker', 'ready.webp', 'image/webp', image, timeout=10)
        file_id = result.get('sticker', {}).get('file_id') if isinstance(result, dict) else None
        if not isinstance(file_id, str) or not file_id:
            return
        temporary = self.cache_path.with_name('.sticker-cache-' + secrets.token_hex(6))
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump({'key': key, 'file_id': file_id}, stream)
            os.replace(temporary, self.cache_path)
        except OSError:
            print('Sticker was sent, but its cache could not be saved.', flush=True)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


STICKERS = StickerSender()


STATES = {
    "none": "Нет профиля", "active": "Активен", "creating": "Создаётся",
    "revoking": "Отключается", "revoked": "Отключён", "expired": "Срок истёк",
}
STATUS_CODES = {"none":"n", "active":"a", "creating":"c", "revoking":"r", "revoked":"x", "expired":"e"}
CODE_STATUSES = {code: status for status, code in STATUS_CODES.items()}
PAGE_SIZE = 8


def button(text, value):
    return {"text": text, "callback_data": value}


def scoped(scope, action):
    return ("t:" if scope == "telegram" else "d:") + action


def app_url(scope=None, admin=False):
    if not settings.PUBLIC_URL:
        return ''
    parsed = urlsplit(settings.PUBLIC_URL)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query['v'] = '31'
    if scope:
        query['scope'] = scope
    path = parsed.path.rstrip('/') + ('/admin' if admin else '/')
    return urlunsplit((parsed.scheme, parsed.netloc, path, urlencode(query), ''))


def refresh_app_menu(chat=None, admin=False):
    if not settings.PUBLIC_URL:
        return
    payload = {'menu_button': {'type':'web_app', 'text':'Админка' if admin else 'Открыть приложение', 'web_app':{'url':app_url(admin=admin)}}}
    if chat is not None:
        payload['chat_id'] = chat
    telegram('setChatMenuButton', payload)


def refresh_chat_menu(chat, admin=False):
    try:
        refresh_app_menu(chat, admin=admin)
    except RequestFailed:
        print('Personal app menu refresh deferred.', flush=True)


def app_rows(scope=None):
    url = app_url(scope)
    return [[{'text':'↗ Открыть приложение', 'web_app':{'url':url}}]] if url else []


COMMAND_BUTTONS = {
    '🏠 Меню': '/start', '📱 Mini App': '/app',
    '🌍 Серверы': '/servers', '👤 Профили': '/status',
    '🛡 VPN': '/device', '✈️ Telegram': '/telegram',
    '⚙️ Конфиг': '/config', '⛔ Отключить': '/revoke',
    '❓ Помощь': '/help', '🆔 Мой ID': '/id',
    '🎉 Стикер': '/sticker', '🔧 Админка': '/admin',
}
LEGACY_COMMAND_BUTTONS = {
    '📱 Приложение':'/app', '👤 Мои профили':'/status', '🛡 Всё устройство':'/device',
    '✈️ Только Telegram':'/telegram', '⚙️ Подключение':'/config', '⛔ Отключить профиль':'/revoke',
}


def command_keyboard(user):
    labels = [label for label, command in COMMAND_BUTTONS.items()
              if command != '/admin' or is_admin(user)]
    return {'keyboard': [[{'text': label} for label in labels[index:index+3]]
                         for index in range(0, len(labels), 3)],
            'resize_keyboard': True, 'is_persistent': True,
            'input_field_placeholder': 'Выберите действие'}


def send(chat, text, buttons=None, message_id=None, reply_markup=None):
    payload = {"chat_id": chat, "text": text, "parse_mode": "HTML",
               "reply_markup": reply_markup if reply_markup is not None else {"inline_keyboard": buttons or []}}
    if message_id:
        payload["message_id"] = message_id
        try:
            return telegram("editMessageText", payload)
        except RequestFailed as error:
            if "message is not modified" in str(error).lower():
                return None
            if not any(reason in str(error).lower() for reason in
                       ("message to edit not found", "message can't be edited")):
                raise
            payload.pop("message_id")
    return telegram("sendMessage", payload)


def mode_choices(action="home"):
    return [[button("▣ Всё устройство", scoped("device", action))],
            [button("↗ Только Telegram", scoped("telegram", action))]]


def menu(chat, user, message_id=None):
    refresh_chat_menu(chat)
    state = api(user, "status")
    profiles = state.get("profiles", {"device":state["profile"]})
    text = "<b>NORTHLINE</b> · <i>безлимит</i>\n\n"
    for scope in SCOPES:
        status = profiles.get(scope, {}).get("status", "none")
        icon = '🛡' if scope == 'device' else '✈️'
        text += f'{icon} <b>{SCOPES[scope]["name"]}</b> · {STATES.get(status, "Нет профиля")}\n'
    text += "\nВыберите режим ↓"
    rows = app_rows() + mode_choices()
    if is_admin(user) and settings.PUBLIC_URL:
        rows.append([{'text':'⚙ Админка', 'web_app':{'url':app_url(admin=True)}}])
    send(chat, text, rows, message_id,
         reply_markup=command_keyboard(user) if message_id is None else None)


def scope_menu(chat, user, scope, message_id=None):
    state = api(user, "status", scope=scope)
    profile = state["profile"]
    text = f'<b>{SCOPES[scope]["name"]}</b> · <i>безлимит</i>\n\n'
    if profile["status"] == "active":
        text += f'● Активен\n{escape(profile["server"])}'
    else:
        text += "Выберите страну для подключения ↓"
    rows = app_rows(scope) + [
        [button("Серверы", scoped(scope, "servers:0")), button("Мой профиль", scoped(scope, "status"))],
        [button("Как подключиться", scoped(scope, "help"))], [button("‹ Режимы", "menu")],
    ]
    send(chat, text, rows, message_id)


def profile_message(chat, profile, mode, message_id=None, scope="device"):
    status = profile["status"]
    text = f'<b>{SCOPES[scope]["name"]}</b>\n\n'
    if status == "none":
        send(chat, text + "Профиля пока нет. Выберите страну ↓",
             [[button("Выбрать сервер", scoped(scope, "servers:0"))],
              [button("‹ Назад", scoped(scope, "home"))]], message_id)
        return
    session = profile.get('session', {})
    label = 'На паузе' if status == 'active' and session.get('controllable') and not session.get('enabled') else STATES.get(status, '—')
    text += f'● {label} · Бессрочно\n{escape(profile["server"])}'
    if profile.get('node_retired'):
        text += '\n<i>Сервер заменён. Обновите подключение.</i>'
    rows = []
    connect = []
    if status == "active" and not profile.get('node_retired'):
        connect.append(button("↗ Подключиться", scoped(scope, "setup")))
    if profile.get("config_available"):
        connect.append(button("↓ Конфиг", scoped(scope, "export")))
    if connect: rows.append(connect)
    if profile.get('node_retired') and profile.get('replacement'):
        rows.append([button('↗ Подключить замену',scoped(scope,'select:'+profile['replacement']['node']))])
    actions = []
    if status not in ("creating", "revoking"):
        actions.append(button("🌍 Серверы", scoped(scope, "servers:0")))
    if status in ("creating", "active"):
        actions.append(button("Убрать" if profile.get('access_type')=='public' else "Отключить", scoped(scope, "confirm-revoke")))
    if actions: rows.append(actions)
    rows += [[button("↻ Обновить", scoped(scope, "status")), button("‹ Назад", scoped(scope, "home"))]]
    send(chat, text, rows, message_id)


def servers(chat, user, page=0, message_id=None, scope="device"):
    state = api(user, "status", scope=scope)
    nodes, profile = state["nodes"], state["profile"]
    pages = max(1, (len(nodes) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    rows = []
    for node in nodes[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]:
        current = profile.get("node") == node["id"] and profile["status"] == "active"
        label = ("⏸ " if node.get('maintenance') else "✓ " if current else "") + node["name"]
        rows.append([button(label, scoped(scope, "select:" + node["id"]))])
    nav = []
    if page:
        nav.append(button("← Назад", scoped(scope, f"servers:{page-1}")))
    if page + 1 < pages:
        nav.append(button("Далее →", scoped(scope, f"servers:{page+1}")))
    if nav:
        rows.append(nav)
    rows.append([button("‹ Назад", scoped(scope, "home"))])
    text = f'<b>Локации</b> · {SCOPES[scope]["name"]}\n{len(nodes)} серверов · {page+1}/{pages} · Безлимит'
    if not nodes:text += "\nСерверы пока недоступны."
    send(chat, text, rows, message_id)


def select_server(chat, user, node_id, message_id=None, scope="device"):
    state = api(user, "status", scope=scope)
    node = next((n for n in state["nodes"] if n["id"] == node_id), None)
    if not node:
        raise RequestFailed("Сервер недоступен. Откройте список заново.")
    if node.get('maintenance'):
        raise RequestFailed('Этот сервер на обслуживании. Выберите другой.')
    profile = state["profile"]
    if profile["status"] in ("creating", "revoking") or (
            profile["status"] == "active" and profile["node"] == node_id):
        return profile_message(chat, profile, state["mode"], message_id, scope)
    switching = profile["status"] == "active"
    title = "Сменить сервер?" if switching else "Создать профиль?"
    text = f'<b>{title}</b>\n{escape(node["name"])} · {SCOPES[scope]["name"]}\n<i>Без ограничения по времени</i>'
    if switching and state["mode"] == "live":
        text += "\nПотребуется новый конфиг или ссылка."
    rows = [[button("Сменить сервер" if switching else "Создать профиль", scoped(scope,
                    f'issue:{node_id}:{profile.get("id", 0)}:{STATUS_CODES[profile["status"]]}'))],
            [button("‹ К серверам", scoped(scope, "servers:0"))]]
    send(chat, text, rows, message_id)


def platform_rows(scope, action="guide"):
    items = [button(name, scoped(scope, action + ":" + key)) for key, name in PLATFORMS.items()]
    return [items[i:i+2] for i in range(0, len(items), 2)]


def help_message(chat, message_id=None, scope="device", platform=None):
    text = f'<b>Подключение</b> · {SCOPES[scope]["name"]}\n\n'
    if platform in PLATFORMS:
        text += f'<b>{PLATFORMS[platform]}</b>\n'
        if scope=='device':
            text += '1. Установите OpenVPN Connect (.ovpn) или WireGuard (.conf).\n2. Получите конфиг в профиле и импортируйте его.\n3. Включите VPN в приложении.'
        else:
            text += '1. Откройте ссылку из профиля.\n2. Подтвердите подключение в Telegram.\nПрокси действует только в Telegram.\n' + escape(instructions(scope, platform)[2])
    else:
        text += "Выберите ваше устройство."
    rows = platform_rows(scope) + [[button("Мой профиль", scoped(scope, "status")), button("‹ Назад", scoped(scope, "home"))]]
    send(chat, text, rows, message_id)


def connection_message(chat, user, scope, message_id=None):
    data = api(user, "connection", scope=scope)
    text = (f'<b>Подключение</b> · {data["protocol"]}\n'
            f'{escape(data["profile"]["server"])}\n\n')
    if data.get('connect_url'):
        text += "Нажмите кнопку ниже и подтвердите прокси в Telegram."
    elif data.get('protocol')=='OpenVPN':
        text += 'Конфиг .ovpn → OpenVPN Connect → включить VPN.'
    else:
        text += "Конфиг .conf → WireGuard → включить туннель."
    if data.get('notice'):
        text += '\n\n<i>' + ('Публичный VPN: оператор ведёт журналы. Отключение — в OpenVPN Connect.' if scope=='device' else 'Публичный прокси. Отключение — в настройках Telegram.') + '</i>'
    rows = [[{'text':'Подключить в Telegram','url':data['connect_url']}]] if data.get('connect_url') else []
    if data.get('download'):rows += [[button("↓ Конфигурация", scoped(scope, "export"))]]
    rows += [[button("Инструкция", scoped(scope, "help")), button("‹ Профиль", scoped(scope, "status"))]]
    send(chat, text, rows, message_id)


def record_interaction(user, action, scope):
    command = action.lstrip('/').partition(':')[0]
    allowed = {'start','menu','id','device','telegram','servers','select','issue','status',
               'confirm-revoke','revoke','setup','config','export','help','guide','sticker','admin','home','app'}
    event = 'chat/' + (command if command in allowed else 'message')
    try:
        api(user,'telemetry',{'action':event},scope=scope,timeout=2)
    except RequestFailed:
        # Logging must not prevent local help or menu access during an outage.
        print('Chat event could not be recorded.', flush=True)


def handle(update):
    callback = update.get("callback_query")
    message = callback.get("message", {}) if callback else update.get("message", {})
    sender = callback.get("from") if callback else message.get("from")
    if not sender or message.get("chat", {}).get("type") != "private":
        return
    chat, user = message["chat"]["id"], sender["id"]
    message_id = message.get("message_id") if callback else None
    if callback:
        try:
            telegram("answerCallbackQuery", {"callback_query_id": callback["id"]})
        except RequestFailed:
            pass
        action = callback.get("data", "")
    else:
        text = message.get("text", "").strip()
        words = text.split()
        action = COMMAND_BUTTONS.get(text, LEGACY_COMMAND_BUTTONS.get(text, words[0].split("@")[0] if words else ""))
    scope, explicit = "device", False
    if action.startswith(("d:", "t:")):
        prefix, _, action = action.partition(":")
        scope, explicit = ("telegram" if prefix == "t" else "device"), True
    identity_token = CURRENT_USER.set(sender)
    record_interaction(user, action, scope)
    try:
        if action == '/app':
            refresh_chat_menu(chat)
            send(chat,'<b>NORTHLINE</b>\nВаш VPN — в одном приложении ↓',app_rows(),message_id)
        elif action == '/admin':
            refresh_chat_menu(chat, admin=is_admin(user))
            if not is_admin(user):
                send(chat, 'Админка доступна только администратору.', [[button('‹ Меню','menu')]], message_id)
            elif settings.PUBLIC_URL:
                send(chat, '<b>Админка Northline</b>\n\nСерверы, пользователи, запросы и настройки.',
                     [[{'text':'Открыть админку','web_app':{'url':app_url(admin=True)}}]], message_id)
            else:
                send(chat, 'Для админки внутри Telegram нужен публичный HTTPS-адрес.')
        elif action in ("/start", "/menu", "menu"):
            menu(chat, user, message_id)
        elif action in ("/device", "/telegram"):
            scope_menu(chat, user, "telegram" if action == "/telegram" else "device", message_id)
        elif action == "home":
            scope_menu(chat, user, scope, message_id)
        elif action == "/id":
            send(chat, f"<b>Ваш Telegram ID</b>\n\n<code>{user}</code>", [[button("‹ Режимы", "menu")]])
        elif action in ("/servers", "/status", "/help", "/config", "/revoke"):
            target = {"/servers":"servers:0", "/status":"status", "/help":"help", "/config":"setup", "/revoke":"confirm-revoke"}[action]
            send(chat, "<b>Выберите режим</b>", mode_choices(target) + [[button("‹ Меню", "menu")]], message_id)
        elif action == "servers" or action.startswith("servers:"):
            page = action.partition(":")[2]
            servers(chat, user, int(page) if page.isdigit() else 0, message_id, scope)
        elif action.startswith("select:"):
            select_server(chat, user, action.partition(":")[2], message_id, scope)
        elif action.startswith("issue:"):
            parts = action.split(":")
            if not explicit or len(parts) != 4 or not parts[2].isdigit() or parts[3] not in CODE_STATUSES:
                select_server(chat, user, parts[1], message_id, scope)
            else:
                profile = api(user, "issue", {"node": parts[1], "expected_profile": int(parts[2]),
                              "expected_status": CODE_STATUSES[parts[3]]}, scope=scope)
                profile_message(chat, profile, settings.MODE, message_id, scope)
        elif action == "status":
            state = api(user, "status", scope=scope)
            profile_message(chat, state["profile"], state["mode"], message_id, scope)
        elif action == "confirm-revoke":
            state = api(user, "status", scope=scope)
            profile = state["profile"]
            if profile["status"] not in ("active", "creating", "revoking"):
                profile_message(chat, profile, state["mode"], message_id, scope)
            else:
                public_note=('\nПубличный конфиг не отзывается. Отключите VPN в OpenVPN Connect.' if scope=='device' else '\nОбщий ключ не отзывается. Выключите прокси в Telegram.') if profile.get('access_type')=='public' else ''
                public = profile.get('access_type')=='public'
                send(chat, f'<b>{"Убрать профиль?" if public else "Отключить профиль?"}</b>\n{SCOPES[scope]["name"]} · второй режим сохранится.'+public_note,
                     [[button("Убрать" if public else "Отключить", scoped(scope, f'revoke:{profile["id"]}:{STATUS_CODES[profile["status"]]}')),
                       button("Отмена", scoped(scope, "status"))]], message_id)
        elif action.startswith("revoke:"):
            parts = action.split(":")
            if explicit and len(parts) == 3 and parts[1].isdigit() and parts[2] in CODE_STATUSES:
                profile = api(user, "revoke", {"expected_profile": int(parts[1]),
                              "expected_status": CODE_STATUSES[parts[2]]}, scope=scope)
                profile_message(chat, profile, settings.MODE, message_id, scope)
            else:
                profile_message(chat, api(user, "status", scope=scope)["profile"], settings.MODE, message_id, scope)
        elif action == "revoke":
            profile_message(chat, api(user, "status", scope=scope)["profile"], settings.MODE, message_id, scope)
        elif action in ("setup", "config"):
            connection_message(chat, user, scope, message_id)
        elif action == "export":
            data = api(user, "connection", scope=scope)
            download = data["download"]
            if not download:
                raise RequestFailed("Файл пока недоступен.")
            upload("sendDocument", chat, "document", download["filename"], "text/plain", download["content"].encode())
        elif action == "help" or action.startswith("guide:"):
            help_message(chat, message_id, scope, action.partition(":")[2] or None)
        elif action == "/sticker":
            STICKERS.submit(chat)
        else:
            menu(chat, user, message_id)
    except RequestFailed as error:
        send(chat, "<b>Не удалось выполнить действие</b>\n\n" + escape(str(error)),
             [[button("↻ Проверить профиль", scoped(scope, "status"))], [button("‹ Режимы", "menu")]], message_id)
    finally:
        CURRENT_USER.reset(identity_token)


def configure_bot():
    telegram("setMyCommands", {"commands": [
        {"command": command, "description": description}
        for command, description in (
            ("start", "Главное меню"), ("app", "Открыть приложение"), ("servers", "Выбрать сервер"),
            ("device", "VPN для всего устройства"), ("telegram", "Прокси только для Telegram"),
            ("status", "Мои профили"), ("config", "Настройка подключения"),
            ("revoke", "Отключить профиль"), ("help", "Как подключиться"),
            ("id", "Мой Telegram ID"), ("sticker", "Стикер"), ("admin", "Администрирование"),
        )
    ]})
    telegram("setMyDescription", {"description": "Northline — два режима: VPN для устройства и прокси только для Telegram. Профили, серверы и инструкции для телефона и компьютера."
})
    telegram("setMyShortDescription", {"short_description": "Northline · Всё устройство / Только Telegram"})
    if settings.PUBLIC_URL:
        refresh_app_menu()
        for value in settings.ADMIN_IDS.split(','):
            if value.strip().isdigit():
                refresh_chat_menu(int(value.strip()),admin=True)


def main():
    if not settings.TOKEN or not settings.BOT_KEY:
        raise SystemExit("Set BOT_TOKEN and BOT_API_KEY before starting the bot.")
    url = urlsplit(settings.PUBLIC_URL)
    if settings.PUBLIC_URL and (url.scheme != "https" or not url.hostname):
        raise SystemExit("PUBLIC_URL must be an HTTPS address.")
    while True:
        try:
            bot = telegram("getMe")
            configure_bot()
            print(f'Bot: @{bot["username"]}', flush=True)
            break
        except RequestFailed as error:
            print(f"Bot setup: {error}; retrying in 5 seconds.", flush=True)
            time.sleep(5)
    offset = 0
    while True:
        try:
            updates = telegram("getUpdates", {"timeout": 25, "offset": offset,
                                             "allowed_updates": ["message", "callback_query"]})
            for update in updates:
                try:
                    handle(update)
                except RequestFailed as error:
                    print(f"Update failed: {error}", flush=True)
                offset = update["update_id"] + 1
        except RequestFailed as error:
            print(f"Polling: {error}", flush=True)
            time.sleep(4)


if __name__ == "__main__":
    main()
