import ipaddress
import re

"""Connection scopes and platform-specific setup instructions."""
SCOPES = {
    "device": {"name": "Всё устройство", "protocol": "WireGuard", "protocols": ["WireGuard", "OpenVPN"], "description": "VPN для приложений и браузера"},
    "telegram": {"name": "Только Telegram", "protocol": "MTProto", "description": "Прокси для приложения Telegram"},
}
PLATFORMS = {
    "android": "Android", "ios": "iPhone / iPad", "windows": "Windows",
    "macos": "macOS", "linux": "Linux", "other": "Другое устройство",
}
TELEGRAM_PRIORITY = ('RU', 'LT', 'US')


def country_metadata(source):
    if 'country' not in source and 'country_name' not in source:return {}
    code=source.get('country');name=source.get('country_name')
    if not isinstance(code,str) or not re.fullmatch('[A-Z]{2}',code) or not isinstance(name,str) or not name.strip() or len(name)>80 or any(ord(c)<32 for c in name):
        raise ValueError('Проверьте страну сервера.')
    return {'country':code,'country_name':name.strip()}


def country_flag(code):
    return ''.join(chr(0x1F1E6+ord(c)-ord('A')) for c in code)


def location_details(name,country='',country_name=''):
    if country and country_name:return {'flag':country_flag(country),'location':country_name}
    match=re.match(r'^([\U0001F1E6-\U0001F1FF]{2})\s*',name)
    return {'flag':match[1] if match else '', 'location':name[match.end():].strip() if match else name}


def node_display_name(node):
    if node.country and node.country_name:return country_flag(node.country)+' '+node.country_name
    return node.name


def instructions(scope, platform):
    """Describe connection setup for the selected platform."""
    if scope == "device":
        first = {
            "android": "Установите приложение WireGuard для Android.",
            "ios": "Установите WireGuard из App Store на iPhone или iPad.",
            "windows": "Установите WireGuard для Windows.",
            "macos": "Установите WireGuard для macOS.",
            "linux": "Установите WireGuard средствами вашего дистрибутива Linux.",
            "other": "Проверьте, поддерживает ли устройство WireGuard. Для роутеров нужна совместимая прошивка.",
        }[platform]
        return [first, "Скачайте конфигурацию .conf после подключения реального сервера.",
                "Импортируйте файл в WireGuard и включите туннель.",
                "При смене сервера скачайте и импортируйте новую конфигурацию."]
    settings_path = {
        "android": "Настройки → Данные и память → Настройки прокси",
        "ios": "Настройки → Данные и память → Прокси",
        "windows": "Настройки → Продвинутые настройки → Тип соединения",
        "linux": "Настройки → Продвинутые настройки → Тип соединения",
        "macos": "В Telegram для macOS: Настройки → Данные и память → Прокси. В Telegram Desktop: Продвинутые настройки → Тип соединения.",
        "other": "Проверьте, поддерживает ли ваш клиент Telegram прокси MTProto.",
    }[platform]
    return ["Используйте приложение Telegram для телефона или компьютера.",
            "Нажмите «Подключить в Telegram» в профиле и подтвердите использование прокси.",
            "Ручная настройка: " + settings_path + ".",
            "Прокси действует только в Telegram. Веб-сайты, Mini Apps и другие приложения используют своё соединение. Для Telegram Web выбирайте режим «Всё устройство»."]


def valid_host(value):
    if not isinstance(value,str) or not value or len(value)>253:
        return False
    host=value[:-1] if value.endswith('.') else value
    try:
        return isinstance(ipaddress.ip_address(host),ipaddress.IPv4Address)
    except ValueError:
        if re.fullmatch(r'[0-9.]+',host):return False
        return all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',label)
                   for label in host.split('.'))
