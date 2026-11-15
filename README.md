<p align="center"><img src="docs/images/overview.svg" alt="Northline architecture: route selection, profiles and network checks" width="100%"></p>

# Northline · VPN & Telegram Mini App

Telegram-бот и Mini App с двумя независимыми подключениями:

- **Всё устройство** — OpenVPN из автоматически проверяемого каталога или собственный WireGuard.
- **Только Telegram** — MTProto-прокси с подключением через Telegram.

Доступ бессрочный. Публичные серверы проверяются при запуске и каждый час: настоящий VPN-туннель с HTTPS либо обмен MTProto с Telegram. Неработающие серверы заменяются проверенными; если замены нет, они исчезают из выбора. Россия обязательна для поиска в обоих каталогах.

## Размещение на сервере

Нужны Linux VPS, Python 3.9+, Docker Engine с доступом к TUN/NET_ADMIN и постоянный HTTPS-домен. Backend и бот используют стандартную библиотеку Python; сетевые проверки запускаются в отдельных Docker-контейнерах.

1. Распакуйте `dist/northline-hosting.tar.gz` в домашний каталог — получится папка `northline`.
2. Скопируйте `.env.example` в `.env`, укажите токен, домен и Telegram ID. Установите права `chmod 600 .env`.
3. Соберите образы проверок:

```bash
docker build -t northline-mtproxy:local -f deploy/mtproxy/Dockerfile deploy
docker build -t northline-openvpn-probe:local deploy/device-probe
```

4. Запустите `python3 run.py`. Он поднимает backend и бота и восстанавливает их при сбое.
5. Настройте Caddy и systemd по [инструкции хостинга](docs/HOSTING.md). Backend слушает только `127.0.0.1:8000`.

Остановите прежний процесс с тем же токеном перед запуском сервера. Для обновления установленного сервиса сохраняйте `.env`, базу и реестры; не заменяйте их файлами новой установки.

## Состав проекта

- `backend/` — API, Mini App, админка, профили и обновление каталогов.
- `bot/` — сообщения и кнопки Telegram.
- `deploy/` — образы проверок, настройка собственных серверов и служба systemd.
- `tests/` — изолированные проверки; они не являются режимом работы приложения.
- `data/`, текущие реестры и `.env` — закрытые данные работающего экземпляра. Они не входят в архив для новой установки.

Для повторной сборки чистого архива выполните `python3 deploy/package.py`.

[Хостинг и ежечасное обновление](docs/HOSTING.md) · [Администрирование](docs/ADMIN.md) · [VPN для устройства](docs/DEVICE_VPN.md) · [Telegram-прокси](docs/FREE_TELEGRAM_PROXIES.md) · [Бессрочный доступ](docs/UNLIMITED_ACCESS.md)


## Публичный исходный код

Здесь опубликованы backend, Telegram-бот, Mini App, инструменты размещения и тесты. Это отдельная копия исходного кода без истории рабочего репозитория. `.env`, ключи, адреса собственных серверов, базы, профили пользователей и рабочие реестры не публикуются.

### Запуск из исходников

```bash
git clone https://github.com/smurfac4/northline-vpn-showcase.git
cd northline-vpn-showcase
cp .env.example .env
chmod 600 .env
```

Заполните `.env` своими значениями. Далее соберите Docker-образы по инструкции выше и выполните `python3 run.py`. Для сборки архива: `python3 deploy/package.py`. Настройки по умолчанию не содержат рабочих учётных данных.

### Изолированные проверки

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```
