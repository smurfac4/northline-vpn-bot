import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"
if ENV_FILE.exists():
    for line in ENV_FILE.read_text().splitlines():
        key, separator, value = line.strip().partition("=")
        if separator and key.isidentifier():
            os.environ.setdefault(key, value.strip())

TOKEN = os.getenv("BOT_TOKEN", "")
BOT_KEY = os.getenv("BOT_API_KEY", "")
PORT = int(os.getenv("PORT", "").strip() or "8000")
if not 1 <= PORT <= 65535:
    raise ValueError("PORT must be between 1 and 65535.")
MODE = "live"
PUBLIC_URL = os.getenv("PUBLIC_URL", "").strip().rstrip("/")
ALLOW = os.getenv("ALLOWED_TELEGRAM_IDS", "").strip()


def env_path(name, default):
    value = os.getenv(name, "").strip()
    path = Path(value).expanduser() if value else Path(default)
    return path if path.is_absolute() else ROOT / path


DB = env_path("DB_PATH", ROOT / "data" / "vpn-live.sqlite3")
NODES = env_path("NODES_PATH", ROOT / "nodes.json")
PROXY_NODES = env_path("PROXY_NODES_PATH", ROOT / "proxy-nodes.json")
# Compatibility field for older API clients. All new VPN profiles are permanent.
TRIAL_HOURS = 0

ADMIN_IDS = os.getenv("ADMIN_TELEGRAM_IDS", "").strip()
RESTART_FILE = ROOT / "data" / "restart.request"
WG_BIN = os.getenv('WG_BIN','').strip() or 'wg'
SSH_CONFIG = str(env_path('SSH_CONFIG', '')) if os.getenv('SSH_CONFIG','').strip() else ''
PERSONAL_TEST = os.getenv('PERSONAL_TEST','0') == '1'
MTPROXY_NODE_ID = os.getenv('MTPROXY_NODE_ID','')
MTPROXY_STATE_DIR = env_path('MTPROXY_STATE_DIR', ROOT/'data/mtproxy')
PROXY_AUTO_UPDATE = os.getenv('PROXY_AUTO_UPDATE', '1') == '1'
DEVICE_AUTO_UPDATE = os.getenv('DEVICE_AUTO_UPDATE', '1') == '1'
DEVICE_NODES = env_path('DEVICE_NODES_PATH', ROOT/'device-vpn-nodes.json')


def personal_test_owner():
    allowed=ALLOW.strip()
    admins={value.strip() for value in ADMIN_IDS.split(',') if value.strip()}
    if PERSONAL_TEST and allowed.isascii() and allowed.isdigit() and 0<int(allowed)<2**63 and allowed in admins:
        return int(allowed)
    return None
