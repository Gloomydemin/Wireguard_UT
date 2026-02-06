from pathlib import Path

APP_ID = 'wireguard.sysadmin'
CONFIG_DIR = Path(f'/home/phablet/.local/share/{APP_ID}')
OLD_CONFIG_DIR = Path('/home/phablet/.local/share/wireguard.davidv.dev')
if not CONFIG_DIR.exists() and OLD_CONFIG_DIR.exists():
    CONFIG_DIR = OLD_CONFIG_DIR
PROFILES_DIR = CONFIG_DIR / 'profiles'
