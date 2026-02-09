import os
from pathlib import Path

APP_ID = 'wireguard.sysadmin'
APP_HOME = Path(os.environ.get("WIREGUARD_APP_HOME", "/home/phablet"))
CONFIG_DIR = APP_HOME / ".local" / "share" / APP_ID
PROFILES_DIR = CONFIG_DIR / 'profiles'
