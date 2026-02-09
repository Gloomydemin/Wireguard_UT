import os
import tempfile


if "WIREGUARD_APP_HOME" not in os.environ:
    os.environ["WIREGUARD_APP_HOME"] = tempfile.mkdtemp(prefix="wg_home_")
