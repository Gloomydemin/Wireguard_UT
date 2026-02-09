import struct
import socket
import subprocess
import time
import os
import sys
import logging

import interface
import vpn

from pathlib import Path

from vendor_paths import resolve_vendor_binary

WG_PATH = resolve_vendor_binary("wireguard")
APP_ID = 'wireguard.sysadmin'
APP_HOME = Path(os.environ.get("WIREGUARD_APP_HOME", "/home/phablet"))
LOG_DIR = APP_HOME / ".cache" / APP_ID
LOG_DIR.mkdir(parents=True, exist_ok=True)
try:
    os.chmod(LOG_DIR, 0o700)
except Exception:
    pass
log = None

def _parse_default_gw(cmd):
    try:
        output = subprocess.check_output(cmd).decode(errors='ignore').splitlines()
    except Exception:
        return None
    for line in output:
        parts = line.split()
        if 'via' in parts:
            try:
                return parts[parts.index('via') + 1]
            except Exception:
                return None
    return None


def _get_default_gw_ipv4():
    gw = _parse_default_gw(['ip', '-4', 'route', 'show', 'default'])
    if gw:
        return gw
    try:
        metric = 999999999
        ip = None
        for line in open('/proc/net/route').readlines():
            line = line.split()
            if line[1] != '00000000' or not int(line[3], 16) & 2:
                # If not default route or not RTF_GATEWAY, skip it
                continue

            _ip = socket.inet_ntoa(struct.pack("<L", int(line[2], 16)))
            _metric = int(line[6])
            if _metric > metric:
                continue
            metric = _metric
            ip = _ip
        return ip
    except Exception:
        return None


def _get_default_gw_ipv6():
    return _parse_default_gw(['ip', '-6', 'route', 'show', 'default'])


def get_preferred_def_route():
    return (_get_default_gw_ipv4(), _get_default_gw_ipv6())


def keep_tunnel(profile_name, sudo_pwd):

    _vpn = vpn.Vpn()
    _vpn.set_pwd(sudo_pwd)

    PROFILE_DIR = vpn.PROFILES_DIR / profile_name
    CONFIG_FILE = PROFILE_DIR / 'config.ini'

    route = get_preferred_def_route()
    profile = _vpn.get_profile(profile_name)
    interface_name = profile['interface_name']
    interface_file = Path('/sys/class/net/') / interface_name
    if not bring_up_interface(interface_name, sudo_pwd):
        log.info("Interface %s could not be created. Exiting", interface_name)
        return

    log.info('Setting up tunnel')
    _vpn.interface.config_interface(profile, CONFIG_FILE)
    log.info('Tunnel is up')

    while interface_file.exists():
        new_route = get_preferred_def_route()
        if route == new_route:
            log.debug('Routes did not change, sleeping')
            time.sleep(2)
            continue
        log.info('New route via %s, reconfiguring interface', new_route)
        route = new_route
        _vpn.interface.config_interface(profile, CONFIG_FILE)
    log.info("Interface %s no longer exists. Exiting", interface_name)

def bring_up_interface(interface_name, sudo_pwd):
    log.info('Bringing up %s', interface_name)
    p = subprocess.Popen(['/usr/bin/sudo', '-S', '-E',
                          str(WG_PATH),
                          interface_name],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         stdin=subprocess.PIPE,
                         env={'WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD': '1',
                              'WG_SUDO': '1',
                              },
                         start_new_session=True,
                      )
    stdout, stderr = p.communicate(input=((sudo_pwd or "") + "\n").encode())

    if p.returncode != 0:
        log.error('Failed to execute wireguard')
        log.error('stdout: %s', stdout)
        log.error('stderr: %s', stderr)
        return False
    return True

def daemonize():
    """
    do the UNIX double-fork magic, see Stevens' "Advanced
    Programming in the UNIX Environment" for details (ISBN 0201563177)
    http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
    """
    try:
        pid = os.fork()
        if pid > 0:
            # exit first parent
            sys.exit(0)
    except OSError as e:
        sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)

    # decouple from parent environment
    os.chdir('/')
    os.setsid()
    os.umask(0)

    # do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # exit from second parent
            sys.exit(0)
    except OSError as e:
        sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)

    # redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()


def _read_pwd_from_stdin():
    try:
        data = sys.stdin.readline()
    except Exception:
        return ""
    return (data or "").rstrip("\n")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write("Missing profile name\n")
        sys.exit(2)
    profile_name = sys.argv[1]
    if len(sys.argv) >= 3:
        sudo_pwd = sys.argv[2]
    else:
        sudo_pwd = _read_pwd_from_stdin()
    logging.basicConfig(filename=str(LOG_DIR / 'daemon-{}.log'.format(profile_name)),
                        level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] %(name)s %(message)s')
    log = logging.getLogger()
    log.info('Started daemon for profile: %s', profile_name)
    log.info('Daemonizing')
    daemonize()
    log.info('Successfully daemonized')
    try:
        keep_tunnel(profile_name, sudo_pwd)
    except Exception as e:
        log.exception(e)
    log.info('Exiting')
