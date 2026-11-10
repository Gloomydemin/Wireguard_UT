import os
import sys
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

import interface  # noqa: E402
import vpn  # noqa: E402


def _ok(cmd):
    args, err = interface._validate_preup_command(cmd)
    return err is None


@pytest.mark.parametrize("cmd", [
    "ip netns exec x /bin/sh -c id",
    "ip -all netns exec /bin/id",
    "ip -b /tmp/cmds",
    "ip -batch /tmp/cmds",
    "nft -f /tmp/rules",
    "sysctl -w kernel.modprobe=/home/phablet/x",
    "sysctl kernel.core_pattern=x",
    "sysctl -p /tmp/x",
    "wg-quick up /tmp/evil.conf",
    "iptables --modprobe=/tmp/x -L",
])
def test_safe_mode_blocks_escapes(cmd):
    assert not _ok(cmd)


@pytest.mark.parametrize("cmd", [
    "sysctl -w net.ipv4.ip_forward=1",
])
def test_safe_mode_allows_normal(cmd):
    # binary may be missing in CI, that's a different error than "not allowed"
    args, err = interface._validate_preup_command(cmd)
    assert err is None or "not available" in err


def test_hook_split_does_not_split_on_letter_n():
    src = Path(interface.__file__).read_text()
    pattern = re.search(r"re\.split\((r'\[;[^']*\]\+')", src).group(1)
    parts = re.split(eval(pattern), "ip link set wg0 up\nnft list ruleset")
    assert parts == ["ip link set wg0 up", "nft list ruleset"]


def test_delete_temp_file_refuses_outside_qr_dir(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("x")
    res = vpn.Vpn.delete_temp_file(None, str(victim))
    assert res["error"]
    assert victim.exists()


def test_delete_temp_file_inside_qr_dir():
    d = vpn._qr_tmp_dir()
    f = d / "frame_0.png"
    f.write_bytes(b"x")
    assert vpn.Vpn.delete_temp_file(None, str(f))["error"] is None
    assert not f.exists()
