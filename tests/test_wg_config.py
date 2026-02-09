from wg_config import build_config


def test_build_config_includes_private_key():
    profile = {
        "profile_name": "test",
        "peers": [
            {
                "name": "peer1",
                "key": "pubkey",
                "allowed_prefixes": "0.0.0.0/0",
                "endpoint": "vpn.example.com:51820",
                "presharedKey": "",
            }
        ],
    }
    text = build_config(profile, "privkey")
    assert "PrivateKey = privkey" in text
    assert "PublicKey = pubkey" in text
