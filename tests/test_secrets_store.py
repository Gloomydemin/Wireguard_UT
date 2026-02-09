import secrets_store


def test_store_roundtrip():
    ok, err = secrets_store.set_private_key("profile1", "privkeydata", "password123")
    assert ok, err
    got = secrets_store.get_private_key("profile1", "password123")
    assert got == "privkeydata"
    bad = secrets_store.get_private_key("profile1", "wrong")
    assert bad is None


def test_delete_secret():
    ok, err = secrets_store.set_private_key("profile2", "k", "pw")
    assert ok, err
    ok, err = secrets_store.delete_private_key("profile2")
    assert ok, err
    assert secrets_store.get_private_key("profile2", "pw") is None
