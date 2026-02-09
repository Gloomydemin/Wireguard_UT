def build_config(profile, private_key):
    profile_name = profile.get("profile_name") or ""
    lines = [
        "[Interface]",
        f"#Profile = {profile_name}",
        f"PrivateKey = {private_key or ''}",
        "",
    ]

    for peer in profile.get("peers", []):
        lines.append("[Peer]")
        name = (peer.get("name") or "").strip()
        if name:
            lines.append(f"#Name = {name}")
        lines.append(f"PublicKey = {(peer.get('key') or '').strip()}")
        lines.append(f"AllowedIPs = {(peer.get('allowed_prefixes') or '').strip()}")
        lines.append(f"Endpoint = {(peer.get('endpoint') or '').strip()}")
        preshared = (peer.get("presharedKey") or "").strip()
        if preshared:
            lines.append(f"PresharedKey = {preshared}")
        lines.append("PersistentKeepalive = 5")
        lines.append("")

    return "\n".join(lines).strip() + "\n"
