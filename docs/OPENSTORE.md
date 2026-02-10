# OpenStore Listing Draft

## Title
Wireguard

## Short description (<= 80 chars)
WireGuard client for Ubuntu Touch with QR import and userspace fallback.

## Long description (EN)
WireGuard VPN client for Ubuntu Touch.

Features:
- Userspace fallback (wireguard-go) if the kernel module is unavailable.
- Import via QR code, .conf, or .zip.
- Extra routes and DNS per profile.
- PreUp hooks (commands executed before interface up).
- Encrypted private key storage (password-based).
- Export all tunnels to a zip file.

Notes:
- The app uses your sudo password to configure networking.
- No tracking or analytics are included.

## Long description (RU)
Клиент WireGuard для Ubuntu Touch.

Возможности:
- Userspace‑fallback (wireguard‑go), если нет модуля ядра.
- Импорт через QR‑код, .conf или .zip.
- Дополнительные маршруты и DNS для профиля.
- PreUp‑хуки (команды до поднятия интерфейса).
- Шифрованное хранение приватных ключей (парольное).
- Экспорт всех туннелей в zip.

Примечания:
- Для настройки сети используется ваш sudo‑пароль.
- В приложении нет аналитики и трекинга.

## Keywords
wireguard, vpn, ubuntu touch, wg, tunnel

## Screenshots
- screenshots/screenshot20260210_132652130.png
- screenshots/screenshot20260210_132705511.png
- screenshots/screenshot20260210_132712196.png

## Release checklist
1. Update version in `manifest.json.in`.
2. Update `docs/CHANGES*.md`.
3. `clickable build --arch arm64`
4. `clickable review --arch arm64`
5. Upload .click + screenshots + description to OpenStore.
