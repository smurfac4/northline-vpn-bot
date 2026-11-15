"use strict";

// Safari handles the user-initiated native link outside Telegram's Mini App WebView.
const launch = document.getElementById('openvpn-launch');
const download = document.getElementById('openvpn-download');
const target = new URL(download.getAttribute('href'), window.location.href);
if (target.origin === window.location.origin && target.pathname.startsWith('/connect-config/')) {
  launch.href = 'openvpn://import-profile/' + target.href;
  launch.removeAttribute('aria-disabled');
  launch.onclick = () => {
    document.getElementById('import-message').textContent = 'Подтвердите открытие OpenVPN Connect. Если окно не появилось, раскройте «Приложение не открывается?» ниже.';
  };
}
