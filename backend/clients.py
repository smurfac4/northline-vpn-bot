"""Official client installation links and supported import mechanisms."""


def client_for(protocol, platform):
    if protocol == 'OpenVPN':
        links = {
            'android': 'https://play.google.com/store/apps/details?id=net.openvpn.openvpn',
            'ios': 'https://apps.apple.com/app/openvpn-connect/id590379981',
            'windows': 'https://openvpn.net/client/',
            'macos': 'https://openvpn.net/client/',
            'linux': 'https://openvpn.net/community-resources/how-to/',
        }
        native = platform in ('android', 'ios', 'windows', 'macos')
        return {'name': 'OpenVPN' if platform == 'linux' else 'OpenVPN Connect',
                'install_url': links.get(platform, 'https://openvpn.net/client/'),
                'open_url': 'openvpn://' if native else None,
                'open_via_store': False, 'external_import': platform == 'ios', 'native_import': native}
    links = {
        'android': 'https://play.google.com/store/apps/details?id=com.wireguard.android',
        'ios': 'https://apps.apple.com/app/wireguard/id1441195209',
        'macos': 'https://apps.apple.com/app/wireguard/id1451685025',
        'windows': 'https://download.wireguard.com/windows-client/wireguard-installer.exe',
    }
    # WireGuard Apple clients register .conf documents, not a URL import scheme.
    store = platform in ('ios', 'macos', 'android')
    return {'name': 'WireGuard', 'install_url': links.get(platform, 'https://www.wireguard.com/install/'),
            'open_url': links[platform] if store else None, 'native_import': False,
            'open_via_store': store}
