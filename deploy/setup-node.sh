#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ ${EUID} -ne 0 || $# -lt 1 || $# -gt 3 ]]; then
  echo 'Usage: sudo bash deploy/setup-node.sh /path/to/controller.pub [10.77.0.0/24] [51820]' >&2
  exit 1
fi
key_file=$(realpath -- "$1")
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
subnet=${2:-10.77.0.0/24}
port=${3:-51820}
read -r key_type key_data _ < "$key_file"
[[ $key_type == ssh-ed25519 && $key_data =~ ^[A-Za-z0-9+/=]+$ ]]
[[ $port =~ ^[0-9]{1,5}$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 ))
port=$((10#$port))
gateway=$(python3 - "$subnet" <<'PY'
import ipaddress
import sys
network = ipaddress.IPv4Network(sys.argv[1])
if network.prefixlen != 24 or not any(network.subnet_of(ipaddress.IPv4Network(prefix)) for prefix in
        ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
    raise SystemExit("Use a private /24 IPv4 subnet.")
print(network.network_address + 1)
PY
)
if [[ -e /etc/wireguard/wg0.conf ]] && ! grep -q '^# Northline VPN managed interface$' /etc/wireguard/wg0.conf; then
  echo 'wg0 is already configured. Use a fresh VPS or preserve that interface.' >&2
  exit 1
fi
if [[ -f /var/lib/northline-wg/subnet && $(cat /var/lib/northline-wg/subnet) != "$subnet" ]]; then
  echo 'This node already uses a different subnet.' >&2
  exit 1
fi
nic=$(ip -4 route get 1.1.1.1 | awk '{for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}')
[[ $nic =~ ^[A-Za-z0-9_.:-]+$ ]]

apt-get update
apt-get install -y wireguard-tools openssh-server iptables sudo
install -d -m 0700 /etc/wireguard /var/lib/northline-wg
printf '%s\n' "$subnet" > /var/lib/northline-wg/subnet
printf '%s\n' 'net.ipv4.ip_forward=1' > /etc/sysctl.d/90-northline-vpn.conf
sysctl -p /etc/sysctl.d/90-northline-vpn.conf
if [[ ! -s /etc/wireguard/northline.key ]]; then
  wg genkey > /etc/wireguard/northline.key
fi
cat > /etc/wireguard/wg0.conf <<EOF
# Northline VPN managed interface
[Interface]
Address = $gateway/24
ListenPort = $port
PrivateKey = $(cat /etc/wireguard/northline.key)
PostUp = iptables -I INPUT -i %i -j DROP; iptables -I FORWARD -i $nic -o %i -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -I FORWARD -i %i -o $nic -s $subnet -j ACCEPT; iptables -I FORWARD -i %i -o $nic -d 10.0.0.0/8 -j DROP; iptables -I FORWARD -i %i -o $nic -d 172.16.0.0/12 -j DROP; iptables -I FORWARD -i %i -o $nic -d 192.168.0.0/16 -j DROP; iptables -I FORWARD -i %i -o $nic -d 169.254.0.0/16 -j DROP; iptables -I FORWARD -i %i -o %i -j DROP; iptables -t nat -A POSTROUTING -s $subnet -o $nic -j MASQUERADE
PostDown = iptables -D INPUT -i %i -j DROP; iptables -D FORWARD -i $nic -o %i -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -D FORWARD -i %i -o $nic -s $subnet -j ACCEPT; iptables -D FORWARD -i %i -o $nic -d 10.0.0.0/8 -j DROP; iptables -D FORWARD -i %i -o $nic -d 172.16.0.0/12 -j DROP; iptables -D FORWARD -i %i -o $nic -d 192.168.0.0/16 -j DROP; iptables -D FORWARD -i %i -o $nic -d 169.254.0.0/16 -j DROP; iptables -D FORWARD -i %i -o %i -j DROP; iptables -t nat -D POSTROUTING -s $subnet -o $nic -j MASQUERADE
EOF

install -m 0755 node_control.py /usr/local/sbin/northline-wg-control
if ! id northline-wg >/dev/null 2>&1; then
  useradd --create-home --shell /bin/sh northline-wg
fi
node_home=$(getent passwd northline-wg | cut -d: -f6)
node_group=$(id -gn northline-wg)
install -d -m 0700 -o northline-wg -g "$node_group" "$node_home/.ssh"
printf 'restrict,command="/usr/local/sbin/northline-wg-ssh" %s %s\n' "$key_type" "$key_data" > "$node_home/.ssh/authorized_keys"
chown "northline-wg:$node_group" "$node_home/.ssh/authorized_keys"
chmod 0600 "$node_home/.ssh/authorized_keys"
cat > /usr/local/sbin/northline-wg-ssh <<'EOF'
#!/bin/sh
printf '%s\n' "$SSH_ORIGINAL_COMMAND" | /usr/bin/sudo -n /usr/local/sbin/northline-wg-control
EOF
chmod 0755 /usr/local/sbin/northline-wg-ssh
printf '%s\n' 'northline-wg ALL=(root) NOPASSWD: /usr/local/sbin/northline-wg-control ""' > /etc/sudoers.d/northline-wg
chmod 0440 /etc/sudoers.d/northline-wg
visudo -cf /etc/sudoers.d/northline-wg
cat > /etc/systemd/system/northline-wg-sync.service <<'EOF'
[Unit]
Description=Restore active Northline peers and remove expired peers
After=wg-quick@wg0.service
Requires=wg-quick@wg0.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/northline-wg-control sync
EOF
cat > /etc/systemd/system/northline-wg-sync.timer <<'EOF'
[Unit]
Description=Reconcile Northline WireGuard peers

[Timer]
OnBootSec=10s
OnUnitActiveSec=20s
AccuracySec=2s
Unit=northline-wg-sync.service

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now ssh.service wg-quick@wg0.service
systemctl restart wg-quick@wg0.service
systemctl enable --now northline-wg-sync.timer
systemctl start northline-wg-sync.service
echo "WireGuard public key: $(wg show wg0 public-key)"
echo "WireGuard UDP port: $port"
echo "SSH host fingerprint: $(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)"
