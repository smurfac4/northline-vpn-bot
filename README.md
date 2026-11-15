<p align="center"><img src="docs/images/overview.svg" alt="Northline: Telegram bot, VPN profiles and network health checks" width="100%"></p>

# Northline · VPN & Telegram Mini App

A public overview of a private Python project combining a Telegram bot, a Mini App and a backend for VPN and Telegram proxy access.

**This repository is a portfolio overview.** The implementation, deployment configuration and operational data are kept in a separate private repository. The illustration is an architecture overview, not a screenshot of a live account.

## Two connection modes

| Mode | Protocols | Experience |
| --- | --- | --- |
| Device VPN | OpenVPN / WireGuard | Choose a location and obtain a device profile |
| Telegram proxy | MTProto | Connect using Telegram's proxy flow |

## Engineering focus

- Python backend and Telegram bot with a web-based Mini App.
- Separate flows for device VPN and Telegram-only connectivity.
- Scheduled checks of server availability and catalog refreshes.
- Isolated Docker containers for network probes.
- Administration, profile management and deployment tooling.

## Architecture

```text
Telegram bot / Mini App
          ↓
     Python backend
       ↙        ↘
VPN profiles   Telegram proxy catalog
       ↘        ↙
   isolated network probes
```

## Privacy boundary

This public overview contains no production addresses, bot tokens, private keys, user records, connection profiles or runtime database. Operational documentation and source history remain private.

[← Back to profile](https://github.com/smurfac4)
