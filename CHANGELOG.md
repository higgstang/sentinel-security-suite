# Sentinel Security Suite — Changelog

---

## v1.0.0-beta (2026-07-09)
Initial private beta release.

### Features
- **Update alerts in bell dropdown** — when a new version is available or downloaded, it appears as a notification in the top-right bell with a toast message; installs automatically on next quit
- Real-time file system protection with YARA rules
- ClamAV virus scanning — fully bundled, no install required
- Network device monitoring and subnet scanning
- Threat quarantine and alert history
- Beta key activation system with admin panel
- Auto-update support — future fixes install silently in background
- Unified download page with OS auto-detection

### Fixes
- **Beta key activation not unlocking features** — beta key now properly gates all features; license status endpoint synced with beta activation; fixed `license.json` path nesting bug in packaged app
- **Scan error / failed to fetch (macOS)** — all writable directories (yara_rules, quarantine, CISA cache) now routed to `~/Library/Application Support/sentinel-security-suite` instead of read-only `.app` bundle
- **Engine crash on macOS** — data directory now written to `~/Library/Application Support/sentinel-security-suite` instead of read-only `.app` bundle (fixes "scan error: failed to fetch")
- **Window not loading after install** — fixed engine working directory for packaged app
- **App shows as damaged on macOS** — PKG installer now includes postinstall script to re-sign app ad-hoc
- **Stale alerts on launch** — previous session alerts are now archived to `alert_history.json` instead of shown on startup
- **Windows compatibility** — fixed `ping` flags, Python interpreter naming, and executable paths
- **ClamAV bundled** — Windows and macOS installers include ClamAV binaries and signature databases

---

_Future entries will be added here as updates and fixes are released._
