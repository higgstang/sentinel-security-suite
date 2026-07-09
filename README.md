# Sentinel Security Suite

A standalone desktop network security application built with Electron and Python.

## What it does

- Discovers devices on your local network
- Scans open ports
- Saves a baseline of known devices
- Alerts you when new or unknown devices appear
- Shows system health and active processes

## Built-in executables

- **Electron app** — the professional desktop UI
- **Python engine** — bundled as `sentinel-engine` (no Python installation required)

## Run the app

After building, double-click:

```
release/mac-arm64/Sentinel Security Suite.app
```

Or install the DMG:

```
release/Sentinel Security Suite-1.0.0-arm64.dmg
```

## Development

```bash
cd security-suite
npm install
npm start
```

## Build from source

1. Build the Python engine:

```bash
cd python-engine
pyinstaller --onefile --name sentinel-engine --hidden-import flask --hidden-import flask_cors --hidden-import psutil --hidden-import security --add-data "security.py:." main.py
cd ..
```

2. Build the Electron app:

```bash
npm run build-mac     # macOS
npm run build-win     # Windows
npm run build-linux   # Linux
```

## Output

- `release/mac-arm64/Sentinel Security Suite.app`
- `release/Sentinel Security Suite-1.0.0-arm64.dmg`
