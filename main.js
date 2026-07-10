const { app, BrowserWindow, ipcMain, dialog, Tray, Menu, nativeImage } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const net = require('net');

let mainWindow;
let pythonProcess;
let enginePort = 18081;
let tray = null;
let isQuitting = false;
let engineRestartCount = 0;

function createTray() {
    const iconPath = path.join(__dirname, 'assets', 'icon.png');
    const icon = fs.existsSync(iconPath)
        ? nativeImage.createFromPath(iconPath).resize({ width: 16, height: 16 })
        : nativeImage.createEmpty();

    tray = new Tray(icon);
    tray.setToolTip('Sentinel Security Suite — Protected');

    const buildMenu = () => Menu.buildFromTemplate([
        { label: 'Sentinel Security Suite', enabled: false },
        { label: 'Protection: Active ✓', enabled: false },
        { type: 'separator' },
        { label: 'Open Dashboard', click: () => showWindow() },
        { type: 'separator' },
        {
            label: 'Launch at Login',
            type: 'checkbox',
            checked: app.getLoginItemSettings().openAtLogin,
            click: (item) => {
                app.setLoginItemSettings({ openAtLogin: item.checked, openAsHidden: true });
            },
        },
        { type: 'separator' },
        { label: 'Quit Sentinel', click: () => { isQuitting = true; app.quit(); } },
    ]);

    tray.setContextMenu(buildMenu());
    tray.on('click', () => showWindow());         // Windows: single click
    tray.on('double-click', () => showWindow());  // Mac: double click
}

function showWindow() {
    if (!mainWindow) {
        createWindow();
    } else if (mainWindow.isMinimized()) {
        mainWindow.restore();
    } else {
        mainWindow.show();
        mainWindow.focus();
    }
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1100,
        minHeight: 700,
        titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: path.join(__dirname, 'preload.js'),
        },
        icon: path.join(__dirname, 'assets', 'icon.png'),
        show: false,
    });

    mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
    });

    // Minimize to tray instead of closing
    mainWindow.on('close', (e) => {
        if (!isQuitting) {
            e.preventDefault();
            mainWindow.hide();
            // Show tray balloon on Windows (first time only)
            if (process.platform === 'win32' && tray) {
                tray.displayBalloon({
                    iconType: 'info',
                    title: 'Sentinel is still running',
                    content: 'Protection is active. Click the tray icon to reopen.',
                });
            }
        }
    });

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

function findFreePort(startPort) {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.listen(startPort, '127.0.0.1', () => {
            const port = server.address().port;
            server.close(() => resolve(port));
        });
        server.on('error', () => {
            findFreePort(startPort + 1).then(resolve).catch(reject);
        });
    });
}

function getEngineExecutablePath() {
    const isWin = process.platform === 'win32';
    const binName = isWin ? 'sentinel-engine.exe' : 'sentinel-engine';

    // In packaged app, the engine is in resources/python-engine/
    const packagedPath = path.join(process.resourcesPath, 'python-engine', binName);
    if (fs.existsSync(packagedPath)) {
        return { exe: packagedPath, args: [], isPy: false };
    }
    // In development, prefer running main.py directly so edits take effect immediately
    const scriptPath = path.join(__dirname, 'python-engine', 'main.py');
    if (fs.existsSync(scriptPath)) {
        const pyExe = isWin ? 'python' : 'python3';
        return { exe: pyExe, args: [scriptPath], isPy: true };
    }
    // Last resort: stale binary
    return { exe: path.join(__dirname, 'python-engine', 'dist', binName), args: [], isPy: false };
}

async function startPythonEngine(isRestart = false) {
    if (!isRestart) {
        enginePort = await findFreePort(enginePort);
    }
    const { exe, args } = getEngineExecutablePath();

    if (!fs.existsSync(exe) && !['python3', 'python'].includes(exe)) {
        console.warn(`Engine not found at ${exe}. Skipping.`);
        return enginePort;
    }

    const engineEnv = { ...process.env };
    if (process.platform !== 'win32' && !engineEnv.PATH) {
        engineEnv.PATH = '/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin';
    }
    const engineCwd = app.isPackaged
        ? path.join(process.resourcesPath, 'python-engine')
        : path.join(__dirname, 'python-engine');

    pythonProcess = spawn(exe, [...args, '--port', String(enginePort)], {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: engineEnv,
        cwd: fs.existsSync(engineCwd) ? engineCwd : path.dirname(exe),
    });

    pythonProcess.stdout.on('data', (data) => {
        console.log(`[Engine] ${data.toString().trim()}`);
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error(`[Engine Error] ${data.toString().trim()}`);
    });

    pythonProcess.on('close', (code) => {
        console.log(`Python engine exited with code ${code}`);
        if (!isQuitting && engineRestartCount < 10) {
            engineRestartCount++;
            const delay = Math.min(5000 * engineRestartCount, 30000);
            console.log(`Restarting engine in ${delay/1000}s (attempt ${engineRestartCount})...`);
            if (tray) tray.setToolTip('Sentinel — Restarting engine...');
            setTimeout(() => {
                startPythonEngine(true).then(() => {
                    if (tray) tray.setToolTip('Sentinel Security Suite — Protected');
                    engineRestartCount = 0;
                });
            }, delay);
        }
    });

    // Wait for engine to be ready
    return new Promise((resolve) => {
        const checkReady = setInterval(async () => {
            try {
                const response = await fetch(`http://127.0.0.1:${enginePort}/api/status`);
                if (response.ok) {
                    clearInterval(checkReady);
                    resolve(enginePort);
                }
            } catch (e) {
                // not ready yet
            }
        }, 500);
        setTimeout(() => {
            clearInterval(checkReady);
            resolve(enginePort);
        }, 15000);
    });
}

ipcMain.handle('install-update-now', () => {
    autoUpdater.quitAndInstall(false, true);
});

ipcMain.handle('get-app-version', () => {
    return app.getVersion();
});

ipcMain.handle('get-engine-url', () => {
    return `http://127.0.0.1:${enginePort}`;
});

ipcMain.handle('pick-file', async () => {
    if (!mainWindow) return null;
    const result = await dialog.showOpenDialog(mainWindow, {
        title: 'Select a file to scan',
        properties: ['openFile'],
    });
    return result.canceled ? null : result.filePaths[0];
});

ipcMain.handle('pick-directory', async () => {
    if (!mainWindow) return null;
    const result = await dialog.showOpenDialog(mainWindow, {
        title: 'Select a directory to scan',
        properties: ['openDirectory'],
    });
    return result.canceled ? null : result.filePaths[0];
});

// Keep app running in background even with no windows open
app.on('window-all-closed', (e) => {
    // Do NOT quit — we stay alive in the tray
});

app.on('before-quit', () => {
    isQuitting = true;
});

app.on('will-quit', () => {
    if (pythonProcess) pythonProcess.kill();
});

app.whenReady().then(async () => {
    // Prevent multiple instances
    const gotLock = app.requestSingleInstanceLock();
    if (!gotLock) {
        app.quit();
        return;
    }
    app.on('second-instance', () => showWindow());

    await startPythonEngine();
    createTray();
    createWindow();

    // Mac: clicking dock icon reopens window
    app.on('activate', () => showWindow());

    // Enable launch at login by default for beta testers
    if (!app.getLoginItemSettings().openAtLogin) {
        app.setLoginItemSettings({ openAtLogin: true, openAsHidden: true });
    }

    // Auto-update: check silently on launch, install on next restart
    if (app.isPackaged) {
        autoUpdater.autoDownload = true;
        autoUpdater.autoInstallOnAppQuit = true;

        autoUpdater.on('update-available', (info) => {
            if (mainWindow) mainWindow.webContents.send('update-available', info);
        });
        autoUpdater.on('download-progress', (progress) => {
            if (mainWindow) mainWindow.webContents.send('update-progress', progress);
        });
        autoUpdater.on('update-downloaded', (info) => {
            if (mainWindow) mainWindow.webContents.send('update-downloaded', info);
        });
        autoUpdater.on('error', (err) => {
            if (mainWindow) mainWindow.webContents.send('update-error', err.message);
        });

        autoUpdater.checkForUpdatesAndNotify().catch(() => {});
        setInterval(() => autoUpdater.checkForUpdatesAndNotify().catch(() => {}), 4 * 60 * 60 * 1000);
    }
});
