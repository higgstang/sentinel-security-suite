const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    getEngineUrl: () => ipcRenderer.invoke('get-engine-url'),
    pickFile: () => ipcRenderer.invoke('pick-file'),
    pickDirectory: () => ipcRenderer.invoke('pick-directory'),
    onUpdateAvailable: (cb) => ipcRenderer.on('update-available', (_e, info) => cb(info)),
    onUpdateProgress: (cb) => ipcRenderer.on('update-progress', (_e, progress) => cb(progress)),
    onUpdateDownloaded: (cb) => ipcRenderer.on('update-downloaded', (_e, info) => cb(info)),
    onUpdateError: (cb) => ipcRenderer.on('update-error', (_e, msg) => cb(msg)),
    installUpdateNow: () => ipcRenderer.invoke('install-update-now'),
});
