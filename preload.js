const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    getEngineUrl: () => ipcRenderer.invoke('get-engine-url'),
    pickFile: () => ipcRenderer.invoke('pick-file'),
    pickDirectory: () => ipcRenderer.invoke('pick-directory'),
    onUpdateAvailable: (cb) => ipcRenderer.on('update-available', (_e, info) => cb(info)),
    onUpdateDownloaded: (cb) => ipcRenderer.on('update-downloaded', (_e, info) => cb(info)),
    installUpdateNow: () => ipcRenderer.invoke('install-update-now'),
});
