const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    getEngineUrl: () => ipcRenderer.invoke('get-engine-url'),
    pickFile: () => ipcRenderer.invoke('pick-file'),
    pickDirectory: () => ipcRenderer.invoke('pick-directory'),
});
