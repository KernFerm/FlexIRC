const { app, BrowserWindow, ipcMain, shell, Menu } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

let mainWindow;
let serverProcess = null;
let serverRunning = false;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false
        },
        icon: path.join(__dirname, 'assets', 'icon.ico'),
        title: 'FlexIRC'
    });

    mainWindow.loadFile('gui.html');

    // Create application menu
    const template = [
        {
            label: 'File',
            submenu: [
                {
                    label: 'Open Chat in Browser',
                    click: () => {
                        if (serverRunning) {
                            shell.openExternal('http://localhost:3000');
                        }
                    }
                },
                { type: 'separator' },
                { label: 'Quit', accelerator: 'CmdOrCtrl+Q', click: () => app.quit() }
            ]
        },
        {
            label: 'Server',
            submenu: [
                {
                    label: 'Start Server',
                    click: () => mainWindow.webContents.send('start-server')
                },
                {
                    label: 'Stop Server', 
                    click: () => mainWindow.webContents.send('stop-server')
                }
            ]
        },
        {
            label: 'Help',
            submenu: [
                {
                    label: 'About',
                    click: () => {
                        const { dialog } = require('electron');
                        dialog.showMessageBox(mainWindow, {
                            type: 'info',
                            title: 'About FlexIRC',
                            message: 'FlexIRC v1.0\nFlexible, secure chat for everyone!',
                            buttons: ['OK']
                        });
                    }
                }
            ]
        }
    ];

    const menu = Menu.buildFromTemplate(template);
    Menu.setApplicationMenu(menu);
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    stopServer();
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

// IPC handlers for GUI communication
ipcMain.handle('get-config', () => {
    try {
        const envPath = path.join(__dirname, '.env');
        if (fs.existsSync(envPath)) {
            const envContent = fs.readFileSync(envPath, 'utf8');
            return parseEnvFile(envContent);
        }
        return getDefaultConfig();
    } catch (error) {
        return getDefaultConfig();
    }
});

ipcMain.handle('save-config', (event, config) => {
    try {
        const envContent = generateEnvFile(config);
        fs.writeFileSync(path.join(__dirname, '.env'), envContent);
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('start-server', () => {
    if (!serverRunning) {
        serverProcess = spawn('node', ['comprehensive-server.js'], {
            cwd: __dirname,
            stdio: 'pipe'
        });

        serverProcess.stdout.on('data', (data) => {
            mainWindow.webContents.send('server-log', data.toString());
        });

        serverProcess.stderr.on('data', (data) => {
            mainWindow.webContents.send('server-error', data.toString());
        });

        serverProcess.on('close', (code) => {
            serverRunning = false;
            mainWindow.webContents.send('server-stopped', code);
        });

        serverRunning = true;
        return { success: true };
    }
    return { success: false, error: 'Server already running' };
});

ipcMain.handle('stop-server', () => {
    return stopServer();
});

function stopServer() {
    if (serverProcess) {
        serverProcess.kill();
        serverProcess = null;
        serverRunning = false;
        return { success: true };
    }
    return { success: false, error: 'Server not running' };
}

function parseEnvFile(content) {
    const config = {};
    const lines = content.split('\n');
    
    lines.forEach(line => {
        line = line.trim();
        if (line && !line.startsWith('#')) {
            const [key, ...valueParts] = line.split('=');
            if (key && valueParts.length > 0) {
                config[key.trim()] = valueParts.join('=').trim();
            }
        }
    });
    
    return config;
}

function generateEnvFile(config) {
    let content = '# FlexIRC Configuration\n\n';
    
    Object.entries(config).forEach(([key, value]) => {
        if (value !== undefined && value !== '') {
            content += `${key}=${value}\n`;
        }
    });
    
    return content;
}

function getDefaultConfig() {
    return {
        PORT: '3000',
        SERVER_NAME: 'my-irc-server',
        ENABLE_FEDERATION: 'true',
        ENABLE_ULTRA_SECURITY: 'true',
        ENABLE_SSL: 'false',
        FEDERATION_PORT: '3001',
        KNOWN_SERVERS: '',
        ADMIN_USERS: 'admin'
    };
}