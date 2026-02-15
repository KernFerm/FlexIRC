# 🚀 FlexIRC - Windows Installer Guide

Welcome to **FlexIRC** - Your flexible IRC chat server with an easy-to-use desktop interface!

## 📦 Installation

### System Requirements
- **Windows 11** (64-bit)
- **4 GB RAM** minimum
- **600 MB free disk space**
- **Internet connection** (for initial setup)

### Installing FlexIRC

1. **Download the installer**: `FlexIRC_Installer_1.0.0.exe`
2. **Right-click** → **"Run as administrator"** (recommended)
3. **Follow the installer wizard**:
   - Choose installation directory
   - Select "Create desktop shortcut" ✅
   - Select "Create Start Menu shortcut" ✅
4. **Click Install** and wait for completion
5. **Launch FlexIRC** from desktop or Start Menu

## 🎮 Using FlexIRC

### First Time Setup

1. **Launch FlexIRC** from your desktop shortcut
2. **Configure your server** in the **Settings** tab:
   - Set your **Server Name** (e.g., "My Chat Server")
   - Choose your **Port** (default: 3000)
   - Select **Security Mode**:
     - **Basic**: Simple chat (recommended for beginners)
     - **Federation**: Connect with friends' servers
     - **Ultra-Secure**: End-to-end encryption + 2FA

3. **Start your server** in the **Control** tab:
   - Click **▶️ Start Server**
   - Wait for **"Server Running"** green status

4. **Open the chat**:
   - Click **🌐 Open Chat** 
   - Browser opens to your chat interface
   - **Register** a new account
   - Start chatting in **#general** channel!

### Daily Usage

1. **Open FlexIRC desktop app**
2. **Click "▶️ Start Server"** 
3. **Click "🌐 Open Chat"** to join the conversation
4. **Leave the desktop app running** while you chat

## 👥 Sharing with Friends

### Local Network (Same WiFi)
1. **Find your IP address**:
   - Press `Win + R`, type `cmd`, press Enter
   - Type `ipconfig` and press Enter
   - Look for **"IPv4 Address"** (e.g., 192.168.1.100)

2. **Share with friends**:
   - Send them: `http://[your-ip]:3000`
   - Example: `http://192.168.1.100:3000`
   - They open it in their browser and register!

### Internet Access (Advanced)
- **Port forwarding**: Configure your router for port 3000
- **Dynamic DNS**: Use services like No-IP for a permanent address
- **Tunneling**: Use ngrok for temporary public access

## ⚙️ Desktop App Features

### 🎮 Control Tab
- **▶️ Start Server**: Launch your IRC server
- **⏹️ Stop Server**: Shut down the server safely
- **🌐 Open Chat**: Open web interface in browser
- **📊 Server Status**: Live connection and message counts

### ⚙️ Settings Tab  
- **Server Configuration**: Name, ports, security settings
- **Feature Toggles**: Enable/disable federation, encryption, 2FA
- **Network Settings**: CORS, rate limits, admin users
- **Save Changes**: Apply new configuration

### 📚 Help & Info Tab
- **Quick Start Guide**: Step-by-step instructions
- **Sharing Instructions**: How friends can connect
- **Command Reference**: Available chat commands
- **Technical Details**: Ports, security features, logs

## 💬 Chat Commands

Once connected to your FlexIRC server, users can use these commands:

| Command | Description | Example |
|---------|-------------|---------|
| `/list` | Show all channels | `/list` |
| `/users #channel` | List users in channel | `/users #general` |
| `/kick username` | Kick user (admin only) | `/kick spammer` |
| `/ban username` | Ban user by IP (admin only) | `/ban troublemaker` |

## 🔒 Security Features

### Basic Mode
- ✅ Password authentication (bcrypt)
- ✅ Input sanitization & XSS protection
- ✅ Rate limiting (anti-spam)
- ✅ IP banning & admin controls

### Ultra-Secure Mode  
- ✅ **All basic features**
- ✅ RSA-2048 + AES-256 encryption
- ✅ Two-factor authentication (2FA)
- ✅ HTTPS/WSS with SSL certificates
- ✅ JWT authentication tokens
- ✅ Advanced security monitoring

## 🆘 Troubleshooting

### "Can't reach this page" when opening chat
**Problem**: Server isn't running
**Solution**: 
1. Open FlexIRC desktop app
2. Click **▶️ Start Server** 
3. Wait for green "Server Running" status
4. Try **🌐 Open Chat** again

### Friends can't connect to your server
**Problem**: Windows Firewall or network settings
**Solution**:
1. **Windows Firewall**: Allow FlexIRC through firewall
2. **Check IP**: Use `ipconfig` to verify your IP address
3. **Test locally**: Try `http://localhost:3000` first
4. **Router settings**: May need port forwarding for internet access

### Desktop app won't start
**Problem**: Installation or system issue
**Solution**:
1. **Run as administrator**: Right-click FlexIRC → "Run as administrator"
2. **Reinstall**: Uninstall and reinstall FlexIRC
3. **Windows updates**: Ensure Windows is up to date
4. **Antivirus**: Check if antivirus blocked the app

### Installer says "Windows protected your PC"  
**Problem**: SmartScreen protection (normal for new apps)
**Solution**:
1. Click **"More info"**
2. Click **"Run anyway"** 
3. This is normal for unsigned applications

## 📂 Important Locations

### Installation Directory
```
C:\Users\[username]\AppData\Local\Programs\flexirc\
```

### Configuration Files
```
C:\Users\[username]\AppData\Roaming\flexirc\
```

### Logs Location
```
C:\Users\[username]\AppData\Roaming\flexirc\logs\
- security.log (auth & admin actions)
- chat.log (all messages)
```

## 🔄 Uninstalling

1. **Windows Settings** → **Apps** → **FlexIRC** → **Uninstall**
2. Or use **Control Panel** → **Programs and Features**
3. **Optional**: Delete configuration files from AppData (see locations above)

## 🎉 You're Ready to Chat!

**FlexIRC is now installed and ready to use!** 

1. **Start the desktop app**
2. **Configure your settings** 
3. **Start the server**
4. **Open chat and register**
5. **Invite your friends!**

**Questions?** Check the **Help & Info** tab in the desktop application for more details and advanced configuration options.

---
**FlexIRC v1.0** - Flexible, secure chat for everyone! 🚀