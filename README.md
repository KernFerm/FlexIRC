# 🚀 FlexIRC

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/username/flexirc)
[![License](https://img.shields.io/badge/license-GNUV3-green.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-14+-brightgreen.svg)](https://nodejs.org)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](https://github.com/username/flexirc)
[![JavaScript](https://img.shields.io/badge/language-JavaScript-yellow.svg)](https://github.com/username/flexirc)
[![Electron](https://img.shields.io/badge/GUI-Electron-9feaf9.svg)](https://electronjs.org)
[![WebSocket](https://img.shields.io/badge/realtime-WebSocket-ff6b6b.svg)](https://github.com/username/flexirc)
[![Security](https://img.shields.io/badge/security-AES%20256%20%7C%20RSA%202048-red.svg)](https://github.com/username/flexirc)

A flexible, feature-complete IRC chat server built with Node.js and WebSockets. Combines basic security, federation networking, and ultra-secure encryption into one configurable application with an intuitive desktop GUI.

## ✨ Features Overview

### 🔐 Core Security
- **Multi-Hash Authentication**: bcrypt or Argon2 password hashing
- **Input Sanitization**: DOMPurify and validator.js prevent XSS/injection attacks  
- **Advanced Rate Limiting**: Configurable per-IP limits for connections, messages, commands
- **IP Banning & Admin Controls**: Kick/ban users with comprehensive logging
- **Security Monitoring**: Real-time anomaly detection and comprehensive audit logs

### 🌐 Federation Network
- **Server-to-Server Communication**: WebSocket-based federation protocol
- **Cross-Server Messaging**: Chat across multiple connected servers  
- **Distributed Presence**: User status synchronized across the network
- **Auto-Discovery**: Automatic connection to known servers

### 🛡️ Ultra Security Mode
- **End-to-End Encryption**: RSA-2048 + AES-256 for all communications
- **JWT Authentication**: Stateless token-based auth with refresh capability
- **Two-Factor Authentication**: TOTP support with QR code generation
- **HTTPS/WSS**: Self-signed SSL certificates with TLS 1.3
- **Advanced Headers**: CSRF, XSS protection, security headers via Helmet

### 💬 IRC Features
- **Real-Time Chat**: WebSocket instant messaging with message history
- **Channel Management**: Create/join multiple channels (#general, #random, etc.)
- **User Presence**: Online/offline status with join/leave notifications  
- **Admin Commands**: Full moderation suite (kick, ban, channel management)
- **Message Validation**: Content filtering, length limits, format validation

### 📱 Modern Web Client
- **Responsive Design**: Works seamlessly on desktop and mobile
- **Dark Theme Interface**: Professional dark mode design
- **Real-Time Updates**: Live user lists, typing indicators, message delivery
- **Security Status**: Shows encryption status and security features enabled

## 🚀 Quick Start

### Prerequisites
- Node.js 14+
- npm (included with Node.js)

### Installation

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Choose your mode and start**:

   **Full-Featured (Recommended)**:
   ```bash
   npm start
   ```
   
   **Basic Chat Server**:
   ```bash
   npm run basic
   ```
   
   **Federated Network**:
   ```bash
   npm run federated  
   ```
   
   **Ultra-Secure Mode**:
   ```bash
   npm run ultra-secure
   ```

3. **Access the chat**:
   - HTTP: `http://localhost:3000`
   - HTTPS: `https://localhost:3443` (ultra-secure mode)

## 🎮 Usage Guide

### Web Client
1. Open `http://localhost:3000` in your browser
2. Register a new account or login with existing credentials
3. Join channels (starts with `#general` by default)
4. Start chatting with other users

### User Authentication
- **Username**: 3-20 alphanumeric characters (including underscore)
- **Password**: 6-100 characters minimum
- **2FA**: Available in ultra-secure mode with QR code setup

### Available Commands

| Command | Description | Admin Only |
|---------|-------------|------------|
| `/list` | List all available channels | No |
| `/users <channel>` | List users in a channel | No |
| `/kick <username> [reason]` | Kick a user from server | Yes |
| `/ban <username>` | Ban a user by IP | Yes |

## ⚙️ Configuration Modes

### 1. Basic Mode (`npm run basic`)
Perfect for simple local chat applications:
- User authentication with bcrypt
- Basic rate limiting and input sanitization
- Channel management and admin commands
- Security logging

### 2. Federated Mode (`npm run federated`)  
For multi-server IRC networks:
- All basic features
- Server-to-server communication
- Cross-server message broadcasting
- Federation management API

### 3. Ultra-Secure Mode (`npm run ultra-secure`)
Maximum security for sensitive environments:
- All basic features  
- RSA-2048 + AES-256 encryption
- JWT authentication with 2FA
- HTTPS/WSS with SSL certificates
- Argon2 password hashing
- Advanced monitoring and protection

### 4. Full-Featured Mode (`npm start`)
Everything enabled for complete functionality:
- All features from all modes combined
- Federated network of ultra-secure servers
- Complete security and networking suite

## 🔧 Environment Configuration

Create a `.env` file to customize behavior:

```bash
# Server Configuration  
PORT=3000                              # HTTP port
HTTPS_PORT=3443                        # HTTPS port
SERVER_NAME=my-irc-server             # Server identifier

# Feature Toggles
ENABLE_FEDERATION=true                 # Enable server networking
ENABLE_ULTRA_SECURITY=true            # Enable encryption & 2FA
ENABLE_SSL=true                       # Enable HTTPS/WSS
ENABLE_2FA=true                       # Enable two-factor auth
USE_ARGON2=true                       # Use Argon2 vs bcrypt

# Federation Settings
FEDERATION_PORT=3001                   # Server-to-server port
KNOWN_SERVERS=server1:3001,server2:3001

# Security
ALLOWED_ORIGINS=http://localhost:3000
NODE_ENV=development
```

## 📁 Project Structure

```
IRC-chat/
├── comprehensive-server.js   # Main server (combines all features)
├── package.json             # Dependencies and scripts
├── public/
│   └── index.html          # Web client interface  
├── ssl/                    # Auto-generated SSL certificates (created on first run)
├── logs/                   # Security and chat logs
│   ├── security.log       # Authentication & admin actions
│   └── chat.log          # Chat messages
├── COMPREHENSIVE-GUIDE.md  # Detailed configuration guide
└── README.md              # This file
```

## 🔒 Security Features Details

### Rate Limiting
- **Connections**: 5 per minute per IP (3 in ultra-secure mode)  
- **Messages**: 30 per minute per IP (20 in ultra-secure mode)
- **Commands**: 10 per minute per IP (5 in ultra-secure mode)
- **Auth Attempts**: 5 per 5 minutes (ultra-secure mode only)

### Encryption (Ultra-Secure Mode)
- **Algorithm**: RSA-2048 for key exchange + AES-256 for data
- **JWT Tokens**: 24-hour expiration with secure secret rotation
- **SSL/TLS**: Auto-generated self-signed certificates with TLS 1.3 enforcement
- **2FA**: TOTP with backup codes and QR code generation

### Input Safety
- **XSS Prevention**: DOMPurify sanitization for all HTML content
- **Injection Protection**: Parameterized queries and input validation  
- **Content Filtering**: Message length limits and character validation
- **Command Validation**: Strict parsing and permission checks

## 🌐 Federation Setup

### Single Server
```bash
npm start
```

### Multi-Server Network
```bash
# Server 1 (Hub)
SERVER_NAME=hub-server PORT=3000 FEDERATION_PORT=3001 npm start

# Server 2 (Branch)  
SERVER_NAME=branch-server PORT=3002 FEDERATION_PORT=3003 \
KNOWN_SERVERS=localhost:3001 npm start
```

### Federation Features
- Automatic server discovery and connection
- Cross-server message broadcasting  
- Federated user presence tracking
- Network topology management
- Server status monitoring

## 📊 Monitoring & Logs

### Health Check
```
GET http://localhost:3000/health
```

Returns server status, feature configuration, and connection counts.

### Federation Status
```
GET http://localhost:3000/federation/status  
```

Shows connected servers and network topology.

### Log Files
- `logs/security.log`: Authentication, bans, admin actions
- `logs/chat.log`: All chat messages and user activity
- `logs/federation.log`: Server-to-server communication (if enabled)

## 🚀 Deployment & Windows Installer

### Preparation Steps
1. **Test thoroughly** with your chosen configuration
2. **Bundle for distribution** using pkg, electron, or similar
3. **Include SSL certificates** if using HTTPS mode  
4. **Create installer** with Inno Setup, NSIS, or Advanced Installer

### Production Considerations
- Replace self-signed certificates with proper SSL certs
- Use environment variables for sensitive configuration
- Set up reverse proxy (nginx/Apache) for public deployment
- Configure firewall rules for federation ports
- Set up database for persistent user data (future enhancement)

## � Installation & User Guide

### Windows Installer
FlexIRC comes with a complete Windows installer and user guide. For end-users who want to install and use FlexIRC:

**📖 See:** [INSTALLER-README.md](INSTALLER-README.md)

This guide includes:
- **System Requirements** - Windows 11 compatibility and hardware needs
- **Installation Steps** - Complete installer walkthrough
- **First-Time Setup** - Desktop app configuration and server startup
- **Usage Instructions** - How to start the server and connect friends
- **Troubleshooting** - Common issues and solutions for end-users

The installer guide is designed for non-technical users who want to quickly set up their own IRC server using the desktop application.

## �🛠️ Available Scripts

| Script | Description | Configuration |
|--------|-------------|---------------|
| `npm start` | Full-featured server | All features enabled |
| `npm run basic` | Lightweight chat | Basic IRC only |
| `npm run federated` | Network mode | Federation enabled |
| `npm run ultra-secure` | Security mode | Encryption + 2FA |
| `npm run dev` | Development mode | Auto-reload |
| `npm test` | Run tests | - |

## 🤝 Contributing

This server is designed to be easily extensible. Key areas for enhancement:
- Database integration for persistent storage
- Mobile app integration APIs  
- Plugin system for custom features
- Advanced moderation tools
- Voice/video chat integration

## 📝 License

GNU V3

## 🆘 Troubleshooting

### Common Issues

**SSL Certificate Errors**: Self-signed certificates trigger browser warnings. Click "Advanced" → "Proceed" for local development.

**Federation Connection Failed**: Check firewall settings and ensure FEDERATION_PORT is accessible.

**Rate Limited**: If testing rapidly, wait a minute or restart the server to reset rate limits.

**2FA Setup Issues**: Ensure system time is synchronized when using TOTP codes.

### Support

For detailed configuration options, see [COMPREHENSIVE-GUIDE.md](COMPREHENSIVE-GUIDE.md)

---

**Ready to build your secure chat network!** 🚀
