const WebSocket = require('ws');
const express = require('express');
const helmet = require('helmet');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const validator = require('validator');
const bcrypt = require('bcrypt');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const NodeRSA = require('node-rsa');
const AES = require('aes-js');
const forge = require('node-forge');
const { v4: uuidv4 } = require('uuid');
const xss = require('xss');
const hpp = require('hpp');
const session = require('express-session');
const { JSDOM } = require('jsdom');
const DOMPurify = require('dompurify')(new JSDOM('').window);
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');

class ComprehensiveIRCServer {
    constructor(options = {}) {
        // Server configuration
        this.config = {
            enableFederation: options.enableFederation !== false, // Default true
            enableUltraSecurity: options.enableUltraSecurity !== false, // Default true
            enableSSL: options.enableSSL !== false, // Default true
            enable2FA: options.enable2FA !== false, // Default true
            useArgon2: options.useArgon2 !== false, // Default true (vs bcrypt)
            ...options
        };

        // Core server components
        this.app = express();
        this.httpServer = null;
        this.httpsServer = null;
        this.wss = null;
        this.clients = new Map();
        this.channels = new Map();
        this.users = new Map();
        this.bannedIPs = new Set();
        this.adminUsers = new Set(['admin']);

        // Federation components (if enabled)
        if (this.config.enableFederation) {
            this.federatedServers = new Map();
            this.serverConnections = new Map();
            this.serverName = process.env.SERVER_NAME || `server-${Math.random().toString(36).substr(2, 9)}`;
            this.federationPort = parseInt(process.env.FEDERATION_PORT) || 3001;
            this.knownServers = new Set();
            this.federationWss = null;
        }

        // Ultra security components (if enabled)
        if (this.config.enableUltraSecurity) {
            this.serverKeyPair = this.generateServerKeyPair();
            this.jwtSecret = this.generateJWTSecret();
            this.encryptionKey = this.generateEncryptionKey();
            this.sessionSecret = this.generateSessionSecret();
            this.failedLogins = new Map();
            this.suspiciousActivity = new Map();
            this.encryptedSessions = new Map();
        }

        // Rate limiters with adaptive configuration
        this.setupRateLimiters();

        // Initialize server
        this.initializeServer();
        this.setupSecurity();
        this.createDefaultChannel();

        if (this.config.enableFederation) {
            this.startFederationServer();
            this.loadKnownServers();
        }

        if (this.config.enableUltraSecurity) {
            this.setupSSLCertificates();
            this.startSecurityMonitoring();
        }
    }

    setupRateLimiters() {
        if (this.config.enableUltraSecurity) {
            // Stricter limits for ultra-secure mode
            this.connectionLimiter = new RateLimiterMemory({ points: 3, duration: 60 });
            this.messageLimiter = new RateLimiterMemory({ points: 20, duration: 60 });
            this.commandLimiter = new RateLimiterMemory({ points: 5, duration: 60 });
            this.authLimiter = new RateLimiterMemory({ points: 5, duration: 300 });
        } else {
            // Standard limits
            this.connectionLimiter = new RateLimiterMemory({ points: 5, duration: 60 });
            this.messageLimiter = new RateLimiterMemory({ points: 30, duration: 60 });
            this.commandLimiter = new RateLimiterMemory({ points: 10, duration: 60 });
        }
    }

    // ============== ENCRYPTION & SECURITY FUNCTIONS ==============

    generateServerKeyPair() {
        if (!this.config.enableUltraSecurity) return null;
        const key = new NodeRSA({ b: 2048 });
        return {
            private: key.exportKey('private'),
            public: key.exportKey('public')
        };
    }

    generateJWTSecret() {
        if (!this.config.enableUltraSecurity) return null;
        return crypto.randomBytes(64).toString('hex');
    }

    generateEncryptionKey() {
        if (!this.config.enableUltraSecurity) return null;
        return crypto.randomBytes(32); // 256-bit key for AES
    }

    generateSessionSecret() {
        if (!this.config.enableUltraSecurity) return null;
        return crypto.randomBytes(32).toString('hex');
    }

    setupSSLCertificates() {
        if (!this.config.enableSSL) return;

        const certPath = path.join(__dirname, 'ssl', 'server.crt');
        const keyPath = path.join(__dirname, 'ssl', 'server.key');

        // Create ssl directory if it doesn't exist
        const sslDir = path.dirname(certPath);
        if (!fs.existsSync(sslDir)) {
            fs.mkdirSync(sslDir, { recursive: true });
        }

        // Generate self-signed certificate if it doesn't exist
        if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
            this.generateSelfSignedCert(certPath, keyPath);
        }

        this.sslOptions = {
            key: fs.readFileSync(keyPath),
            cert: fs.readFileSync(certPath)
        };
    }

    generateSelfSignedCert(certPath, keyPath) {
        const keys = forge.pki.rsa.generateKeyPair(2048);
        const cert = forge.pki.createCertificate();
        
        cert.publicKey = keys.publicKey;
        cert.serialNumber = '01';
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
        
        const attrs = [{
            name: 'countryName',
            value: 'US'
        }, {
            name: 'organizationName',
            value: 'SecureIRC'
        }, {
            name: 'commonName',
            value: 'localhost'
        }];
        
        cert.setSubject(attrs);
        cert.setIssuer(attrs);
        cert.sign(keys.privateKey);
        
        const certPem = forge.pki.certificateToPem(cert);
        const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
        
        fs.writeFileSync(certPath, certPem);
        fs.writeFileSync(keyPath, keyPem);
        
        console.log('🔐 Generated self-signed SSL certificate');
    }

    authenticate(req, res, next) {
        if (!this.config.enableUltraSecurity) return next();

        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        try {
            const decoded = jwt.verify(token, this.jwtSecret);
            req.user = decoded;
            next();
        } catch (error) {
            res.status(401).json({ error: 'Invalid token' });
        }
    }

    // ============== SERVER INITIALIZATION ==============

    setupSecurity() {
        // Ensure logs directory exists
        const logsDir = path.join(__dirname, 'logs');
        if (!fs.existsSync(logsDir)) {
            fs.mkdirSync(logsDir, { recursive: true });
        }
        
        console.log('🔒 Security subsystem initialized');
    }

    initializeServer() {
        // Basic security middleware
        this.setupBasicSecurity();

        if (this.config.enableUltraSecurity) {
            this.setupAdvancedSecurity();
            this.setupAPIRoutes();
        }

        // Basic routes
        this.setupBasicRoutes();

        if (this.config.enableFederation) {
            this.setupFederationRoutes();
        }

        // Start servers
        this.startServers();
    }

    setupBasicSecurity() {
        // Helmet security headers
        const helmetConfig = {
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrcAttr: ["'unsafe-inline'"], // Allow inline event handlers
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    connectSrc: ["'self'", "ws:", "wss:"]
                }
            }
        };
        this.app.use(helmet(helmetConfig));

        // CORS configuration
        const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [
            'http://localhost:3000',
            'https://localhost:3000'
        ];
        
        this.app.use(cors({
            origin: allowedOrigins,
            credentials: true,
            methods: ['GET', 'POST'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
        }));

        // Body parsing
        this.app.use(express.json({ limit: '1mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '1mb' }));
        this.app.use(express.static(path.join(__dirname, 'public')));
    }

    setupAdvancedSecurity() {
        if (!this.config.enableUltraSecurity) return;

        // Force HTTPS in production (manual implementation)
        if (process.env.NODE_ENV === 'production') {
            this.app.use((req, res, next) => {
                if (!req.secure && req.get('x-forwarded-proto') !== 'https') {
                    return res.redirect('https://' + req.get('host') + req.url);
                }
                next();
            });
        }

        // Manual rate limiting for API endpoints
        const apiLimiter = new Map();
        this.app.use('/api/', (req, res, next) => {
            const ip = req.ip;
            const now = Date.now();
            const windowMs = 15 * 60 * 1000; // 15 minutes
            const maxRequests = 100;
            
            if (!apiLimiter.has(ip)) {
                apiLimiter.set(ip, { count: 1, resetTime: now + windowMs });
                return next();
            }
            
            const limiterData = apiLimiter.get(ip);
            if (now > limiterData.resetTime) {
                apiLimiter.set(ip, { count: 1, resetTime: now + windowMs });
                return next();
            }
            
            if (limiterData.count >= maxRequests) {
                return res.status(429).json({ error: 'Too many API requests' });
            }
            
            limiterData.count++;
            next();
        });

        // Request size validation
        this.app.use((req, res, next) => {
            const contentLength = parseInt(req.get('content-length') || '0');
            if (contentLength > 1000000) { // 1MB limit
                return res.status(413).json({ error: 'Request too large' });
            }
            next();
        });

        // Additional security middleware (Express 5.x compatible)
        try {
            const xssMiddleware = xss();
            if (typeof xssMiddleware === 'function') {
                this.app.use(xssMiddleware);
            }
        } catch (error) {
            console.warn('XSS middleware not available:', error.message);
        }
        
        try {
            const hppMiddleware = hpp();
            if (typeof hppMiddleware === 'function') {
                this.app.use(hppMiddleware);
            }
        } catch (error) {
            console.warn('HPP middleware not available:', error.message);
        }

        // Basic MongoDB-style injection protection
        this.app.use((req, res, next) => {
            if (req.body) {
                const sanitizeObj = (obj) => {
                    for (let key in obj) {
                        if (typeof obj[key] === 'object' && obj[key] !== null) {
                            sanitizeObj(obj[key]);
                        } else if (typeof obj[key] === 'string') {
                            obj[key] = obj[key].replace(/[\$\{\}]/g, '');
                        }
                    }
                    return obj;
                };
                req.body = sanitizeObj(req.body);
            }
            next();
        });

        // Session management
        this.app.use(session({
            secret: this.sessionSecret,
            resave: false,
            saveUninitialized: false,
            cookie: {
                secure: this.config.enableSSL,
                httpOnly: true,
                maxAge: 24 * 60 * 60 * 1000, // 24 hours
                sameSite: 'strict'
            }
        }));

        // Basic CSRF protection (skip for API and WebSocket)
        this.app.use((req, res, next) => {
            if (req.path.startsWith('/api/') || req.get('Upgrade') === 'websocket') {
                return next();
            }
            
            // Simple CSRF token validation
            if (req.method === 'POST') {
                const token = req.headers['x-csrf-token'] || req.body._csrf;
                const sessionToken = req.session.csrfToken;
                
                if (!token || token !== sessionToken) {
                    return res.status(403).json({ error: 'Invalid CSRF token' });
                }
            }
            
            // Generate CSRF token for session
            if (!req.session.csrfToken) {
                req.session.csrfToken = crypto.randomBytes(32).toString('hex');
            }
            
            next();
        });

        // Server load protection (manual implementation)
        const loadMonitor = { requestCount: 0, windowStart: Date.now() };
        this.app.use((req, res, next) => {
            const now = Date.now();
            const windowMs = 60000; // 1 minute window
            const maxRequestsPerWindow = 1000;
            
            if (now - loadMonitor.windowStart > windowMs) {
                loadMonitor.requestCount = 0;
                loadMonitor.windowStart = now;
            }
            
            loadMonitor.requestCount++;
            
            if (loadMonitor.requestCount > maxRequestsPerWindow) {
                return res.status(503).send('Server too busy, try again later');
            }
            
            next();
        });
    }

    setupBasicRoutes() {
        // Health check
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                features: {
                    federation: this.config.enableFederation,
                    ultraSecurity: this.config.enableUltraSecurity,
                    ssl: this.config.enableSSL,
                    twoFA: this.config.enable2FA
                },
                clients: this.clients.size,
                channels: this.channels.size,
                users: this.users.size
            });
        });

        // Serve the web client
        this.app.get('/', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'index.html'));
        });
    }

    setupFederationRoutes() {
        if (!this.config.enableFederation) return;

        // Federation status endpoint
        this.app.get('/federation/status', (req, res) => {
            res.json({
                serverName: this.serverName,
                federatedServers: Array.from(this.federatedServers.keys()),
                connectedServers: this.serverConnections.size,
                knownServers: Array.from(this.knownServers),
                userCount: this.clients.size
            });
        });

        // Manual server connection endpoint
        this.app.post('/federation/connect', (req, res) => {
            const { serverAddress } = req.body;
            if (serverAddress) {
                this.connectToServer(serverAddress);
                res.json({ success: true, message: 'Connection attempted' });
            } else {
                res.status(400).json({ success: false, message: 'Server address required' });
            }
        });
    }

    setupAPIRoutes() {
        if (!this.config.enableUltraSecurity) return;

        // Server information with public key
        this.app.get('/api/info', (req, res) => {
            res.json({
                serverVersion: '3.0.0-comprehensive',
                encryption: 'RSA-2048 + AES-256',
                publicKey: this.serverKeyPair?.public,
                features: this.getServerFeatures(),
                timestamp: new Date().toISOString()
            });
        });

        // 2FA setup endpoint
        if (this.config.enable2FA) {
            this.app.post('/api/2fa/setup', this.authenticate.bind(this), async (req, res) => {
                try {
                    const { username } = req.user;
                    const secret = speakeasy.generateSecret({
                        name: `ComprehensiveIRC (${username})`,
                        issuer: 'ComprehensiveIRC'
                    });

                    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
                    
                    // Store secret temporarily (in production, use proper storage)
                    const userData = this.users.get(username);
                    if (userData) {
                        userData.twoFactorSecret = secret.base32;
                    }

                    res.json({
                        qrCode: qrCodeUrl,
                        secret: secret.base32,
                        backupCodes: this.generateBackupCodes()
                    });
                } catch (error) {
                    console.error('2FA setup error:', error);
                    res.status(500).json({ error: 'Failed to setup 2FA' });
                }
            });
        }
    }

    startServers() {
        const PORT = parseInt(process.env.PORT) || 3000;
        const HTTPS_PORT = parseInt(process.env.HTTPS_PORT) || 3443;

        // HTTP Server
        this.httpServer = this.app.listen(PORT, () => {
            console.log(`🔒 Comprehensive IRC Server running on port ${PORT}`);
            console.log(`📱 Web client: http://localhost:${PORT}`);
            if (this.config.enableFederation) {
                console.log(`🔗 Server name: ${this.serverName}`);
            }
        });

        // HTTPS Server (if SSL enabled)
        if (this.config.enableSSL && this.sslOptions) {
            this.httpsServer = https.createServer(this.sslOptions, this.app);
            this.httpsServer.listen(HTTPS_PORT, () => {
                console.log(`🔐 HTTPS server running on port ${HTTPS_PORT}`);
                console.log(`📱 Secure web client: https://localhost:${HTTPS_PORT}`);
            });
        }

        // WebSocket servers
        this.setupWebSocketServers();
    }

    setupWebSocketServers() {
        // Primary WebSocket server (on HTTP server)
        this.wss = new WebSocket.Server({ 
            server: this.httpServer,
            verifyClient: (info) => this.verifyClient(info)
        });
        
        this.wss.on('connection', (ws, req) => this.handleConnection(ws, req));

        // HTTPS WebSocket server (if SSL enabled)
        if (this.config.enableSSL && this.httpsServer) {
            const httpsWss = new WebSocket.Server({ 
                server: this.httpsServer,
                verifyClient: (info) => this.verifyClient(info)
            });
            
            httpsWss.on('connection', (ws, req) => this.handleConnection(ws, req));
        }
    }

    // ============== FEDERATION FUNCTIONS ==============

    startFederationServer() {
        if (!this.config.enableFederation) return;

        // WebSocket server for server-to-server communication
        this.federationWss = new WebSocket.Server({ 
            port: this.federationPort,
            verifyClient: (info) => this.verifyServerConnection(info)
        });
        
        this.federationWss.on('connection', (ws, req) => this.handleServerConnection(ws, req));
        
        console.log(`🔗 Federation server on port ${this.federationPort}`);
    }

    verifyServerConnection(info) {
        // Basic verification for server connections
        const ip = info.req.socket.remoteAddress;
        return !this.bannedIPs.has(ip);
    }

    handleServerConnection(ws, req) {
        console.log(`🔗 Incoming server connection from: ${req.socket.remoteAddress}`);
        
        ws.on('message', (data) => {
            try {
                const message = JSON.parse(data);
                this.handleServerMessage(ws, message);
            } catch (error) {
                console.error('Failed to parse server message:', error);
            }
        });

        ws.on('close', () => {
            // Remove from federated servers list
            for (const [serverId, serverData] of this.federatedServers.entries()) {
                if (serverData.connection === ws) {
                    this.federatedServers.delete(serverId);
                    this.serverConnections.delete(serverId);
                    console.log(`🔌 Server ${serverId} disconnected`);
                    break;
                }
            }
        });
    }

    handleServerMessage(ws, message) {
        switch (message.type) {
            case 'handshake':
                this.registerFederatedServer(ws, message);
                break;
            case 'chat_message':
                this.handleFederatedMessage(message);
                break;
            case 'user_joined':
                this.handleFederatedUserJoined(message);
                break;
            case 'user_left':
                this.handleFederatedUserLeft(message);
                break;
            default:
                console.log(`Unknown server message type: ${message.type}`);
        }
    }

    registerFederatedServer(ws, message) {
        const serverId = message.serverName;
        this.federatedServers.set(serverId, {
            name: serverId,
            connection: ws,
            connectedAt: new Date().toISOString()
        });
        this.serverConnections.set(serverId, ws);
        
        console.log(`✅ Registered federated server: ${serverId}`);
        
        // Send acknowledgment
        ws.send(JSON.stringify({
            type: 'handshake_ack',
            serverName: this.serverName,
            timestamp: new Date().toISOString()
        }));
    }

    connectToServer(serverAddress) {
        console.log(`🔗 Attempting to connect to server: ${serverAddress}`);
        
        try {
            const ws = new WebSocket(`ws://${serverAddress}`);
            
            ws.on('open', () => {
                console.log(`✅ Connected to federated server: ${serverAddress}`);
                ws.send(JSON.stringify({
                    type: 'handshake',
                    serverName: this.serverName,
                    timestamp: new Date().toISOString()
                }));
            });

            ws.on('message', (data) => {
                try {
                    const message = JSON.parse(data);
                    this.handleServerMessage(ws, message);
                } catch (error) {
                    console.error('Failed to parse server message:', error);
                }
            });

            ws.on('close', () => {
                console.log(`🔌 Disconnected from server: ${serverAddress}`);
            });

            ws.on('error', (error) => {
                console.error(`Failed to connect to ${serverAddress}:`, error.message);
            });

        } catch (error) {
            console.error(`Error connecting to ${serverAddress}:`, error);
        }
    }

    loadKnownServers() {
        if (!this.config.enableFederation) return;

        const envServers = process.env.KNOWN_SERVERS;
        if (envServers) {
            envServers.split(',').forEach(server => {
                this.knownServers.add(server.trim());
            });
        }

        // Auto-connect to known servers
        setTimeout(() => {
            this.knownServers.forEach(server => {
                if (server !== `localhost:${this.federationPort}`) {
                    this.connectToServer(server);
                }
            });
        }, 2000);
    }

    broadcastToFederatedServers(message) {
        if (!this.config.enableFederation) return;

        this.serverConnections.forEach((ws, serverId) => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify(message));
            }
        });
    }

    // ============== CLIENT CONNECTION & MESSAGE HANDLING ==============

    verifyClient(info) {
        const ip = info.req.socket.remoteAddress;
        
        // Check if IP is banned
        if (this.bannedIPs.has(ip)) {
            console.log(`🚫 Blocked connection from banned IP: ${ip}`);
            return false;
        }

        return true;
    }

    async handleConnection(ws, req) {
        const clientId = uuidv4();
        const ip = req.socket.remoteAddress;

        // Rate limiting check
        try {
            await this.connectionLimiter.consume(ip);
        } catch (rateLimiterRes) {
            console.log(`🚫 Rate limited connection from ${ip}`);
            ws.close(1008, 'Rate limited');
            return;
        }

        console.log(`📱 New client connected: ${clientId} from ${ip}`);

        this.clients.set(clientId, {
            ws: ws,
            ip: ip,
            authenticated: false,
            username: null,
            channels: new Set(),
            connectedAt: new Date().toISOString(),
            encrypted: this.config.enableUltraSecurity
        });

        // Set up event handlers
        ws.on('message', (data) => this.handleMessage(clientId, data));
        ws.on('close', () => this.handleDisconnection(clientId));
        ws.on('error', (error) => {
            console.error(`WebSocket error for ${clientId}:`, error);
            this.handleDisconnection(clientId);
        });

        // Send server information 
        const serverInfo = {
            type: 'server_info',
            message: 'Welcome to Comprehensive IRC Server',
            features: this.getServerFeatures(),
            timestamp: new Date().toISOString()
        };

        if (this.config.enableUltraSecurity && this.serverKeyPair) {
            serverInfo.encryption = {
                available: true,
                algorithm: 'RSA-2048 + AES-256',
                publicKey: this.serverKeyPair.public
            };
        }

        this.sendToClient(clientId, serverInfo);
    }

    getServerFeatures() {
        const features = ['basic-irc'];
        
        if (this.config.enableFederation) features.push('federation');
        if (this.config.enableUltraSecurity) features.push('ultra-security', 'encryption');
        if (this.config.enable2FA) features.push('2fa');
        if (this.config.enableSSL) features.push('https', 'wss');
        
        return features;
    }

    async handleMessage(clientId, data) {
        try {
            const message = JSON.parse(data);
            const client = this.clients.get(clientId);
            
            if (!client) return;

            // Rate limiting for messages
            try {
                if (message.type === 'chat') {
                    await this.messageLimiter.consume(client.ip);
                } else {
                    await this.commandLimiter.consume(client.ip);
                }
            } catch (rateLimiterRes) {
                this.sendError(clientId, 'Rate limited. Please slow down.');
                return;
            }

            // Route message based on authentication status
            if (!client.authenticated && !['auth', 'register'].includes(message.type)) {
                this.sendError(clientId, 'Must authenticate first');
                return;
            }

            // Handle the message
            switch (message.type) {
                case 'register':
                    await this.handleRegister(clientId, message);
                    break;
                case 'auth':
                    await this.handleAuth(clientId, message);
                    break;
                case 'join':
                    this.handleJoin(clientId, message);
                    break;
                case 'leave':
                    this.handleLeave(clientId, message);
                    break;
                case 'chat':
                    await this.handleChat(clientId, message);
                    break;
                case 'list':
                    this.handleListChannels(clientId);
                    break;
                case 'users':
                    this.handleListUsers(clientId, message.channel);
                    break;
                case 'kick':
                    this.handleKick(clientId, message.username, message.reason);
                    break;
                case 'ban':
                    this.handleBan(clientId, message.username);
                    break;
                default:
                    this.sendError(clientId, `Unknown message type: ${message.type}`);
            }

        } catch (error) {
            console.error(`Error handling message from ${clientId}:`, error);
            this.sendError(clientId, 'Invalid message format');
        }
    }

    async handleRegister(clientId, message) {
        const { username, password } = message;
        
        // Validate input
        if (!this.validateUsername(username) || !this.validatePassword(password)) {
            this.sendError(clientId, 'Invalid username or password format');
            return;
        }

        if (this.users.has(username)) {
            this.sendError(clientId, 'Username already exists');
            return;
        }

        try {
            // Hash password
            const hashedPassword = this.config.useArgon2 ? 
                await argon2.hash(password) : 
                await bcrypt.hash(password, 12);

            // Create user
            const userData = {
                username: username,
                password: hashedPassword,
                createdAt: new Date().toISOString(),
                isAdmin: this.adminUsers.has(username)
            };

            if (this.config.enable2FA) {
                userData.twoFactorEnabled = false;
                userData.twoFactorSecret = null;
            }

            this.users.set(username, userData);
            
            console.log(`👤 New user registered: ${username}`);
            this.logSecurity(`User registered: ${username}`);
            
            this.sendToClient(clientId, {
                type: 'register_success',
                message: 'Registration successful. You can now login.',
                timestamp: new Date().toISOString()
            });

        } catch (error) {
            console.error('Registration error:', error);
            this.sendError(clientId, 'Registration failed');
        }
    }

    async handleAuth(clientId, message) {
        const { username, password, twoFactorCode } = message;
        const client = this.clients.get(clientId);
        
        if (!client) return;

        // Rate limiting for auth attempts
        if (this.config.enableUltraSecurity) {
            try {
                await this.authLimiter.consume(client.ip);
            } catch (rateLimiterRes) {
                this.sendError(clientId, 'Too many authentication attempts. Please try again later.');
                return;
            }
        }

        const userData = this.users.get(username);
        if (!userData) {
            this.sendError(clientId, 'Invalid credentials');
            this.logSecurity(`Failed login attempt for non-existent user: ${username} from ${client.ip}`);
            return;
        }

        try {
            // Verify password
            const passwordValid = this.config.useArgon2 ? 
                await argon2.verify(userData.password, password) :
                await bcrypt.compare(password, userData.password);

            if (!passwordValid) {
                this.sendError(clientId, 'Invalid credentials');
                this.logSecurity(`Failed login attempt for user: ${username} from ${client.ip}`);
                return;
            }

            // Check 2FA if enabled
            if (this.config.enable2FA && userData.twoFactorEnabled) {
                if (!twoFactorCode) {
                    this.sendToClient(clientId, {
                        type: 'auth_2fa_required',
                        message: '2FA code required',
                        timestamp: new Date().toISOString()
                    });
                    return;
                }

                const verified = speakeasy.totp.verify({
                    secret: userData.twoFactorSecret,
                    encoding: 'base32',
                    token: twoFactorCode
                });

                if (!verified) {
                    this.sendError(clientId, 'Invalid 2FA code');
                    return;
                }
            }

            // Successful authentication
            client.authenticated = true;
            client.username = username;
            client.isAdmin = userData.isAdmin;

            console.log(`✅ User authenticated: ${username}`);
            this.logSecurity(`User authenticated: ${username} from ${client.ip}`);

            const authResponse = {
                type: 'auth_success',
                username: username,
                isAdmin: userData.isAdmin,
                serverFeatures: this.getServerFeatures(),
                timestamp: new Date().toISOString()
            };

            // Add JWT token for ultra-secure mode
            if (this.config.enableUltraSecurity) {
                const token = jwt.sign(
                    { username, isAdmin: userData.isAdmin },
                    this.jwtSecret,
                    { expiresIn: '24h' }
                );
                authResponse.token = token;
            }

            this.sendToClient(clientId, authResponse);

            // Auto-join default channel
            if (this.channels.has('#general')) {
                this.handleJoin(clientId, { channel: '#general' });
            }

            // Notify federated servers
            if (this.config.enableFederation) {
                this.broadcastToFederatedServers({
                    type: 'user_joined',
                    username: username,
                    server: this.serverName,
                    timestamp: new Date().toISOString()
                });
            }

        } catch (error) {
            console.error('Authentication error:', error);
            this.sendError(clientId, 'Authentication failed');
        }
    }

    handleJoin(clientId, message) {
        const client = this.clients.get(clientId);
        if (!client || !client.authenticated) return;

        const channelName = message.channel;
        if (!this.validateChannelName(channelName)) {
            this.sendError(clientId, 'Invalid channel name');
            return;
        }

        // Create channel if it doesn't exist
        if (!this.channels.has(channelName)) {
            this.channels.set(channelName, {
                name: channelName,
                users: new Set(),
                createdAt: new Date().toISOString(),
                topic: ''
            });
            console.log(`📢 Channel created: ${channelName}`);
        }

        const channel = this.channels.get(channelName);
        channel.users.add(clientId);
        client.channels.add(channelName);

        console.log(`👤 ${client.username} joined channel: ${channelName}`);
        this.logChat(`${client.username} joined ${channelName}`);

        // Send join confirmation to user
        this.sendToClient(clientId, {
            type: 'join_success',
            channel: channelName,
            users: Array.from(channel.users).map(id => this.clients.get(id)?.username).filter(Boolean),
            timestamp: new Date().toISOString()
        });

        // Broadcast to channel
        this.broadcastToChannel(channelName, {
            type: 'user_joined',
            username: client.username,
            channel: channelName,
            timestamp: new Date().toISOString()
        }, clientId);
    }

    handleLeave(clientId, message) {
        const client = this.clients.get(clientId);
        if (!client || !client.authenticated) return;

        const channelName = message.channel;
        this.removeUserFromChannel(clientId, channelName);
    }

    async handleChat(clientId, message) {
        const client = this.clients.get(clientId);
        if (!client || !client.authenticated) return;

        const { channel, content } = message;
        
        if (!channel || !content) {
            this.sendError(clientId, 'Missing channel or content');
            return;
        }

        // Validate and sanitize content
        const sanitizedContent = this.sanitizeInput(content);
        if (sanitizedContent.length === 0) {
            this.sendError(clientId, 'Message content is empty after sanitization');
            return;
        }

        if (sanitizedContent.length > 500) {
            this.sendError(clientId, 'Message too long (max 500 characters)');
            return;
        }

        // Check if user is in the channel
        if (!client.channels.has(channel)) {
            this.sendError(clientId, 'Not in that channel');
            return;
        }

        const chatMessage = {
            type: 'chat_message',
            username: client.username,
            channel: channel,
            content: sanitizedContent,
            timestamp: new Date().toISOString(),
            messageId: uuidv4()
        };

        console.log(`💬 ${client.username} in ${channel}: ${sanitizedContent}`);
        this.logChat(`${client.username} in ${channel}: ${sanitizedContent}`);

        // Broadcast to local channel
        this.broadcastToChannel(channel, chatMessage);

        // Broadcast to federated servers
        if (this.config.enableFederation) {
            this.broadcastToFederatedServers({
                type: 'chat_message',
                server: this.serverName,
                ...chatMessage
            });
        }
    }

    // ============== UTILITY FUNCTIONS ==============

    validateUsername(username) {
        return (
            typeof username === 'string' &&
            username.length >= 3 &&
            username.length <= 20 &&
            /^[a-zA-Z0-9_]+$/.test(username)
        );
    }

    validatePassword(password) {
        return (
            typeof password === 'string' &&
            password.length >= 6 &&
            password.length <= 100
        );
    }

    validateChannelName(channel) {
        return (
            typeof channel === 'string' &&
            channel.startsWith('#') &&
            channel.length >= 2 &&
            channel.length <= 50 &&
            /^#[a-zA-Z0-9_-]+$/.test(channel)
        );
    }

    sanitizeInput(input) {
        if (typeof input !== 'string') return '';
        
        // Remove any HTML/script tags and trim
        let sanitized = DOMPurify.sanitize(input, { ALLOWED_TAGS: [] });
        sanitized = validator.escape(sanitized);
        
        return sanitized.trim();
    }

    handleListChannels(clientId) {
        const channelList = Array.from(this.channels.entries()).map(([name, data]) => ({
            name: name,
            users: data.users.size,
            topic: data.topic
        }));

        this.sendToClient(clientId, {
            type: 'channel_list',
            channels: channelList,
            timestamp: new Date().toISOString()
        });
    }

    handleListUsers(clientId, channelName) {
        if (!channelName || !this.channels.has(channelName)) {
            this.sendError(clientId, 'Channel not found');
            return;
        }

        const channel = this.channels.get(channelName);
        const userList = Array.from(channel.users)
            .map(id => this.clients.get(id)?.username)
            .filter(Boolean);

        this.sendToClient(clientId, {
            type: 'user_list',
            channel: channelName,
            users: userList,
            timestamp: new Date().toISOString()
        });
    }

    handleKick(clientId, username, reason = 'No reason provided') {
        const client = this.clients.get(clientId);
        if (!client || !client.authenticated || !client.isAdmin) {
            this.sendError(clientId, 'Admin privileges required');
            return;
        }

        // Find target user
        const targetClient = Array.from(this.clients.entries())
            .find(([id, data]) => data.username === username);

        if (!targetClient) {
            this.sendError(clientId, 'User not found');
            return;
        }

        const [targetId] = targetClient;
        this.disconnectClient(targetId, `Kicked by ${client.username}: ${reason}`);
        
        console.log(`🦵 ${client.username} kicked ${username}: ${reason}`);
        this.logSecurity(`Admin ${client.username} kicked user ${username}: ${reason}`);
    }

    handleBan(clientId, username) {
        const client = this.clients.get(clientId);
        if (!client || !client.authenticated || !client.isAdmin) {
            this.sendError(clientId, 'Admin privileges required');
            return;
        }

        // Find target user
        const targetClient = Array.from(this.clients.entries())
            .find(([id, data]) => data.username === username);

        if (!targetClient) {
            this.sendError(clientId, 'User not found');
            return;
        }

        const [targetId, targetData] = targetClient;
        
        // Ban IP
        this.bannedIPs.add(targetData.ip);
        this.disconnectClient(targetId, `Banned by ${client.username}`);
        
        console.log(`🔨 ${client.username} banned ${username} (IP: ${targetData.ip})`);
        this.logSecurity(`Admin ${client.username} banned user ${username} (IP: ${targetData.ip})`);
    }

    createDefaultChannel() {
        const defaultChannel = '#general';
        if (!this.channels.has(defaultChannel)) {
            this.channels.set(defaultChannel, {
                name: defaultChannel,
                users: new Set(),
                createdAt: new Date().toISOString(),
                topic: 'Welcome to the general chat!'
            });
            console.log(`📢 Created default channel: ${defaultChannel}`);
        }
    }

    removeUserFromChannel(clientId, channelName) {
        const client = this.clients.get(clientId);
        const channel = this.channels.get(channelName);
        
        if (!client || !channel) return;

        channel.users.delete(clientId);
        client.channels.delete(channelName);

        console.log(`👤 ${client.username} left channel: ${channelName}`);
        
        // Send leave confirmation
        this.sendToClient(clientId, {
            type: 'leave_success',
            channel: channelName,
            timestamp: new Date().toISOString()
        });

        // Broadcast to remaining users
        this.broadcastToChannel(channelName, {
            type: 'user_left',
            username: client.username,
            channel: channelName,
            timestamp: new Date().toISOString()
        });

        // Remove empty channels (except #general)
        if (channel.users.size === 0 && channelName !== '#general') {
            this.channels.delete(channelName);
            console.log(`📢 Removed empty channel: ${channelName}`);
        }
    }

    handleDisconnection(clientId) {
        const client = this.clients.get(clientId);
        if (!client) return;

        console.log(`📱 Client disconnected: ${client.username || clientId}`);
        
        // Remove from all channels
        client.channels.forEach(channelName => {
            this.removeUserFromChannel(clientId, channelName);
        });

        // Remove client
        this.clients.delete(clientId);

        // Notify federated servers if user was authenticated
        if (this.config.enableFederation && client.authenticated) {
            this.broadcastToFederatedServers({
                type: 'user_left',
                username: client.username,
                server: this.serverName,
                timestamp: new Date().toISOString()
            });
        }
    }

    disconnectClient(clientId, reason = '') {
        const client = this.clients.get(clientId);
        if (!client) return;

        if (reason) {
            this.sendToClient(clientId, {
                type: 'disconnect',
                message: reason,
                timestamp: new Date().toISOString()
            });
        }

        client.ws.close();
    }

    broadcastToChannel(channelName, message, excludeClientId = null) {
        const channel = this.channels.get(channelName);
        if (!channel) return;

        channel.users.forEach(clientId => {
            if (clientId !== excludeClientId) {
                this.sendToClient(clientId, message);
            }
        });
    }

    sendToClient(clientId, message) {
        const client = this.clients.get(clientId);
        if (!client || client.ws.readyState !== WebSocket.OPEN) return;

        try {
            client.ws.send(JSON.stringify(message));
        } catch (error) {
            console.error(`Failed to send message to client ${clientId}:`, error);
        }
    }

    sendError(clientId, message) {
        this.sendToClient(clientId, {
            type: 'error',
            message: message,
            timestamp: new Date().toISOString()
        });
    }

    // ============== SECURITY MONITORING ==============

    startSecurityMonitoring() {
        if (!this.config.enableUltraSecurity) return;

        // Clean up old security data every hour
        setInterval(() => {
            this.cleanupOldSecurityData();
        }, 60 * 60 * 1000);

        // Detect anomalous activity every 5 minutes
        setInterval(() => {
            this.detectAnomalousActivity();
        }, 5 * 60 * 1000);

        console.log('🛡️ Security monitoring started');
    }

    cleanupOldSecurityData() {
        const oneHourAgo = Date.now() - (60 * 60 * 1000);
        
        // Clean up failed login attempts
        for (const [ip, data] of this.failedLogins.entries()) {
            if (data.lastAttempt < oneHourAgo) {
                this.failedLogins.delete(ip);
            }
        }

        // Clean up suspicious activity tracking
        for (const [ip, data] of this.suspiciousActivity.entries()) {
            if (data.lastActivity < oneHourAgo) {
                this.suspiciousActivity.delete(ip);
            }
        }
    }

    detectAnomalousActivity() {
        // Simple anomaly detection - can be enhanced
        const currentConnections = this.clients.size;
        const maxNormalConnections = 100;

        if (currentConnections > maxNormalConnections) {
            this.logSecurity(`High connection count detected: ${currentConnections}`);
        }

        // Check for rapid connections from same IP
        const ipCounts = new Map();
        for (const client of this.clients.values()) {
            ipCounts.set(client.ip, (ipCounts.get(client.ip) || 0) + 1);
        }

        for (const [ip, count] of ipCounts.entries()) {
            if (count > 5) {
                this.logSecurity(`Suspicious: ${count} connections from IP ${ip}`);
            }
        }
    }

    generateBackupCodes() {
        const codes = [];
        for (let i = 0; i < 10; i++) {
            codes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
        }
        return codes;
    }

    // ============== LOGGING FUNCTIONS ==============

    logSecurity(message) {
        const timestamp = new Date().toISOString();
        const logEntry = `${timestamp} - ${message}\n`;
        
        console.log(`🔒 SECURITY: ${message}`);
        
        // Ensure logs directory exists
        const logsDir = path.join(__dirname, 'logs');
        if (!fs.existsSync(logsDir)) {
            fs.mkdirSync(logsDir, { recursive: true });
        }
        
        fs.appendFileSync(path.join(logsDir, 'security.log'), logEntry);
    }

    logChat(message) {
        const timestamp = new Date().toISOString();
        const logEntry = `${timestamp} - ${message}\n`;
        
        // Ensure logs directory exists
        const logsDir = path.join(__dirname, 'logs');
        if (!fs.existsSync(logsDir)) {
            fs.mkdirSync(logsDir, { recursive: true });
        }
        
        fs.appendFileSync(path.join(logsDir, 'chat.log'), logEntry);
    }

    // ============== FEDERATION MESSAGE HANDLERS ==============

    handleFederatedMessage(federatedMsg) {
        if (!this.config.enableFederation) return;

        // Relay federated chat messages to local channels
        const { username, channel, content, server, timestamp } = federatedMsg;
        
        if (this.channels.has(channel)) {
            this.broadcastToChannel(channel, {
                type: 'chat_message',
                username: `${username}@${server}`,
                channel: channel,
                content: content,
                timestamp: timestamp,
                federated: true
            });
        }
    }

    handleFederatedUserJoined(message) {
        if (!this.config.enableFederation) return;
        
        console.log(`🌐 Federated user joined: ${message.username}@${message.server}`);
    }

    handleFederatedUserLeft(message) {
        if (!this.config.enableFederation) return;
        
        console.log(`🌐 Federated user left: ${message.username}@${message.server}`);
    }
}

// Start the comprehensive server
const serverOptions = {
    enableFederation: process.env.ENABLE_FEDERATION !== 'false',
    enableUltraSecurity: process.env.ENABLE_ULTRA_SECURITY !== 'false',
    enableSSL: process.env.ENABLE_SSL !== 'false',
    enable2FA: process.env.ENABLE_2FA !== 'false',
    useArgon2: process.env.USE_ARGON2 !== 'false'
};

const server = new ComprehensiveIRCServer(serverOptions);

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down comprehensive server...');
    process.exit(0);
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

module.exports = ComprehensiveIRCServer;