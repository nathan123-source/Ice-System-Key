const http = require('http');
const fs = require('fs');
const url = require('url');
const crypto = require('crypto');

const PORT = 3000;
const KEYS_FILE = 'keys.json';
const USERS_FILE = 'users.json';
const SERVICES_FILE = 'services.json';

function loadFile(filename, defaultData) {
    try {
        if (fs.existsSync(filename)) {
            return JSON.parse(fs.readFileSync(filename, 'utf8'));
        } else {
            fs.writeFileSync(filename, JSON.stringify(defaultData, null, 2));
            return defaultData;
        }
    } catch (error) {
        console.error(`Erro ao carregar ${filename}:`, error);
        return defaultData;
    }
}

function saveFile(filename, data) {
    try {
        fs.writeFileSync(filename, JSON.stringify(data, null, 2));
    } catch (error) {
        console.error(`Erro ao salvar ${filename}:`, error);
    }
}

let keys = loadFile(KEYS_FILE, []);
let users = loadFile(USERS_FILE, []);
let services = loadFile(SERVICES_FILE, []);

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function getUserByToken(token) {
    return users.find(u => u.token === token);
}

const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }
    
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;
    
    console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${pathname}`);
    
    if (pathname === '/register' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            try {
                const payload = JSON.parse(body || '{}');
                const username = (payload.username || '').toString().trim();
                const password = (payload.password || '').toString();
                const email = (payload.email || '').toString().trim();

                if (!username || !password || !email) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Campos faltando: username, email e password são obrigatórios.' }));
                    return;
                }

                if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Usuário já existe!' }));
                    return;
                }

                const newUser = {
                    id: Date.now().toString(),
                    username,
                    email,
                    password: hashPassword(password),
                    token: generateToken(),
                    createdAt: new Date().toISOString()
                };
                
                users.push(newUser);
                saveFile(USERS_FILE, users);
                
                console.log(`✅ Novo usuário: ${username}`);
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ 
                    success: true, 
                    token: newUser.token,
                    username: newUser.username,
                    userId: newUser.id
                }));
            } catch (error) {
                console.error('register error:', error);
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Erro no registro', error: error.message }));
            }
        });
        return;
    }
    
    if (pathname === '/login' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            try {
                const payload = JSON.parse(body || '{}');
                const username = (payload.username || '').toString().trim();
                const password = (payload.password || '').toString();

                if (!username || !password) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Campos faltando: username e password são obrigatórios.' }));
                    return;
                }

                const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());

                if (!user || user.password !== hashPassword(password)) {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Usuário ou senha incorretos!' }));
                    return;
                }

                user.token = generateToken();
                saveFile(USERS_FILE, users);

                console.log(`✅ Login: ${username}`);

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ 
                    success: true, 
                    token: user.token,
                    username: user.username,
                    userId: user.id
                }));
            } catch (error) {
                console.error('login error:', error);
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Erro no login', error: error.message }));
            }
        });
        return;
    }
    
    if (pathname === '/verify-token' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            try {
                const payload = JSON.parse(body || '{}');
                const token = (payload.token || '').toString();
                const user = getUserByToken(token);

                if (user) {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: true, 
                        username: user.username,
                        userId: user.id
                    }));
                } else {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Token inválido' }));
                }
            } catch (error) {
                console.error('verify-token error:', error);
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Erro ao verificar token', error: error.message }));
            }
        });
        return;
    }
    
    if (pathname === '/verify' && req.method === 'GET') {
        const keyCode = parsedUrl.query.key;
        const hwid = parsedUrl.query.hwid;
        const token = parsedUrl.query.token;
        const serviceId = parsedUrl.query.serviceId;

        // Log basic request info for debugging (mask token)
        const maskedToken = token ? (token.slice(0,6) + '...' + token.slice(-6)) : null;
        console.log(`🔍 /verify req - url=${req.url} | key=${keyCode} | hwid=${hwid} | token=${maskedToken} | serviceId=${serviceId}`);
        // Also log a few headers that may help diagnosing hosting/proxy issues
        console.log('headers:', {
            host: req.headers.host,
            'user-agent': req.headers['user-agent'],
            accept: req.headers.accept
        });

        if (!keyCode || !hwid || !token || !serviceId) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ valid: false, message: 'Parâmetros faltando' }));
            return;
        }

        const user = getUserByToken(token);
        if (!user) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ valid: false, message: 'Token inválido' }));
            return;
        }

        const key = keys.find(k => k.code === keyCode);

        if (!key) {
            console.log('❌ Key não encontrada');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ valid: false, message: '❌ Key inválida!' }));
            return;
        }

        // Ensure the key belongs to the authenticated user
        if (key.ownerId !== user.id) {
            console.log('🚫 Key pertence a outro usuário');
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ valid: false, message: '🔒 Esta key não pertence ao usuário autenticado.' }));
            return;
        }

        // Ensure the key is for the requested service
        if (!key.serviceId || key.serviceId !== serviceId) {
            console.log('🚫 Key não pertence ao serviço solicitado');
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ valid: false, message: '🔒 Esta key não é válida para este serviço.' }));
            return;
        }

        if (key.expirationDate && new Date() > new Date(key.expirationDate)) {
            console.log('⏰ Key expirada');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ valid: false, message: '⏰ Key expirou!' }));
            return;
        }

        if (!key.hwid) {
            key.hwid = hwid;
            key.firstUsed = new Date().toISOString();
            saveFile(KEYS_FILE, keys);
            console.log('✅ HWID vinculado');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ valid: true, message: '✅ Key validada!' }));
            return;
        }

        if (key.hwid === hwid) {
            console.log('✅ Key válida');
            key.lastUsed = new Date().toISOString();
            saveFile(KEYS_FILE, keys);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ valid: true, message: '✅ Key validada!' }));
            return;
        } else {
            console.log('🔒 HWID diferente');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ 
                valid: false, 
                message: 'Essa key já está sendo usada',
                reason: 'hwid_mismatch'
            }));
            return;
        }
    }
    
    if (pathname === '/keys' && req.method === 'GET') {
        const token = parsedUrl.query.token;
        const user = getUserByToken(token);

        if (!user) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false }));
            return;
        }

        const serviceId = parsedUrl.query.serviceId;

        const userKeys = keys.filter(k => k.ownerId === user.id && (!serviceId || k.serviceId === serviceId));

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(userKeys));
        return;
    }
    
    if (pathname === '/addkey' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            try {
                const data = JSON.parse(body);
                const user = getUserByToken(data.token);
                
                if (!user) {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false }));
                    return;
                }
                
                const newKey = {
                    code: data.code,
                    name: data.name,
                    serviceId: data.serviceId || null,
                    ownerId: user.id,
                    ownerUsername: user.username,
                    hwid: null,
                    expirationDate: data.expirationDate,
                    createdAt: new Date().toISOString()
                };
                
                keys.push(newKey);
                saveFile(KEYS_FILE, keys);
                
                console.log(`✅ Key criada: ${newKey.code} por ${user.username}`);
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, key: newKey }));
            } catch (error) {
                console.error('Erro ao criar key:', error);
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
        return;
    }
    
    if (pathname === '/deletekey' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            try {
                const data = JSON.parse(body);
                const user = getUserByToken(data.token);
                
                if (!user) {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false }));
                    return;
                }
                
                const index = keys.findIndex(k => k.code === data.code && k.ownerId === user.id);
                
                if (index !== -1) {
                    keys.splice(index, 1);
                    saveFile(KEYS_FILE, keys);
                    console.log(`🗑️ Key deletada: ${data.code}`);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true }));
                } else {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false }));
                }
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false }));
            }
        });
        return;
    }
    
    if (pathname === '/reset-hwid' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            try {
                const data = JSON.parse(body);
                const user = getUserByToken(data.token);
                
                if (!user) {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false }));
                    return;
                }
                
                const key = keys.find(k => k.code === data.code && k.ownerId === user.id);
                
                if (key) {
                    key.hwid = null;
                    saveFile(KEYS_FILE, keys);
                    console.log(`🔄 HWID resetado: ${data.code}`);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true }));
                } else {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false }));
                }
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false }));
            }
        });
        return;
    }

    // Services endpoints
    if (pathname === '/services' && req.method === 'GET') {
        const token = parsedUrl.query.token;
        const user = getUserByToken(token);
        if (!user) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false }));
            return;
        }

        const userServices = services.filter(s => s.ownerId === user.id);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(userServices));
        return;
    }

    if (pathname === '/addservice' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            try {
                const data = JSON.parse(body);
                const user = getUserByToken(data.token);
                if (!user) {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false }));
                    return;
                }

                const newService = {
                    id: Date.now().toString(),
                    name: data.name,
                    ownerId: user.id,
                    ownerUsername: user.username,
                    createdAt: new Date().toISOString()
                };

                services.push(newService);
                saveFile(SERVICES_FILE, services);

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, service: newService }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false }));
            }
        });
        return;
    }

    if (pathname === '/deleteservice' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            try {
                const data = JSON.parse(body);
                const user = getUserByToken(data.token);
                if (!user) {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false }));
                    return;
                }

                const index = services.findIndex(s => s.id === data.serviceId && s.ownerId === user.id);
                if (index !== -1) {
                    // remove service
                    services.splice(index, 1);
                    // remove keys for this service
                    keys = keys.filter(k => k.serviceId !== data.serviceId);
                    saveFile(SERVICES_FILE, services);
                    saveFile(KEYS_FILE, keys);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true }));
                } else {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false }));
                }
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false }));
            }
        });
        return;
    }
    
    if (pathname === '/ping') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'online' }));
        return;
    }

    if (pathname === '/status' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', users: users.length, keys: keys.length, services: services.length }));
        return;
    }
    
    if (pathname === '/' || pathname === '/index.html') {
        fs.readFile('index.html', (err, data) => {
            if (err) {
                res.writeHead(404, { 'Content-Type': 'text/html' });
                res.end('<h1>404</h1>');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
        return;
    }
    
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: '404' }));
});

server.listen(PORT, () => {
    console.log('\n╔════════════════════════════════════════╗');
    console.log('║   🔐 SERVIDOR INICIADO! 🔐            ║');
    console.log('╠════════════════════════════════════════╣');
    console.log(`║  🌐 http://localhost:${PORT}              ║`);
    console.log(`║  👥 Usuários: ${users.length}                       ║`);
    console.log(`║  🔑 Keys: ${keys.length}                           ║`);
    console.log('╚════════════════════════════════════════╝\n');
});

server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
        console.error(`❌ Porta ${PORT} em uso!`);
    }
    process.exit(1);
});