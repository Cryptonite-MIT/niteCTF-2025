const express = require('express');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const path = require('path');



const app = express();
const PORT = process.env.PORT || 3000;
const FLAG = process.env.FLAG || 'nite{ihaventlookedatthesunforsooolooong}';
const BOT_URL = process.env.BOT_URL


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


const sess = new Map();
const toks = new Map();

function gen() {
    return crypto.randomBytes(32).toString('hex');
}

function auth(req, res, next) {
    const s = req.cookies.session;
    if (!s || !sess.has(s)) {
        return res.redirect('/login');
    }
    req.user = sess.get(s);
    next();
}


const data = new Map();
const limits = new Map();
const WINDOW = 30000;

function check(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();

    if (limits.has(ip)) {
        const last = limits.get(ip);
        if (now - last < WINDOW) {
            const wait = Math.ceil((WINDOW - (now - last)) / 1000);
            return res.status(429).json({
                success: false,
                error: `Rate limit exceeded. Wait ${wait}s`
            });
        }
    }

    limits.set(ip, now);
    next();
}



app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const { username, password, leakUrl } = req.body;
    

    if (username === 'user' && password === 'demo123') {
      
        const s = gen();
        const t = gen();

        const botSecret = process.env.BOT_SECRET;
        if (!botSecret) {
            console.error('[CRITICAL] BOT_SECRET environment variable not set');
            return res.status(500).send('Server misconfiguration');
        }

        const providedSecret = req.headers['x-bot-secret'];
        const isBot = providedSecret === botSecret;

        sess.set(s, {
            username: 'user',
            email: 'user@nitevault.com',
            role: 'security-analyst',
            authToken: t,
            flag: isBot ? FLAG : null,
            leakUrl: leakUrl || null
        });

        toks.set(t, {
            sessionToken: s,
            createdAt: Date.now()
        });

        const cb = `/auth/callback?token=${t}`;
        res.redirect(cb);
    } else {
       
        res.render('login', { error: 'Invalid credentials' });
    }
});

app.get('/auth/callback', (req, res) => {
    const { token } = req.query;

    if (!token || !toks.has(token)) {
        return res.redirect('/login');
    }

    const td = toks.get(token);
    const s = td.sessionToken;
    const sessionData = sess.get(s);
    const leakUrl = sessionData?.leakUrl;

    res.cookie('session', s, { httpOnly: true });

    const csp = leakUrl
        ? "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src * data:; connect-src 'none'; frame-src 'none'"
        : "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; frame-src 'none'";

    res.setHeader('Content-Security-Policy', csp);

    const leakImage = leakUrl ? `<img src="${leakUrl.replace(/"/g, '&quot;')}" style="display:none">` : '';

    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Authenticating...</title>
      <meta http-equiv="refresh" content="2;url=/dashboard">
    </head>
    <body>
      <div>
        <p>Authentication successful! Redirecting...</p>
      </div>
      ${leakImage}
    </body>
    </html>
  `);
});

app.get('/dashboard', auth, (req, res) => {
    if (req.user.flag) {
        res.render('admin-dashboard', { user: req.user });
    } else {
        res.render('dashboard', { user: req.user });
    }
});

app.post('/auth/session/validate', express.json(), (req, res) => {
    const { token } = req.body;

    if (!token || !toks.has(token)) {
        return res.status(400).json({ error: 'Invalid token' });
    }

    const td = toks.get(token);

    if (Date.now() - td.createdAt > 60000) {
        toks.delete(token);
        return res.status(400).json({ error: 'Token expired' });
    }

    const s = td.sessionToken;
    if (!sess.has(s)) {
        return res.status(400).json({ error: 'Session not found' });
    }

    const sd = sess.get(s);

    if (!sd.flag) {
        return res.status(403).json({
            error: 'Unauthorized',
            message: 'This endpoint is only accessible by the admin bot'
        });
    }

    res.json({
        user: {
            username: sd.username,
            email: sd.email,
            role: sd.role
        },
        flag: sd.flag
    });
});

app.get('/logout', (req, res) => {
    const s = req.cookies.session;
    if (s) {
        sess.delete(s);
    }
    res.clearCookie('session');
    res.redirect('/login');
});



app.get('/submit', (req, res) => {
    res.render('index');
});

app.post('/submit', check, async (req, res) => {
    const { url } = req.body;
   

    if (!url) {
       return res.status(400).json({ success: false, error: 'Missing URL' });
    }

    try {
        const parsed = new URL(url);
        if (!['http:', 'https:'].includes(parsed.protocol)) {
           return res.status(400).json({ success: false, error: 'Invalid protocol' });
        }
    } catch (error) {
       return res.status(400).json({ success: false, error: 'Invalid URL' });
    }

    const id = uuidv4();

    data.set(id, {
        status: 'running',
        url: url,
        startTime: new Date()
    });

    handle(id, url);

    res.json({
        success: true,
        id: id
    });
});

app.get('/status/:id', (req, res) => {
    const id = req.params.id;

    if (!data.has(id)) {
        return res.status(404).json({ success: false, error: 'Not found' });
    }

    res.json(data.get(id));
});

app.get('/result/:id', (req, res) => {
    const id = req.params.id;

    if (!data.has(id)) {
        return res.status(404).send('Not found');
    }

    const review = data.get(id);
    res.render('result', { review: review });
});

async function handle(id, url) {
    try {
        const targetUrl = `${BOT_URL}/simulate`;
        
        const resp = await axios.post(targetUrl, {
            attackerUrl: url
        }, {
            timeout: 60000
        });

        const result = resp.data;

        data.set(id, {
            status: 'completed',
            url: url,
            success: result.success,
            vulnerable: result.vulnerable,
            error: result.error,
            completedTime: new Date()
        });

    } catch (error) {
        let errorDetails = error.message;
        if (error.response) {
            errorDetails += ` (Status: ${error.response.status}, Data: ${JSON.stringify(error.response.data)})`;
        } else if (error.request) {
            errorDetails += ' (No response received)';
        }


        data.set(id, {
            status: 'error',
            url: url,
            error: errorDetails,
            completedTime: new Date()
        });
    }
}

app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});


app.listen(PORT, () => {
    console.log(`Consolidated web service running on port ${PORT}`);
    console.log(`Bot service URL: ${BOT_URL}`);
});

module.exports = app;
