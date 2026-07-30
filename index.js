require('dotenv').config();
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const CSRF_SECRET = process.env.CSRF_SECRET || crypto.randomBytes(32).toString('hex');
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET;

// ═══════════════════════════════════════════
//  SEGURIDAD: Headers HTTP (Helmet)
// ═══════════════════════════════════════════
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "https://challenges.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "fonts.googleapis.com"],
            fontSrc: ["'self'", "fonts.gstatic.com", "cdn.jsdelivr.net"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'", "https://challenges.cloudflare.com"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "same-origin" },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
}));

// ═══════════════════════════════════════════
//  SEGURIDAD: CORS — solo mismo origen
// ═══════════════════════════════════════════
const allowedOrigins = ['http://localhost:' + PORT, 'https://tigerdevlabs.up.railway.app'];
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('No permitido por CORS'));
        }
    },
    methods: ['GET', 'POST'],
    credentials: true,
}));

// ═══════════════════════════════════════════
//  SEGURIDAD: Cookies seguras y parseo
// ═══════════════════════════════════════════
app.use(cookieParser());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ═══════════════════════════════════════════
//  SEGURIDAD: Ocultar tecnología del servidor
// ═══════════════════════════════════════════
app.disable('x-powered-by');

// ═══════════════════════════════════════════
//  SEGURIDAD: Rate Limit global
// ═══════════════════════════════════════════
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Demasiadas solicitudes. Intenta de nuevo en unos minutos.' },
    validate: false,
});
app.use(globalLimiter);

// ═══════════════════════════════════════════
//  SEGURIDAD: Rate Limit estricto para contacto
// ═══════════════════════════════════════════
const contactLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Ya enviaste varios mensajes. Intenta de nuevo en 1 hora.' },
    validate: { xForwardedForHeader: false, default: true },
});

// ═══════════════════════════════════════════
//  SEGURIDAD: Generación y validación CSRF
// ═══════════════════════════════════════════
function generateCsrfToken(sessionId) {
    const hmac = crypto.createHmac('sha256', CSRF_SECRET);
    hmac.update(sessionId + ':' + Math.floor(Date.now() / 3600000));
    return hmac.digest('hex');
}

function validateCsrfToken(token, sessionId) {
    const currentHour = Math.floor(Date.now() / 3600000);
    for (let i = 0; i <= 1; i++) {
        const hmac = crypto.createHmac('sha256', CSRF_SECRET);
        hmac.update(sessionId + ':' + (currentHour - i));
        if (crypto.timingSafeEqual(Buffer.from(hmac.digest('hex')), Buffer.from(token || ''))) {
            return true;
        }
    }
    return false;
}

function ensureSessionId(req, res) {
    let sid = req.cookies._sid;
    if (!sid) {
        sid = crypto.randomBytes(16).toString('hex');
        res.cookie('_sid', sid, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 24 * 60 * 60 * 1000,
        });
    }
    return sid;
}

// ═══════════════════════════════════════════
//  SEGURIDAD: Validación Cloudflare Turnstile
// ═══════════════════════════════════════════
async function verifyTurnstile(token) {
    if (!token) return false;
    try {
        const formData = new URLSearchParams();
        formData.append('secret', TURNSTILE_SECRET);
        formData.append('response', token);
        const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            body: formData
        });
        const outcome = await result.json();
        return outcome.success;
    } catch (err) {
        console.error('Error validando Turnstile:', err.message);
        return false;
    }
}

// ═══════════════════════════════════════════
//  SEGURIDAD: Sanitización contra XSS/Injection
// ═══════════════════════════════════════════
function sanitize(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;')
        .trim()
        .slice(0, 1000);
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

// ═══════════════════════════════════════════
//  SMTP: Configuración de Nodemailer
// ═══════════════════════════════════════════
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT, 10),
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

// ═══════════════════════════════════════════
//  ARCHIVOS ESTÁTICOS
// ═══════════════════════════════════════════
app.use(express.static(path.join(__dirname, 'public'), {
    dotfiles: 'deny',
    index: false,
}));

// ═══════════════════════════════════════════
//  RUTA: Página principal
// ═══════════════════════════════════════════
const homepageFile = 'TigerDevLabs.html';

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', homepageFile));
});

// ═══════════════════════════════════════════
//  API: Obtener token CSRF
// ═══════════════════════════════════════════
app.get('/api/csrf-token', (req, res) => {
    const sid = ensureSessionId(req, res);
    const token = generateCsrfToken(sid);
    res.json({ token });
});

// ═══════════════════════════════════════════
//  API: Enviar mensaje de contacto
// ═══════════════════════════════════════════
app.post('/api/contacto', contactLimiter, async (req, res) => {
    try {
        const sid = req.cookies._sid;
        const csrfToken = req.headers['x-csrf-token'];

        if (!sid || !csrfToken) {
            return res.status(403).json({ error: 'Sesión inválida. Recarga la página.' });
        }

        let isValid;
        try {
            isValid = validateCsrfToken(csrfToken, sid);
        } catch {
            isValid = false;
        }
        if (!isValid) {
            return res.status(403).json({ error: 'Token de seguridad inválido. Recarga la página.' });
        }

        if (req.body._website) {
            return res.json({ ok: true });
        }

        const turnstileToken = req.body.turnstile;
        if (!await verifyTurnstile(turnstileToken)) {
            return res.status(403).json({ error: 'Fallo la verificación de seguridad (antibot). Por favor intenta de nuevo.' });
        }

        const nombre = sanitize(req.body.nombre);
        const email = sanitize(req.body.email);
        const mensaje = sanitize(req.body.mensaje);

        if (!nombre || nombre.length < 2) {
            return res.status(400).json({ error: 'Nombre inválido.' });
        }
        if (!isValidEmail(email)) {
            return res.status(400).json({ error: 'Correo inválido.' });
        }
        if (!mensaje || mensaje.length < 10) {
            return res.status(400).json({ error: 'El mensaje es muy corto (mínimo 10 caracteres).' });
        }

        await transporter.sendMail({
            from: `"Tiger DevLabs Contacto" <${process.env.SMTP_USER}>`,
            to: process.env.CONTACT_EMAIL,
            replyTo: email,
            subject: `📬 Nuevo mensaje de ${nombre} — Tiger DevLabs`,
            text: `Nombre: ${nombre}\nCorreo: ${email}\n\nMensaje:\n${mensaje}`,
            html: `
                <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;background:#0d0d16;color:#e9e9f1;border-radius:16px;">
                    <h2 style="color:#22d3ee;margin-bottom:4px;">📬 Nuevo mensaje de contacto</h2>
                    <hr style="border-color:#222;">
                    <p><strong style="color:#c084fc;">Nombre:</strong> ${nombre}</p>
                    <p><strong style="color:#c084fc;">Correo:</strong> <a href="mailto:${email}" style="color:#22d3ee;">${email}</a></p>
                    <p><strong style="color:#c084fc;">Mensaje:</strong></p>
                    <div style="background:#07070b;padding:16px;border-radius:12px;border:1px solid #333;white-space:pre-wrap;">${mensaje}</div>
                    <p style="color:#6b7280;font-size:12px;margin-top:20px;">Enviado desde el formulario de tigerdevlabs.com</p>
                </div>
            `,
        });

        res.json({ ok: true });
    } catch (err) {
        console.error('Error al enviar correo:', err.message);
        res.status(500).json({ error: 'Error al enviar el mensaje. Intenta de nuevo.' });
    }
});

// ═══════════════════════════════════════════
//  SEGURIDAD: Bloquear rutas no definidas
// ═══════════════════════════════════════════
app.use((req, res) => {
    res.status(404).json({ error: 'Recurso no encontrado.' });
});

// ═══════════════════════════════════════════
//  SEGURIDAD: Manejador global de errores
// ═══════════════════════════════════════════
app.use((err, req, res, next) => {
    console.error('Error interno:', err.message);
    res.status(500).json({ error: 'Error interno del servidor.' });
});

app.listen(PORT, () => {
    console.log(`\n🚀 Servidor encendido en http://localhost:${PORT}`);
    console.log(`🛡️  Seguridad activa: Helmet, CORS, CSRF, Rate-Limit, Sanitización`);
    console.log(`📬 Los mensajes se enviarán a: ${process.env.CONTACT_EMAIL}\n`);
});
