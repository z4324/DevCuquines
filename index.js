require('dotenv').config();
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const WHATSAPP_NUMBER = process.env.WHATSAPP_NUMBER;
const WHATSAPP_MESSAGE = 'Hola, quiero información sobre sus servicios de Tiger DevLabs.';

// ═══════════════════════════════════════════
//  SEGURIDAD: Headers HTTP (Helmet)
// ═══════════════════════════════════════════
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
            styleSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "fonts.googleapis.com"],
            fontSrc: ["'self'", "fonts.gstatic.com", "cdn.jsdelivr.net"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'", "cdn.jsdelivr.net"],
            frameSrc: ["'none'"],
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
//  SEGURIDAD: CORS — orígenes permitidos
// ═══════════════════════════════════════════
const allowedOriginPatterns = [
    /^http:\/\/localhost:\d+$/,
    /^https:\/\/(www\.)?tigerdevlabs\.lat$/,
    /^https:\/\/.+\.up\.railway\.app$/,
];
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOriginPatterns.some((pattern) => pattern.test(origin))) {
            callback(null, true);
        } else {
            callback(new Error('No permitido por CORS'));
        }
    },
    methods: ['GET', 'OPTIONS'],
}));

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
//  ARCHIVOS ESTÁTICOS
// ═══════════════════════════════════════════
app.use(express.static(path.join(__dirname, 'public'), {
    dotfiles: 'deny',
    index: false,
}));

// ═══════════════════════════════════════════
//  RUTA: Página principal
// ═══════════════════════════════════════════
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'TigerDevLabs.html'));
});

// ═══════════════════════════════════════════
//  RUTA: Redirección a WhatsApp (número no expuesto en el HTML)
// ═══════════════════════════════════════════
app.get('/ir/whatsapp', (req, res) => {
    if (!WHATSAPP_NUMBER) {
        return res.status(503).json({ error: 'WhatsApp no configurado.' });
    }
    const url = `https://wa.me/${WHATSAPP_NUMBER}?text=${encodeURIComponent(WHATSAPP_MESSAGE)}`;
    res.redirect(302, url);
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
    console.log(`🛡️  Seguridad activa: Helmet, CORS, Rate-Limit`);
    console.log(`💬 WhatsApp configurado: ${WHATSAPP_NUMBER ? 'sí' : 'NO — falta WHATSAPP_NUMBER en .env'}\n`);
});
