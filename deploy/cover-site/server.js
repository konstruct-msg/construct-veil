/*
 * Диваны и Кресла — cover-site for veil-front.
 *
 *  :80   — host-exposed. ACME http-01 challenge + 301 redirect to https.
 *  :8080 — internal (docker network). Landing + SSE production tracker +
 *          contact form endpoint. Upstream for veil-front-relay's --site flag.
 */

const express = require('express');
const path = require('path');
const fs = require('fs');

const ACME_ROOT  = '/var/www/certbot';
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR   = path.join(__dirname, 'data');

// ── :80 — ACME + redirect ───────────────────────────────────────────────────

const acme = express();

acme.use('/.well-known/acme-challenge', express.static(
  path.join(ACME_ROOT, '.well-known/acme-challenge'),
  { dotfiles: 'allow', fallthrough: false }
));

acme.use((req, res) => {
  const host = (req.headers.host || '').split(':')[0];
  res.redirect(301, `https://${host}${req.originalUrl}`);
});

acme.listen(80, '0.0.0.0', () => {
  console.log('[acme]   listening on :80 (challenge + redirect)');
});

// ── :8080 — main site (relay upstream) ──────────────────────────────────────

const app = express();
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

app.use('/.well-known', express.static(path.join(PUBLIC_DIR, '.well-known'), {
  dotfiles: 'allow',
  setHeaders: (res, p) => {
    if (p.endsWith('security.txt')) res.setHeader('Content-Type', 'text/plain');
  },
}));

// Host-aware root: a real workshop would have `api.<domain>` serve a JSON
// "what is this" response rather than the marketing landing. Hitting api.* in
// a browser and getting the same shop landing as the apex would look odd to
// a curious inspector. Root domain → landing; api.* → minimal JSON pointing
// back at root. All other paths (assets, /api/feed, /api/contact) fall
// through to the normal handlers below regardless of host.
app.get('/', (req, res, next) => {
  const host = (req.headers.host || '').toLowerCase().split(':')[0];
  if (host.startsWith('api.')) {
    return res.json({
      service: 'divany-kresla-api',
      version: '1.0.0',
      endpoints: ['/api/feed', '/api/contact', '/api/status'],
      docs: `https://${host.replace(/^api\./, '')}/about`,
    });
  }
  return next();
});

// `extensions: ['html']` lets clean URLs like /about resolve to /about.html
// without needing the extension — what real sites do.
app.use(express.static(PUBLIC_DIR, { extensions: ['html'] }));

// ── Production tracker data ────────────────────────────────────────────────

let items, stages, cities;
try {
  const data = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'items.json'), 'utf8'));
  items  = data.items;
  stages = data.stages;
  cities = data.cities;
} catch (_) {
  // Inline fallback so the cover-site is self-contained.
  items = [
    'кресло «Версаль»',
    'кресло «Лондон»',
    'диван 2-местный «Челси»',
    'диван 3-местный «Кенсингтон»',
    'банкетка «Мэйфэр»',
    'кресло-качалка «Кэмден»',
    'пуф «Сохо»',
    'кресло «Виндзор»',
    'диван угловой «Гайд-парк»',
    'оттоманка «Бэйкер-стрит»',
  ];
  stages = [
    'каркас',
    'набивка',
    'обтяжка',
    'фурнитура',
    'упаковка',
    'отгрузка',
  ];
  cities = [
    'Лондон',
    'Манчестер',
    'Бирмингем',
    'Эдинбург',
    'Глазго',
    'Бристоль',
    'Лидс',
    'Ливерпуль',
  ];
}

const orderCode = () =>
  'DK-' + (4200 + Math.floor(Math.random() * 600)).toString();

const pick = (a) => a[Math.floor(Math.random() * a.length)];

const eventTypes = ['stage_update', 'stage_update', 'stage_update', 'new_order', 'completion'];

function nextEvent() {
  const type = pick(eventTypes);
  if (type === 'new_order') {
    return {
      type,
      order: orderCode(),
      item: pick(items),
      city: pick(cities),
      ts: Date.now(),
    };
  }
  if (type === 'completion') {
    return {
      type,
      order: orderCode(),
      item: pick(items),
      ts: Date.now(),
    };
  }
  return {
    type: 'stage_update',
    order: orderCode(),
    item: pick(items),
    stage: pick(stages),
    ts: Date.now(),
  };
}

// SSE — live workshop tracker. Auto-opens on every landing page load → long-lived H2.
app.get('/api/feed', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  res.write(`data: ${JSON.stringify({ type: 'connected', ts: Date.now() })}\n\n`);

  let timer;
  const tick = () => {
    res.write(`data: ${JSON.stringify(nextEvent())}\n\n`);
    timer = setTimeout(tick, 2500 + Math.random() * 3500);   // 2.5–6 s
  };
  tick();

  const heartbeat = setInterval(() => res.write(': keepalive\n\n'), 15000);

  req.on('close', () => {
    clearTimeout(timer);
    clearInterval(heartbeat);
    res.end();
  });
});

// Contact form — accepts name + phone + (optional) message. No DB; logs to
// stdout and returns 200. A real workshop would send these to an email or
// CRM, but for the cover narrative "submitted, we'll be in touch" suffices.
app.post('/api/contact', (req, res) => {
  const { name, phone, message } = req.body || {};
  if (!name || !phone) {
    return res.status(400).json({ ok: false, error: 'name_and_phone_required' });
  }
  const safe = (s) => String(s || '').slice(0, 200).replace(/[\r\n]/g, ' ');
  console.log(
    `[contact] name=${safe(name)} phone=${safe(phone)} ` +
    `message=${safe(message)} ts=${new Date().toISOString()}`
  );
  res.json({ ok: true, message: 'Заявка принята, перезвоним в течение дня.' });
});

app.get('/api/status', (req, res) => {
  res.json({ status: 'ok', uptime: Math.round(process.uptime()), version: '1.0.0' });
});

app.listen(8080, '0.0.0.0', () => {
  console.log('[site]   listening on :8080 (landing + SSE + contact)');
});
