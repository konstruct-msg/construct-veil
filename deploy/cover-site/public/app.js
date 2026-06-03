// ── Live workshop feed (SSE) ────────────────────────────────────────────
const feedEl    = document.getElementById('feed');
const statusEl  = document.getElementById('connection-status');
const countEl   = document.getElementById('active-count');

if (feedEl && statusEl) {
  const orders = new Set();
  const evt = new EventSource('/api/feed');

  const fmt = (ts) => new Date(ts).toLocaleTimeString('ru-RU', {
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });

  evt.onopen = () => {
    statusEl.textContent = '● в эфире';
    statusEl.style.color = '#5a7a2f';
  };

  evt.onmessage = (ev) => {
    let data;
    try { data = JSON.parse(ev.data); } catch (_) { return; }
    if (data.type === 'connected') return;

    if (data.type === 'new_order')  orders.add(data.order);
    if (data.type === 'completion') orders.delete(data.order);
    if (data.type === 'stage_update') orders.add(data.order);

    countEl.textContent = `${orders.size} заказ${plural(orders.size)} в работе`;

    const row = document.createElement('div');
    row.className = 'event ' + data.type;

    const ord = `<span class="ord">${escapeHtml(data.order)}</span>`;
    const ts  = `<span class="ts">${fmt(data.ts)}</span>`;
    let mid;
    if (data.type === 'new_order') {
      mid = `<span class="stage">${escapeHtml(data.item)} → ${escapeHtml(data.city)}</span>`;
    } else if (data.type === 'completion') {
      mid = `<span class="stage">${escapeHtml(data.item)}</span>`;
    } else {
      mid = `<span class="stage">${escapeHtml(data.item)} — ${escapeHtml(data.stage)}</span>`;
    }
    row.innerHTML = ord + mid + ts;
    feedEl.insertBefore(row, feedEl.firstChild);
    while (feedEl.children.length > 30) feedEl.removeChild(feedEl.lastChild);
  };

  evt.onerror = () => {
    statusEl.textContent = '○ переподключение…';
    statusEl.style.color = '#a4422a';
  };
}

function plural(n) {
  const m10 = n % 10, m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return '';
  if (m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20)) return 'а';
  return 'ов';
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[c]);
}

// ── Contact form ────────────────────────────────────────────────────────
const form    = document.getElementById('contact-form');
const formStatus = document.getElementById('form-status');

if (form && formStatus) {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const button = form.querySelector('button[type=submit]');
    button.disabled = true;
    formStatus.className = 'form-status';
    formStatus.textContent = 'Отправляем…';

    const payload = {
      name: form.name.value.trim(),
      phone: form.phone.value.trim(),
      message: form.message.value.trim(),
    };

    try {
      const r = await fetch('/api/contact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await r.json().catch(() => ({}));
      if (r.ok && data.ok) {
        formStatus.className = 'form-status ok';
        formStatus.textContent = data.message || 'Заявка принята.';
        form.reset();
      } else {
        formStatus.className = 'form-status error';
        formStatus.textContent = 'Не удалось отправить. Попробуйте ещё раз или позвоните напрямую.';
      }
    } catch (_) {
      formStatus.className = 'form-status error';
      formStatus.textContent = 'Сеть недоступна. Проверьте подключение.';
    } finally {
      button.disabled = false;
    }
  });
}
