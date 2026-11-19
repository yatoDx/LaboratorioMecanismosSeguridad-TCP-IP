/* Cliente web (sin frameworks). Todo el contenido que viene de la API se inserta
   con textContent / createTextNode: nunca con innerHTML. */
'use strict';

const $ = (sel, root = document) => root.querySelector(sel);
const fmt = (iso) => (iso ? new Date(iso).toLocaleString('es-CO') : '—');
const STATUS = { pending: 'pendiente', approved: 'aprobado', denied: 'rechazado', revoked: 'revocado', expired: 'vencido' };
const ACTIONS = {
  grant_requested: 'pidió permiso', grant_approved: 'permiso aprobado', grant_denied: 'permiso rechazado',
  grant_revoked: 'permiso revocado', grant_cancelled_by_watcher: 'el observador canceló',
  location_viewed: 'consultó la ubicación', history_viewed: 'consultó el historial',
  geofence_created: 'creó una zona', sharing_on: 'activó el uso compartido', sharing_off: 'pausó el uso compartido',
};

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, '');
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

let session = null;          // { token, role }
let timers = [];             // se cancelan al cambiar de pantalla
try { session = JSON.parse(sessionStorage.getItem('session') || 'null'); } catch (e) { session = null; }

function saveSession(s) {
  session = s;
  try { s ? sessionStorage.setItem('session', JSON.stringify(s)) : sessionStorage.removeItem('session'); } catch (e) { /* sin almacenamiento */ }
}
function clearTimers() { timers.forEach(clearInterval); timers = []; }

async function api(method, path, body) {
  const headers = {};
  if (session) headers.Authorization = 'Bearer ' + session.token;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  if (r.status === 204) return null;
  let data = null;
  try { data = await r.json(); } catch (e) { /* sin cuerpo */ }
  if (!r.ok) {
    if (r.status === 401 && session) { saveSession(null); render(); }
    const d = data && data.detail;
    throw new Error(typeof d === 'string' ? d : Array.isArray(d) ? d.map((x) => x.msg).join('; ') : 'Error ' + r.status);
  }
  return data;
}

function notice(host, kind, text) {
  const old = $('.msg', host); if (old) old.remove();
  host.prepend(h('div', { class: 'msg ' + kind, role: 'status' }, text));
}
const safe = (host, fn) => async (...a) => { try { await fn(...a); } catch (e) { notice(host, 'err', e.message); } };

/* ------------------------------------------------------------------ acceso */
function renderLogin(app) {
  let step = 1, phone = '', devCode = null;
  const box = h('div', { class: 'card' });
  const draw = () => {
    box.replaceChildren(h('h2', null, 'Ingresar con su número telefónico'));
    if (step === 1) {
      const p = h('input', { id: 'phone', type: 'tel', placeholder: '+573001234567', autocomplete: 'tel', value: phone });
      const role = h('select', { id: 'role' },
        h('option', { value: 'device' }, 'Soy el dueño del teléfono: quiero compartir mi ubicación'),
        h('option', { value: 'viewer' }, 'Quiero ver la ubicación de alguien que me autorice'));
      const label = h('input', { id: 'label', placeholder: 'Mi teléfono', maxlength: 40 });
      box.append(
        h('label', { for: 'phone' }, 'Número (formato internacional)'), p,
        h('label', { for: 'role' }, '¿Qué desea hacer?'), role,
        h('label', { for: 'label' }, 'Nombre del dispositivo (solo si comparte su ubicación)'), label,
        h('p', { class: 'consent-text' }, 'Le enviaremos un código por SMS para comprobar que el número es suyo. Nadie puede ver su ubicación sin que usted lo apruebe.'),
        h('button', {
          id: 'send', onclick: safe(box, async () => {
            phone = p.value;
            const r = await api('POST', '/api/auth/request-code', { phone });
            devCode = r.dev_code || null; step = 2; draw();
            app.dataset.role = role.value; app.dataset.label = label.value;
          }),
        }, 'Enviar código'));
    } else {
      const c = h('input', { id: 'code', inputmode: 'numeric', maxlength: 6, placeholder: '123456', autocomplete: 'one-time-code' });
      box.append(
        h('p', null, 'Código enviado a ', h('b', null, phone), '.'),
        devCode ? h('div', { class: 'msg info' }, 'Modo demostración (sin SMS real): su código es ', h('b', { id: 'devcode' }, devCode)) : null,
        h('label', { for: 'code' }, 'Código de 6 dígitos'), c,
        h('div', { class: 'row' },
          h('button', {
            id: 'verify', onclick: safe(box, async () => {
              const role = app.dataset.role || 'device';
              const r = await api('POST', '/api/auth/verify', { phone, code: c.value, role, device_label: role === 'device' ? (app.dataset.label || undefined) : undefined });
              saveSession({ token: r.token, role: r.role }); render();
            }),
          }, 'Verificar'),
          h('button', { class: 'ghost', onclick: () => { step = 1; draw(); } }, 'Cambiar número')));
    }
  };
  draw();
  app.replaceChildren(box);
}

/* ------------------------------------------------------------- dispositivo */
function getPosition() {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) return reject(new Error('Este navegador no tiene geolocalización'));
    navigator.geolocation.getCurrentPosition((p) => resolve(p.coords),
      (e) => reject(new Error(e.code === 1 ? 'Permiso de ubicación denegado en el navegador' : 'No se pudo obtener la ubicación')),
      { enableHighAccuracy: true, timeout: 15000, maximumAge: 30000 });
  });
}

function renderDevice(app) {
  const root = h('div');
  app.replaceChildren(root);
  let state = null, autoTimer = null;

  const send = async (source, manual) => {
    const body = manual || (({ latitude: lat, longitude: lon, accuracy: accuracy_m }) => ({ lat, lon, accuracy_m }))(await getPosition());
    await api('POST', '/api/device/locations', { ...body, source });
  };

  const refresh = async () => { state = await api('GET', '/api/device/status'); draw(); scheduleAuto(); };

  function scheduleAuto() {
    clearInterval(autoTimer);
    if (state.device.sharing_enabled) {
      autoTimer = setInterval(() => send('periodic').then(refresh).catch((e) => notice(root, 'err', e.message)), state.device.interval_s * 1000);
      timers.push(autoTimer);
    }
  }

  function draw() {
    const d = state.device, active = state.grants.filter((g) => g.status === 'approved');
    const bannerText = d.sharing_enabled
      ? `Se está compartiendo su ubicación cada ${Math.round(d.interval_s / 60)} min con ${active.length} persona(s) autorizada(s).`
      : 'Su ubicación NO se está compartiendo. Nadie puede ver dónde está.';
    const interval = h('select', { id: 'interval' }, [60, 300, 600, 1800, 3600].map((s) =>
      h('option', { value: s, selected: s === d.interval_s }, s < 3600 ? s / 60 + ' min' : '1 hora')));
    const lat = h('input', { id: 'mlat', placeholder: '4.6097' }), lon = h('input', { id: 'mlon', placeholder: '-74.0817' });

    root.replaceChildren(
      h('div', { class: 'banner ' + (d.sharing_enabled ? 'on' : 'off'), id: 'banner' }, bannerText),
      h('div', { class: 'grid' },
        h('div', { class: 'card' },
          h('h2', null, 'Mi dispositivo: ' + d.label),
          h('div', { class: 'kv' }, h('b', null, 'Número'), state.phone, h('b', null, 'Último envío'), fmt(d.last_seen_at)),
          h('label', { for: 'interval' }, 'Enviar cada'), interval,
          h('div', { class: 'row', style: 'margin-top:10px' },
            h('button', {
              id: 'toggle', onclick: safe(root, async () => {
                await api('PUT', '/api/device/sharing', { enabled: !d.sharing_enabled, interval_s: Number(interval.value) });
                if (!d.sharing_enabled) await send('manual').catch((e) => notice(root, 'info', 'Activado. ' + e.message));
                await refresh();
              }),
            }, d.sharing_enabled ? 'Pausar uso compartido' : 'Activar uso compartido'),
            h('button', { id: 'now', class: 'ghost', disabled: !d.sharing_enabled, onclick: safe(root, async () => { await send('manual'); await refresh(); notice(root, 'ok', 'Ubicación enviada.'); }) }, 'Enviar ahora (GPS)')),
          h('details', { style: 'margin-top:10px' }, h('summary', null, 'Enviar coordenadas manuales (pruebas sin GPS)'),
            h('div', { class: 'row' }, h('div', { class: 'grow' }, lat), h('div', { class: 'grow' }, lon),
              h('button', { id: 'manual', class: 'ghost', disabled: !d.sharing_enabled, onclick: safe(root, async () => { await send('manual', { lat: Number(lat.value), lon: Number(lon.value) }); await refresh(); notice(root, 'ok', 'Coordenadas enviadas.'); }) }, 'Enviar'))),
          h('p', { class: 'consent-text' }, 'El uso compartido está apagado hasta que usted lo active. Puede pausarlo o revocar cualquier permiso en cualquier momento.')),
        h('div', { class: 'card' }, h('h2', null, 'Solicitudes de permiso'),
          state.requests.length ? state.requests.map(requestRow) : h('p', { class: 'muted' }, 'No hay solicitudes pendientes.'))),
      h('div', { class: 'grid' },
        h('div', { class: 'card' }, h('h2', null, 'Quién puede ver mi ubicación'),
          state.grants.length ? h('table', null, h('thead', null, h('tr', null, ['Persona', 'Estado', 'Vence', ''].map((t) => h('th', null, t)))),
            h('tbody', null, state.grants.map((g) => h('tr', null,
              h('td', null, g.watcher_phone), h('td', null, h('span', { class: 'pill ' + g.status }, STATUS[g.status])),
              h('td', null, g.status === 'approved' ? fmt(g.expires_at) + (g.share_history ? ' · con historial' : '') : '—'),
              h('td', null, g.status === 'approved' ? h('button', { class: 'danger', onclick: safe(root, async () => { await api('POST', `/api/device/grants/${g.id}/revoke`); await refresh(); }) }, 'Revocar') : null)))))
            : h('p', { class: 'muted' }, 'Nadie tiene acceso.'),
          state.geofences.length ? h('div', null, h('h2', { style: 'margin-top:14px' }, 'Zonas definidas sobre mí'),
            h('ul', { class: 'plain' }, state.geofences.map((z) => h('li', { class: 'row' }, h('span', { class: 'grow' }, `${z.name} (${z.radius_m} m) · de ${z.watcher_phone}`),
              h('button', { class: 'danger', onclick: safe(root, async () => { await api('DELETE', `/api/device/geofences/${z.id}`); await refresh(); }) }, 'Quitar'))))) : null),
        h('div', { class: 'card' }, h('h2', null, 'Registro de actividad'), h('div', { id: 'audit' }, h('p', { class: 'muted' }, 'Cargando…')))),
      h('div', { class: 'card' }, h('h2', null, 'Mis datos'),
        h('div', { class: 'row' },
          h('button', { class: 'danger', onclick: safe(root, async () => { if (confirm('¿Borrar todo su historial de ubicaciones?')) { await api('DELETE', '/api/device/locations'); notice(root, 'ok', 'Historial borrado.'); } }) }, 'Borrar mi historial'),
          h('button', { class: 'danger', onclick: safe(root, async () => { if (confirm('Se borrará su cuenta y todos sus datos. ¿Continuar?')) { await api('DELETE', '/api/me'); saveSession(null); render(); } }) }, 'Eliminar mi cuenta'))));
    api('GET', '/api/device/audit').then((rows) => {
      const box = $('#audit', root); if (!box) return;
      box.replaceChildren(rows.length ? h('ul', { class: 'plain' }, rows.map((r) => h('li', null, h('span', { class: 'muted' }, fmt(r.at) + ' · '), r.action === 'sharing_on' || r.action === 'sharing_off' ? '' : r.who + ' ', ACTIONS[r.action] || r.action, r.detail ? ` (${r.detail})` : ''))) : h('p', { class: 'muted' }, 'Sin actividad todavía.'));
    }).catch(() => {});
  }

  function requestRow(r) {
    const days = h('select', null, [1, 7, 30, 90].map((n) => h('option', { value: n, selected: n === 7 }, n + (n === 1 ? ' día' : ' días'))));
    const hist = h('input', { type: 'checkbox' });
    return h('div', { class: 'card', style: 'background:#fffaf0' },
      h('p', null, h('b', null, r.watcher_phone), ' quiere ver su ubicación.', r.message ? h('i', null, ' «' + r.message + '»') : ''),
      h('div', { class: 'row' }, h('label', null, 'Permitir por '), days,
        h('label', null, hist, ' incluir historial')),
      h('div', { class: 'row', style: 'margin-top:8px' },
        h('button', { class: 'approve', onclick: safe(root, async () => { await api('POST', `/api/device/grants/${r.id}/approve`, { days: Number(days.value), share_history: hist.checked }); await refresh(); }) }, 'Aprobar'),
        h('button', { class: 'danger deny', onclick: safe(root, async () => { await api('POST', `/api/device/grants/${r.id}/deny`); await refresh(); }) }, 'Rechazar')));
  }

  refresh().catch((e) => notice(root, 'err', e.message));
  timers.push(setInterval(() => refresh().catch(() => {}), 15000)); // detecta solicitudes nuevas
}

/* --------------------------------------------------------------- observador */
function renderViewer(app) {
  const root = h('div');
  app.replaceChildren(root);
  let grants = [], selected = null, map = null, layers = null, pickedZone = null;

  const load = async () => { grants = await api('GET', '/api/viewer/grants'); draw(); };

  function draw() {
    const phone = h('input', { id: 'tphone', type: 'tel', placeholder: '+573001234567' });
    const msg = h('input', { id: 'tmsg', maxlength: 140, placeholder: 'Quién es usted y por qué lo pide' });
    root.replaceChildren(
      h('div', { class: 'grid' },
        h('div', { class: 'card' }, h('h2', null, 'Pedir permiso para ver a alguien'),
          h('label', { for: 'tphone' }, 'Número de la persona'), phone,
          h('label', { for: 'tmsg' }, 'Mensaje (lo verá la persona)'), msg,
          h('div', { class: 'row', style: 'margin-top:10px' },
            h('button', { id: 'ask', onclick: safe(root, async () => { const r = await api('POST', '/api/viewer/requests', { phone: phone.value, message: msg.value }); await load(); notice(root, 'info', r.note); }) }, 'Enviar solicitud')),
          h('p', { class: 'consent-text' }, 'La persona recibe la solicitud en su app y decide si acepta, por cuánto tiempo y si comparte el historial. Puede retirar el permiso cuando quiera.')),
        h('div', { class: 'card' }, h('h2', null, 'Mis solicitudes'),
          grants.length ? h('table', null, h('thead', null, h('tr', null, ['Persona', 'Estado', 'Vence', ''].map((t) => h('th', null, t)))),
            h('tbody', null, grants.map((g) => h('tr', { class: selected === g.id ? 'sel' : '' },
              h('td', null, g.owner_phone), h('td', null, h('span', { class: 'pill ' + g.status }, STATUS[g.status])),
              h('td', null, g.status === 'approved' ? fmt(g.expires_at) : '—'),
              h('td', { class: 'row' },
                g.status === 'approved' ? h('button', { class: 'open', onclick: () => { selected = g.id; draw(); openGrant(g); } }, 'Ver mapa') : null,
                g.status === 'pending' || g.status === 'approved' ? h('button', { class: 'ghost', onclick: safe(root, async () => { await api('POST', `/api/viewer/grants/${g.id}/cancel`); selected = null; await load(); }) }, 'Cancelar') : null)))))
            : h('p', { class: 'muted' }, 'Todavía no ha pedido permiso a nadie.'))),
      h('div', { id: 'detail' }));
    if (selected) { const g = grants.find((x) => x.id === selected); if (g && g.status === 'approved') openGrant(g, true); }
  }

  async function openGrant(g, keep) {
    const box = $('#detail', root);
    const status = h('div', { id: 'status' });
    const zname = h('input', { id: 'zname', placeholder: 'Nombre de la zona', maxlength: 40 });
    const zrad = h('input', { id: 'zrad', type: 'number', min: 20, max: 50000, value: 300 });
    box.replaceChildren(h('div', { class: 'card' }, h('h2', null, 'Ubicación de ' + g.owner_phone), status,
      h('div', { id: 'map' }), h('p', { class: 'legend' }, 'Marcador = última ubicación · línea = recorrido · círculos = zonas. Haga clic en el mapa para elegir el centro de una zona nueva.'),
      h('div', { class: 'kv', id: 'info', style: 'margin-top:8px' }),
      h('div', { class: 'row' }, h('div', { class: 'grow' }, zname), h('div', null, zrad), h('button', { id: 'addzone', class: 'ghost', onclick: safe(box, async () => {
        if (!pickedZone) throw new Error('Haga clic en el mapa para elegir el centro de la zona');
        await api('POST', `/api/viewer/grants/${g.id}/geofences`, { name: zname.value, lat: pickedZone.lat, lon: pickedZone.lng, radius_m: Number(zrad.value) });
        pickedZone = null; await refreshMap(g);
      }) }, 'Crear zona')),
      h('h2', { style: 'margin-top:14px' }, 'Alertas de zonas'), h('div', { id: 'alerts' })));
    if (map) { map.remove(); map = null; }
    map = L.map('map').setView([4.6097, -74.0817], 5);
    L.Icon.Default.imagePath = '/static/vendor/images/';
    L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 19, attribution: '© OpenStreetMap' }).addTo(map);
    layers = L.layerGroup().addTo(map);
    let pick = null;
    map.on('click', (e) => { pickedZone = e.latlng; if (pick) pick.remove(); pick = L.circleMarker(e.latlng, { radius: 6, color: '#b3261e' }).addTo(map); });
    await refreshMap(g, !keep);
    timers.push(setInterval(() => refreshMap(g, false).catch(() => {}), 15000));
  }

  let mapSeq = 0;   // evita que dos refrescos en paralelo dupliquen las capas
  async function refreshMap(g, fit = true) {
    const status = $('#status', root); if (!status) return;
    const seq = ++mapSeq;
    layers.clearLayers();
    const bounds = [];
    status.replaceChildren();
    try {
      const loc = await api('GET', `/api/viewer/grants/${g.id}/latest`);
      if (seq !== mapSeq) return;
      const m = L.marker([loc.lat, loc.lon]).addTo(layers);
      m.bindPopup(`Registrada: ${fmt(loc.recorded_at)}` + (loc.accuracy_m != null ? ` · precisión ±${Math.round(loc.accuracy_m)} m` : ''));
      bounds.push([loc.lat, loc.lon]);
      const info = $('#info', root);
      info.replaceChildren(h('b', null, 'Última ubicación'), `${loc.lat.toFixed(5)}, ${loc.lon.toFixed(5)}`, h('b', null, 'Registrada'), fmt(loc.recorded_at));
      api('GET', `/api/viewer/geocode?lat=${loc.lat}&lon=${loc.lon}`).then((a) => { if (a.address) info.append(h('b', null, 'Dirección'), a.address); }).catch(() => {});
    } catch (e) { status.append(h('div', { class: 'msg info' }, e.message)); }
    if (g.share_history) {
      try {
        const hist = await api('GET', `/api/viewer/grants/${g.id}/history?limit=1000`);
        if (seq !== mapSeq) return;
        if (hist.length > 1) { L.polyline(hist.map((p) => [p.lat, p.lon]), { color: '#0b5cab', weight: 3 }).addTo(layers); hist.forEach((p) => bounds.push([p.lat, p.lon])); }
        const st = await api('GET', `/api/viewer/grants/${g.id}/stats`);
        const info = $('#info', root);
        if (info) info.append(h('b', null, 'Recorrido'), `${st.points} puntos · ${(st.distance_m / 1000).toFixed(2)} km`);
      } catch (e) { /* sin historial */ }
    }
    try {
      const zones = await api('GET', `/api/viewer/grants/${g.id}/geofences`);
      if (seq !== mapSeq) return;
      zones.forEach((z) => { L.circle([z.lat, z.lon], { radius: z.radius_m, color: '#9a5b00' }).bindTooltip(z.name).addTo(layers); });
      const al = await api('GET', `/api/viewer/grants/${g.id}/alerts`), box = $('#alerts', root);
      if (box) box.replaceChildren(al.length ? h('ul', { class: 'plain' }, al.map((a) => h('li', null, `${fmt(a.at)} · ${a.kind === 'enter' ? 'entró a' : 'salió de'} «${a.zone}»`))) : h('p', { class: 'muted' }, 'Sin alertas.'));
    } catch (e) { /* consentimiento retirado */ }
    if (fit && bounds.length) map.fitBounds(bounds, { maxZoom: 16, padding: [30, 30] });
  }

  load().catch((e) => notice(root, 'err', e.message));
}

/* -------------------------------------------------------------------- shell */
async function logout() {
  try { await api('POST', '/api/auth/logout'); } catch (e) { /* ya vencido */ }
  saveSession(null); render();
}

function render() {
  clearTimers();
  const app = $('#app'), who = $('#who');
  who.replaceChildren();
  if (!session) return renderLogin(app);
  who.append(h('span', null, session.role === 'device' ? 'Modo: compartir mi ubicación' : 'Modo: observador'),
    h('button', { class: 'ghost', id: 'logout', onclick: logout }, 'Salir'));
  (session.role === 'device' ? renderDevice : renderViewer)(app);
}

render();
