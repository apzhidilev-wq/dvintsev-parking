/**
 * Cloudflare Worker — прокси к Supabase для обхода блокировок в РФ.
 *
 * ─── ЗАЧЕМ ────────────────────────────────────────────────────────────────
 * Российские мобильные операторы / провайдеры часто блокируют или урезают
 * длинные TLS-ответы от *.supabase.co (хостится на AWS Frankfurt).
 * Симптом: HEAD-запросы проходят, GET с body > 50 КБ — TypeError: Load failed.
 *
 * Cloudflare Workers НЕ блокируется в РФ — это популярный CDN, через который
 * работают тысячи российских сайтов. Этот Worker проксирует любые запросы
 * (REST + Realtime WebSocket + Auth) к Supabase, делая клиента невидимым
 * для DPI как "пользователь Cloudflare".
 *
 * ─── РАЗВОРОТ (5 ШАГОВ) ───────────────────────────────────────────────────
 * 1. Зарегистрироваться на https://dash.cloudflare.com (бесплатно).
 * 2. Слева в меню: "Workers & Pages" → "Create" → "Hello World".
 * 3. Дать имя, например `dvintsev-proxy` → "Deploy".
 * 4. Открыть деплоенный Worker → "Edit code" → удалить весь код,
 *    вставить содержимое ЭТОГО файла → "Save and deploy".
 * 5. Получить адрес вида `dvintsev-proxy.<your-account>.workers.dev`.
 *    В parking.html заменить значение `SB_PROXY_URL`. Закоммитить, запушить.
 *
 * После этого открыть приложение на iPhone БЕЗ VPN — данные подтянутся.
 *
 * ─── ЛИМИТЫ БЕСПЛАТНОГО ТАРИФА ────────────────────────────────────────────
 * - 100 000 запросов/день (хватит на тысячи активных пользователей)
 * - 10 мс CPU на запрос (нашему трафику нужно < 1 мс)
 * - WebSocket поддерживается без ограничения по времени
 *
 * ─── БЕЗОПАСНОСТЬ ─────────────────────────────────────────────────────────
 * Worker НЕ требует никаких секретов — он просто переписывает Host-заголовок.
 * Anon-ключ Supabase передаётся клиентом так же, как и при прямом обращении.
 * Если в будущем нужно ограничить доступ — добавьте проверку Origin
 * (см. ALLOWED_ORIGINS ниже).
 */

const SUPABASE_HOST = 'swxssesgfojoklrsnago.supabase.co';

// Опционально: ограничить, с каких сайтов можно дёргать прокси.
// Оставьте пустым массивом, чтобы разрешить всем.
const ALLOWED_ORIGINS = [
  'https://apzhidilev-wq.github.io',
  'http://localhost:8000',
  'http://127.0.0.1:8000'
];

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin)
      });
    }

    // Опциональная проверка Origin (если ALLOWED_ORIGINS не пуст)
    if (ALLOWED_ORIGINS.length && origin && !ALLOWED_ORIGINS.includes(origin)) {
      return new Response('Forbidden origin: ' + origin, { status: 403 });
    }

    // ─── Special-case: query-param→header перевод (для simple-cors) ───
    // iPhone Safari через iCloud Private Relay тормозит CORS preflight.
    // Чтобы избежать preflight, клиент может передать auth-токены через
    // query string, и Worker перепишет их в нужные заголовки.
    //   ?_apikey=... → apikey: ...
    //   ?_token=...  → Authorization: Bearer ...
    // Эти query params удаляются перед проксированием в Supabase.
    const xApikey = url.searchParams.get('_apikey');
    const xToken = url.searchParams.get('_token');
    if (xApikey) url.searchParams.delete('_apikey');
    if (xToken) url.searchParams.delete('_token');

    // Подменяем хост: дальше всё как у Supabase
    const upstreamUrl = `https://${SUPABASE_HOST}${url.pathname}${url.search}`;

    // ─── WebSocket (Realtime) ───
    if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
      return handleWebSocket(upstreamUrl, request);
    }

    // ─── HTTP REST ───
    // Копируем заголовки запроса, заменив Host
    const upstreamHeaders = new Headers(request.headers);
    upstreamHeaders.set('Host', SUPABASE_HOST);
    // Если auth передан через query — перенесём в headers (приоритет query)
    if (xApikey) upstreamHeaders.set('apikey', xApikey);
    if (xToken) upstreamHeaders.set('Authorization', 'Bearer ' + xToken);
    // Убираем CF-специфичные заголовки, которые Supabase не ждёт
    upstreamHeaders.delete('cf-connecting-ip');
    upstreamHeaders.delete('cf-ipcountry');
    upstreamHeaders.delete('cf-ray');
    upstreamHeaders.delete('cf-visitor');

    let upstreamResp;
    try {
      upstreamResp = await fetch(upstreamUrl, {
        method: request.method,
        headers: upstreamHeaders,
        body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
        redirect: 'manual'
      });
    } catch (e) {
      return new Response('Upstream error: ' + e.message, {
        status: 502,
        headers: corsHeaders(origin)
      });
    }

    // Копируем ответ и добавляем CORS-заголовки
    const respHeaders = new Headers(upstreamResp.headers);
    const cors = corsHeaders(origin);
    Object.keys(cors).forEach(k => respHeaders.set(k, cors[k]));

    return new Response(upstreamResp.body, {
      status: upstreamResp.status,
      statusText: upstreamResp.statusText,
      headers: respHeaders
    });
  }
};

function corsHeaders(origin) {
  const allow = (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin))
    ? (origin || '*')
    : '*';
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD',
    'Access-Control-Allow-Headers': 'authorization, apikey, content-type, content-profile, accept-profile, x-client-info, prefer, range, range-unit, x-supabase-api-version',
    'Access-Control-Expose-Headers': 'content-range, content-length, content-type',
    'Access-Control-Max-Age': '86400'
  };
}

async function handleWebSocket(upstreamUrl, request) {
  // Cloudflare Workers поддерживает WebSocket-проксирование через fetch с
  // Upgrade-заголовком к upstream — пара socket'ов соединяется напрямую.
  const upstream = await fetch(
    upstreamUrl.replace(/^http/, 'wss').replace(/^https/, 'wss'),
    {
      headers: stripUpgradeHeaders(request.headers)
    }
  );

  // Если upstream вернул не 101 — отдадим клиенту как есть
  if (upstream.status !== 101) {
    return upstream;
  }

  return new Response(null, {
    status: 101,
    webSocket: upstream.webSocket
  });
}

function stripUpgradeHeaders(headers) {
  const h = new Headers(headers);
  h.set('Host', SUPABASE_HOST);
  h.delete('cf-connecting-ip');
  h.delete('cf-ipcountry');
  h.delete('cf-ray');
  h.delete('cf-visitor');
  return h;
}
