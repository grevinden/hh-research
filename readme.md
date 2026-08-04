# Досье по работе с hh.ru (Исследовательские данные)

> Исчерпывающий самоучитель по внутреннему устройству, API и защитным механизмам hh.ru.
> Составлено на основе данных исследования (2026-08-02 … 2026-08-04). Здесь сведены все
> наблюдения из базы знаний `findings/` (auth.md, api.md, gib.md, search_query_language.md,
> rag.md, agent.md, sessions/), чтобы исходные файлы можно было удалить без потери
> ценной информации.
>
> **Легенда пометок:** `[ПРОВЕРЕНО]` — наблюдалось лично через MCP DevTools (запрос/ответ/консоль/куки);
> `[ГИПОТЕЗА]` — предположение, требует проверки; `[ОБНОВЛЕНО YYYY-MM-DD]` — запись изменена.

---

## 1. Авторизация и Сессии

### 1.1. Cookie на hh.ru — полная таблица [ПРОВЕРЕНО 2026-08-02]

Атрибуты сняты из Set-Cookie ответа `GET /` (редирект с `/account/login`).

| Имя | Пример | Домен | Path | httpOnly | Secure | SameSite | Жизнь | Роль |
|---|---|---|---|---|---|---|---|---|
| `crypted_id` | `8EA61D4B...` | .hh.ru | / | нет | нет | lax | сессия | id соискателя; = crypted_id метрики; выставляется при логине, удаляется при логауте |
| `crypted_hhuid` | `43DE76D4...` | .hh.ru | / | нет | нет | lax | сессия | id пользователя; = UserID метрики |
| `hhuid` | `XD_QlYGnU2IBe2puahsumg--` | .hh.ru | / | нет | да | none | +2 года | анонимный id устройства; = puid2 adfox; = x-hhuid ответа |
| `_hi` | `17192618` | hh.ru | / | нет | да | lax | сессия | внутренний id пользователя; = x-hhid ответа; = _hi чатика |
| `hhul` | `96409811...` (64 hex) | .hh.ru | / | **да** | да | lax | +2 года | постоянный id устройства |
| `_xsrf` | `a87f319a15353c2e881d1ad3f77c2567` | hh.ru | / | нет | нет | lax | сессия | CSRF; уходит в заголовке `x-xsrftoken` |
| `hhrole` | `applicant` | hh.ru | / | нет | нет | lax | сессия | роль: `applicant` / `employer` / `anonymous` |
| `display` | `desktop` | .hh.ru | / | нет | нет | lax | сессия | режим отображения |
| `__ddg8_`/`__ddg9_`/`__ddg10_` | `qja3W9PF...` / IP / ts | .hh.ru | / | нет | нет | — | ~20 мин | DataDome антибот (обновляются на каждом ответе; `__ddg9_` = IP клиента) |
| `__ddg1_` | `YpHh4VrMVEfiF2JBy3sh` | .hh.ru | — | — | — | — | ~20 мин | DataDome (первый визит) |
| `hhtoken` | `Lb_Vs1_QBbYk69C8ouOlso!Xggtf` | .hh.ru | / | **да** | **да** | **none** | сессия; ротируется | **сессионный токен**; есть и у анонима; ротируется при логине, логауте и смене роли; при логауте удаляется, новый выдаётся на GET / |
| `just_logged_in` | `1` | hh.ru | / | нет | нет | lax | 15 сек | маркер «только что вошёл» (одноразовый) |
| `_ibc` | `False` | ? | ? | ? | ? | ? | ? | ? |
| `regions` | `1` | .hh.ru | / | нет | нет | lax | сессия | регион (Москва = 1) |
| `GMT`, `TZ` | `3`, `Europe%2FMoscow` | .hh.ru | / | нет | нет | lax | сессия | таймзона |
| `uxs_uid` | `ffe1dbb0-...-3ffb801e5450` | .hh.ru | / | нет | нет | lax | сессия | = `uid` в запросе `widget-api.uxfeedback.ru` |
| `domain_sid` | `_BQagITvjuBaJJj8LoI7m:1785621022811` | .hh.ru | / | нет | нет | lax | сессия | сессия домена |
| `iap.uid` | `31b5b78e7e5d4dcc8cb31a93f1870bfb` | ? | ? | ? | ? | ? | ? | ? |
| `cookie_policy_agreement` | `true` | .hh.ru | / | нет | нет | lax | сессия | согласие на cookie |
| `__zzatgib-w-hh` | `MDA0dC0jViV+...==` | .hh.ru | / | нет | нет | none | +1 год | зашифрованная кука протокола gib (v004) |
| `cfidsgib-w-hh` | base64+шифр | .hh.ru | / | нет | да | none | +1 год | зашифрованный fingerprint устройства (gib) |
| `gsscgib-w-hh` | base64 (~400-500 симв.) | .hh.ru | / | нет | да | none | +1 год | «сессия»/ключ серверного шифрования (gib) |
| `fgsscgib-w-hh` | `zMX5381a781878c058f8e5eb12fe451d4b0f9d73` | .hh.ru | / | нет | нет | none | +1 год | подпись запроса (gib), 40 симв. |
| `HOSTILE_ON` | `0` | .hh.ru | / | нет | нет | lax | сессия | ? |
| `region_clarified` | `NOT_SET` | .hh.ru | / | нет | нет | lax | сессия | состояние уточнения региона |
| `device_breakpoint`, `device_magritte_breakpoint` | `l` | .hh.ru | / | нет | нет | lax | сессия | брейкпоинт вёрстки |

Замечания:
- `hhtoken` — токен **браузерной сессии**, а не авторизации: он есть и у анонима. Где/как он
  связывается с пользователем при логине — открытый вопрос [ГИПОТЕЗА].
- `hhul` — httpOnly, живёт 2 года, что кодирует — открытый вопрос [ГИПОТЕЗА]. При логауте НЕ удаляется.
- gib-куки выставляются ответом `/api/fl` и главной (Secure, SameSite=None, +1 год).
- `_hi` и `hhuid` дублируются в заголовках ответа (`x-hhid`, `x-hhuid`).
- В localStorage/sessionStorage дублируются зашифрованные значения gib-кук (ключи с теми же именами).

### 1.2. Связи идентификаторов [ПРОВЕРЕНО]

```
crypted_hhuid (cookie) = UserID (site-info метрики) = _tads_uid (localStorage)
crypted_id     (cookie) = crypted_id (site-info метрики) = cryptedUserId (globalVars)
hhuid          (cookie) = puid2 (adfox) = x-hhuid (заголовок ответа)
_hi            (cookie) = counterId (чат) = x-hhid (заголовок ответа) = hhid (globalVars)
uxs_uid        (cookie) = uid (widget-api.uxfeedback.ru)
```

После выхода из аккаунта: `crypted_id` и `_hi` удаляются (маркеры залогиненности);
`crypted_hhuid`/`hhuid`/`hhul` остаются (постоянные id); `hhrole` → `anonymous`.

### 1.3. Процесс входа (Login Flow) [ПРОВЕРЕНО 2026-08-02, частично]

Полный порядок: `GET /account/login` → `POST /account/login` → `GET /?role=applicant`.

**Шаг 0 — `GET /account/login?role=applicant&backurl=%2F&hhtmFrom=main`** (200):
- `globalVars.cryptedUserId` = "" (аноним), `hhtmSource: account_login`, `role: applicant`.
- Set-Cookie: продлевает `crypted_hhuid`, `hhuid` (+2 года), `_xsrf`, `display`; **удаляет**
  `crypted_id=""` (expires 2025) и `_hi` (Max-Age=0); `hhrole=anonymous`; `hhtoken` не трогается.
- В HTML (globalVars) два ключа для логина:
  - **`loginTrustFlagsSecret`** — RSA-публичный ключ в PEM (2048 бит, PKCS#8/SPKI), им клиент
    шифрует поле `loginTrustFlags` (см. 1.4);
  - **`loginForm`** — конфигурация формы: `socialNetworks`, `registration` (code `REG_APPLICANT`),
    `passwordRecovery`, `savedAreaIds`.
- Соцсети (все через `/account/connect`):
  `?backurl=%2F&role=applicant&site=ESIA|VK|GPLUS|MAIL|OK&_xsrf=<токен>&hhtmSource=account_login&userType=applicant&entrypoint=login_button_signup`.

**Шаг 1 — форма (3 шага, SPA, между шагами серверных запросов НЕТ)**:
1. Выбор типа: radio `account-type` (`APPLICANT` checked / `EMPLOYER`).
2. Вход по телефону/почте: radio `:r2:` (`phone` checked / `email`), скрытый `isBot=false`.
3. Пароль: `input type=password name=password`. hh запоминает последний логин (приходит в authUrl).

Все шаги — одна `<form method=POST>` с hidden `_xsrf`; `action` пустой — отправка через fetch.

**Шаг 2 — `POST /account/login?backurl=%2F&role=applicant`** (`hhtmFrom` уходит заголовком):
- Заголовки: `content-type: multipart/form-data` (не urlencoded!), `x-xsrftoken` (= кука `_xsrf`),
  `x-requested-with: XMLHttpRequest`, `accept: application/json`, `x-hhtmfrom: main`,
  `x-hhtmsource: account_login`, `referer`, `origin: https://hh.ru`,
  gib-заголовки `x-gib-gsscgib-w-hh`/`x-gib-fgsscgib-w-hh`.
- Тело (multipart/form-data):

| Поле | Значение |
|---|---|
| `username` | телефон или почта |
| `password` | пароль в открытом виде |
| `accountType` | `APPLICANT` |
| `failUrl` | `/account/login?backurl=%2F&role=applicant` |
| `remember` | `true` |
| `loginTrustFlags` | base64 (~700 симв.), RSA-OAEP-шифрблоб (см. 1.4) |
| `captchaText` | пусто (если isBot=false) |

- Ответ 200 JSON (не редирект при ошибке). Ключевые поля:
  - `loginError: {code, trl}` — код ошибки. Возможные: `mismatch` (неверные данные),
    `PASSWORD_REQUIRED`, `BAD_LOGIN`, `ACCOUNT_NOT_FOUND`, `ACCOUNT_BLOCKED`,
    `UNEXPECTED_USER_TYPE`, `CODE_SEND_OK`, `CODE_SEND_BLOCKED`;
  - `recaptcha: {isBot, siteKey}` и `hhcaptcha: {isBot, captchaError, captchaKey}` — капча;
  - `redirectConfig: {strictMode, topLevelDomain: "hh.ru", permittedHosts[], permittedAppSchemes[]}`
    (список доменов группы HeadHunter);
  - `authUrl: {"login-url": ...}`, `css_links[]`, `inline_script`, `isLightPage`, `supernovaUserType`.
- При неверном пароле Set-Cookie не меняет ничего кроме `__ddg*`/продления — сессия остаётся анонимной.
- При успехе клиент делает `window.location.assign(s.data.backurl)`.

**Шаг 3 — успешный вход: Set-Cookie ответа POST (порядок появления)**:
`__ddg8_/9_/10_` → `crypted_hhuid` → очистка старой `crypted_id=""` → `display` →
`crypted_hhuid` (повтор) → **новая `crypted_id`** (id соискателя) → **`hhul`** (HttpOnly, +2 года) →
`just_logged_in=1` (15 сек) → `_xsrf` → `hhuid` (SameSite=None, Secure, +2 года) →
`hhrole=anonymous` (**пока аноним!**) → **ротация `hhtoken`** (HttpOnly, Secure, SameSite=None, +2 года) →
**новая `_hi`**. Заголовки ответа: `x-hhid: 17192618` (= `_hi`), `x-hhuid`.

**Шаг 4 — редирект на backurl: `GET /?role=applicant`**:
- В cookie уже `crypted_id` (новая), `hhtoken` (новый), `just_logged_in=1`, `_hi`; `hhrole` всё ещё `anonymous`.
- Set-Cookie ответа подтверждает куки и **выставляет `hhrole=applicant`** — роль меняется именно
  на GET главной, когда сервер видит валидные `crypted_id` + `hhtoken`.
- globalVars после входа: `cryptedUserId` = `crypted_id`, `userType: "applicant"`, `hhid` = `_hi`,
  `apiHost: https://api.hh.ru`, `apiXhhHost: https://hh.ru`, `topLevelDomain: hh.ru`, `build: 26.31.5`.

Итого: `GET /account/login` (RSA-ключ + `_xsrf`) → `POST /account/login` (`crypted_id`, `hhul`,
`hhtoken`, `_hi`, `just_logged_in`; `hhrole` пока anonymous) → `GET /?role=applicant`
(`hhrole=applicant`) → залогиненный SPA.

### 1.4. Протокол `loginTrustFlags` [ПРОВЕРЕНО по коду бандлов]

Поле `loginTrustFlags` — шифрованный JSON-блоб (бандл `autoGenerated`, модуль 441763, экспорт `M`):
1. Сервер отдаёт в HTML `loginTrustFlagsSecret` = RSA-публичный ключ (PEM, SPKI, 2048).
2. Клиент: `crypto.subtle.importKey('spki', <PEM без BEGIN/END и пробелов, base64>, {name:'RSA-OAEP', hash:'SHA-256'}, false, ['encrypt'])`.
3. Данные: `JSON.stringify({...state.loginTrustFlags, ts: Date.now()})`, где `state.loginTrustFlags` —
   Redux-стора, редьюсер `SET_INPUT_TRUST_FLAGS` (`{inputType, flags}`) пишет `state[inputType] = {...}`.
   `inputType` = имя поля (`login`/`password`/...), `flags` — флаги способа ввода:
   `suggest`, `paste`, `drop`, `insertFromPaste`, `insertFromDrop`, `insertReplacementText` (bool).
   Пример возможного содержимого: `{"password":{"paste":true},"ts":1785622657000}` [ГИПОТЕЗА о полях].
4. `TextEncoder.encode(json)` → `crypto.subtle.encrypt({name:'RSA-OAEP'}, key, data)` → base64 → поле.

**Ограничение:** один блок RSA-2048-OAEP-SHA256 вмещает ≤190 байт данных — при превышении encrypt
падает, и клиент шлёт `loginTrustFlags` отсутствующим/null.

### 1.5. Вход по SMS-коду (OTP) [ПРОВЕРЕНО по коду бандлов, вживую не снимался]

- `POST /account/otp_generate` — запрос кода. FormData: `login`, `otpType`, `operationType`
  (`ApplicantOtpAuth`/`EmployerOtpAuth`), `authScenario`, `backurl`, `loginTrustFlags`, капча-параметры.
  Коды ответа: `CODE_SEND_OK`, `CODE_SEND_BLOCKED`, `BAD_LOGIN`, `PASSWORD_REQUIRED`.
- `POST /account/login/by_code` — отправка кода. FormData: `username`, `code`, `operationType`,
  `backurl`, `isApplicantSignup`, `remember=true`, `loginTrustFlags`, `authScenario`; при
  мульти-аккаунте — `accountType`. Успех: `data.success=true` → `window.location.assign(data.backurl)`.

### 1.6. Вход по кукам браузера (обход 403 скриптового логина) [ПРОВЕРЕНО 2026-08-03]

Проблема: `POST /account/login` из скрипта (httpx без реального браузера) периодически отвечает
403/капчей — DataDome решает, что запрос бот (нет отпечатков браузера). Надёжный обход — скопировать
куки залогиненного браузера в сессию httpx (`HHSession.load_cookies`, CLI-флаг `--cookies`,
env `HH_COOKIE_FILE`).

- **Формат файла кук:** простой текст как Cookie-заголовок: строки `name=value`, разделители `;` или `\n`;
  строки с `#` и пустые значения пропускаются.
  Пример: `hhul=96409811...; hhtoken=Lb_Vs1_QBbYk69C8ouOlso!Xggtf; crypted_id=8EA61D4B...; _xsrf=a87f319a...`
- **Минимальный набор:** `hhul` + `hhtoken` + `crypted_id` (связывают сессию с пользователем) +
  `_xsrf` (нужна для POST — заголовок `x-xsrftoken`, в т.ч. `/chatik/api/leave`).
  Остальные (регионы, `_hi`, `hhrole`, DataDome) — желательны, но не обязательны.
- **Проверка живой сессии:** `probe_session()` делает лёгкий авторизованный запрос
  (например, список резюме); если куки мёртвые — `SessionLost`, fallback на `api.login` (пароль).
- **Как снять куки:** DevTools → Application → Cookies → hh.ru → скопировать как строку
  `name=value; ...` (важно: httpOnly `hhtoken`/`hhul` через `document.cookie` недоступны).
- После Set-Cookie из ответов в jar может оказаться **две `_xsrf`** — клиент должен перебирать
  jar вручную (httpx `.get()` бросает исключение).

### 1.7. Выход из аккаунта (logout) [ПРОВЕРЕНО 2026-08-02]

1. `POST https://hh.ru/account/logout` (обычная навигация, `sec-fetch-dest: document`);
   `content-type: application/x-www-form-urlencoded`; **тело формы: `_xsrf=<токен>`** — CSRF-токен
   уходит в теле POST (не в заголовке!); ответ **302 Location: https://hh.ru**; Set-Cookie:
   удаляет `_hi`, `hhtoken` (expires 2024, HttpOnly), `remember=0`, `lrp=""`, `lrr=""`;
   продлевает `hhuid` (+2 года, SameSite=None, Secure), `__ddg8_/9_/10_`.
2. `GET https://hh.ru/` (редирект) — Set-Cookie: удаляет `crypted_id`, `_hi` (Max-Age=0);
   меняет роль `hhrole=applicant` → `anonymous`; **выдаёт новый анонимный `hhtoken`**;
   продлевает `crypted_hhuid`, `hhuid`, `_xsrf`, `display`; `hhul` не трогается.

**Куки после выхода — что маркер сессии, а что нет:**

| Кука | До | После | Вывод |
|---|---|---|---|
| `crypted_id` | 8EA61D4B... | **удалена** | маркер соискателя |
| `_hi` | 17192618 | **удалена** | маркер пользователя (внутр. id) |
| `hhrole` | applicant | **anonymous** | маркер роли |
| `hhtoken` | Lb_Vs1_QB... | **199Hvr5hlE!!...** (новая) | сессионный, ротируется |
| `crypted_hhuid` | 43DE76D4... | осталась | постоянный id (не сессия) |
| `hhuid` | XD_QlYGnU2IBe2puahsumg-- | осталась | id устройства |
| `hhul` | 96409811... | осталась (httpOnly) | постоянная |
| `_xsrf` | a87f319a... | осталась (та же) | CSRF, не ротируется при логауте |
| gib-куки | ... | остались | не сбрасываются при логауте |

Симптомы после выхода: метрики `{"status":"anonymous",...}` (crypted_id и collar исчезли);
`adsrv.hh.ru/pv` — `type=unknown` без персональных данных; чатик `chatik/api/unread` и
`websocket.hh.ru/proxy-webapp*` исчезают из трафика. Интересный факт: в HTML анонимной главной
`globalVars.cryptedUserId` всё ещё старый (8EA61D4B...) — источник неясен [ГИПОТЕЗА: из hhul
или серверного состояния].

### 1.8. Заголовки авторизации/идентификации [ПРОВЕРЕНО 2026-08-02]

| Заголовок | Значение | Откуда берётся |
|---|---|---|
| `x-xsrftoken` | `a87f319a15353c2e881d1ad3f77c2567` | кука `_xsrf` |
| `x-requested-with` | `XMLHttpRequest` | фиксированный |
| `x-hhtmsource` | `main` | источник страницы (из globalVars.analyticsParams) |
| `x-hhtmfrom` | (пусто) | источник перехода |
| `x-cfids` | зашифр. | кука `cfidsgib-w-hh` (только /api/fl) |
| `x-gib-gsscgib-w-hh` | зашифр. | кука `gsscgib-w-hh` (только /api/fl) |
| `x-gib-fgsscgib-w-hh` | зашифр. | кука `fgsscgib-w-hh` (только /api/fl) |
| `referer` | `https://hh.ru/` | текущая страница |
| `origin` | `https://hh.ru` | только POST |
| `baggage`, `sentry-trace` | sentry-трейс из meta-тегов HTML | из HTML |

### 1.9. localStorage / sessionStorage (ключи, 2026-08-02)

- `cfidsgib-w-hh`, `__zzatgib-w-hh`, `__gitd`, `__est__` — зашифрованные строки (localStorage и
  sessionStorage), значения совпадают с cookie-версией там, где обе есть.
- `ss_incoming_params` — параметры входа: `[{role: applicant, backurl: %2F, hhtmFrom: main, ...}]`.
- `__chatikIntegration_counterUpdater` — `{unreadCount, unreadSupportCount, counterId: 17192618}`.
- `HH-TAB-COUNT-ID-2.495450800195721` — счётчик вкладок.
- sessionStorage: `__gti__` = GUID; `__pcode_page_visit_info_storage__` = `{lastVisitPagePath, isFirstVisitPage}`.

---

## 2. Анти-бот Протокол «Gib» (Защита API) [ПОЛНОСТЬЮ РАЗГАДАН И ПОДТВЕРЖДЁН 2026-08-02]

Система кастомных заголовков/кук `*gib*`, которую hh.ru навешивает на запросы. Часть анти-бот
защиты (совместно с DataDome `__ddg*`). Формула `fgssc` воспроизведена в Python и сверена с двумя
живыми парами (gssc, fgssc) из реального браузера — совпало 100%. Шифрование тела `POST /api/fl`
(версия `005`, класс `kn`) и куки `__zzatgib-w-hh` (версия `004`, класс `I`) — полностью разгадано
и портировано в Python (`fl_encode.py`, `fl_encode_v004.py`, эталонные семплы в `fl_constants.json` —
все 16/16 семплов **ALL MATCH**).

### 2.1. Сущности

| Имя | Где живёт | Формат | Назначение |
|---|---|---|---|
| `gsscgib-w-hh` | кука + заголовок `x-gib-gsscgib-w-hh` | base64 (~400-500 симв., меняется) | «сессия»/ключ серверного шифрования |
| `cfidsgib-w-hh` | кука + заголовок `x-cfids` | base64 (~150-300 симв., меняется) | зашифрованный fingerprint устройства |
| `fgsscgib-w-hh` | кука + заголовок `x-gib-fgsscgib-w-hh` | `PREFIX(4) + hex(36)` = 40 симв. | подпись запроса |
| `__zzatgib-w-hh` | кука | base64 (`MDA0dC0jViV+...==`) + 4-байтовая «подпись» | зашифрованный маркер сессии браузера |

### 2.2. Формула подписи `fgssc` [ПРОВЕРЕНО]

`fgssc = prefix + SHA1(ce + gssc + prefix).slice(4)`, где:
- `prefix` — 4 случайных символа из алфавита `[a-zA-Z0-9]` (62 символа), новый на каждый запрос;
- `ce = "shgkla34ty3gg354g34wf"` — константа из string table бандла `i.hh.ru/shared/413.2b730bc58fc45025.js`
  (модуль 825; декодировано: `ko("9lAG", 1837)` → `t(912, "9lAG")`);
- SHA1 — стандартный, над UTF-8 конкатенацией `ce + gssc + prefix`; от результата берутся символы с 4-го (36 hex).

```python
import hashlib, random, string

CE = "shgkla34ty3gg354g34wf"
PREFIX_ALPHABET = string.ascii_lowercase + string.ascii_uppercase + string.digits  # 62

def make_fgssc(gssc: str) -> str:
    prefix = "".join(random.choice(PREFIX_ALPHABET) for _ in range(4))
    digest = hashlib.sha1((CE + gssc + prefix).encode("utf-8")).hexdigest()
    return prefix + digest[4:]     # всего 4 + 36 = 40 символов
```

Проверка на реальных парах (браузер → формула): `5YOXawb8Wx1DmV6wE4T0l0FAUyY...` +
`eO7dc2855480efd529dc6e480f08b41b45b45fb2` → да; тот же gssc + `NeiG5fa5a34946fde423cd7d2f1a9e8541d494e7` → да.
Префикс и хэш меняются от запроса к запросу даже при одном и том же `gssc`.

### 2.3. Ротация Fingerprint (`/api/fl`) [ПРОВЕРЕНО]

**`GET /api/fl/idgib-w-hh`** (заголовки: `x-cfids`, `x-gib-fgsscgib-w-hh`, `x-gib-gsscgib-w-hh`, куки целиком):
- Ответ 200 JSON: `{"status":"success","error":null,"data":{"cfids":"<новый cfids, ~230 симв. base64>"}}`.
- `Set-Cookie: cfidsgib-w-hh=<новый cfids>; Path=/; Expires=<+1 год>; Secure; SameSite=None` —
  сервер ротирует cfids при каждом вызове. ETag меняется; клиент шлёт `if-none-match` от прошлого ответа.

**`POST /api/fl?u=<uuid>&cfidsgib-w-hh=<текущий cfids>`**:
- Заголовки: `content-type: text/plain;charset=UTF-8`, `x-cfids: <СТАРЫЙ cfids>`,
  `x-gib-gsscgib-w-hh: <старый gssc>`, `x-gib-fgsscgib-w-hh: <новый fgssc>`, куки, `origin: https://hh.ru`.
- `u` — **UUIDv1, стабильный в рамках сессии** (одинаковый на разных страницах/перезагрузках:
  hhpro, chat, vacancy; пример `8904b7c0-4a21-11f1-9913-3b69330000001`). Хранится, по-видимому, в памяти JS.
- Тело (plain text, base64-секции, ~4.5 КБ):
  `MDA1<uuid без последнего символа>TEdXeSd2...FH1h9Qg==HmZKbg==rMoJlQ==`
  - `MDA1` = base64 от `"005"` — версия протокола;
  - `<uuid>` = 36 символов: статическая константа `VI` бандла (= `u` без последнего символа);
  - `<большой base64-блоб>` — закодированные данные fingerprint (для клиента — любая строка, сервер принимает);
  - `HmZKbg==` (4 байта) и `rMoJlQ==` (4 байта) — CRC32-контрольные суммы.
- Ответ 200 JSON: `{"status":"success","error":null,"data":{"cfids":"<новый>","cs":{"cfids":"<тот же>","gssc":"<новый gssc, ~400 симв.>"}}}`.
- `Set-Cookie: gsscgib-w-hh=<cs.gssc>` и `cfidsgib-w-hh=<cs.cfids>` — сервер ротирует ОБЕ куки.

**Последовательность браузера:**
1. При загрузке любой страницы: `GET /api/fl/idgib-w-hh` (с текущими куками и заголовками).
2. Если есть свежий cfids → `POST /api/fl?u=<uuid>&cfidsgib-w-hh=<cfids>` (иногда 2 раза подряд).
3. Все последующие запросы — с заголовками `x-cfids`/`x-gib-gsscgib-w-hh`/`x-gib-fgsscgib-w-hh` = актуальные куки.
Триггеры POST /api/fl: загрузка страницы (после GET idgib), открытие чата, переходы между разделами.

### 2.4. Передача данных (важно для клиента)

- **hh.ru (www)**: отправляет и заголовки (`x-gib-gsscgib-w-hh`, `x-gib-fgsscgib-w-hh`, `x-cfids`), и куки.
- **`x-cfids` шлётся НЕ на все запросы**: на `/api/fl/idgib-w-hh` и `/api/fl` — да; на мутациях
  (`/applicant/favorite_vacancies/add|remove`, отклик, profile.update) — только
  `x-gib-gsscgib-w-hh` + `x-gib-fgsscgib-w-hh` [ПРОВЕРЕНО 2026-08-02].
- **chatik.hh.ru**: только куки `gsscgib-w-hh`, `cfidsgib-w-hh`, `fgsscgib-w-hh`, `__zzatgib-w-hh`;
  заголовков `x-gib-*`/`x-cfids` НЕТ [ПРОВЕРЕНО 2026-08-02].
- **websocket.hh.ru**: тоже только куки.
- `cfidsgib-w-hh` и `__zzatgib-w-hh` дублируются в localStorage (ключи с теми же именами) [ПРОВЕРЕНО 2026-08-02].

### 2.5. Шифрование тела POST /api/fl — ВЕРСИЯ 005 (класс `kn`) [ПОЛНОСТЬЮ РАЗГАДАНО]

```
encode(s) = b64("005") + VI + b64(data) + b64(4 байта BE: ~e & 0xFFFFFFFF) + b64(4 байта BE: ~n & 0xFFFFFFFF)
где data, n, e, i = Ht(s, n=-1, e=-1, i=0)
```

- `VI = "8904b7c0-4a21-11f1-9913-3b6933000000"` (36 симв.) — статический префикс UUIDv1;
  query-параметр `u` = VI + 1 динамический символ (37).
- `n`, `e` — два CRC32-аккумулятора (таблица 256 uint32, стандартная reflected CRC-32, полином
  0xEDB88320, инициализация 0xFFFFFFFF, без финального XOR — его делает `~` в encode).
  `n` обновляется от ВЫХОДНЫХ байтов, `e` — от ВХОДНЫХ code units.
- `i` — индекс в таблицах сдвига (vn/wn/Sn/Cn/yn по 26 значений), инкрементируется на КАЖДОЙ итерации.
- Обработка символа (по UTF-16 code units, `charCodeAt`):
  - `m < 8` — пропуск (нетто-0);
  - `m < 128` — 1 байт: `r = 8 + (m-8 + vn[i%26]) % 120`;
  - `m < 2048` — 2 байта: `r = 128 + (m-128 + wn[i%26]) % 1920`;
  - `m < 55296` — 3 байта: `r = 2048 + (m-2048 + Sn[i%26]) % 53248`;
  - high surrogate без low следом — пропуск; иначе ждёт пару;
  - low surrogate — 4 байта через `Cn` (комбинируется с предыдущим high);
  - `m >= 57344` — 3 байта: `r = 57344 + ((m-57344) + yn[i%26]) % 8192`.
- В суррогатной ветке v005: `n` — 4 шага CRC по байтам закодированного `r`; `e` — 4 шага по байтам
  НАСТОЯЩЕГО code point `p`.

**Python-порт (полный рабочий код):** `findings/reference/fl_encode.py` — встроен в Приложение B.
Эталон/константы/ground truth — `fl_constants.json` (Приложение A): `kn.*`, `arrays.*`,
`encode_samples` (16 семплов: ASCII, кириллица, JSON, 500×x, эмодзи, астральные символы, битые
суррогаты, комбинируемые знаки — ALL MATCH).

### 2.6. Кука `__zzatgib-w-hh` — ВЕРСИЯ 004 (класс `I`) [ПОЛНОСТЬЮ РАЗГАДАНО]

```
encode(s) = b64("004") + b64(data) + b64(4 байта BE: ~n & 0xFFFFFFFF)
где data, n, e = Ht(s, n=-1, e=0)
```

Отличия от v005: НЕТ `VI`-префикса и второй контрольной суммы; `e` — счётчик итераций (индекс в
`key`), стартует с 0; единственный CRC `n` обновляется ТОЛЬКО от выходных байтов (в суррогатной
ветке — без «настоящего» code point); таблицы сдвига: `key[0]` (1 байт), `key[1]` (2 байта),
`key[2]` (3 байта BMP), `key[3]` (m>=57344), `key[4]` (суррогаты) — те же формулы, что в v005.

**Python-порт (полный рабочий код):** `findings/reference/fl_encode_v004.py` — встроен в Приложение B.
Ground truth — `fl_constants.json` → `v004.*` + `encode_samples_v004` (16/16 ALL MATCH).
У класса `I` есть и `decode()`/`Wt()` (проверка версии и контрольной суммы) — для клиента не обязательны.

### 2.7. Инфраструктура и смежные механизмы [ПРОВЕРЕНО]

- Антибот: куки `__ddg8_/__ddg9_/__ddg10_` (DataDome, живут ~20 мин, обновляются на каждом ответе);
  `__ddg9_` = IP клиента.
- Перед hh.ru стоит **DDoS-Guard** (`server: ddos-guard`), бэкенд — **frontik** (`server-timing: frontik`,
  Python/Tornado).
- В ответах заголовки `x-hhid` (= кука `_hi`) и `x-hhuid` (= кука `hhuid`).
- Флаг `fingerprinting_enable: true` в globalVars (для залогиненных).

### 2.8. Открытые вопросы по gib [ГИПОТЕЗЫ]

1. Откуда берётся `u` (UUIDv1) — только в JS-памяти fp-библиотеки; `VI`-префикс в теле — статическая
   константа бандла; последний символ `u` (37-й) пока не локализован.
2. Нужны ли gib-заголовки вообще для простых GET (выдача/вакансия) или достаточно кук — проверить экспериментально.
3. Какие именно поля fingerprint собирает клиент перед `POST /api/fl` (canvas, шрифты, экран и пр.) —
   формат данных внутри блоба не критичен: тело можно собрать из ЛЮБОЙ строки (проверено: encode()
   валиден для произвольных строк).
---

## 3. Язык поисковых запросов (вакансии и резюме) [ПРОВЕРЕНО — текст официальной статьи]

Источник: официальная статья `https://hh.ru/article/25295` «Как использовать язык
поисковых запросов на hh.ru» (материал обновлён 6 декабря 2023; прочитана в браузере
2026-08-02). [ПРОВЕРЕНО] — текст статьи, не сетевой трафик.

Один и тот же язык работает для поиска вакансий (`/search/vacancy`),
резюме (`/search/resume`) и компаний. Запрос передаётся в параметре `text`
(см. §4.3).

### 3.1. Поведение по умолчанию

- **Синонимы (умный поиск):** «директор» найдёт также «управляющий», «руководитель», CEO;
  «менеджер проектов» — также Project Manager, «руководитель проектов».
- **Нормализация склонений:** «менеджер проектов» найдёт «менеджеров проектов»,
  «менеджера проекта» и т.п. (число/род/падеж приводятся к одной форме).

### 3.2. Точное слово / точная фраза — `!`

Восклицательный знак **перед словом без пробела** отключает синонимы и нормализацию:

- `!директор` — точное слово «директор» (без «руководитель» и склонений);
- `!"главный директор"` — точная фраза.

### 3.3. Фраза (слова рядом) — кавычки

Без кавычек `международная отчётность` = оба слова в документе, но не обязательно рядом.
В кавычках `"международная отчётность"` — слова стоят рядом как словосочетание.

### 3.4. Слова рядом с допуском — `"..."~N`

`"менеджер холодные"~5` — слова «менеджер» и «холодные» в кавычках, между ними
допускается до 5 слов. Тильда сразу после закрывающей кавычки, без пробела.

### 3.5. Часть слова — `*` (суффикс-префикс)

`гео*` — все слова с префиксом «гео»: геолог, географ, география, геология, геодезист.
Звёздочка в конце части слова.

### 3.6. Поиск по конкретному полю — `ПОЛЕ:значение`

Двоеточие после названия поля, **без пробела** между двоеточием и словом.
Неправильно: `POSITION директор`, `POSITION: директор`. Правильно: `POSITION:директор`.

Поля поиска **по вакансиям**:

| Поле | Назначение |
|---|---|
| `NAME` | название вакансии |
| `COMPANY_NAME` | название компании |
| `DESCRIPTION` | описание вакансии |

Поля поиска **по резюме**:

| Поле | Назначение |
|---|---|
| `POSITION` | желаемая должность (название резюме) |
| `EDUCATION` | образование |
| `KEYWORDS` | ключевые навыки |
| `CONTACT_INFO` | персональные данные (имя и фамилия) |
| `WORKPLACE_ORGANIZATION` | наименования компаний-работодателей |
| `WORKPLACE_POSITION` | должности на прошлых местах работы |
| `WORKPLACE_DESCRIPTION` | описание обязанностей |

### 3.7. Полное равенство поля — `^ПОЛЕ:значение`

Крышечка перед `ПОЛЕ:` — значение поля должно полностью равняться слову/фразе
(не быть одним из нескольких слов):

- `^NAME:программист`, `^NAME:"java программист"` — вакансии;
- `^POSITION:программист`, `^POSITION:"java программист"` — резюме.

Поля с поддержкой равенства: вакансии — `NAME`, `COMPANY_NAME`;
резюме — `POSITION`, `EDUCATION`, `WORKPLACE_ORGANIZATION`, `WORKPLACE_POSITION`.

### 3.8. Булевы операторы

Приоритет от высшего к низшему: **NOT → AND → OR**. Пробел между словами =
неявный AND.

| Оператор | Смысл | Пример |
|---|---|---|
| `NOT` | исключить слово/фразу | `!директор NOT !заместитель` |
| `AND` | оба условия | `!"консолидированная отчётность" AND МСФО AND IPO` |
| `OR` | хотя бы одно | `!B2B OR "корпоративные клиенты"` |
| `( )` | приоритет | `(руководитель OR директор) AND NOT заместитель` |

Примеры:

- `руководитель OR директор AND NOT заместитель` = сначала исключаются документы
  со словом «заместитель», затем среди них ищется «директор», затем добавляются все
  документы со словом «руководитель».
- `(руководитель OR директор) AND NOT заместитель` = сначала объединение
  «руководитель|директор», затем исключение «заместитель».
- `(аналитик NOT младший) OR (!data AND (!scientist OR !analyst))` — вложенные скобки.
- `POSITION:(!"финансовый директор" and not !заместитель) EDUCATION:("Финансовый университет" OR "Финансовая академия") WORKPLACE_DESCRIPTION:("консолидированная отчётность" and МСФО)`
  — несколько условий в разных полях в одной строке (AND по умолчанию между группами).

Операторы регистронезависимы (в примерах встречаются `and not` в нижнем регистре).

### 3.9. Спецполя вакансий

| Синтаксис | Назначение |
|---|---|
| `!id:(87905442)` | найти вакансию по ID |
| `!id:(87905442) OR !id:(87997162)` | несколько вакансий по ID |
| `!manager_id:(11373850)` | все вакансии конкретного менеджера |
| `!manager_id:(11373850) AND менеджер холодные` | вакансии менеджера + ключевые слова |
| `!description:(Мы ищем опытного инженера) NOT технолог` | фраза в описании + исключение |

### 3.10. Полезное

- Пустая поисковая строка → алгоритм на ML сам строит подборку (сотни признаков).
- Интерфейс «Расширенный поиск по резюме» (графический) даёт только часть возможностей;
  сложные вложенные запросы — только языком.
- Для клиента: `text` принимает запрос «как есть», URL-энкодинг — стандартный
  (пробелы `+` или `%20`, кавычки `%22`, скобки и `!` кодируются httpx автоматически).

---

## 4. Каталог эндпоинтов hh.ru

Правило исходника: только наблюдения через MCP DevTools. Дата = когда проверено.

### 4.1. Авторизация (account)

| Метод | Path | Параметры | Статус | Назначение | Проверено |
|---|---|---|---|---|---|
| GET | `/account/login` | `role`, `backurl`, `hhtmFrom` | 200 | страница входа (SPA); отдаёт `loginTrustFlagsSecret` (RSA-ключ) и `loginForm` в globalVars | 2026-08-02 |
| POST | `/account/login` | query: `backurl`, `role`; тело multipart: `username`, `password`, `accountType`, `failUrl`, `remember`, `loginTrustFlags`, `captchaText` | 200 JSON | вход по паролю; успех: Set-Cookie `crypted_id`+`hhul`+`_hi`+новый `hhtoken` (см. §1.3 «Шаг 3») | 2026-08-02 |
| POST | `/account/otp_generate` | FormData: `login`, `otpType`, `operationType`, `authScenario`, `backurl`, `loginTrustFlags` | 200 | запрос SMS-кода (по коду бандла) | 2026-08-02 |
| POST | `/account/login/by_code` | FormData: `username`, `code`, `operationType`, `backurl`, `isApplicantSignup`, `remember`, `loginTrustFlags`, `authScenario` | 200 | вход по SMS-коду (по коду бандла) | 2026-08-02 |
| GET | `/account/connect` | `backurl`, `role`, `site=ESIA\|VK\|GPLUS\|MAIL\|OK`, `_xsrf`, `hhtmSource`, `userType`, `entrypoint` | — | вход через соцсети/Госуслуги | 2026-08-02 |
| GET | `/account/signup` | `backurl`, `role` | — | регистрация (поля в globalVars.applicantSignup: login, password 6–32, firstName, lastName) | 2026-08-02 |
| POST | `/account/logout` | тело формы `_xsrf=<токен>` | 302 → `/` | выход (см. §1.7) | 2026-08-02 |

Заметки по логину (детально см. §1.3–1.6):
- POST /account/login — `content-type: multipart/form-data`; заголовки `x-xsrftoken` (= `_xsrf`),
  `x-requested-with: XMLHttpRequest`, `accept: application/json`, `x-hhtmfrom`, `x-hhtmsource`, gib-заголовки [ПРОВЕРЕНО].
- `loginTrustFlags` — RSA-OAEP(SHA-256)-шифрованный JSON `{...флаги ввода, ts}` публичным ключом
  из `globalVars.loginTrustFlagsSecret`; флаги ввода — `state.loginTrustFlags` (Redux):
  `{inputType: {suggest|paste|drop|insertFromPaste|insertFromDrop|insertReplacementText: bool}}` [ПРОВЕРЕНО].
- Ответ POST /account/login при ошибке: 200 JSON `loginError{code,trl}`, `recaptcha{isBot,siteKey}`,
  `hhcaptcha`, `redirectConfig{permittedHosts,permittedAppSchemes}`, `authUrl{...}` [ПРОВЕРЕНО].
- При успехе клиент делает `window.location.assign(data.backurl)` (навигация на backurl) [ПРОВЕРЕНО по коду].

### 4.2. Главная страница и «вакансии дня»

| Метод | Path | Параметры | Статус | Назначение | Проверено |
|---|---|---|---|---|---|
| GET | `/` | — | 200 | SPA-оболочка (React) | 2026-08-02 |
| POST | `/account/logout` | тело формы `_xsrf=<токен>` | 302 → `/` | выход из аккаунта (см. §1.7) | 2026-08-02 |
| POST | `/api/fl?idgib-w-hh` | — | 200 | фича-флаги, первый вызов без u/cfids | 2026-08-02 |
| GET | `/api/fl/idgib-w-hh` | — | 200 | gib: GET-инициализация, новый `cfids` + Set-Cookie `cfidsgib-w-hh` (детали в §2) | 2026-08-02 |
| POST | `/api/fl?u={uuid}&cfidsgib-w-hh={enc}` | `u` — UUID (`8904b7c0-4a21-11f1-9913-3b69330000001`); `cfidsgib-w-hh` — зашифрованная строка | 200 | gib: загрузка состояния (детали в §2) | 2026-08-02 |
| GET | `/shards/vacancies_of_the_day` | — | 200 | вакансии дня (блок главной) | 2026-08-02 |
| POST | `/shards/enrich_vod` | — | 200 | обогащение вакансий дня | 2026-08-02 |
| GET | `content.hh.ru/api/v1/vacancy_of_the_day/click` | `vacancyId`, `contentId`, `contentPlaceId`, `domainAreaId`, `host`, `turbo` | 200 | клик по вакансии дня (из `links.desktop`) | 2026-08-02 |
| GET | `content.hh.ru/api/v1/vacancy_of_the_day/impression` | `contentId`, `contentPlaceId` | 200 | показ вакансии дня (из `viewUrl`) | 2026-08-02 |

Структура `/shards/vacancies_of_the_day` (JSON):
`{"vacancies": [{area:{id,name}, name, vacancyId, company:{id, visibleName, department?, logoUrl, employerOnAdditionalCheck},
chatWritePossibility, compensation:{from,to,currencyCode,perModeFrom,perModeTo,mode,gross}, employmentForm,
links:{desktop}, pfpVacancy, showContact, userTestPresent, vacancyOfTheDayId, viewUrl}]` [ПРОВЕРЕНО]

Заметки:
- `u` в `/api/fl` — UUID v1 (time-based, содержит `11f1`): клиентский id; виден в открытом виде в теле запроса [ПРОВЕРЕНО].
- **Протокол синхронизации состояния «gib»**: клиентский стейт зашифрован и живёт в куках
  `cfidsgib-w-hh` / `gsscgib-w-hh` / `fgsscgib-w-hh` / `__zzatgib-w-hh` (и в localStorage).
  При каждом запросе сервер возвращает новые значения через Set-Cookie (Expires +1 год,
  Secure, SameSite=None) [ПРОВЕРЕНО].
- Ответ `/api/fl`: `{"status":"success","error":null,"data":{"cfids":"<enc>","cs":{"cfids":"<enc>","gssc":"<enc>"}}}` —
  сервер отдаёт новые зашифрованные значения состояния [ПРОВЕРЕНО].
- Тело POST `/api/fl` — зашифрованный блоб (`content-type: text/plain;charset=UTF-8`),
  в начале в открытом виде: `MDA1` + UUID `u` + base64-блоб [ПРОВЕРЕНО].
- Заголовки запроса `/api/fl`: `x-cfids` (= cfidsgib-w-hh), `x-gib-gsscgib-w-hh` (= gsscgib-w-hh),
  `x-gib-fgsscgib-w-hh` (= fgsscgib-w-hh), `origin: https://hh.ru` [ПРОВЕРЕНО].
- `_xsrf` ходит в заголовке **`x-xsrftoken`** (видно на `/shards/vacancies_of_the_day`) [ПРОВЕРЕНО].

### 4.3. Поиск вакансий (`/search/vacancy`)

> Синтаксис запросов (`text=...`): операторы `!`, `""`, `~N`, `*`, `ПОЛЕ:`, `^ПОЛЕ:`,
> `AND/OR/NOT/( )` — см. §3 (источник: статья hh.ru/article/25295).

| Метод | Path | Параметры | Статус | Назначение | Проверено |
|---|---|---|---|---|---|
| GET | `/search/vacancy` | `text`, `area`, `page`, `search_session_id`, `hhtmFrom`, ... | 200 | выдача: **SSR-документ**, карточки в HTML; JSON-API при загрузке не вызывается | 2026-08-02 |
| POST | `/highlight` | тело JSON `{query, strings[]}` | 200 | серверная подсветка совпадений в сниппетах: ответ — те же строки с `<highlighttext>` | 2026-08-02 |
| GET | `/api/fl/idgib-w-hh` | — | 200 | gib-инициализация (GET-вариант): отдаёт новый `cfids` + Set-Cookie `cfidsgib-w-hh` | 2026-08-02 |
| POST | `/api/fl` | query: `u={uuid}`, `cfidsgib-w-hh={enc}` | 200 | gib-загрузка состояния (см. §2) | 2026-08-02 |

Структура выдачи (в HTML): карточка вакансии — `<div class="vacancy-card--<hash>" id="<vacancy_id>">`;
внутри: название (`a[href="/vacancy/{id}?query=...&hhtmFrom=vacancy_search_list"]`), зарплата,
опыт, компания, метро, сниппеты описания. Пагинация — обычные ссылки `page=0..39`
с `search_session_id` (UUID в URL) [ПРОВЕРЕНО].

`POST /highlight` [ПРОВЕРЕНО]:
- Заголовки: `x-xsrftoken: <_xsrf>`, `x-hhtmsource: vacancy_search_list`, `x-hhtmfrom:`,
  `x-requested-with: XMLHttpRequest`, `accept: application/json`, `content-type: application/json`,
  `referer: https://hh.ru/search/vacancy?...`, `origin: https://hh.ru`.
- Тело: `{"query":"python","strings":["<сниппет1>","..."]}` — клиент шлёт сниппеты
  видимых карточек; ответ: `{"query":"python","strings":["...<highlighttext>Python</highlighttext>..."]}`.
- Вызывается по несколько раз (по мере скролла/догрузки), всегда POST.

Gib-протокол на выдаче (сводка, подробности в §2):
- `GET /api/fl/idgib-w-hh`: заголовки `x-cfids` (= `cfidsgib-w-hh`), `x-gib-gsscgib-w-hh`
  (= `gsscgib-w-hh`), `x-gib-fgsscgib-w-hh` (= `fgsscgib-w-hh`), `if-none-match` (= ETag прошлого ответа).
  Ответ `{"status":"success","error":null,"data":{"cfids":"<enc>"}}`; Set-Cookie:
  `cfidsgib-w-hh=<enc>` (Path=/, Expires +1 год, Secure, SameSite=None); заголовок `etag` в ответе.
- `POST /api/fl?u=8904b7c0-4a21-11f1-9913-3b69330000001&cfidsgib-w-hh=<новый cfids из GET>`:
  тело `text/plain;charset=UTF-8`: префикс `MDA1` (base64 «005» — версия) + открытый UUID из `u`
  (в теле без последней цифры) + base64-блоб(ы) с `=`-паддингом внутри (конкатенация блоков).
  Заголовки: `x-cfids: <СТАРЫЙ cfids>`, `x-gib-gsscgib-w-hh: <старый gssc>`, `x-gib-fgsscgib-w-hh: <новый fgssc>`.
  Ответ `{"status":"success","error":null,"data":{"cfids":"<enc>","cs":{"cfids":"<enc>","gssc":"<enc>"}}}`;
  Set-Cookie: новые `gsscgib-w-hh` + `cfidsgib-w-hh` (оба +1 год, Secure, SameSite=None).
- Вызовы повторяются периодически (несколько POST /api/fl и /highlight на странице).

Заметки:
- Set-Cookie на документе выдачи: `total_searches=1` (счётчик поисков, без HttpOnly),
  продлеваются `regions`, `display=desktop`, `_xsrf`, `hhuid`, `hhul` (HttpOnly), `hhrole=applicant`,
  `_hi` (Path=/, Secure), `crypted_id`, `crypted_hhuid`; DataDome `__ddg8_/9_/10_` [ПРОВЕРЕНО].
- Заголовки ответа выдачи: `server: ddos-guard`, `server-timing: frontik`,
  `x-hhid: 17192618` (= `_hi`), `x-hhuid` (= `hhuid`), `cache-control: no-store` [ПРОВЕРЕНО].
- globalVars на выдаче: `pageName: vacancy_search_list`, `luxPageName: VacancySearch`,
  `analyticsParams: {hhtmSource: vacancy_search_list, screenType: SIMPLE}`,
  `area: 113`, `country: 1`, `apiHost: https://api.hh.ru` [ПРОВЕРЕНО].
- В `globalVars.features`: `fingerprinting_enable: true` (для залогиненных),
  `employer_chrome_extensions_to_detect` (список расширений-конкурентов),
  `secure_portal_enabled`, `yandex_adfox_enabled` [ПРОВЕРЕНО].
- Вебсокет-соединение на выдаче не открывается (только `websocket.hh.ru/proxy-webapp/index.html` +
  `proxy-webapp-config` загружаются) [ПРОВЕРЕНО].
- Сборка бандлов: `https://i.hh.ru/build/*.js`, роут `VacancySearch-route.c98e842b7fa51001.js` [ПРОВЕРЕНО].

**Структура карточки выдачи (вёрстка magritte 2026) [ПРОВЕРЕНО 2026-08-02]:**
- Контейнер: `<div class="vacancy-card--<hash>" id="<vacancy_id>">`; 20 карточек на страницу.
- Заголовок: `a[data-qa=serp-item__title]` (href на /vacancy/{id}?query=...&hhtmFrom=vacancy_search_list),
  текст — `span[data-qa=serp-item__title-text]`.
- Зарплата: `span` БЕЗ data-qa, внутри `<data value="300000">300 000</data> <data value="RUB">₽</data>`
  (`value` — число и валюта ISO), текст: «от 300 000 ₽ за месяц, на руки». Старый data-qa
  `vacancy-serp__vacancy-compensation` в новой вёрстке отсутствует.
- Выплаты: `span[data-qa=vacancy-serp__vacancy-compensation-frequency-MONTHLY|TWICE_PER_MONTH|WEEKLY|PER_PROJECT]`
  («Выплаты: Два раза в месяц») — отдельно от суммы.
- Компания: `a[data-qa=vacancy-serp__vacancy-employer]` (href /employer/{id}), текст —
  `span[data-qa=vacancy-serp__vacancy-employer-text]`; рядом `trusted-employer-link`,
  `company-review-rating-value`, `vacancy-serp__vacancy_employer-hh-rating`.
- Опыт: `[data-qa=vacancy-serp__vacancy-work-experience-between1And3]` и др. (текст «Опыт 1-3 года»);
  график: `[data-qa=vacancy-label-work-schedule-remote]` («Можно удалённо»), `vacancy-label-side-job`.
- Адрес: `[data-qa=vacancy-serp__vacancy-address]`; станции метро — вложенные
  `[data-qa=address-metro-station-name]`.
- Сниппеты: `[data-qa=vacancy-serp__vacancy_snippet_responsibility]` и `_requirement`.
- Кнопки: `[data-qa=vacancy-serp__vacancy_response]` («Откликнуться»), `[data-qa=vacancy-serp__vacancy_contacts]`.
- Счётчик: `h1[data-qa=title]` → «Найдена 3 301 вакансия» (число с пробелами).
- Пагинация: `nav[data-qa=pager-block]` → `a[data-qa=pager-page]`; href содержит
  `text=...&area=...&page=N&search_session_id=<uuid>&hhtmFrom=vacancy_search_list`;
  текущая страница — `aria-current="true"`. `search_session_id` — UUID, стабилен для выдачи.
- Сортировка в URL: `order_by=salary_desc` и т.п. [ГИПОТЕЗА: работает как и раньше].
- `GET /search/vacancy` без `page` = страница 0; выдачу можно пагинировать, передавая
  `page=N` + `search_session_id` (как ссылки в пейджере). [ПРОВЕРЕНО: реализовано в hh.api.search_vacancy].

### 4.4. Страница вакансии (`/vacancy/{id}`)

| Метод | Path | Параметры | Статус | Назначение | Проверено |
|---|---|---|---|---|---|
| GET | `/vacancy/{id}` | `query`, `hhtmFrom` (из выдачи) | 200 | SSR-документ: заголовок, зарплата, опыт, описание, JSON-LD `JobPosting` | 2026-08-02 |
| GET | `/applicant/vacancy_response/popup` | `isTest=no`, `lux=true`, `withoutTest=no`, `isCheckingResponseType=true`, `isChatWithoutResponse=true`, `vacancyId={id}` | 200 | данные модалки отклика (iframe: `css_links`, `inline_script`, `type`), вызывается 3× | 2026-08-02 |
| GET | `/applicant/blacklist/state` | `vacancyId`, `employerId` | 200 | статус чёрного списка: `{vacancyIsBlacklisted, employerIsBlacklisted, limitReached}` | 2026-08-02 |
| GET | `/shards/vacancy_view_count` | `vacancyId` | 200 | «смотрят N человек»: `{vacancyViewCount: null\|int}` | 2026-08-02 |
| GET | `/shards/vacancies/feedback/roulette` | `employerId`, `vacancyId` | 200 | предложение отзыва: `{ask: false}` | 2026-08-02 |
| GET | `/shards/vacancy/related_vacancies` | `vacancyId`, `page`, `search_session_id`, `hhtmSourceLabel=suitable_vacancies` | 200 | похожие вакансии (подборка «подходящие») | 2026-08-02 |
| GET | `/shards/vacancy/related_vacancies` | + `employerId`, `hhtmSourceLabel=suitable_employer_vacancies` | 200 | вакансии работодателя (подборка) | 2026-08-02 |
| GET | `/shards/banners/targeting_params` | `area`, `roles`, `vacancyTitle` | 200 | таргетинг баннеров: возвращает `bannersBatchUrl` с профильными данными (см. ниже) | 2026-08-02 |
| GET | `/shards/employer_reviews/big_widget` | `employerId`, `vacancyId` | 200 | блок отзывов о компании | 2026-08-02 |
| GET | `employer-reviews-front.hh.ru/employer_reviews/proxy_components/{complain_button\|small_widget\|big_widget}` | `employerId`, `vacancyId`, `success`, `noticeable`, `is_magritte`, `is_on_employer_page` | 200 | микро-виджеты отзывов (отдельный фронт) | 2026-08-02 |

Заметки:
- Все шарды вакансии ходят с заголовками: `x-hhtmsource: vacancy`, `x-hhtmfrom: <источник>`,
  `x-requested-with: XMLHttpRequest`, `accept: application/json`, `x-xsrftoken: <_xsrf>`,
  `referer: https://hh.ru/vacancy/{id}?...` + gib-заголовки на части запросов [ПРОВЕРЕНО].
- `GET /shards/banners/targeting_params` → `{"bannersBatchUrl": "https://adsrv.hh.ru/pv?vacancyTitle=...&rId=<x-request-id>&age=45&salary=200000&type=applicant&gender=MALE&position=...&regions=1,2025,2019,142,113,232&professionalRoles=160,96,165&languages=eng,rus&profileRegions=...&profileSpecs=273,221&profileProfessionalRoles=160,96&profileLanguages=eng,rus&profileSalary=200000&contextRegions=1&contextProfessionalRoles=165&domainAreaId=1"}` —
  **сервер сам подставляет данные профиля/резюме** (возраст, пол, зарплата, позиции, регионы, роли,
  языки, специализации) [ПРОВЕРЕНО].
- `search_session_id` на `/shards/vacancy/related_vacancies` — новый UUID (не тот, что в URL выдачи) [ПРОВЕРЕНО].
- В HTML вакансии: JSON-LD `<script type="application/ld+json">` со схемой `JobPosting`:
  `description` (HTML), `datePosted`, `validThrough`, `title`, `hiringOrganization{name}`,
  `jobLocation{address}`, `applicantLocationRequirements`, `identifier{value: vacancyId}`;
  `og:image: https://thumbnail.hh.ru/vacancy/{id}.png` [ПРОВЕРЕНО].
- globalVars на вакансии: `pageName: vacancy`, `luxPageName: VacancyView`,
  `analyticsParams: {vacancyId, active, archived, disabled, brandingType: MAKEUP, hhtmFrom, hhtmSource: vacancy}`,
  `userType: applicant`, `hhid: <_hi>` [ПРОВЕРЕНО].
- Контакт в вакансии: `heading «Контакты»` + имя (`Ким Елизавета`); «Связаться» — отдельная кнопка [ПРОВЕРЕНО].

**Data-qa для парсера страницы вакансии [ПРОВЕРЕНО 2026-08-02]:**

| data-qa | Что даёт | Пример |
|---|---|---|
| `vacancy-title` | название | `Data Scientist в Сетку` |
| `vacancy-salary`, `vacancy-salary-compensation-type-net` | зарплата (текст) | `от 300 000 ₽ за месяц, на руки` |
| `vacancy-experience` | опыт | `1–3 года` |
| `work-experience-text` | опыт (полная строка) | `Опыт работы: 1–3 года` |
| `common-employment-text` | занятость | `Полная занятость` |
| `work-schedule-by-days-text` | график | `График: 5/2` |
| `work-formats-text` | формат | `Формат работы: удалённо или гибрид` |
| `vacancy-company-name` | работодатель | `ООО HeadHunter::Analytics/Data Science` |
| `vacancy-description` | описание (HTML) | — |
| `skills-element` | ключевые навыки (по одному элементу) | `WMS-системы`, `HTTP` |

- Зарплата также разбита на `<data value="300000">300 000</data> <data value="RUB">₽</data>`
  (value = число и ISO-валюта), как в выдаче [ПРОВЕРЕНО].
- JSON-LD `JobPosting` (единственный `script[type=application/ld+json]`): `title`, `description` (HTML),
  `datePosted`/`validThrough` (ISO+03:00), `identifier.value` (vacancyId), `hiringOrganization.name`,
  `jobLocation.address.{addressLocality,addressRegion,addressCountry,streetAddress}`,
  `applicantLocationRequirements.name` (страна). `baseSalary` в JSON-LD отсутствует [ПРОВЕРЕНО].

### 4.5. Отклик на вакансию (apply, `/applicant/vacancy_response/popup`)

| Метод | Path | Параметры | Статус | Назначение | Проверено |
|---|---|---|---|---|---|
| POST | `/shards/vacancy/register_interaction` | тело JSON `{"vacancyId": int}` | 200 | регистрация взаимодействия с вакансией при клике «Откликнуться»; ответ = JSON попапа (css_links + inline_script) | 2026-08-02 |
| GET | `/applicant/vacancy_response/popup` | `vacancyId`, `isTest=no`, `withoutTest=no`, `lux=true`, `alreadyApplied=false` | 200 | данные модалки отклика: `type: "modal"`, `responsePopup`, `responseStatus`, `letterMaxLength`, `shortVacancy` (полная карточка) | 2026-08-02 |
| POST | `/shards/hhpro_ai_letter` | тело JSON `{"resumeHash", "vacancyId"}` | 200 XML `<doc/>` | регистрация запроса AI-письма (hhpro) | 2026-08-02 |
| GET | `/shards/hhpro_ai_letter` | `resumeHash`, `vacancyId` | 200 | сгенерированное AI-сопроводительное: `{vacancyId, resumeId, generatedLetter, status: "SUCCESS"}` | 2026-08-02 |
| POST | `/applicant/vacancy_response/popup` | multipart-форма (поля ниже) | 200 | **отправка отклика**; ответ `{success, topic_id, chat_id, response_label, ...}` | 2026-08-02 |
| GET | `/applicant/vacancy_response/popup` | `isTest=no`, `lux=true`, `withoutTest=no`, `isCheckingResponseType=true`, `isChatWithoutResponse=false`, `vacancyId` | 200 | проверка типа ответа после отправки (нужны ли доп. вопросы) | 2026-08-02 |
| GET | `/shards/have_area_districts` | `area`, `filterMicro=true` | 200 | есть ли районы у населённого пункта: `{result: bool}` (для модалки «Где ищете работу») | 2026-08-02 |

**Тело POST `/applicant/vacancy_response/popup` (multipart/form-data) [ПРОВЕРЕНО]:**

```
_xsrf                               = <кука _xsrf>
vacancy_id                          = 135638814
resume_hash                         = 27127c3eff01cbb4a80039ed1f677470496a44  (40-hex hash резюме)
ignore_postponed                     = true
incomplete                          = false
mark_applicant_visible_in_vacancy_country = false
country_ids                         = []
letter                              = <текст сопроводительного письма>
lux                                 = true
withoutTest                         = no
hhtmFromLabel                       = suitable_vacancies
hhtmSourceLabel                     = (пусто)
```

**Ответ POST (успех):**

`{"success":"true","topic_id":"5471456270","chat_id":"5519016396","response_label":"nonreq-letter-no-test-with-letter",
"vacancy_id":"135638814","applicantActivity":{"userActivityScore":12,"userActivityScoreChange":8,"showActivity":true},
"requiredAdditionalData":["PREFERRED_WORK_AREAS"],"resumeFields":{...полное резюме: salary, experience[]...}}`

- `topic_id` — id переговоров (negotiation), `chat_id` — id чата [ПРОВЕРЕНО].
- `response_label` — строка-маркер типа отклика: `nonreq-letter-no-test-with-letter` (без теста, с письмом) [ПРОВЕРЕНО].
- `requiredAdditionalData` — что дозаполнить после отклика: `PREFERRED_WORK_AREAS` → модалка
  «Где ищете работу?» (город поиска, районы, метро) [ПРОВЕРЕНО].
- `resumeFields` — сервер возвращает полный опыт из резюме (места работы, описания) [ПРОВЕРЕНО].

**Ответ GET попапа (до отклика) — ключевые поля:**

- `type: "modal"`; `responsePopup: {type: "normal", startedWithQuestion: bool, vacancy: {vacancyId}}` [ПРОВЕРЕНО].
- `responseStatus`: `{test: {hasTests}, resumeInconsistencies: {}, negotiations: {topicList, total, readOnlyInterval: 180,
  untrustedEmployerRestrictionsApplied}, by_country_applicant_visibility: {responseAllowed}}` [ПРОВЕРЕНО].
- `letterMaxLength: 10000`; `shortVacancy` — полная карточка вакансии: `@workSchedule`, `@showContact`,
  `@responseLetterRequired`, `vacancyId`, `name`, `company` (id, name, logos, badges, аккредитация),
  `compensation`, `publicationTime`, `area`, `employerManager` (ФИО, @hhid, @managerId, @userId),
  `inboxPossibility`, `chatWritePossibility`, `links.{desktop, mobile}`, `acceptTemporary`,
  `creationSite`, `displayHost`, `vacancyProperties` (пакеты HH_STANDARD и пр.) [ПРОВЕРЕНО].
- Попап рендерится в модалке из JSON: `css_links[]` + `inline_script` (JS-бандл), `sentry_traceparent/baggage` [ПРОВЕРЕНО].
- Заголовки всех запросов отклика: `x-hhtmsource: vacancy`, `x-hhtmfrom: <источник>`,
  `x-requested-with: XMLHttpRequest`, `accept: application/json`, `x-xsrftoken: <_xsrf>`,
  gib-заголовки (`x-gib-gsscgib-w-hh`, `x-gib-fgsscgib-w-hh`) [ПРОВЕРЕНО].
- После отклика кнопка на вакансии меняется на «Вы откликнулись» + «Отклик другим резюме» + «Чат» [ПРОВЕРЕНО].

**Ошибки POST (тело JSON, HTTP 400) [ПРОВЕРЕНО 2026-08-02]:**

- `{"error":"unknown"}` — неверный `resume_hash` (в т.ч. внутренний id резюме вместо 40-hex hash)
  или несуществующий `vacancy_id`.
- HTTP 403 — нет авторизации/антибот (в api.apply_vacancy ловится отдельно).
- `{"error":"test-required"}` — вакансия требует прохождение теста (§4.6).

**Вакансии с тестом: GET popup → `type: test-required` [ПРОВЕРЕНО 2026-08-02]:**

Для вакансии с тестовым заданием (`userTestPresent:true` в JSON карточки, `userTestId` рядом)
GET popup (любой комбинацией `isTest`/`withoutTest`) НЕ отдаёт модалку, а отвечает:

```json
{"type":"test-required", "redirect_uri":"/applicant/vacancy_response?vacancyId=<id>&startedWithQuestion=false&hhtmFrom=vacancy", ...}
```

Т.е. отклик идёт через страницу `/applicant/vacancy_response?vacancyId=<id>&startedWithQuestion=false`
(анкета с вопросами работодателя = «тест»). Замечание: `test.hh.ru` — диагностическая страница,
не платформа тестов; «тест» = вопросы при отклике (сервис «Вопросы и тесты» работодателя).

### 4.6. Тесты и вопросы при отклике (`/applicant/vacancy_response`) [ПРОВЕРЕНО 2026-08-02]

| Метод | Path | Параметры | Статус | Назначение | Проверено |
|---|---|---|---|---|---|
| GET | `/applicant/vacancy_response` | `vacancyId`, `startedWithQuestion=false`, `hhtmFrom` | 200 | страница отклика: анкета-тест + резюме + письмо; JSON `vacancyTests` и `applicantVacancyResponseStatuses` в HTML (SSR) | 2026-08-02 |

Признак теста (без открытия страницы):
- в выдаче: `userTestPresent` (`:t`/`:f` — минификатор вместо true/false) и `userTestId` в JSON карточки;
- GET popup → `type: "test-required"` (см. выше).

**JSON `applicantVacancyResponseStatuses[vacancyId]` (SSR-страница отклика):**

`{test: {hasTests: true, testId: <id>, required: true}, resumeInconsistencies: {}, negotiations: {topicList, total, ...}, ...}` —
`test.testId` == `userTestId` из карточки [ПРОВЕРЕНО].

**JSON `vacancyTests[vacancyId]` (SSR-страница отклика) — сам тест:**

```json
{
  "uidPk": "348989082",
  "guid": "2807D79A-297B-C754-0104-289D9C1B842B",
  "name": "Backend Fast API (Лайт)",
  "description": "...",
  "required": "true",
  "startTime": "1785693838",
  "tasks": [
    {"id": 348989083, "description": "...", "multiple": "false", "open": "true",
     "candidateSolutions": [{"id": "348989084", "text": "Да"}, {"id": "348989085", "text": "Нет"}]}
  ]
}
```

- `uidPk`/`guid` — идентификатор экземпляра теста; `startTime` — unixtime старта (генерируется при загрузке страницы);
- `tasks[]` — вопросы: `id`, `description` (HTML), `multiple` (checkbox|radio), `open` (есть свободный ответ),
  `candidateSolutions[]` — варианты `{id, text}`.
- В SSR-HTML ключи/значения экранированы: `&#34;` вместо `"`, `&amp;` вместо `&`, `&lt;`/`&gt;` в description.
  В DOM (`document.documentElement.outerHTML`) — обычный JSON [ПРОВЕРЕНО].

**Форма ответа (поля):**

- Ответ на задачу с вариантами: `task_<taskId>` = id выбранного `candidateSolution` (radio/checkbox),
  либо значение `open` (свой вариант);
- Свободный ответ (в т.ч. `candidateSolutions: []`): `task_<taskId>_text` = текст;
- Скрытые поля формы: `uidPk`, `guid`, `startTime`, `testRequired=true` (кроме стандартных из apply).

**POST `/applicant/vacancy_response/popup` с ответами на тест [ПРОВЕРЕНО вживую]:**

К стандартным полям формы apply добавляются:

```
uidPk       = <uidPk из vacancyTests>
guid        = <guid из vacancyTests>
startTime   = <unixtime старта>
testRequired = true
task_<id>   = <id варианта | open>        # для задач с candidateSolutions
task_<id>_text = <текст>                  # для открытых задач
```

Успех: `{"success":"true","topic_id":...,"chat_id":...,"response_label":"nonreq-letter-req-test-without-letter",...}` —
`response_label` содержит `req-test`, т.е. тест пройден [ПРОВЕРЕНО 2026-08-02, вакансия 133876888, task_326857913_text + task_326857914_text].

### 4.7. Профиль соискателя (`/applicant/profile/me`)

| Метод | Path | Параметры | Статус | Назначение | Проверено |
|---|---|---|---|---|---|
| GET | `/applicant/profile/me` | `hhtmFrom`, `hhtmFromLabel` | 200 | профиль соискателя: **SSR** (данные резюме/контакты/опыт прямо в HTML) | 2026-08-02 |
| POST | `/shards/applicant/profile/update` | тело JSON `{"profile":{...}}` | 200 | сохранение/дозаполнение анкеты соискателя (напр. `preferredWorkAreas` после отклика); **ответ = полный профиль** `profile.fields` | 2026-08-02 |
| GET | `/applicant/resumes` | `hhtmFrom`, `hhtmFromLabel` | **302** → `/applicant/profile/me` | старый путь списка резюме редиректит на профиль | 2026-08-02 |
| GET | `resume-profile-front.hh.ru/applicant/profile/shards/suitable_vacancies` | `hashes=<hash>&hashes=<hash>` (по одному на резюме) | 200 | число подходящих вакансий: `{counters: {<hash>: 1060, ...}}` | 2026-08-02 |
| GET | `resume-profile-front.hh.ru/profile/shards/artifacts/get` | `type=RESUME_PHOTO` | 200 | фото профиля: `{images:[{id, state, type, artifactType, big/preview/avatar, creationTime}]}` | 2026-08-02 |
| GET | `resume-profile-front.hh.ru/applicant/profile/shards/obtain_epgu_cert_banner` | — | 200 | баннер сертификата ЕПГУ: `{noContent:true}` | 2026-08-02 |
| GET | `resume-profile-front.hh.ru/profile/shards/maps/yandex` | `lang=ru_RU` | 200 | карта «где живу» | 2026-08-02 |
| GET | `career.hh.ru/career_platform/proxy_components/entrypoint_widget` | `entryPoint=RESUME_LIST` | 200 | виджет карьерной платформы | 2026-08-02 |

Заметки:
- Профиль — **микрофронт** `resume-profile-front.hh.ru` (module federation: бандлы
  `https://resume-profile-front.hh.ru/static/*.js`, стили `*.css`), подключается через
  `ProxyExternalService-route.*` в оболочке hh.ru; данные — SSR в HTML документа `/applicant/profile/me` [ПРОВЕРЕНО].
- Резюме в SSR: `<div data-qa="resume" data-qa-id="30127272" data-qa-title="разработчик 1С, python-backend">`,
  ссылка `a[data-qa="resume-card-link-<hash>"]`; hash резюме — 40 hex (`27127c3eff01cbb4a80039ed1f677470496a44`),
  внутренний id — `data-qa-id` (`282869653`, `30127272` — те же, что в `/shards/applicant/header_resumes`) [ПРОВЕРЕНО].
- Подходящие вакансии: `/search/vacancy?resume=<hash>&from=resumelist` [ПРОВЕРЕНО].
- Шарды микрофронта ходят с заголовками: `x-hhtmsource: applicant_profile`, `x-hhtmfrom`,
  `x-hhtmsourcelabel`/`x-hhtmfromlabel`, `x-requested-with: XMLHttpRequest`, `x-xsrftoken`,
  `origin: https://hh.ru`, `referer: https://hh.ru/` (не URL профиля!), gib-куки [ПРОВЕРЕНО].
- `obtain_epgu_cert_banner` дополнительно: `x-proxied-place: obtainEpguCertBanner`,
  `x-proxied-hhtm-source: applicant_profile`, `x-proxied-page-name: applicant_profile`,
  `x-proxied-type: Component`, `x-is-spa: true`, `x-use-ssr: False` — BFF-проксирование
  компонентов на фронт-домене [ПРОВЕРЕНО].
- В документе профиля: `analyticsParams.hhtmSource: resume_profile_front`; `pageName: applicant_profile` [ГИПОТЕЗА — уточнить].
- Фото профиля: `img.hhcdn.ru/photo/<id>.jpeg?t=<ts>&h=<hash>` (big/preview/avatar варианты) [ПРОВЕРЕНО].
- Бандлы профиля грузятся медленно (микрофронт): страница «пустая» до загрузки
  `notSharedVendors.*.js` + `applicant_profile-route.*.js` (~40 с в нашем случае) [ПРОВЕРЕНО].
- «Вы откликнулись N раз» и статистика резюме (просмотры, приглашения) — в SSR-данных [ПРОВЕРЕНО].
- `POST /shards/applicant/profile/update` — тело `{"profile":{"preferredWorkAllAreas":false,"preferredWorkAreas":[{"area":2025,"districts":[],"metroLines":[],"metroStations":[]}]}}`
  (JSON, не multipart). Ответ: `{"nextIncompleteScreenId":null, "screens":null, "profile":{...}}` —
  `nextIncompleteScreenId: null` = анкета больше не требует дозаполнения [ПРОВЕРЕНО 2026-08-02].
- Ответ `profile.fields` содержит **весь профиль**: `experience[]` (id, startDate/endDate, companyName,
  companyId/employerId, position, description, companyLogos, verification, `resumes:[{hash}]`),
  `additionalEducation`, `attestationEducation[]` (id, name, organization, result, year, `resumes:[{hash}]`),
  `elementaryEducation`, `birthday`, `citizenship[{string}]`, `educationLevel`, `driverLicenseTypes`,
  `communicationMethods` (telegram/whatsapp/viber/setka/max), `area[{string}]`, `areaInfo[{areaId,lat,lng}]`,
  `addressCoordinates[{lat,lng}]` — т.е. одна ручка отдаёт полный профиль соискателя [ПРОВЕРЕНО 2026-08-02].
- Ответ дополнительно продлевает куки `hhuid`, `_hi`, обновляет DataDome-куки `__ddg8_/9_/10_` [ПРОВЕРЕНО].

### 4.8. Резюме: страница и скачивание (`/resume/{hash}`, `/resume_converter/`) [ПРОВЕРЕНО 2026-08-02]

| Метод | Path | Параметры | Статус | Назначение | Проверено |
|---|---|---|---|---|---|
| GET | `/resume/{hash}` | `hash` — 40 hex (см. профиль), `query` | 200 | страница резюме: **SSR**, данные (ФИО, контакты, опыт, образование, навыки) прямо в HTML; XHR к API hh.ru НЕ делает (только `/api/fl`, `chatik`) | 2026-08-02 |
| GET | `/resume_converter/{filename}.{ext}` | `hash` (обязателен), `type=doc\|rtf\|pdf\|txt`, `hhtmFrom`, `hhtmSource` | 200 | скачивание резюме в формате; **требует авторизации** (403 без кук сессии) | 2026-08-02 |

Форматы (меню «Скачать», `data-qa="resume-download-button"` → dropdown `drop-base`):

| type | Возврат | content-type | Примечание |
|---|---|---|---|
| `txt` | HTML-документ с разметкой резюме | `text/html; charset=utf-8` | **не сырой txt!** — текст в HTML (классы `resume__*`, см. ниже) |
| `pdf` | бинарный PDF | `application/pdf; charset=utf-8` | `content-disposition: attachment; filename*=UTF-8''<имя>.pdf`; `%PDF-1.5` (360 КБ в тесте) |
| `doc` | MS Word | `application/octet-stream`? | **фактически RTF** (`{\rtf1`, 213 КБ в тесте) — сервер отдаёт doc как RTF |
| `rtf` | RTF | — | `{\rtf1`, 213 КБ; **идентичен doc-версии по байтам** (одинаковый размер/магия) |

Заметки:
- `hash` в URL = hash резюме (тот же, что в `/resume/{hash}` и `a[data-qa="resume-card-link-<hash>"]`).
- **Имя файла в пути игнорируется**: запрос `/resume_converter/arbitrary-name.txt?hash=<hash>&type=txt`
  вернул то же резюме (title «Резюме \"разработчик 1С, python-backend\"»). Сервер берёт данные по `hash`;
  имя нужно только для `content-disposition` при скачивании (подставляется из URL: `filename*=UTF-8''test.pdf`).
  Клиент может подставить любое имя (лучше ФИО/должность) [ПРОВЕРЕНО].
- **Авторизация обязательна**: в чистом изолированном контексте (без кук) → **403**, отдаётся SPA-оболочка
  (title «HeadHunter»), не данные [ПРОВЕРЕНО].
- Ссылки меню формируются на клиенте (React): `https://hh.ru/resume_converter/<ФИО>.<ext>?hash=<hash>&type=<ext>&hhtmFrom=&hhtmSource=resume`
  (в профиле соискателя встречалась ссылка с именем = должность и `hhtmFrom=vacancy&hhtmSource=applicant_profile`).
  `hhtmFrom`/`hhtmSource` — только аналитика, для скачивания не нужны [ПРОВЕРЕНО].
- Навигация браузера на `type=pdf` даёт `net::ERR_ABORTED` — браузер уходит в download (attachment);
  из JS `fetch(..., {credentials:'include'})` отдаёт 200 + полный PDF (заголовки выше).
- fetch из консоли на PDF иногда падает «Failed to fetch» (DataDome/первый запрос) — повторить с `cache:'no-store'`.

Сквозной тест клиента (2026-08-02, из Python `hh.api`): login → скачивание всех 4 форматов —
работает. Размер PDF совпал с браузерным байт-в-байт (360851). doc/rtf — оба RTF, 213462 байта.

Разметка TXT-версии (классы в `<style>` документа): `resume__title` (ФИО), `resume__block`
(заголовки блоков: «Желаемая должность и зарплата», «Опыт работы — N лет»), `resume__position`,
`resume__salary`, `resume-profession-role`, `resume-specialization`, `resume-experience` (компания/период/должность/описание),
`resume-education`, `resume-certificates`, `resume-skils__item`, `resume-additional__item`, `info`, `info-footer`
(дата обновления). Первый элемент — `<p class="info-footer">Резюме обновлено …</p>`. [ПРОВЕРЕНО]

### 4.9. Поднятие резюме (поднять в поиске, `resume/touch`) [ПРОВЕРЕНО 2026-08-02]

| Метод | Path | Параметры | Статус | Назначение | Проверено |
|---|---|---|---|---|---|
| POST | `resume-profile-front.hh.ru/profile/shards/resume/touch` | тело JSON `{"hash": "<40-hex hash резюме>"}` | 200, **пустое тело** | «поднять в поиске» (продлить актуальность резюме) | 2026-08-02 |

Заголовки запроса (снято с браузера):
- `x-xsrftoken: <_xsrf>` (обязателен), `x-requested-with: XMLHttpRequest`,
  `accept: application/json`, `content-type: application/json`;
- `x-hhtmsource: applicant_profile`, `x-hhtmfrom:`, `x-hhtmsourcelabel:`, `x-hhtmfromlabel:` (пустые);
- `origin: https://hh.ru`, `referer: https://hh.ru/` (**не URL профиля!** — как у остальных шардов микрофронта);
- gib-куки идут в `Cookie` (gssc/fgssc/cfids/`__zzatgib-w-hh`), но **заголовков `x-gib-*`/`x-cfids` НЕТ**
  (паттерн микрофронта, как на chatik.hh.ru) [ПРОВЕРЕНО].

Ответ: `200` с `content-length: 0` (пустое тело); обновляет куки DataDome (`__ddg8_/9_/10_`)
и `_xsrf`. Ход в метриках: `applicant_resume_renew_modal_opened` →
`applicant_resume_renew_complete_success` [ПРОВЕРЕНО].

Коды ответа (проверено из Python-клиента hh.api):
- `200` — успех (пустое тело);
- `403` — нет авторизации (без кук сессии / без `hhrole=applicant`);
- `409` — **резюме уже поднято**: сработал лимит частоты поднятия, тело пустое.
  В тесте 2026-08-02 резюме, поднятое в браузере за ~9 минут до запроса,
  вернуло 409. [ПРОВЕРЕНО 2026-08-02]

Заметки:
- Модалка «Поднять в поиске» — чисто клиентская (React): после подтверждения идёт **один**
  POST resume/touch, других запросов нет [ПРОВЕРЕНО].
- `hash` в теле = hash конкретного резюме (у пользователя их несколько; touch — по выбранному) [ПРОВЕРЕНО].
- Сразу после touch браузер повторно дёргает `/applicant/profile/shards/suitable_vacancies`
  (обновление счётчика подходящих вакансий) [ПРОВЕРЕНО].
- Успех также фиксирует аналитика-цель `applicant_resume_renew_complete_success` —
  отдельного API-подтверждения нет, 200 + пустое тело = успех [ПРОВЕРЕНО].
- Реализация в `hh.api`: `resume.touch_resume(session, resume_hash)` [ПРОВЕРЕНО].

### 4.10. Отклики и приглашения (`/applicant/negotiations`) [ОБНОВЛЕНО 2026-08-02]

| Метод | Path | Параметры | Статус | Назначение | Проверено |
|---|---|---|---|---|---|
| GET | `applicant/negotiations` | `filter=all\|response\|invitation\|interview\|offer\|refused`, `state` | 200 | список откликов: **SSR**; данные карточек — JSON в `<template id="HH-Lux-InitialState">` (Redux-стейт), не в DOM-карточках | 2026-08-02 |
| POST | `/applicant/negotiations/decline` | multipart: `topic`, `vacancyId`, `employerId`, `query` | 200 | отказаться от отклика (кнопка «Отказаться») | 2026-08-02 |
| POST | `/applicant/negotiations/trash` | multipart: `topic`, `vacancyId`, `employerId`, `query` | 200 | удалить отклик (кнопка «Удалить», substate=HIDE) | 2026-08-02 |

**Данные: `<template id="HH-Lux-InitialState">`**

Внутри template — полный JSON Redux-стейта (у SPA-страниц hh.ru, напр. отклики).
Парсинг: `document.querySelector('#HH-Lux-InitialState').content.textContent` → `JSON.parse`.

Ключи для откликов [ПРОВЕРЕНО]:
- `applicantNegotiations`:
  - `topicList[]` — карточки (20 на страницу), у каждой:
    - `id` — **topicId** (переговоры), `chatId` — **id чата** (для chatik);
    - `applicantUserId`, `employerId`, `employerManagerId`, `vacancyId`, `resumeId`;
    - `initialState`/`lastState` — статус отклика: `RESPONSE` (откликнулся),
      также `INVITATION`/`INTERVIEW`/`OFFER`/`DECLINE`… (по счётчикам);
    - `applicantSubState` (`SHOW`), `employerSubState` (`NEW`);
    - `initialTopicType`/`currentTopicType` — `RESPONSE_BY_APPLICANT`;
    - `hasNewMessages`, `hasText`, `hasResponseLetter`, `viewedByOpponent`,
      `conversationMessagesCount`, `conversationUnreadByEmployerCount`;
    - `chatIsArchived`, `lastModified`, `creationTime` (ISO+03:00), `lastModifiedMillis`;
    - `declineByApplicantAllowed`, `declinedByApplicant`, `employerViolatesRules`;
    - `actions[]` — доступные действия: `[{name: "decline", method: "POST", href: "/applicant/negotiations/decline"}, {name: "delete", method: "POST", href: "/applicant/negotiations/trash", substate: "HIDE"}]`;
    - `resources[]` (`VACANCY`/`RESUME`/`RESPONSE_LETTER` id), `communicationContext.chatData` (`{id, type: NEGOTIATION}`);
  - `total`, `pageCount`, `paging`, `filterInUse`;
- `applicantNegotiationsCounters` — счётчики табов: `{new: {all, awaiting, invitation, discard, deleted, archived, interview, hired}, total: {...}, activeFilterTab}`
  (в примере: total `{all: 202, awaiting: 167, discard: 31, deleted: 1785, interview: 4}`) [ПРОВЕРЕНО];
- `applicantNegotiationsActionsData` — общие данные действий: `{deleteAction: {name, method: "POST", href: "/applicant/negotiations/trash", substate: "HIDE"}}` [ПРОВЕРЕНО].

**Действия (decline/trash) [ПРОВЕРЕНО по коду бандла ApplicantNegotiations-route.*.js]:**

Тело POST — multipart/form-data: `topic` (=topicId), `vacancyId`, `employerId`,
`query` (router location.search — `?filter=...`). Кнопка «Усилить отклик» без hh PRO —
редирект на `/applicant-services/hhpro` (API не вызывается).

Статусы табов (из счётчиков): `all` — Все, `awaiting` — Ожидание, `invitation` — Приглашение,
`interview` — Собеседование, `hired` — Выход на работу, `discard` — Отказ, `deleted` — Удалённые,
`archived` — Архив. URL-фильтр: `?filter=all` (по названию таба).

Карточка в DOM (для справки): `div[data-qa="negotiations-item"]`; ссылки
`a[href="/vacancy/{id}?..."]`, `a[href="/employer/{id}?..."]`; кнопки
`[data-qa=open_chat]` («Перейти в чат»), `[data-qa=negotiations-decline]`, `[data-qa=negotiations-delete]`;
метки-теги `negotiations-tag negotiations-item-not-viewed|viewed|discard`. [ПРОВЕРЕНО]

Дополнительно [ПРОВЕРЕНО]:
- Табы состояний и их URL-параметры: Все → `?filter=all`; «Собеседование» → `?filter=all&state=INTERVIEW`;
  остальные (Приглашение/Выход на работу/Ожидание/Отказ/Удалённые/Архив) — предположительно
  `state=INVITATION|OFFER|RESPONSE|DECLINE|REMOVED|ARCHIVE` [ГИПОТЕЗА по названиям].
- Переключение таба — чисто клиентское: меняется URL (history), данные уже в SSR-документе,
  новых XHR нет [ПРОВЕРЕНО].
- Карточка отклика (SSR): `a[href="/vacancy/{id}?hhtmFrom=negotiation_list"]` (название),
  `a[href="/employer/{id}?hhtmFrom=negotiation_list"]`, кнопки «Оставить отзыв», «Перейти в чат»,
  «Усилить отклик», «Удалить»/«Отказаться»; метки «Был онлайн N дней назад», «Разбирает N% откликов» [ПРОВЕРЕНО].
- Счётчики табов: Все 186, Собеседование 4, Ожидание 151, Отказ 31, Удалённые 1785 [ПРОВЕРЕНО].
- Блок «Вам подойдут эти вакансии» — SSR, ссылки `?hhtmFromLabel=suitable_vacancies&hhtmFrom=negotiation_list` [ПРОВЕРЕНО].
- Пагинация — кнопки 1–10 (без href, клиентская) [ПРОВЕРЕНО].
- globalVars: `pageName: negotiation_list`, `analyticsParams.hhtmFrom: resume_profile_front` [ГИПОТЕЗА].

### 4.11. Избранное (`/applicant/favorite_vacancies`)

| Метод | Path | Тело | Статус | Назначение | Проверено |
|---|---|---|---|---|---|
| POST | `applicant/favorite_vacancies/add` | multipart: `vacancyId`, `employerId` | 200 `{}` | добавить в избранное | 2026-08-02 |
| POST | `applicant/favorite_vacancies/remove` | multipart: `vacancyId`, `employerId` | 200 `{}` | убрать из избранного | 2026-08-02 |
| GET | `applicant/favorite_vacancies` | — | 200 | список (серверный рендеринг; при пустом списке API-вызова нет) | 2026-08-02 |

Заголовки add/remove: `x-hhtmsource: vacancy`, `x-hhtmfrom: <источник>`, `x-xsrftoken`, `x-requested-with: XMLHttpRequest`,
`accept: application/json`, `content-type: multipart/form-data`, `origin: https://hh.ru`, `x-gib-gsscgib-w-hh`, `x-gib-fgsscgib-w-hh` (куки gssc/fgssc). **`x-cfids` в этих запросах не шлётся** [ПРОВЕРЕНО 2026-08-02].
Ответ: `{}` + обновление кук `hhuid`/`_hi`/`_xsrf`.

«Усилить отклик» (кнопка на карточке отклика): без активной подписки hh PRO клик редиректит на
`GET /applicant-services/hhpro?hhtmFrom=negotiation_list` — статичный промо-лендинг (тарифы 279 ₽/нед, 799 ₽/мес, 1499 ₽/3 мес),
никакого API усиления не вызывается [ПРОВЕРЕНО 2026-08-02]. Сам эндпоинт усиления недоступен без подписки [ОГРАНИЧЕНИЕ].

### 4.12. Бутстрап SPA (window.globalVars в HTML `GET /`)

| Ключ | Значение | Назначение | Проверено |
|---|---|---|---|
| `apiHost` | `https://api.hh.ru` | публичный API-хост | 2026-08-02 |
| `apiXhhHost` | `https://hh.ru` | основной хост | 2026-08-02 |
| `cryptedUserId` | 40 hex | = кука `crypted_id` | 2026-08-02 |
| `build` | `26.31.5` | версия сборки (= sentry-release xhh@26.31.5) | 2026-08-02 |
| `area`, `country` | `113`, `1` | регион/страна | 2026-08-02 |
| `analyticsParams` | `{hhtmFrom, hhtmFromLabel, hhtmSource: main, ...}` | источники перехода | 2026-08-02 |
| `features.fingerprinting_enable` | `true` | fingerprinting включён (для залогиненных) | 2026-08-02 |
| `cryptedUserId` (аноним) | старый 40-hex | после выхода в globalVars всё ещё старый id — источник неясен [ГИПОТЕЗА] | 2026-08-02 |

В HTML есть `<meta name="sentry-trace">` и `<meta name="baggage">` — трейс идёт из HTML в JS [ПРОВЕРЕНО].

### 4.13. Чат (chatik.hh.ru)

Хостится на `chatik.hh.ru`; полноэкранная версия открывается по `hh.ru/chat/{chatId}` (редирект с `chatik.hh.ru/chat/{id}`),
панель в шапке — iframe `chatik.hh.ru/?platform=xhh&dest=iframe`. При отклике сервер создаёт чат и возвращает `chat_id`
(в ответе apply: `chat_id=5519016396`, `topic_id=5471456270`).

**Важно:** запросы к `chatik.hh.ru` идут с gib-**куками** (`gsscgib-w-hh`, `cfidsgib-w-hh`, `fgsscgib-w-hh`, `__zzatgib-w-hh`),
но БЕЗ заголовков `x-gib-*`/`x-cfids` (в отличие от hh.ru). Обязательные заголовки: `x-xsrftoken: <_xsrf>`,
`x-requested-with: XMLHttpRequest`, `accept: application/json`, `x-hhtmsource: app`, `origin: https://hh.ru`;
POST-ы `content-type: application/json`. Куки `filters{userId}={"showFilters":false,...}` и `device_magritte_breakpoint` — состояние UI.

**Каталог эндпоинтов:**

| Метод | Path | Параметры | Назначение | Проверено |
|---|---|---|---|---|
| GET | `chatik/api/unread` | — | `{"unreadCount":100,"unreadSupportCount":0}` (кап 100) | 2026-08-02 |
| GET | `chatik/api/filter_clusters` | `filterUnread`, `filterHasTextMessage`, `do_not_track_session_events` | кластеры вакансий для фильтра списка чатов | 2026-08-02 |
| GET | `chatik/api/chats` | `ids=<csv>`, `do_not_track_session_events` | список чатов по id: `chats.items[]` + `lastMessage`, `chatsDisplayInfo`, `resources` | 2026-08-02 |
| GET | `chatik/api/chat_data` | `chatId`, `applicantId`, `do_not_track_session_events` | полный чат: `chat.messages.items[]` (история), `resources` (вакансия, резюме, участники, negotiation_topics), `display`, `chatStates` | 2026-08-02 |
| GET | `chatik/api/quick_replies` | `chatId`, `messageId`, `do_not_track_session_events` | быстрые ответы `[{id,type:"send",text,label,metadata}]` | 2026-08-02 |
| GET | `chatik/api/search` | ? | поиск по чатам | 2026-08-02 (по коду) |
| GET | `chatik/api/get_link_preview` | `urls=<csv>` | `{"result":[{"ok":true,"url","image","title","status"}]}` (кэш 7 дней) | 2026-08-02 |
| GET | `chatik/api/check_link` | ? | проверка ссылки | 2026-08-02 (по коду) |
| GET | `chatik/api/maps` | ? | карты/адреса в сообщениях | 2026-08-02 (по коду) |
| GET | `chatik/api/get_employer_managers` | ? | менеджеры работодателя | 2026-08-02 (по коду) |
| GET | `chatik/api/similar_counters` | ? | счётчики похожих вакансий | 2026-08-02 (по коду) |
| GET | `chatik/api/get_or_create_bot_dialog` | ? | диалог с ботом (техподдержка) | 2026-08-02 (по коду) |
| POST | `chatik/api/send` | — | **отправка сообщения** (тело ниже) | 2026-08-02 (по коду бандла 198) |
| POST | `chatik/api/mark_read` | — | `{"chatId","messageId","hasUnreadDiscardMessage":false}` → `{"enable_dark_theme":false,...}` | 2026-08-02 |
| POST | `chatik/api/notify_chat_opened` | — | `{"chatId"}` → `{"enable_dark_theme":false,"enable_zp_theme":false}` | 2026-08-02 |
| POST | `chatik/api/save` | — | редактирование: `{"text","messageId","metadata"?}` | 2026-08-02 (по коду) |
| POST | `chatik/api/upload_file` | `upload_id`, `filename` (query) | FormData `file` → возвращает `uploadId` для `send` | 2026-08-02 (по коду) |
| POST | `chatik/api/send_event` | — | кнопки-события: `{"chatId","messageId","event","eventParams"}` | 2026-08-02 (по коду) |
| DELETE | `chatik/api/delete_message` | `messageId`, `chatId` (query) | удаление своего сообщения | 2026-08-02 (по коду) |
| POST | `chatik/api/leave` | — | `{"chatId"}` — выйти из чата | 2026-08-02 (по коду) |
| POST | `chatik/api/toggle_notification` | — | `{"chatId","status":bool}` | 2026-08-02 (по коду) |
| POST | `chatik/api/rate_chat` | — | `{"chatId"}` (оценить поддержку) | 2026-08-02 (по коду) |
| POST | `chatik/api/set_write_possibility` | — | `{"chatId","writePossibility":bool}` | 2026-08-02 (по коду) |
| POST | `chatik/api/participant_action` | — | `{"chatId","actionType"}` | 2026-08-02 (по коду) |
| POST | `chatik/api/add_manager_participant` | — | добавить менеджера в чат | 2026-08-02 (по коду) |
| POST | `chatik/api/notify_admin` | — | уведомить администратора | 2026-08-02 (по коду) |

**POST /chatik/api/send (тело, из бандла 198):**

```json
{"chatId": 5519016396, "idempotencyKey": "<uuid-v4>", "text": "...", "uploadId"?: "...", "suggestionUuid"?: "..."}
```

- `idempotencyKey` — случайный UUID v4 на каждое сообщение (генератор `(0,s.Z)()`).
- `uploadId` — если есть файл (возвращается `POST /upload_file`).
- `metadata` добавляется только для чатов `BOT`/`SUPPORT` или при явной передаче: `{...metadata, chatType, parentWindowUrl, location, platform:{name, data}}`.
- Query-параметры: `hhtmSourceLabel=chat|spoiler|inlineChat`, `hhtmSource=...`.

**GET /chatik/api/chat_data — ключевые поля ответа:**

- `chat.id`, `chat.type` (`NEGOTIATION`), `chat.resources` (`{NEGOTIATION_TOPIC:[topicId], RESUME:[resumeId], VACANCY:[vacancyId], RESPONSE_LETTER:[...], UNKNOWN:[...]}`),
  `chat.operations` (`{enabled:[LEAVE_CHAT, DISABLE_NOTIFICATIONS], allowed:[...]}`), `chat.writePossibility.name` (`ENABLED_FOR_ALL`).
- `chat.messages.items[]`: `id`, `chatId`, `creationTime` (ISO+03:00), `text`, `type` (`SIMPLE`), `canEdit`, `canDelete`,
  `workflowTransitionId`, `flags.shouldCheckLinks`, `hasContent`, `hidden`, `workflowTransition` `{id, topicId, applicantState}` (у отклика),
  `participantDisplay` `{name, isBot, avatar}`, `participantId` (applicantId у соискателя, employerUserId у рекрутера).
- `resources.resumes.{resumeId}`: `hash` (40-hex, тот же что в apply `resume_hash`), `title`, `salary`, `area`, `phone[]` (raw/форматированный), `photoUrls`, `userId`.
- `resources.participants.{externalId}`: `type` (`APPLICANT_USER`/`EMPLOYER_USER`), `role.name` (`applicant`/`employer`), `display.name`, `employerManagerId`, `lastActivityTime`, `onlineUntilTime`.
- `resources.negotiation_topics.{topicId}`: `vacancyId`, `resumeId`, `initialTopicType` (`RESPONSE_BY_APPLICANT`), `initialApplicantState` (`RESPONSE`), `currentApplicantState`.
- `chatStates.writeMessageState.allowed`, `chatStates.sendFileState.allowed`, `chatStates.responseReminderState.allowed`.
- `resources.vacancies.{vacancyId}` — полная карточка вакансии в XML-подобном JSON (логотипы, бейджи, публикация, area, links).

**WebSocket:**

Отдельного websocket для чата не обнаружено: `websocket.hh.ru/proxy-webapp*` — это прокси с sentry-конфигом
(`proxy-webapp-config` → `{sentryDsn, appVersion}`), а не канал сообщений. Обновления, видимо, только через polling API [ГИПОТЕЗА].

**Вопросы по вакансии (робот-рекрутер, «тест-лёгкий») [ПРОВЕРЕНО 2026-08-02]:**

После отклика в чат приходит **Робот-рекрутер** (бот) с вопросами работодателя
(кнопка «Ответить на вопросы по вакансии» в списке откликов — открывает тот же чат):

1. Сообщение-приглашение: «Чтобы работодатель узнал о вас больше, ответьте на
   несколько вопросов» (`participantDisplay.isBot=true`, `type=SIMPLE`).
2. Каждый вопрос — сообщение бота с полем `actions.text_buttons`:
   `{"text_buttons": [{"size":"full","text":"Да"},{"size":"full","text":"Нет"}]}`.
3. **Ответ на кнопку** = обычный `POST /chatik/api/send`, но с `metadata`:
   ```json
   {"chatId":5519685657,"idempotencyKey":"<uuid4>","text":"Да",
    "metadata":{"source":{"source_type":"chat_text_button"},
      "messageId":14963643144,"chatType":"NEGOTIATION",
      "parentWindowUrl":"https://hh.ru/applicant/negotiations",
      "location":"chatik","platform":{"name":"xhh","data":{}}}}
   ```
   Ключевое: `metadata.source.source_type="chat_text_button"` + `metadata.messageId`
   (id сообщения ВОПРОСА). Query: `hhtmSourceLabel=chat&hhtmSource=chat`.
4. После ответа бот задаёт следующий вопрос (очередь), в конце — финал.
5. `GET /chatik/api/quick_replies?chatId&messageId` — быстрые ответы, но для
   text_buttons возвращает `{"quick_replies":[]}` — кнопки уже в `actions`.
6. У вакансии в `resources.vacancies` есть признаки: `userTestPresent` (bool),
   `autoResponse.acceptAutoResponse` (бот-опрос активен), `civilLawContracts`
   (варианты: SELF_EMPLOYED/INDIVIDUAL_ENTREPRENEUR/INDIVIDUAL_PERSON),
   `chatWritePossibility` (`ENABLED_AFTER_INVITATION`).

Отличие от «настоящего» теста (test.hh.ru): при `userTestPresent=true` и отклике
без теста POST apply возвращает `{"error":"test-required"}` — flow test.hh.ru
пока НЕ исследован.

**Список чатов, «Отказ», архив вакансии, «Покинуть чат» [ПРОВЕРЕНО 2026-08-03]:**

**GET `/chatik/api/chats`** — список чатов (пагинация `page=N`, по 20;
`filterUnread=false&filterHasTextMessage=false&do_not_track_session_events=false`).
Список отсортирован по активности (новые первым). Ключевые поля элемента:

```json
{"id": 5490559766,
 "lastActivityTime": "2026-08-03T03:58:56.018+03:00",
 "resources": {"RESUME": ["30127272"], "NEGOTIATION_TOPIC": ["5472433930"],
                "VACANCY": ["133876888"]},
 "lastMessage": {"workflowTransition": {"id": ..., "topicId": ...,
   "applicantState": "DISCARD", "declinedByApplicant": false}}}
```

- **Бейдж «Отказ»** в чат-листе = `lastMessage.workflowTransition.applicantState ==
  "DISCARD"` (и `declinedByApplicant == false`). `declinedByApplicant=true` —
  соискатель отказался сам (другой бейдж). Состояния: RESPONSE / INTERVIEW /
  DISCARD / …
- **«Вакансия в архиве»** = `GET /chatik/api/chat_data?chatId=` →
  `resources.vacancies.<id>.archived` — ключ **присутствует** у архивированной
  вакансии и **отсутствует** у живой (проверено: Копылова 5490397501 — ключ есть;
  Сбер 5490559766 — ключа нет). Там же `resources.negotiation_topics.<id>.currentApplicantState`.
- **«Покинуть чат»** — `POST /chatik/api/leave` тело `{"chatId": <id>}`.
  Единственный способ убрать чат из списка: кнопки «Удалить» в меню чата НЕТ
  ни у отказов, ни у архива (только «О компании», «Участники», «Отключить
  уведомления», «Покинуть чат»). Ответ 200 `{"enable_dark_theme":false,...}`;
  после него чат исчезает из /chatik/api/chats. **POST требует заголовок
  `x-xsrftoken`** (= кука `_xsrf`) — без него 403 (GET-эндпоинты работают и без).
- **Таб «Отказ» в UI пуст** (`?filter=all&state=DISCARD` → «Сейчас тут пусто»):
  hh сам убирает отказной отклик (state=DISCARD) в корзину «Удалённые»
  (там `actions=["restore","feedback"]` — повторно удалять нечего).
- `filter=discard` в API **не работает** (возвращает копию all) — для поиска
  отказов использовать поле `state` в табе `all`.
- `POST /applicant/negotiations/trash` на архивированный отклик **не работает**
  (multipart → 502; json → 200 с `<doc/>`-пустышкой, отклик остаётся).

**Обход 403 на логин** (после серии запросов hh блокирует POST /account/login
на 403; браузер при этом работает): импортировать куки браузера в HHSession
через `set_cookie(name, value, domain="hh.ru")` — куки берутся из реального
запроса (в т.ч. HttpOnly `hhul`/`hhtoken`/`crypted_id`). Сессия с этими куками
полностью авторизована: чаты, chat_data, leave работают. Куки `_xsrf` нужна
для POST; после Set-Cookie из ответов в jar может оказаться две `_xsrf` —
HHSession.cookie() перебирает jar вручную (httpx .get() бросает исключение).

### 4.14. Вебсокет-приложение

| Метод | Path | Параметры | Статус | Назначение | Проверено |
|---|---|---|---|---|---|
| GET | `websocket.hh.ru/proxy-webapp/index.html` | — | 200 | клиент вебсокета | 2026-08-02 |
| GET | `websocket.hh.ru/proxy-webapp-config` | — | 200 | конфигурация вебсокета (`{sentryDsn, appVersion: 1.1.24}`) | 2026-08-02 |

### 4.15. Персональная выдача (adsrv)

| Метод | Path | Параметры | Статус | Назначение | Проверено |
|---|---|---|---|---|---|
| GET | `adsrv.hh.ru/pv` | `type=applicant`, `age`, `salary`, `gender`, `position`, `regions`, `professionalRoles`, `languages`, `profile*`, `puid*` | 200 | персональная выдача с данными профиля | 2026-08-02 |
| POST | `adsrv.hh.ru/hb/bids` | JSON | 200 | header-bidding ставки (запускается после `yandex.ru/ads/system/header-bidding.js`) | 2026-08-02 |

Анонимный вариант `GET adsrv.hh.ru/pv` (после выхода): `type=unknown&regions=1,232,113&profileRegions=1,232,113`,
без age/salary/gender/position/professionalRoles/languages; в adfox-запросах `puid6=anonymous`,
`puid42/44/45/46/48/49/53` и др. = null, `puid10` — короткий список экспериментов
(`emp_reg_company_type_c`, `frk_anonymous_employer_v3`, `free_search_onboarding`, ...).
В `bids=` (base64) уходит JSON-массив ставок: `[{"bidderName":"hhru","campaign_id":3164620,"response_time":140,"bid":35320,"cpmAdjustment":1,"currency":"RUR","unit":0,"placement_id":"358"}]`.

После выхода `adsrv.hh.ru/pv` по-прежнему вызывается, но без персональных данных [ПРОВЕРЕНО].

Заметки:
- В `puid10` — список экспериментальных фич (`experience_recommendations_v2`, `hhpro_*`, ...): видны A/B-группы пользователя.
- `puid2`, `rId` — opaque-идентификаторы, происхождение выяснить [ГИПОТЕЗА].
---

## 5. RAG в hh-agent: база кейсов соискателя → сопроводительные письма

> [ПРОВЕРЕНО 2026-08-03] Полный путь: эмбеддинг (netcraze) → upsert в Qdrant (NAS)
> → query top-k → подстановка в `LetterContext.cases` → письмо использует кейсы.

### 5.1. Что внедрено (S1)

Векторная память кейсов соискателя: полное резюме с hh.ru + файлы
`~/.hh-agent/cases`
(портфолио, `.md`/`.txt`) разбиваются на чанки и индексируются в Qdrant. Для каждой
вакансии retrieve top-k семантически похожих чанков → `LetterContext.cases` →
агент письма использует их как конкретику в `fit_points`.

### 5.2. Что внедрено (S1.5 — письма как эталоны стиля)

Каждое **отправленное** сопроводительное письмо сохраняется в коллекцию с
`src="letter"` (`RagStore.save_letter` → `index_text` с extra_payload
`vacancy`/`employer`/`date`, дедуп по sha1). При генерации нового письма
`retrieve_letter_examples(query, top_k=3)` возвращает прошлые письма на похожие
вакансии как **эталоны стиля**: агент повторяет структуру/тон/обороты, но НЕ
копирует дословно и НЕ переносит факты из чужих писем (правила в промпте).

Ключевое отличие: `retrieve_cases` фильтрует `src != "letter"` (`_src_filter` с
`exclude_src`) — письма никогда не попадают в кейсы/портфолио и наоборот.

### 5.3. Компоненты

- **Эмбеддинги**: netcraze-прокси, модель `embeddings/qwen3-embedding:0.6b`,
  dim=1024, через OpenAI-совместимый `/embeddings` (env `OPENAI_BASE_URL`/
  `OPENAI_API_KEY`). Проверено: отвечает, русский текст ок.
- **Векторная БД**: Qdrant на NAS, REST `http://192.168.1.1:30413`, gRPC `30414`
  (DNS-имя `nas.local` с рабочей машины не резолвится — используется IP).
  Версия сервера 1.18.2.
- **Коллекция**: `hh_agent_cases_knowledge_base` (длинное понятное имя),
  size=1024, distance=Cosine.
- **Модуль**: `packages/hh-agent/src/hh_agent/rag.py` — `RagStore` (ленивый
  синглтон), `ensure_indexed(resume_text)` (инкрементальная индексация,
  чанк пропускается по sha1-хэшу в payload), `retrieve_cases(query, top_k=5)`.

### 5.4. Чанкинг: LLM-нарезка конспектов (gemma через netcraze)

Конспекты `.md` режет не регулярками, а модель gemma (`lmstudio/google/gemma-4-31b-qat`
на netcraze): она чувствует смысловые границы на русском — заголовки, абзацы,
код-блоки ```bsl``` (не разрывает), секцию «Как об этом говорить в чате»
выделяет отдельным чанком, приклеивает путь заголовков («Раздел › Подраздел»).
Файл конспекта — один смысловой раздел, **никакой пре-нарезки по алгоритмам**:
текст подаётся целиком, модель сама делит его на смысловые фрагменты и
возвращает `list[str]` через structured output pydantic-ai (`temperature=0`,
`max_tokens=8000`). Модель — та же, что у основного агента
(`_chunk_model_name`: `HH_AGENT_MODEL` или `DEFAULT_MODEL`). `.txt`
(резюме/письма) режутся по-прежнему `_chunk_text` — LLM им не нужен.

Защита от сбоев (RAG не должен пустеть/падать):
- любой сбой LLM (нет сети, таймаут, невалидный ответ, модель «потеряла» текст —
  суммарная длина чанков < 60% исходника) — тихий fallback на ручной
  `_chunk_markdown`;
- при недоступности netcraze LLM-нарезка отключается до конца процесса
  (`_llm_chunk_disabled`) — не жечь таймаут на каждый файл;
- файлы > 60К симв. (LLM теряет контекст) — сразу ручной чанкинг;
- `retries=2` на ошибки формата (структуру ответа валидирует pydantic-ai).

### 5.5. Переиндексация: демон сам подхватывает новые/изменённые файлы

Демон (`run_daemon`) каждые `--reindex-every-min` (по умолчанию 30 мин) зовёт
`reindex_cases()`: новые/изменённые конспекты (e1c и др.) попадают в Qdrant без
перезапуска процесса. Первый прогон — не сразу: на старте `ensure_indexed`
отрабатывает в первом apply-цикле.

Дедуп по (mtime_ns, size) файла (`_case_mtimes`): LLM-нарезка недетерминирована,
поэтому sha1 чанков меняется между прогонами даже для неизменённого файла —
без mtime-дедупа каждая переиндексация плодила бы дубли. Переименование/удаление
файла не чистит старые чанки в Qdrant (принято; полная замена коллекции при
изменении — отдельная задача).

### 5.6. Конфигурация (env)

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `QDRANT_URL` | `http://192.168.1.1:30413` | REST Qdrant |
| `QDRANT_GRPC_PORT` | `30414` | gRPC-порт (для prefer_grpc) |
| `QDRANT_PREFER_GRPC` | `0` | `1` — ходить по gRPC |
| `HH_AGENT_CASES_DIR` | `~/.hh-agent/cases` | каталог кейсов (портфолио, проекты) |
| `HH_AGENT_CACHE_DIR` | `~/.cache/hh-agent` | каталог кеша (diskcache досье) |

Каталог кейсов создаётся автоматически с README-инструкцией, если его нет.

### 5.7. Точки интеграции в коде

- `pipeline.py::run_apply_cycle` — `await ensure_indexed(resume_text)` один раз
  за процесс (после построения агентов).
- `pipeline.py::_process_vacancy` шаг 4 — `cases = await retrieve_cases(f"{vs.name}\n{vs.description}")`
  → `LetterContext(cases=cases)`; там же `letter_examples = await retrieve_letter_examples(...)`
  → `LetterContext(letter_examples=...)`.
- `pipeline.py::_process_vacancy` после успешного отклика —
  `await save_letter(outcome.letter, vacancy=vs.name, employer=vs.employer)`
  (тихий fallback: при сбое отклик не откатывается).
- `letter.py::LetterContext` — новые поля `cases: list[str]` (default_factory=list)
  и `letter_examples: list[str]` (эталоны стиля); системный промпт письма —
  блоки «КЕЙСЫ (cases)» и «ПРОШЛЫЕ ПИСЬМА (letter_examples)»: стиль повторять,
  факты из чужих писем не переносить.

### 5.8. Отказоустойчивость (важно)

Любой сбой RAG (нет сети, сервер недоступен, нет ключа) — тихий fallback:
`retrieve_cases()` вернёт `[]`, письмо генерируется как раньше, цикл не падает.
При первом сбое RAG отключается до конца процесса (`_disabled=True`), чтобы
не спамить в лог.

### 5.9. Тесты

- `uv run python scripts/test_rag_live.py` — живой: индексация 3 кейсов
  (src=test) → поиск по 2 запросам (с exclude_src=letter, как в проде
  retrieve_cases — иначе 347 писем-эталонов глушат кейсы) → проверка топ-1 по
  маркеру → блок писем (save_letter → найдено среди примеров → retrieve_cases
  НЕ отдаёт письмо → точечная очистка) → очистка тестовых точек (счётчик
  именно по фильтру src=test, а не по всей коллекции).
- `uv run python scripts/test_letter_osint_live.py` — живое письмо: OSINT-досье
  компании → RAG-кейсы → письмо (нет обещаний/канцелярита, OSINT-мост, живой
  стиль, кейс упомянут, эталоны стиля передаются без падения).
- `uv run python scripts/backfill_letters.py /tmp/hh_cookies.txt --limit N` —
  бэкфилл писем из дампа чатов `scripts/_chats_full.json` (1686 чатов):
  письмо = первое сообщение топика с `participantId == currentParticipantId`
  (соискатель) и непустым текстом; ответы работодателя и отклики без письма
  пропускаются. Прогон 2026-08-03: 347 писем.
- `uv run python scripts/test_letter_cases_live.py` — живое письмо с кейсами:
  проверка, что модель использует кейс (маркер — основа слова, покрывает
  падежи: «бухгалтер» вместо «1С:Бухгалтерия»).
- `uv run python scripts/test_letter_live.py` — регрессия письма без кейсов.
- `uv run python scripts/test_cases_e1c_live.py` — кейсы e1c (справочники 1С
  из ИТС): ensure_indexed индексирует файлы из `~/.hh-agent/cases/e1c-*.md`
  (симлинки на `cases/e1c/` в проекте) с src=file:*; retrieve_cases по 1С-
  запросам возвращает релевантные чанки (проверено 2026-08-03: БП/ЗУП/ERP/
  интеграции — топ-3 из правильного файла).
- `uv run pytest packages/hh-agent/tests/test_rag.py` — юниты без сети:
  `_trim_query` (обрезка поискового запроса до 512 симв. по границе
  предложения), `_src_filter` (включение/исключение источника `letter`),
  `_chunk_model_name` (берёт `HH_AGENT_MODEL` как есть или `DEFAULT_MODEL`).

### 5.10. Кейс-файлы e1c (справочники 1С из ИТС)

`cases/e1c/` в проекте — систематические справочники по конфигурациям 1С
(источник: its.1c.ru, руководства по ведению учёта, срез 03.08.2026):

- `1c-platform-v8.md` — платформа 8.3.27/8.5, режимы, БСП 3.1.12.281, механизмы
  интеграции (HTTP-сервисы, OData, Фреш).
- `1c-buhgalteria.md` — БП 8.3 (3.0.203.18): 14 глав, ЕНС, НДС, прослеживаемость,
  маркетплейсы, ДиректБанк, цифровой рубль, закрытие месяца.
- `1c-zup.md` — ЗУП 3.1 (3.1.38.40): кадры, штатка, воинский учёт, отпуска,
  больничные, НДФЛ/взносы, ЕФС-1, зарплатные проекты.
- `1c-erp-ka-ut.md` — ERP 2.5 / КА 2.5 / УТ 11.5 (2.5.27.70 / 11.5.27.70):
  планирование, производство, казначейство, бюджетирование, МСФО.
- `1c-unf-retail.md` — УНФ 3.0.14.108 и Розница 3.0.14.108.
- `1c-integration.md` — 1С-Отчетность (ФНС/СФР/Росстат/МЧД), ЭДО, банки,
  маркетплейсы, Честный знак, технические интеграции.

Связь с RAG: `~/.hh-agent/cases/e1c-*.md` — симлинки на файлы проекта, так что
правки в `cases/e1c/` автоматически попадают в индекс при следующем запуске
(ensure_indexed индексирует `CASES_DIR` инкрементально по sha1).

### 5.11. Наблюдения

- qwen3-embedding:0.6b адекватно ранжирует русские кейсы (проверено на 3 кейсах
  про 1С / парсинг / чат-бот — топ-1 всегда ожидаемый).
- Модель письма реально использует кейсы в `fit_points`, но пересказывает своими
  словами и в нужных падежах — тесты должны проверять основу слова, не точную
  подстроку.
- Qdrant 1.18.2 remote принимает `create_collection` повторно без ошибки
  (игнорирует, если есть) — можно вызывать на каждый старт без проверки.

### 5.12. Планы (S2+)

- S2: история решений фильтра (`vacancy_text, fits, reason`) → RAG-контекст в
  `run_fit_decision` (консистентность фильтра).
- S3: семантическая память досье компаний (сейчас кеш по `employer_id` на 100 дней).
- Бэкфилл остальных писем: в `_chats_full.json` чаты без текста письма (отклик
  без сопроводительного) — в RAG не кладём (эталон стиля должен быть письмом).
- Актуальные предупреждения Qdrant-скиллов: learned sparse (BM42/miniCOIL/SPLADE++)
  — только английский; RF API требует калибровки весов на 50-200 реальных запросах.

---

## 6. Агент: как hh.web/hh.api потребляется агентом поиска работы

Заметки по интеграции `hh.web`/`hh.api` в автономного агента
(`packages/hh-agent`). Это не про сам hh.ru, а про паттерны использования
клиента — чтобы не переоткрывать их заново.

### 6.1. Два режима управления

1. **LLM через MCP** (`hh-agent hunt`) — pydantic-ai агент вызывает
   инструменты `hh.mcp` (stdio). Удобно для интерактивной работы, но
   reasoning-модель (gemma-4) зацикливается: вместо final_result зовёт
   web_search/инструменты по кругу. [ПРОВЕРЕНО]
2. **Python-driven** (`hh-agent auto`) — механику (поиск, страницы, отклик,
   чат) делает Python, LLM получает только маленькие структурированные задачи:
   фильтр вакансии (1 шаг), анализ вакансии (2 шага), исследование компании
   (1 прогон deep_research), письмо (2 агента). Каждый шаг —
   `output_type=BaseModel`, проверяется verifier'ом (та же модель) и при
   плохом ответе переделывается. [ПРОВЕРЕНО 2026-08-02]

### 6.2. Порядок обработки вакансии в `auto`

страница вакансии (Python) → fit-фильтр (LLM) → анализ (LLM) → досье компании
(deep_research: gemma-4-31b + инструменты + кеш 100 дней) → письмо (LLM) →
отклик (Python) → дозаполнение анкеты PREFERRED_WORK_AREAS.

Дорогие LLM-шаги — только после дешёвого фильтра.

### 6.3. Deep research компании (deep_research.py) — gemma-4-31b ищет и структурирует сама

Разделение труда (подтверждено живыми тестами, tmp_test_gemma_research.py):
- **gemma-4 31b** (MODEL_GEMMA) — reasoning-модель: ИЩЕТ САМА инструментами
  web_search/fetch_url (Python-реализации, webtools.py, без внешних ключей) и
  возвращает ВЕСЬ отчёт структурой CompanyReport за один прогон
  (output_type=BaseModel). 49–110с на компанию: 5–9 интеллектуальных
  запросов, честное «недостаточно информации» вместо выдумок, без
  зацикливания (usage: requests=4, tool_calls=12, reasoning_tokens=2644).
- **deepseek-zen/big-pickle** (MODEL_DEEPSEEK) — больше НЕ используется в
  research (не умеет structured output). Оставлен как запасная модель.
- 5-шаговая research_chain с verifier'ом удалена из analysis.py (была нужна
  gemma-4-26b, которая срывалась на больших заданиях).

Ключевые правила:
- модель ОБЯЗАТЕЛЬНО читает входные данные — в промпте (deep_research.md)
  отдельно написано: «читай сообщения чата, в них ссылки». Ссылки из чата/
  вакансии выгребаются extract_urls() и передаются полем extracted_urls
  структуры ResearchInput (model_dump_json — «передавай всё моделями»);
  employer_url передаётся отдельным полем.
- кеш cashews[diskcache] 100 дней, ключ company-dossier:{employer_id} (id из
  /employer/{id} в employer_url, хелпер employer_id_from_url). Повторные
  отклики на вакансии той же компании не ходят в сеть и не тратят токены
  (важно для вечного daemon). force=True — переисследовать.
- запись кеша ВАЛИДИРУЕТСЯ при чтении (CompanyReport.model_validate): если в
  кеше лежит битая/старая запись (например, str-досье от прошлой версии
  кода), она не возвращается — компания переисследуется, и ключ
  перезаписывается корректным dict-отчётом. [БАГ ПОЙМАН 2026-08-02:
  dict(старое_str-досье) падал ValueError: dictionary update sequence].
- страховка от вечного цикла: usage_limits(request_limit=50,
  tool_calls_limit=40) в run_deep_research; max_tokens=8000 (иначе JSON
  обрезается).
- подключено: pipeline._process_vacancy шаг 3 и agent.research_company —
  оба вызывают get_company_dossier(...) → dict полей CompanyReport.

### 6.4. Проверенные ограничения pydantic-ai 2.22

- `Agent.run(user_prompt)` принимает `str | Sequence[UserContent]`, где
  `UserContent = str | TextContent | MultiModalContent | CachePoint`.
  Передать `BaseModel` напрямую НЕЛЬЗЯ: `UserPromptPart` создаётся (это
  dataclass без валидации), но `OpenAIChatModel._map_user_prompt` падает на
  `assert_never(item)` → `AssertionError: Expected code to be unreachable`.
  [ПРОВЕРЕНО 2026-08-02 — экспериментально на установленной версии]
- Правильный способ передать структуру: `agent.run([ctx.model_dump_json(indent=2)])`.
  Это и есть «передавай всё моделями»: поля модели доходят целиком, без ручной
  склейки и обрезок. (graph.py, ExecuteStep)
- reasoning-модель gemma-4 сначала «думает»: не отключаем reasoning, даём
  запас токенов (max_tokens 1500–4000). `max_tokens` шлётся как `max_tokens`,
  а не `max_completion_tokens` (профиль `openai_chat_supports_max_completion_tokens=False`
  в models.py), иначе хвост из повторов вместо JSON.
- Имя модели для LM Studio: `openai-chat:lmstudio/<модель>` — префикс
  `openai:` резолвится в Responses API (не подходит для Chat-прокси).
- Не использовать `run_stream` — потоковый вывод с reasoning-моделями через
  Chat-прокси нестабилен; обычный `run()`/`run_sync()`.

### 6.5. Автоответы в чатах (`monitor --reply`)

- `ChatWatch` хранит `last_seen[topic_id] = id последнего обработанного
  сообщения`. Отвечаем только когда id последнего сообщения изменился; после
  отправки last_seen переходит на id НАШЕГО сообщения → на собственный ответ
  цикл не срабатывает. На старте last_seen инициализируется текущими
  последними сообщениями — старые переписки не флудим.
- Бот-сообщения (`is_bot`) и служебные (workflowTransition/без текста)
  пропускаются: на них реагирует уведомление о смене state.
- Контекст ответа: ВЕСЬ диалог списком сообщений (не только последнее) +
  краткая вакансия (со страницы) + резюме (download_txt_text). Компания — пусто,
  reply-цепочка сама читает контекст.

### 6.6. Демон (`hh-agent daemon`) — бесконечный цикл вместо пользователя

Один процесс делает всё (решение пользователя: полная замена без присмотра,
персистентность НЕ нужна — после отклика вакансия не появляется в поиске,
чаты инициализируются на старте):

- каждый тик (interval сек, по умолчанию 60): unread + снэпшот откликов +
  diff → apprise-уведомления; с `--reply` — автоответы на новые сообщения;
- каждые apply_hours (по умолчанию 4ч): прогон поиска/откликов
  (`run_apply_cycle`, теперь идёт по ВСЕМ страницам выдачи до max_pages;
  max_applies — лимит за прогон, не жжём дневную квоту);
- каждые touch_hours (по умолчанию 24ч): `touch_resume` (409 уже поднято —
  не ошибка, печать + тик продолжается);
- всё обёрнуто в session guard (pydantic-graph, session.py).

### 6.7. Человекоподобный темп откликов (throttle.py) — cashews «N/час»

Цель — быть похожим на человека: ~10 откликов в час с вариативной паузой
(jitter), а не пачка из 5 за минуту. Механика (проверено вживую):

- `ApplyThrottle.acquire()` перед РЕАЛЬНЫМ откликом (после всех LLM-шагов)
  занимает слот: `cache.incr("applies:hour", expire=3600)` — атомарный
  инкремент; в diskcache-бэкенде cashews TTL ставится ТОЛЬКО при создании
  ключа (res==1, touch), инкременты TTL НЕ продлевают → строгое скользящее
  окно «отклики за последний час»;
- счётчик персистентен (diskcache, HH_AGENT_CACHE_DIR) — рестарт демона НЕ
  сбрасывает окно (проверено: второй процесс продолжил счёт с 4);
- если слот исчерпан (count > лимит) — acquire() возвращает причину стопа,
  outcome.rate_limited=True, run_apply_cycle делает break — вакансии дальше
  НЕ анализируются (не жжём LLM-токены);
- если слот есть — jitter-пауза `random.uniform(pause_min, pause_max)`
  (по умолчанию 180–480с, среднее 5.5 мин ≈ 10/час) с логом «слот N,
  осталось K; пауза Xс»;
- конфиг: env HH_AGENT_APPLIES_PER_HOUR (дефолт 10), HH_AGENT_APPLY_PAUSE_MIN
  (180), HH_AGENT_APPLY_PAUSE_MAX (480); CLI --applies-per-hour /
  --apply-pause-min / --apply-pause-max (auto и daemon).

### 6.8. Session guard (session.py) — восстановление сессии через pydantic-graph

Граф: CheckSession (probe → лёгкий авторизованный запрос `list_resumes`,
ProfileError/HTTP 401/403 → SessionLost) → Relogin (`api.login` повторно) →
CheckSession → RunWork (тело тика). Детали:

- капча при входе: apprise-уведомление + WaitBackoff (растущая пауза
  base*2^n, до backoff_max) + повтор; после max_relogin_attempts (3) — End
  с ошибкой, демон спит долгую паузу (мин(interval*10, 3600)с) — сессию не жжём;
- `LoginError` (неверный пароль) — End сразу, попытки не тратим;
- потеря сессии ВО ВРЕМЯ work: `raise_if_session_lost(e)` в except-блоках тика
  пробрасывает SessionLost → граф перелогинивается и перезапускает work
  (max_work_retries=1);
- лимит перелогинов за тик: если relogin не помогает (probe падает всегда),
  после max_relogin_attempts — End(relogin exhausted), без зацикливания;
- каждый тик — СВЕЖИЙ SessionGuardState (счётчики между тиками не текут);
- `is_session_error()`: SessionLost, api.LoginError, api.CaptchaRequired,
  httpx.HTTPStatusError 401/403. ProfileError (резюме пусты) сессионным НЕ
  считается — probe_session оборачивает его в SessionLost вручную.

Мониторинг (снэпшоты, diff, автоответы) вынесен в monitor.py — общий для
`monitor` и `daemon` (diff_snapshots → события new_topic/more_messages/
state_changed; только more_messages триггерит автоответ).

### 6.9. Решение вопросов по вакансии (робот-рекрутер) — РЕАЛИЗОВАНО

«Тесты» на hh.ru бывают двух видов:

1. **Вопросы по вакансии** — чат с Роботом-рекрутером (бот) после отклика
   (кнопка «Ответить на вопросы по вакансии» открывает тот же чат). Вопросы —
   сообщения бота с `actions.text_buttons`; ответ — `api.quick_reply(chat_id,
   text, message_id)` (POST /chatik/api/send с metadata source_type=
   chat_text_button + messageId). В hh-agent это `_reply_button` в pipeline.py:
   LLM-агент `build_button_chooser` выбирает кнопку, при сбое — первая кнопка.
   [ПРОВЕРЕНО 2026-08-02, см. §4.13 «Вопросы по вакансии»]
2. **Анкета-тест при отклике** (`userTestPresent:true`/`userTestId` в JSON
   карточки, `get_popup` → `type: "test-required"`) — РЕАЛИЗОВАНО 2026-08-02:
   - `api.get_vacancy_test(session, vacancy_id)` — парсит `vacancyTests`
     из SSR-страницы `/applicant/vacancy_response` (декоируя &#34;-сущности);
   - субагент `test_solver.build_test_agent` отвечает на вопросы теста
     (1 шаг с verifier'ом): по каждому task_id — option_id (вариант) или
     text (открытый ответ);
   - `api.build_test_form_fields(test, answers)` собирает поля формы
     `uidPk/guid/startTime/testRequired` + `task_<id>/task_<id>_text`;
   - отклик: `api.apply_vacancy(..., test_fields=...)` — ответ POST popup
     `response_label` содержит `req-test` (тест пройден).
   В `_process_vacancy` шаг теста выполняется перед apply, если тест
   обязательный (`required=true`) и есть вопросы. [ПРОВЕРЕНО вживую:
   вакансия 133876888 — отклик с тестом принят].
   Детали — §4.5–4.6.

### 6.10. Финальная конфигурация запуска (2026-08-02, netcraze-прокси)

Рабочая связка «модель → эндпоинт» для автономного режима:

- литералы моделей в models.py: MODEL_GEMMA = openai-chat:lmstudio/google/gemma-4-31b-qat
  (исследователь/структуризатор/дефолт, DEFAULT_MODEL), MODEL_DEEPSEEK = openai-chat:deepseek-zen/big-pickle
  (запасная, для тяжёлых задач);
- эндпоинт/ключ: env `OPENAI_BASE_URL=https://ai.albus.netcraze.link/openai/v1`
  и `OPENAI_API_KEY=...` (читает сам `OpenAIProvider`, код не меняется);
- эти три значения — DEFAULT_MODEL в models.py и `.env` в корне workspace
  (`.gitignore`, авто-подхват `_load_env` в run.py — также читает
  `~/.hh-agent.env`);
- запуск одним процессом: `hh-agent {login} {password}` == `hh-agent daemon ...`;
  баннер в stdout печатает всю конфигурацию (модель, endpoint, запрос,
  интервалы, автоответы) и WARN, если модель lmstudio без OPENAI_BASE_URL.

### 6.11. Уведомления через apprise [ПРОВЕРЕНО 2026-08-02]

- URL задаётся `--notify` / env `HH_NOTIFY_URL` (в .env). Без URL notify()
  только пишет строку `[notify] ...` в stdout и возвращает False.
- **Telegram: префикс `tgram://`, не `telegram://`!** В apprise 1.12.0
  `telegram://<token>/<chat_id>` НЕ парсится (a.add → False), а
  `tgram://<token>/<chat_id>` работает. Проверено доставкой.
- `make_notifier(urls)` — приоритет аргумент > env; пустой URL → None.

### 6.12. Уроки работы с reasoning-моделью (gemma-4) [ПРОВЕРЕНО 2026-08-02]

1. **Зависает на больших заданиях** — «анализ компании со всеми полями
   сразу» на gemma-4-26b → модель генерирует бесконечный повторяющийся хвост
   (в логе пачка одинаковых блоков `(End of response)**...`). Для коротких
   цепочек лечится разбиением на 2–3 маленьких шага по 2–3 поля, каждый с
   verifier'ом (та же модель, a2a) — «пусть модель проверяет себя и
   переделывает». Для deep research оказалось НАОБОРОТ: gemma-4-31b с
   инструментами возвращает весь отчёт одним прогоном (5-шаговая цепочка
   удалена, см. выше).
2. **Не задавать «безумные вопросы»** — запрошенный «финансовый анализ
   компании» модель генерирует, но срывается (галлюцинации, повторяющийся
   хвост). Финансы/цифры компании НЕ просить у модели вообще.
3. **`output_mode=tool` по умолчанию работает** — НЕ передавать явно
   `tool_choice` (объект) — прокси отвечает `Invalid tool_choice type: 'object'`;
   достаточно `output_type=BaseModel` + результат pydantic-а.
4. **Не использовать `run_stream`** — нестабилен с reasoning-моделями через
   Chat-прокси; обычный `run()`/`run_sync()`.
5. Контекст в промпт — моделью (BaseModel), а не ручной склейкой строк;
   для чата передавать ВЕСЬ диалог, а не последнее сообщение.

### 6.13. MCP-сервер `hh.mcp` и первый живой прогон `hunt` [ПРОВЕРЕНО]

- `hh.mcp` (FastMCP): 18 инструментов (login, session_info, search_vacancies, get_vacancy,
  list_resumes, get_resume, download_resume, touch_resume, apply_vacancy,
  update_preferred_work_areas, list_negotiations, decline_negotiation, trash_negotiation,
  chat_unread, chat_messages, chat_send, chat_mark_read, logout). Авто-логин из env
  HH_USERNAME/HH_PASSWORD. E2E через fastmcp-клиент: login→search→vacancy→unread→negotiations — OK.
- `hh-agent` (pydantic-ai 2.22): `build_agent()` подключает hh.mcp через StdioTransport
  (FastMCPClient); системный промпт с профилем соискателя и правилами отклика/общения.
  CLI: `hunt` (LLM-проход), `monitor` (цикл без LLM: unread + новые сообщения/статусы → apprise),
  `chat` (ручная отправка). Проверено: MCP-клиент видит все 18 инструментов по stdio.
- Модель по умолчанию openai:gpt-4o-mini (env HH_AGENT_MODEL; нужен OPENAI_API_KEY).

Первый живой прогон `hunt` (OpenAI-совместимый эндпоинт):
- Эндпоинт LM Studio-прокси: `OPENAI_BASE_URL` + `OPENAI_API_KEY` + `HH_AGENT_MODEL`;
  имя модели без префикса `openai:` нормализуется в `build_agent` (провайдер openai
  сам читает OPENAI_BASE_URL/OPENAI_API_KEY).
- Прогон: login → search('python', area=1) → изучение → 1 успешный отклик
  (topic_id 5472035556, chat_id 5519661712) + 1 отказ из-за `{"error":"test-required"}`
  (вакансия с тестом — агент корректно пропустил).
- Первая попытка упала: агент передал неверный resume_hash → 400 `{"error":"unknown"}`
  и `Exceeded maximum output retries (1)`. Исправления:
  - `api.apply_vacancy`: 4xx → `ApplyError` с телом ответа + подсказкой (было голое raise_for_status);
  - `build_agent`: `retries=3`;
  - промпт: `resume_hash` — 40-hex из `list_resumes`, НЕ внутренний id.
- ВАЖНО: тело 400 `{"error":"unknown"}` — на неверный resume_hash ИЛИ vacancy_id;
  `{"error":"test-required"}` — вакансия требует тест.

Исследование компании перед откликом (веб-инструменты):
- `get_vacancy` теперь отдаёт `employer_url` (парсер берёт href с
  `data-qa="vacancy-company-name"` → `https://hh.ru/employer/{id}?dpt=...&hhtmFrom=vacancy`).
- Новый модуль `hh_agent/webtools.py` (локальные инструменты агента, без ключей):
  - `web_search(query)` — Bing RSS (`/search?q=...&format=rss`), до 5 результатов
    (title/url/snippet);
  - `fetch_url(url)` — httpx + html.parser: title, текст (~4000 симв.), до 15 ссылок.
  - Ошибки не бросают: возвращают dict с полем `error` (агент продолжает работу).
- Подключение: `agent.tool_plain(...)` (НЕ `agent.tool` — в pydantic-ai 2.22
  `agent.tool` принимает только функции с RunContext; иначе UserError
  «First parameter of tools that take context must be annotated with RunContext»).
- Промпт: перед откликом обязательны get_resume → get_vacancy → web_search компании
  → fetch_url сайта/hh-страницы. Письмо: 3-8 коротких деловых фраз, уверенно
  заявлять требуемые навыки (не скромничать), без литературщины/канцелярита,
  не выдумывать конкретные проекты/должности/даты.
- Проверено вживую: модель реально вызывает web_search (GET bing.com) и
  fetch_url (ya.ru) и строит осмысленный вывод; hunt отправляет отклик после
  исследования (topic_id 5472059324, chat_id 5519685657 — Fullstack Python,
  ООО ИД ПАНОРАМА).

### 6.14. Как pydantic-ai 2.22 делает `output_type=BaseModel` (tool mode)

Проверено вживую (перехват HTTP-запросов pydantic-ai через httpx event_hooks):

- При `output_type=BaseModel` pydantic-ai создаёт служебный инструмент
  `final_result` (константа `DEFAULT_OUTPUT_TOOL_NAME` в `pydantic_ai/_output.py`),
  описание «The final response which ends this conversation».
- `default_structured_output_mode` в `DEFAULT_PROFILE` = `'tool'` — то есть
  структурированный вывод идёт ЧЕРЕЗ инструмент `final_result`, а не через
  `response_format=json_schema`.
- `tool_choice` уходит на прокси строкой `"required"` (НЕ объектом), tools =
  `['web_search', 'fetch_url', 'final_result']`. Модель сама выбирает, когда
  позвать `final_result` с JSON — схема прогона 6 запросов:
  web_search → fetch_url → fetch_url → … → final_result.
- Прокси (LM Studio/Bifrost) принимает `tool_choice="required"` строкой;
  объектный `{"type":"function","function":{"name":"emit"}}` даёт 400
  «Invalid tool_choice type: 'object'». Текущий код НЕ шлёт объект — это была
  ошибка старой версии с явным `tool_choice=ToolOrOutput(...)`.
- Схема `final_result` строгая: `additionalProperties: false`, все поля
  required, `strict: true` (если профиль не выключает
  `openai_supports_strict_tool_definition`). Модель успешно заполняет поля
  по `Field(description=...)` — пример ответа:
  `{'name': 'ООО «ИД Панорама»', 'niche': 'Разработка ПО для геодезии и кадастра.',
  'business_model': 'недостаточно информации'}`.
- ВАЖНО: не просить модель «заполни поля структуры» сверх меры — инструкция
  вшита в `Field(description=...)` и в текст системного промпта; лишний текст
  уводит модель в цикл. Финансовый анализ модель не делает (сходит с ума) —
  исключён.

Профиль модели для OpenAI-совместимого Chat-эндпоинта:
- Имя: `openai-chat:lmstudio/gemma-4-26b-a4b-it-qat` (префикс `openai-chat:`
  резолвится в `OpenAIChatModel` = Chat Completions; `openai:` — это Responses
  API, на прокси не работает).
- Профиль: `{"openai_chat_supports_max_completion_tokens": False}` — чтобы
  `max_tokens` слался как `max_tokens`, а не `max_completion_tokens`
  (LM Studio понимает только `max_tokens`). Без этого reasoning-модель
  генерирует бесконечный повторяющийся хвост.
- `OpenAIChatModel` создаётся напрямую в `hh_agent/models.py::make_model`
  (провайдер `OpenAIProvider` читает `OPENAI_BASE_URL`/`OPENAI_API_KEY` из env).
- Endpoint: `https://ai.albus.netcraze.link/openai/v1` (домен `netcraze`,
  не `netcrake`). Без ключа — 401.
- `make_model` возвращает объект Model; НЕ передавать строку
  `openai-chat:lmstudio/...` в `Agent(model=...)` напрямую: pydantic-ai
  парсит префикс `lmstudio` и не находит провайдера (Unknown model) — нужен
  объект из make_model.

### 6.15. Тесты агента

- test_session.py (граф: happy/relogin/captcha/login-error/work-retry/
  лимиты), test_daemon.py (diff, _do_tick с мокнутыми api), test_chat_buttons.py
  (message_buttons, тело quick_reply). Все 40 — зелёные, без сети/LLM.
- test_tests.py + test_solver в test_pipeline.py (тест-анкета). Все 47 — зелёные.
---

## 7. Инвентарь исходных данных, хронология и открытые вопросы

### 7.1. Состав базы знаний `findings/` (что было перенесено в это досье)

| Файл | Содержимое | Куда перенесено |
|---|---|---|
| `README.md` | легенда пометок `[ПРОВЕРЕНО]`/`[ГИПОТЕЗА]`/`[ОБНОВЛЕНО]` | шапка досье |
| `auth.md` | авторизация: flow, cookie, токены, где хранятся | §1 |
| `gib.md` | gib-протокол, fgssc, шифрование /api/fl | §2 |
| `search_query_language.md` | язык поисковых запросов | §3 |
| `api.md` | каталог эндпоинтов: method, path, параметры, где лежат данные | §4 |
| `rag.md` | RAG в hh-agent: база кейсов → письма | §5 |
| `agent.md` | как клиент потребляется агентом | §6 |
| `sessions/2026-08-02.md` | хронология наблюдений по дням | §7.3 + тематически в §1–§6 |
| `reference/` | Python-порты, константы, JS-пробы реверса | §7.2, Приложения A–C |
| `captures/` | пустой каталог | — (удаляется без потерь) |
| `SKILL.md` | сам навык `hh-web`: цель, жёсткие правила, подключение MCP DevTools, рабочий цикл, фильтр шума, структура findings/, критерий готовности к клиенту | §8 (полный текст, дословно) |

### 7.2. Инвентарь `reference/` (что есть и зачем)

| Файл | Назначение | Где теперь |
|---|---|---|
| `fl_constants.json` | **эталонные константы** и семплы (ground truth): kn/v004, массивы сдвига, CRC-таблицы, encode_samples | **Приложение A** (полностью inline) |
| `fl_encode.py` | Python-порт шифровальщика **v005** (тело POST /api/fl, класс `kn`) — 16/16 ALL MATCH | **Приложение B** |
| `fl_encode_v004.py` | Python-порт шифровальщика **v004** (кука `__zzatgib-w-hh`, класс `I`) — 16/16 ALL MATCH | **Приложение B** |
| `gib.py` | Python-референс gib: `make_fgssc` + декодер string table бандла 413 (extract_string_table / rotate_table / _rc4 / _b64_decode_custom / decode_bundle_strings) | §2.2 (fgssc) + **Приложение C** (полный код) |
| `decode_strings.py` | хелпер: декодирует ВСЕ `ko("xxx",NNN)`/`t(NNN,"xxx")` строки бандла 413 (поверх gib.py) | §7.2 (описание; код — производное от gib.py) |
| `decoded_constants.json` | декодированные константы бандла: `ce`, `alphabet` (62 симв. — префиксы fgssc), `base64_alphabet`, ko-строки | факты — в §2; ko-строки дублируются в `fl_constants.json.di_helpers`/`w_calls` |
| `decoded_strings.txt` | вывод `decode_strings.py` — **сбойный прогон** (traceback) | можно удалять без потерь |
| `kn_object.js` | исходник извлечённого объекта `kn` (v005, JS) — реверс-эталон | суть — в Приложении A/B; бандл пере-скачиваем |
| `khyrzu.js` | функция `KhYRzU` (кастомный base64 + RC4) — реверс-эталон | полный код в Приложении C (`_b64_decode_custom` + `_rc4`) |
| `probe.js`, `probe_node.js`, `probe_rotate.js` | JS-проверки декодера string table и ротации | суть — в Приложении C |
| `probe_encode.js` | эталон: извлечение kn/I через Node VM, генерация `fl_constants.json` | суть — в Приложении A/B |
| `extract_objects.js` | хелпер извлечения Di/kn с обработкой regex-литералов | суть — в Приложении A/B |
| `di_object.js` | **1 байт («D»)** — мусор неудачной экстракции | можно удалять без потерь |
| `bundles/` | скачанные бандлы `i.hh.ru`: `413.2b730bc58fc45025.js` (главный, 168 КБ), `remote.xhhshared.7f14db501d269e57.js`, `secureportal.v29.9f6480404f7022c5.js`, `__federation_expose_security.796ba0b43d8f9136.js` | пере-скачиваемы (URL в §4.3); бандл 413 нужен только для нового реверса |
| `__pycache__/` | кеш Python | удаляется без потерь |

### 7.3. Хронология наблюдений

**2026-08-02 (полная сессия, sessions/2026-08-02.md, 743 строки):**
- Разбор связей, тел запросов; logout (reqid 1098–1310); страница логина и `POST /account/login`
  (3-шаговая форма, ошибки, `loginTrustFlags` — протокол расшифрован по коду бандлов);
- Успешный вход (reqid 203, 205) — auth-flow соискателя закрыт;
- Выдача `/search/vacancy?text=python&area=1`; страница вакансии `/vacancy/132929510`;
- Личный кабинет: профиль `/applicant/profile/me`, отклики `/applicant/negotiations`;
- Полный flow отклика `/vacancy/135638814` (попап, AI-письмо hhpro, POST popup, follow-up);
- Дозаполнение PREFERRED_WORK_AREAS (модалка «Где ищете работу?»);
- «Усилить отклик» = hh PRO; чат (chatik.hh.ru) — полный разбор; gib-протокол — первый разбор;
- Скачивание резюме (resume_converter) — все 4 формата; сквозной тест клиента;
- Избранное (favorites); язык поисковых запросов + поиск в клиенте;
- Поднятие резюме (touch), вакансия/отклики/чат в клиенте;
- MCP-сервер `hh.mcp` (18 инструментов) и первый живой прогон `hunt`;
- Исследование компании перед откликом (webtools: Bing RSS + fetch_url);
- structured output pydantic-ai через OpenAI-совместимый прокси (tool mode, `final_result`);
- Вопросы по вакансии (робот-рекрутер) — механизм раскрыт;
- daemon + session guard (pydantic-graph); тест-анкета при отклике — раскрыт и реализован.

**2026-08-03:**
- Вход по кукам браузера (обход 403 скриптового логина) — §1.6;
- Чат: список чатов, бейдж «Отказ», архив вакансии, «Покинуть чат» (`chatik/api/leave`) — §4.13;
- RAG: кейсы соискателя → письма, письма-эталоны (src="letter"), бэкфилл 347 писем из `_chats_full.json`,
  e1c-справочники — §5.

**2026-08-04:** сведение всех данных в это досье.

**2026-08-05:**
- `findings/` в `applicant/.agents/skills/hh-web/` удалён — все данные перенесены в это досье;
- `SKILL.md` перенесён дословно в §8; каталог навыка `applicant/.agents/skills/hh-web/` удалён целиком;
- копия в замороженном `hh/.agents/skills/hh-web/` осталась нетронутой.

### 7.4. Открытые вопросы и гипотезы (сводка)

| № | Вопрос | Статус | Где |
|---|---|---|---|
| 1 | Откуда берётся `u` (UUIDv1) и его 37-й символ | [ГИПОТЕЗА] | §2.8 |
| 2 | Нужны ли gib-заголовки для простых GET или достаточно кук | [ГИПОТЕЗА] | §2.8 |
| 3 | Какие поля fingerprint собирает клиент перед POST /api/fl (не критично — тело из любой строки) | [ГИПОТЕЗА] | §2.8 |
| 4 | Как `hhtoken` связывается с пользователем при логине | [ГИПОТЕЗА] | §1.1 |
| 5 | Что кодирует `hhul` (httpOnly, 2 года) | [ГИПОТЕЗА] | §1.1 |
| 6 | Почему в анонимном `globalVars.cryptedUserId` остаётся старый id | [ГИПОТЕЗА: из hhul или серверного состояния] | §1.7 |
| 7 | Точные `state=`-значения табов откликов (`INVITATION\|OFFER\|RESPONSE\|DECLINE\|REMOVED\|ARCHIVE`) | [ГИПОТЕЗА по названиям] | §4.10 |
| 8 | `filter=discard` в API не работает; trash на архив → 502/пустышка | [ПРОВЕРЕНО — баг hh] | §4.13 |
| 9 | Flow test.hh.ru (настоящие тестовые задания) не исследован | [ГИПОТЕЗА] | §4.13 |
| 10 | Обновления чата — только polling? Отдельного websocket нет | [ГИПОТЕЗА] | §4.13 |
| 11 | Происхождение `puid2`/`rId` (adsrv) | [ГИПОТЕЗА] | §4.15 |
| 12 | Точные поля `loginTrustFlags` (`{inputType:{...флаги, ts}}`) | [ГИПОТЕЗА о полях] | §1.4 |
| 13 | `pageName`/`luxPageName` профиля (`resume_profile_front`?) | [ГИПОТЕЗА] | §4.7 |
| 14 | `_ibc`, `iap.uid` куки — назначение | неизвестно | §1.1 |
| 15 | Сортировка выдачи `order_by=` | [ГИПОТЕЗА: как раньше] | §4.3 |

### 7.5. Что можно удалить после переноса (чек-лист)

1. **Одна из двух копий `findings/`** — каталоги идентичны:
   `applicant/.agents/skills/hh-web/findings/` и `ubuntu/hh/skill/findings/` (`diff -rq` → exit 0,
   обрабатывать можно только одну). Достаточно оставить одну (или обе — по вкусу).
2. `findings/reference/bundles/` — бандлы пере-скачиваемы с `i.hh.ru`; нужны только для нового реверса.
3. `findings/reference/di_object.js` (1 байт, мусор) и `decoded_strings.txt` (сбойный прогон) — мусор.
4. `findings/reference/__pycache__/` — кеш.
5. `findings/captures/` — пустой каталог.
6. **Сам `findings/`** после этого досье — вся ценная информация перенесена: константы и семплы
   в Приложении A, рабочие Python-порты в Приложении B, декодер string table в Приложении C,
   все наблюдаемые факты — в §1–§6.
7. **`SKILL.md`** — полный текст в §8; каталог навыка `applicant/.agents/skills/hh-web/` удалён
   2026-08-05 (копия в замороженном `hh/.agents/skills/hh-web/` не тронута).

Статус на 2026-08-05: для `applicant`-копии выполнены все пункты; `hh`-копия заморожена и не тронута.

---

## 8. Навык `hh-web` — методика исследования hh.ru (полный текст SKILL.md)

Перенесён дословно из `applicant/.agents/skills/hh-web/SKILL.md` (2026-08-05, перед удалением
каталога навыка). Это процедурный рецепт: как исследовать hh.ru через MCP DevTools в открытом
браузере, что фиксировать, как вести базу знаний, когда можно писать клиент. Все факты из
`findings/`, на которые ссылается навык, — в §1–§7 и Приложениях A–C.

```markdown
---
name: hh-web
description: >
  Исследование и документирование hh.ru через MCP DevTools в открытом браузере:
  авторизация, cookie, токены, API-эндпоинты, расположение данных. Ведёт живую
  базу знаний (findings/) для написания Python-пакета hh.web/hh.api — клиента,
  повторяющего поведение браузера.
---

# hh-web: как работает hh.ru (живая база знаний)

## Цель

Восстановить устройство hh.ru с точки зрения сети и данных:

1. Как проходит авторизация (вход, сессия, токены, cookie).
2. Где какие данные лежат (эндпоинты, структура JSON-ответов, шарды).
3. Набрать деталей, чтобы написать Python-клиент, который выглядит как браузер
   (заголовки, cookie, рефереры) и работает как пакет:
   - `hh.web` — транспорт: сессия, cookie-стенд, подделка браузерных заголовков;
   - `hh.api` — типизированные вызовы эндпоинтов.

## Жёсткие правила

1. **Не выдумывать факты.** Фактом считается только то, что реально увидено
   в запросах/ответах/консоли/куках через MCP DevTools.
2. **Не запускать Chrome/браузер самостоятельно.** MCP DevTools подключён
   к уже открытому браузеру пользователя по WebSocket. Никаких команд запуска.
3. Помечать каждую запись: `[ПРОВЕРЕНО]` — лично наблюдали, `[ГИПОТЕЗА]` —
   предположение, требующее проверки.
4. findings/ — история. Старые факты не удалять; при изменении — пометка
   `[ОБНОВЛЕНО YYYY-MM-DD]`.
5. Сначала фиксируем поведение в findings, потом пишем код.

## Подключение и проверка

1. `list_pages` — убедиться, что вкладка hh.ru открыта и выбрана.
2. Снять состояние: `list_network_requests` (фильтр xhr/fetch/document) +
   `list_console_messages`.
3. Работать через браузер пользователя, новые вкладки — только при необходимости.

## Рабочий цикл исследования

1. Пользователь совершает действие (переход, клик, логин, поиск).
2. Вы фиксируете «до» и «после»: `list_network_requests`, при необходимости
   `list_console_messages`.
3. Разбираете цепочку: какой запрос породил какие, какие заголовки и куки.
4. Значимые находки — в findings (см. ниже).
5. В конце сессии — запись в `findings/sessions/YYYY-MM-DD.md`.

## Фильтр шума (НЕ документировать)

Трекеры/реклама/виджеты — игнорировать, если не несут прикладных данных:

- `mc.yandex.com`, `yandex.ru/ads/adfox` — метрика/реклама
- `eye.targetads.io`, `hybrid.ai`, `bobid-ip.hybrid.ai` — трекеры
- `sentry.hh.ru` — только для отладки ошибок
- `uxfeedback`, `hhcdn.ru/uxfeedback`, `widget-api.uxfeedback.ru` — виджеты
- `chrome-extension://*` (обычно net::ERR_FAILED) — мусор

## Интересующие домены (прикладная логика)

| Домен/префикс | Что это | Комментарий |
|---|---|---|
| `hh.ru/api/*` | основной JSON-API | главный объект изучения |
| `hh.ru/shards/*` | серверные шарды данных | части страницы отдельными запросами |
| `websocket.hh.ru/*` | вебсокет-приложение | `proxy-webapp/index.html`, `proxy-webapp-config` |
| `adsrv.hh.ru/pv` | персональная выдача | содержит данные профиля (puid-*) |
| `hh.ru/*` документы | SPA-оболочка | статика на hhcdn.ru |

## Что фиксировать по каждому шагу

1. Страница/URL и как туда попали (клик, редирект, `hhtmFrom`, `backurl`).
2. Запрос: method, path, query-параметры, status, тип (xhr/fetch/document).
3. Заголовки для авторизации: `Cookie`, `x-*`, `Authorization`, `Referer`,
   `Origin`, `x-region`, `x-appversion`.
4. Ответ: где лежат данные (структура JSON, ключи).
5. Cookie: имя, значение, домен, path, httpOnly/secure, когда выставлены, роль.
6. localStorage/sessionStorage: ключи (через консоль браузера).
7. Токены: где появляются, в каких заголовках, как обновляются.

## Форматы записей

### Эндпоинт (таблица в findings/api.md)

| Метод | Path | Параметры | Статус | Назначение | Проверено |

### Cookie (таблица в findings/auth.md)

| Имя | Домен | Путь | httpOnly | Secure | Роль | Проверено |

### Событие авторизации (лог в findings/sessions/)

URL → запросы → заголовки → куки/токены → что изменилось.

## Структура findings/

- `findings/README.md` — оглавление и легенда пометок
- `findings/auth.md` — авторизация: flow, cookie, токены, хранение
- `findings/api.md` — каталог эндпоинтов и данных
- `findings/sessions/YYYY-MM-DD.md` — хронология наблюдений

## Критерий готовности к написанию клиента

В findings есть:
- полный flow входа/восстановления сессии (запросы, куки, порядок);
- набор заголовков для «браузероподобного» запроса;
- каталог эндпоинтов для нужных экранов (главная, поиск, вакансия, профиль);
- подтверждение, какие данные приходят с сервера, а какие считаются на клиенте.
```

---

## Приложение A. `fl_constants.json` (эталонные константы и семплы gib)

Полное содержимое файла `findings/reference/fl_constants.json` (33 КБ) — ground truth для
портов из Приложения B. Ключи:

- `rotations` — число ротаций string table при декоде бандла (189);
- `eval_error` — ошибка VM-прогона бандла при извлечении (не мешает работе);
- `ce` — константа подписи fgssc (см. §2.2);
- `w_calls` — карта адресов string table (121 запись) для реверса;
- `arrays` — таблицы сдвига `vn`/`wn`/`Sn`/`Cn`/`yn` (по 26 значений, v005);
- `di_helpers` — 319 декодированных строк/функций бандла (названия методов, CSS, строки ошибок,
  список шрифтов/плагинов для fingerprint);
- `kn` — v005: `version="005"`, `Vi="8904b7c0-4a21-11f1-9913-3b6933000000"`, `Ut=26`,
  `tn` (65 символов base64-алфавита), `table` (CRC32, 256 uint32);
- `v004` — `version="004"`, `table` (CRC32, 256), `key` (5 таблиц сдвига по 26), `Ut=26`;
- `encode_samples` — 16 семплов v005: вход → ожидаемое тело POST /api/fl;
- `encode_samples_v004` — 16 семплов v004: вход → ожидаемое значение куки `__zzatgib-w-hh`.

```json
{
  "rotations": 189,
  "eval_error": "Cannot read properties of undefined (reading 'prototype')",
  "ce": "shgkla34ty3gg354g34wf",
  "w_calls": {
    "iFJq:806": "73",
    "bF&k:390": "37",
    "Of2d:386": "91",
    "yG4D:411": "24",
    ")e$W:560": "61",
    "yG4D:247": "45",
    "fwT4:553": "32",
    "iFJq:404": "71",
    "D2]c:818": "115",
    "Hxl0:514": "44",
    ")6gn:294": "45",
    "GNAc:427": "114",
    "6rq5:788": "69",
    "qiXA:650": "51",
    "&nzk:256": "85",
    "l8(R:398": "73",
    ")6gn:488": "73",
    "!jr8:454": "55",
    "^1Cz:769": "83",
    "JOmw:537": "35",
    "Zc1Z:819": "9",
    "JOmw:621": "66",
    "$*!b:781": "93",
    "fwT4:478": "60",
    "zvF(:425": "23",
    "C6Fq:746": "43",
    "#tGq:507": "49552",
    "INlK:377": "35204",
    "@fdD:702": "37111",
    "eY(Q:279": "13657",
    "H&VL:284": "5501",
    "iFJq:403": "12339",
    "#tGq:532": "27652",
    "IgsC:498": "31648",
    "F9AY:583": "10762",
    "zA#H:598": "39953",
    "^1Cz:667": "34780",
    "Zc1Z:321": "37111",
    "tQCg:578": "21940",
    "&e4z:723": "36740",
    "^ir6:395": "26185",
    "bF&k:442": "27895",
    "mELX:619": "27184",
    "GNAc:509": "45762",
    "#tGq:293": "13115",
    "1^UI:379": "2004",
    "#tGq:463": "30286",
    ")e$W:793": "47837",
    "9lAG:592": "971",
    "uRNJ:652": "607",
    "qiXA:358": "1048",
    "eY(Q:288": "328",
    "GNAc:343": "1396",
    "zriJ:381": "337",
    "bF&k:480": "998",
    "bF&k:643": "959",
    "Gs7^:540": "849",
    "1^UI:558": "865",
    "#tGq:610": "1121",
    "zA#H:434": "1409",
    "H&VL:325": "473",
    "RZuu:687": "1805",
    "hf6D:579": "574",
    "!jr8:464": "206",
    "D2]c:580": "1864",
    "!jr8:392": "1059",
    ")6gn:706": "109",
    "hf6D:743": "415",
    "JOmw:423": "90",
    "Gs7^:437": "371",
    "1^UI:299": "594",
    "^1Cz:611": "401",
    "qiXA:639": "fromCharCode",
    "GNAc:571": "706",
    "9lAG:242": "556",
    "tQCg:345": "115",
    "GNAc:766": "677",
    "GNAc:776": "440",
    "Gs7^:714": "483",
    "yG4D:543": "776",
    "bF&k:691": "921",
    "$Lqo:252": "292",
    "^1Cz:645": "195",
    "H&VL:707": "12",
    "^1Cz:795": "332",
    "&nzk:724": "806",
    "c@eq:266": "206",
    "iFJq:791": "815",
    ")e$W:439": "484",
    "tQCg:260": "16",
    "@fdD:604": "741",
    "GNAc:774": "639",
    "@EdF:779": "226",
    "hf6D:449": "834",
    "&e4z:629": "790",
    ")6gn:826": "567",
    "$Lqo:675": "22",
    "Of2d:435": "7279",
    "D2]c:626": "5377",
    "INlK:603": "4088",
    "qiXA:555": "5254",
    "fwT4:813": "qhPVv",
    "[geN:339": "7989",
    "IgsC:701": "5637",
    "H&VL:494": "6847",
    "$*!b:570": "7644",
    "qiXA:523": "2306",
    "@fdD:346": "5088",
    "$*!b:376": "5894",
    "eY(Q:409": "6818",
    "Of2d:291": "8025",
    "$Lqo:573": "4088",
    ")6gn:485": "3393",
    "eY(Q:440": "1709",
    "zriJ:496": "3331",
    "*^*G:805": "817",
    "Hxl0:445": "712",
    "Of2d:574": "2813",
    "#tGq:562": "3349",
    "mELX:754": "2329",
    "fwT4:686": "table"
  },
  "arrays": {
    "vn": [
      "73",
      "37",
      "91",
      "24",
      "61",
      "45",
      "32",
      "71",
      "115",
      "44",
      "45",
      "114",
      "69",
      "51",
      "85",
      "73",
      "73",
      "55",
      "83",
      "35",
      "9",
      "66",
      "93",
      "60",
      "23",
      "43"
    ],
    "wn": [
      "971",
      "607",
      "1048",
      "328",
      "583",
      "1396",
      "337",
      "998",
      "959",
      "849",
      "865",
      "1121",
      "1409",
      "473",
      "1805",
      "574",
      "206",
      "1864",
      "1059",
      "109",
      "415",
      "90",
      "1340",
      "371",
      "594",
      "401"
    ],
    "Sn": [
      "49552",
      "12909",
      "35204",
      "37111",
      "13657",
      "5501",
      "12339",
      "39432",
      "27652",
      "31648",
      "10762",
      "39953",
      "34780",
      "37111",
      "21940",
      "36740",
      "26185",
      "27895",
      "27184",
      "37124",
      "45762",
      "13115",
      "2004",
      "6101",
      "30286",
      "47837"
    ],
    "Cn": [
      "706",
      "556",
      "547",
      "115",
      "677",
      "440",
      "483",
      "776",
      "921",
      "292",
      "195",
      "12",
      "332",
      "806",
      "206",
      "815",
      "484",
      "959",
      "16",
      "741",
      "639",
      "226",
      "834",
      "790",
      "567",
      "22"
    ],
    "yn": [
      "7279",
      "5377",
      "4088",
      "5254",
      "444",
      "1101",
      "7989",
      "5637",
      "6847",
      "7644",
      "2306",
      "5088",
      "5894",
      "6818",
      "8025",
      "4088",
      "3393",
      "7262",
      "1709",
      "3331",
      "817",
      "712",
      "5380",
      "2813",
      "3349",
      "2329"
    ]
  },
  "di_helpers": {
    "pZSlY": "function(t,n){return t>=n}",
    "sqjRW": "function(t,n,e){return t(n,e)}",
    "MjfTm": "OGKDx",
    "wCOEg": "function(t,n){return t+n}",
    "AWMZB": "function(t,n){return t(n)}",
    "dVnJp": "function(t,n){return t!=n}",
    "SyiCh": "undefined",
    "nVrUn": "function(t,n){return t!==n}",
    "HiqzD": "persistent",
    "EQuhI": "storage",
    "yxOnQ": "boolean",
    "PtcwF": "function(t,n){return t(n)}",
    "PZkHF": "function(t,n){return t==n}",
    "BZBrN": "number",
    "MHngU": "string",
    "MPyfn": "function(t,n){return t&n}",
    "uTZNY": "function(t,n){return t>>n}",
    "eDuau": "function(t,n){return t>n}",
    "PeWsS": "function(t,n){return t*n}",
    "oOKCm": "function(t,n){return t<n}",
    "BZWqJ": "function(t,n){return t-n}",
    "otfCQ": "function(t,n){return t||n}",
    "sXOau": "function(t,n){return t||n}",
    "TKQfp": "encryption",
    "AANSL": "sha1",
    "nsmiv": "__hash",
    "OqrYs": ".frbGGLsfmAfX{display:none;position:absolute;left:-9999px;}.OXmQLkcsGTmV{display:inline;}.DUkiLGEXXUwX{display:none;}",
    "JLpKJ": "getExtension",
    "TcjGF": "UNMASKED_RENDERER_WEBGL",
    "pMTvC": "VERSION",
    "OlJuL": "getParameter",
    "ypEkR": "depthFunc",
    "gxraO": "MAX_VARYING_COMPONENTS",
    "TAdGg": "precision",
    "KcwhH": "getShaderPrecisionFormat",
    "fcCCg": "canvas",
    "EbYOr": "function(t,n){return t!==n}",
    "GbwoX": "vendorAndRenderer",
    "jdBYK": "unmaskedVendor",
    "GfrxZ": "sharingLangVersion",
    "nsyiM": "function(t,n){return t===n}",
    "eHsUT": "complete",
    "evryi": "function(t){return t()}",
    "tNXrp": "hostname",
    "WOnag": "function(t,n){return t==n}",
    "nBrND": "function(t,n){return t+n}",
    "WVWVa": "request is broken (event: abort), original:",
    "loNZq": "XDomainRequest doesn't exist",
    "pyaYa": "Microsoft.XMLHTTP",
    "UquqQ": "__g_internal",
    "llgcq": "send",
    "lDjgm": "status",
    "XNAAr": "data",
    "lBRTW": "function(t,n){return t&n}",
    "JJagW": "X-GIB-GSSC",
    "XXdIH": "cid",
    "PpMho": "fillRect",
    "yOQmq": "webkit",
    "xcKvG": "pushNotification",
    "hVzvw": "safari",
    "rixIS": "navigator",
    "nvfOG": "canvasText",
    "aKTfJ": "pointerCoarse",
    "zVSTY": "(pointer:fine)",
    "GWkSX": "matches",
    "bvlho": "screen",
    "cbIIR": "isBrave",
    "yRJlP": "value",
    "XLqBP": "mediaDevices",
    "reEhF": "function(t,n){return t>n}",
    "adfMN": "function(t,n,e){return t(n,e)}",
    "OaVvT": "createBuffer",
    "OmzgZ": "ARRAY_BUFFER",
    "gbeAd": "createShader",
    "AOWqX": "attachShader",
    "mOFKp": "sKQLg",
    "HIbaB": "productSub",
    "tpxrZ": "language",
    "TOgSn": "Promise constructor takes a function argument",
    "NnbUj": "resolve",
    "ylvMP": "function(t,n){return t in n}",
    "OTrUR": "pending",
    "aseOP": "function(t,n){return t===n}",
    "rvlnA": "function(t,n){return t!=n}",
    "VpbMY": "function(t,n,e){return t(n,e)}",
    "XEHPa": "function(t){return t()}",
    "yuMZI": "fpEncrypt",
    "nRUkw": "gibHash_sha256",
    "oJeKl": "events",
    "VofOh": "yjaKR",
    "UeBFo": "function(t,n){return t!==n}",
    "FPfXX": "create-packet",
    "PYaIl": "inputSpeed",
    "jfLfN": "function(t,n){return t===n}",
    "cDGIa": "function(t,n){return t(n)}",
    "HEfqM": "function(t,n){return t<n}",
    "sGIvK": "function(t,n){return t>>n}",
    "dTURq": "function(t,n){return t&n}",
    "ehBJP": "function(t,n){return t<<n}",
    "mZGVw": "function(t,n){return t>>n}",
    "BXYAu": "function(t,n){return t%n}",
    "BMzBk": "function(t,n){return t^n}",
    "uzVDb": "function(t,n){return t^n}",
    "gBaMX": "function(t,n){return t|n}",
    "udtlV": "function(t,n){return t|n}",
    "aIeNz": "function(t,n){return t^n}",
    "PsHfC": "function(t,n){return t^n}",
    "fdhoT": "function(t,n){return t^n}",
    "Zltnl": "function(t,n){return t>>>n}",
    "XjeZs": "function(t,n){return t<<n}",
    "xUGLD": "function(t,n){return t^n}",
    "lgHmg": "function(t,n){return t&n}",
    "UISkE": "SRRpa",
    "nhEPi": "function(t,n){return t+n}",
    "YwLgr": "function(t,n){return t%n}",
    "oTSPr": "function(t,n){return t(n)}",
    "wXaYy": "FMeua",
    "vfYwQ": "before-fetch-request",
    "rLCoj": "DyEnu",
    "gcukp": "function(t,n){return t/n}",
    "BPMjY": "function(t,n){return t*n}",
    "uMcbu": "KJCUQ",
    "yMdDx": "tjIYx",
    "VXjLd": "function(t,n){return t<=n}",
    "XXgrX": "function(t,n){return t>>n}",
    "dUvij": "function(t,n){return t-n}",
    "THOdy": "function(t,n){return t-n}",
    "zBCSg": "function(t,n){return t+n}",
    "asgat": "function(t,n){return t<<n}",
    "SnTTz": "function(t,n){return t===n}",
    "ofoZV": "function(t,n){return t<n}",
    "zztmq": "function(t,n){return t+n}",
    "DMhhd": "function(t,n){return t<<n}",
    "gaVnW": "function(t,n){return t>n}",
    "EmUmS": "function(t,n){return t>n}",
    "ISrwE": "function(t,n){return t==n}",
    "iObDO": "function(t,n){return t%n}",
    "IEBox": "function(t,n){return t-n}",
    "KwQVh": "function(t,n){return t>n}",
    "ardDs": "function(t,n){return t-n}",
    "gdblm": "function(t,n){return t&n}",
    "ADyMm": "subtle",
    "wBCTu": "digest",
    "SftGU": "function(t,n){return t&n}",
    "OOvaT": "function(t,n){return t-n}",
    "yKOyp": "crypto",
    "tYsvX": "encode",
    "DkKZy": "GqKaa",
    "nFXwi": "function(t,n){return t<n}",
    "EtwNt": "__zzat",
    "EvuPk": "function(t,n,e,i){return t(n,e,i)}",
    "knsrW": "rsaModulus",
    "EeGkP": "domain",
    "FkOYY": "function(t,n){return t===n}",
    "znISM": "attribute",
    "vAVzj": " is deprecated, please, use ",
    "MxkTK": "function(t,n,e,i){return t(n,e,i)}",
    "xyaPL": "function(t,n){return t(n)}",
    "qTZHI": "function(t,n){return t==n}",
    "sXmHf": "function(t,n){return t==n}",
    "KzpFf": "function(t,n){return t==n}",
    "mHLEn": "create-packet-force",
    "uiRHm": "mQpii",
    "OXEio": "transmission-queue-length",
    "EWvFt": "function(t,n){return t!==n}",
    "GYRwO": "function(t,n,e,i){return t(n,e,i)}",
    "jtrpZ": "dischargingtimechange",
    "ilitB": "getBattery",
    "qoGpz": "function(t,n,e){return t(n,e)}",
    "daFHi": "width",
    "JMZfz": "cpu",
    "OaYuF": "webgl-hash-calculate",
    "YbXbz": "platform",
    "geiOk": "function(t){return t()}",
    "QgSJN": "function(t,n){return t(n)}",
    "hEMHp": "function(t,n){return t-n}",
    "WgJqv": "function(t,n){return t^n}",
    "VbsZU": "12909",
    "cscll": "39432",
    "RaNzJ": "37124",
    "DnZSm": "6101",
    "CnzFX": "583",
    "hKzFw": "1340",
    "yPDbj": "function(t,n){return t>>>n}",
    "mMNSI": "function(t,n){return t^n}",
    "fPnHs": "function(t,n){return t^n}",
    "KQdSm": "function(t,n){return t^n}",
    "qHBYP": "function(t,n){return t>n}",
    "CevFj": "547",
    "CLJeO": "function(t,n){return t>=n}",
    "bNTwG": "function(t,n){return t+n}",
    "iSwCj": "function(t,n){return t&n}",
    "Oxltt": "444",
    "qhPVv": "1101",
    "zvgXX": "7262",
    "MRLWw": "5380",
    "zEhUW": "function(t,n){return t-n}",
    "kENFY": "function(t,n){return t&n}",
    "kYfeV": "function(t,n){return t(n)}",
    "EsRJj": "send-data",
    "atOGX": "_cid",
    "lgABB": "sharedCookieName",
    "Kptkm": "get-custom-backend-url-flow",
    "prQGl": "get-custom-backend-url-etag",
    "tChmO": "info",
    "SvtCh": "secureCookie",
    "RqrPx": "function(t,n){return t>n}",
    "LuchN": "WBUGt",
    "hKHFv": "function(t,n,e){return t(n,e)}",
    "xJQUY": "arialFontHash_sha256",
    "nMwfY": "regexp",
    "ljmeF": "RTmTS",
    "xKRLM": "function(t,n){return t(n)}",
    "sWYvK": "iframeSrc",
    "XXjEY": "headers",
    "HFsFD": "function(t,n){return t(n)}",
    "NJhLU": "function(t,n,e){return t(n,e)}",
    "QvOpn": "customerHash",
    "SxhRe": "function(t,n,e,i){return t(n,e,i)}",
    "plZwQ": "function",
    "wlIGs": "location",
    "iAOap": "function(t,n,e){return t(n,e)}",
    "hmNKH": "function(t,n){return t*n}",
    "pCLaX": "function(t,n){return t(n)}",
    "sWEpb": "get-packet-info",
    "UnRri": "function(t,n){return t==n}",
    "Bbenn": "function(t,n){return t==n}",
    "TxDgh": "function(t,n){return t(n)}",
    "KdsIO": "page-changed",
    "AGHgE": "href",
    "QQUSK": "navigate",
    "NoOjG": "function(t,n){return t===n}",
    "aFdef": "flow",
    "UGeSR": "function(t,n){return t(n)}",
    "ExnTL": "mouseup",
    "CXTpl": "touch",
    "Prqyj": "mousemove",
    "sfSNW": "plugins",
    "xAuSo": "browser",
    "LwMqr": "totalJSHeapSize",
    "QYJMh": "function(t,n,e,i){return t(n,e,i)}",
    "eZISP": "colorDepth",
    "CkYSx": "availTop",
    "Ezdtw": "function(t,n){return t===n}",
    "JtHtb": "Unknown",
    "wFfPi": "enableUserAgentCH",
    "jCsll": "formFactor",
    "iKeYq": "function(t,n,e){return t(n,e)}",
    "ajfts": "function(t,n){return t*n}",
    "WyzOA": "target",
    "jRjrF": "function(t,n){return t+n}",
    "ejMEr": "documentElement",
    "pzNKW": "altKey",
    "yXTbG": "selector",
    "MgaWh": "__est__",
    "EFaYj": "error",
    "tUEbg": "none",
    "Mqdmf": "CQHpa",
    "akZDI": "function fetch() { [native code] }",
    "Feydk": "prototype",
    "EDPZa": "function(t,n){return t!==n}",
    "IrvIG": "function(t){return t()}",
    "Yrfzm": "warning",
    "qLJPz": "oEiCA",
    "UqnTS": "bglUn",
    "LLSRG": "bRpmb",
    "pmNUC": "request_iOS_SDK",
    "nrBcm": "{\"alive\":{\"tickTimeout\":100},\"sysInfo\":{\"enableUserAgentCH\":true},\"iframeSrc\":{},\"oneTimeToken\":{\"allowedDomains\":[]},\"platform\":{},\"userActivity\":{\"clipboardLogEnable\":false}}",
    "AKtve": "launch",
    "RzbKc": "backend-post-response",
    "RVPrw": "F10",
    "vZlDx": "AltRight",
    "UyoCQ": "PageUp",
    "ECwjc": "MetaLeft",
    "zBujo": "tabInfo",
    "YoTWJ": "function(t,n){return t==n}",
    "NPWFG": "function(t,n){return t&n}",
    "ZzRoS": "^kep\\.tr$",
    "SrBXY": "^city\\.yokohama\\.jp",
    "VUsNa": "^[a-zA-Z][a-zA-Z0-9\\-]+$",
    "ZaZIp": "function(t,n){return t==n}",
    "CPoOT": "\"cid\" is required field. It must be string and match this regexp \"",
    "BAgFm": "setAttribute",
    "hmDKt": "setSessionID",
    "LiYdI": "removeAttribute",
    "jQtZP": "function(t,n){return t+n}",
    "DhEsf": "0.0.1",
    "jHwSi": "gafUrl",
    "aQlfn": "function(t,n,e){return t(n,e)}",
    "ALMXl": "stop-",
    "vMDJf": "init",
    "GjYuZ": "stop-all",
    "slwFc": "Book Antiqua",
    "bfeGf": "Calibri",
    "sbcKW": "Gentium",
    "RaxdW": "Kartika",
    "Lkytv": "Malgun Gothic",
    "wSQmr": "Mangal",
    "ZFZva": "Pristina",
    "VhbwV": "Rockwell",
    "VdXWV": "Open Sans",
    "lRoMT": "function(t,n){return t*n}",
    "fdrMx": "forceSSL",
    "jUmXX": "\"sharedCookieName\" field must be string",
    "WRDfN": "transmission",
    "DXczR": "setCFIDS",
    "PSPJU": "isContentWindowTopNull",
    "ElWLJ": "useSeleniumIframe",
    "OGFVs": "^(data:image\\/png;base64)[,;].*",
    "JkBpu": "^(data:image\\/jpeg;base64)[,;].*",
    "bWbZl": "^(data:image\\/svg\\+xml)[,;].*",
    "uJQbX": "shgkla34ty3gg354g34wf",
    "lrGNP": "getOTTHeaders",
    "sSmdi": "silentAlive",
    "OlOab": "QuickTime.QuickTime",
    "mOPHt": "WMPlayer.OCX",
    "txKzr": "rmocx.RealPlayer G2 Control",
    "XDKEp": "{22D6F312-B0F6-11D0-94AB-0080C74C7E95}",
    "xfaHe": "active_tab"
  },
  "kn": {
    "version": "005",
    "Vi": "8904b7c0-4a21-11f1-9913-3b6933000000",
    "Ut": 26,
    "tn": [
      "A",
      "B",
      "C",
      "D",
      "E",
      "F",
      "G",
      "H",
      "I",
      "J",
      "K",
      "L",
      "M",
      "N",
      "O",
      "P",
      "Q",
      "R",
      "S",
      "T",
      "U",
      "V",
      "W",
      "X",
      "Y",
      "Z",
      "a",
      "b",
      "c",
      "d",
      "e",
      "f",
      "g",
      "h",
      "i",
      "j",
      "k",
      "l",
      "m",
      "n",
      "o",
      "p",
      "q",
      "r",
      "s",
      "t",
      "u",
      "v",
      "w",
      "x",
      "y",
      "z",
      "0",
      "1",
      "2",
      "3",
      "4",
      "5",
      "6",
      "7",
      "8",
      "9",
      "+",
      "/",
      "="
    ],
    "table": [
      0,
      1996959894,
      3993919788,
      2567524794,
      124634137,
      1886057615,
      3915621685,
      2657392035,
      249268274,
      2044508324,
      3772115230,
      2547177864,
      162941995,
      2125561021,
      3887607047,
      2428444049,
      498536548,
      1789927666,
      4089016648,
      2227061214,
      450548861,
      1843258603,
      4107580753,
      2211677639,
      325883990,
      1684777152,
      4251122042,
      2321926636,
      335633487,
      1661365465,
      4195302755,
      2366115317,
      997073096,
      1281953886,
      3579855332,
      2724688242,
      1006888145,
      1258607687,
      3524101629,
      2768942443,
      901097722,
      1119000684,
      3686517206,
      2898065728,
      853044451,
      1172266101,
      3705015759,
      2882616665,
      651767980,
      1373503546,
      3369554304,
      3218104598,
      565507253,
      1454621731,
      3485111705,
      3099436303,
      671266974,
      1594198024,
      3322730930,
      2970347812,
      795835527,
      1483230225,
      3244367275,
      3060149565,
      1994146192,
      31158534,
      2563907772,
      4023717930,
      1907459465,
      112637215,
      2680153253,
      3904427059,
      2013776290,
      251722036,
      2517215374,
      3775830040,
      2137656763,
      141376813,
      2439277719,
      3865271297,
      1802195444,
      476864866,
      2238001368,
      4066508878,
      1812370925,
      453092731,
      2181625025,
      4111451223,
      1706088902,
      314042704,
      2344532202,
      4240017532,
      1658658271,
      366619977,
      2362670323,
      4224994405,
      1303535960,
      984961486,
      2747007092,
      3569037538,
      1256170817,
      1037604311,
      2765210733,
      3554079995,
      1131014506,
      879679996,
      2909243462,
      3663771856,
      1141124467,
      855842277,
      2852801631,
      3708648649,
      1342533948,
      654459306,
      3188396048,
      3373015174,
      1466479909,
      544179635,
      3110523913,
      3462522015,
      1591671054,
      702138776,
      2966460450,
      3352799412,
      1504918807,
      783551873,
      3082640443,
      3233442989,
      3988292384,
      2596254646,
      62317068,
      1957810842,
      3939845945,
      2647816111,
      81470997,
      1943803523,
      3814918930,
      2489596804,
      225274430,
      2053790376,
      3826175755,
      2466906013,
      167816743,
      2097651377,
      4027552580,
      2265490386,
      503444072,
      1762050814,
      4150417245,
      2154129355,
      426522225,
      1852507879,
      4275313526,
      2312317920,
      282753626,
      1742555852,
      4189708143,
      2394877945,
      397917763,
      1622183637,
      3604390888,
      2714866558,
      953729732,
      1340076626,
      3518719985,
      2797360999,
      1068828381,
      1219638859,
      3624741850,
      2936675148,
      906185462,
      1090812512,
      3747672003,
      2825379669,
      829329135,
      1181335161,
      3412177804,
      3160834842,
      628085408,
      1382605366,
      3423369109,
      3138078467,
      570562233,
      1426400815,
      3317316542,
      2998733608,
      733239954,
      1555261956,
      3268935591,
      3050360625,
      752459403,
      1541320221,
      2607071920,
      3965973030,
      1969922972,
      40735498,
      2617837225,
      3943577151,
      1913087877,
      83908371,
      2512341634,
      3803740692,
      2075208622,
      213261112,
      2463272603,
      3855990285,
      2094854071,
      198958881,
      2262029012,
      4057260610,
      1759359992,
      534414190,
      2176718541,
      4139329115,
      1873836001,
      414664567,
      2282248934,
      4279200368,
      1711684554,
      285281116,
      2405801727,
      4167216745,
      1634467795,
      376229701,
      2685067896,
      3608007406,
      1308918612,
      956543938,
      2808555105,
      3495958263,
      1231636301,
      1047427035,
      2932959818,
      3654703836,
      1088359270,
      936918000,
      2847714899,
      3736837829,
      1202900863,
      817233897,
      3183342108,
      3401237130,
      1404277552,
      615818150,
      3134207493,
      3453421203,
      1423857449,
      601450431,
      3009837614,
      3294710456,
      1567103746,
      711928724,
      3020668471,
      3272380065,
      1510334235,
      755167117
    ]
  },
  "v004": {
    "version": "004",
    "table": [
      0,
      1996959894,
      3993919788,
      2567524794,
      124634137,
      1886057615,
      3915621685,
      2657392035,
      249268274,
      2044508324,
      3772115230,
      2547177864,
      162941995,
      2125561021,
      3887607047,
      2428444049,
      498536548,
      1789927666,
      4089016648,
      2227061214,
      450548861,
      1843258603,
      4107580753,
      2211677639,
      325883990,
      1684777152,
      4251122042,
      2321926636,
      335633487,
      1661365465,
      4195302755,
      2366115317,
      997073096,
      1281953886,
      3579855332,
      2724688242,
      1006888145,
      1258607687,
      3524101629,
      2768942443,
      901097722,
      1119000684,
      3686517206,
      2898065728,
      853044451,
      1172266101,
      3705015759,
      2882616665,
      651767980,
      1373503546,
      3369554304,
      3218104598,
      565507253,
      1454621731,
      3485111705,
      3099436303,
      671266974,
      1594198024,
      3322730930,
      2970347812,
      795835527,
      1483230225,
      3244367275,
      3060149565,
      1994146192,
      31158534,
      2563907772,
      4023717930,
      1907459465,
      112637215,
      2680153253,
      3904427059,
      2013776290,
      251722036,
      2517215374,
      3775830040,
      2137656763,
      141376813,
      2439277719,
      3865271297,
      1802195444,
      476864866,
      2238001368,
      4066508878,
      1812370925,
      453092731,
      2181625025,
      4111451223,
      1706088902,
      314042704,
      2344532202,
      4240017532,
      1658658271,
      366619977,
      2362670323,
      4224994405,
      1303535960,
      984961486,
      2747007092,
      3569037538,
      1256170817,
      1037604311,
      2765210733,
      3554079995,
      1131014506,
      879679996,
      2909243462,
      3663771856,
      1141124467,
      855842277,
      2852801631,
      3708648649,
      1342533948,
      654459306,
      3188396048,
      3373015174,
      1466479909,
      544179635,
      3110523913,
      3462522015,
      1591671054,
      702138776,
      2966460450,
      3352799412,
      1504918807,
      783551873,
      3082640443,
      3233442989,
      3988292384,
      2596254646,
      62317068,
      1957810842,
      3939845945,
      2647816111,
      81470997,
      1943803523,
      3814918930,
      2489596804,
      225274430,
      2053790376,
      3826175755,
      2466906013,
      167816743,
      2097651377,
      4027552580,
      2265490386,
      503444072,
      1762050814,
      4150417245,
      2154129355,
      426522225,
      1852507879,
      4275313526,
      2312317920,
      282753626,
      1742555852,
      4189708143,
      2394877945,
      397917763,
      1622183637,
      3604390888,
      2714866558,
      953729732,
      1340076626,
      3518719985,
      2797360999,
      1068828381,
      1219638859,
      3624741850,
      2936675148,
      906185462,
      1090812512,
      3747672003,
      2825379669,
      829329135,
      1181335161,
      3412177804,
      3160834842,
      628085408,
      1382605366,
      3423369109,
      3138078467,
      570562233,
      1426400815,
      3317316542,
      2998733608,
      733239954,
      1555261956,
      3268935591,
      3050360625,
      752459403,
      1541320221,
      2607071920,
      3965973030,
      1969922972,
      40735498,
      2617837225,
      3943577151,
      1913087877,
      83908371,
      2512341634,
      3803740692,
      2075208622,
      213261112,
      2463272603,
      3855990285,
      2094854071,
      198958881,
      2262029012,
      4057260610,
      1759359992,
      534414190,
      2176718541,
      4139329115,
      1873836001,
      414664567,
      2282248934,
      4279200368,
      1711684554,
      285281116,
      2405801727,
      4167216745,
      1634467795,
      376229701,
      2685067896,
      3608007406,
      1308918612,
      956543938,
      2808555105,
      3495958263,
      1231636301,
      1047427035,
      2932959818,
      3654703836,
      1088359270,
      936918000,
      2847714899,
      3736837829,
      1202900863,
      817233897,
      3183342108,
      3401237130,
      1404277552,
      615818150,
      3134207493,
      3453421203,
      1423857449,
      601450431,
      3009837614,
      3294710456,
      1567103746,
      711928724,
      3020668471,
      3272380065,
      1510334235,
      755167117
    ],
    "key": [
      [
        113,
        11,
        53,
        101,
        47,
        23,
        41,
        103,
        19,
        37,
        29,
        73,
        109,
        97,
        89,
        71,
        59,
        107,
        31,
        79,
        83,
        43,
        13,
        17,
        61,
        67
      ],
      [
        1009,
        131,
        1699,
        1283,
        587,
        967,
        929,
        271,
        773,
        1811,
        1373,
        1319,
        809,
        971,
        1249,
        1361,
        1697,
        593,
        367,
        1879,
        1667,
        523,
        1789,
        1523,
        557,
        1049
      ],
      [
        7127,
        15313,
        3203,
        9181,
        16927,
        42169,
        48079,
        49853,
        23417,
        30851,
        21401,
        28793,
        17449,
        16067,
        38281,
        33637,
        44711,
        7853,
        16657,
        46831,
        19913,
        1987,
        47111,
        51449,
        27767,
        17747
      ],
      [
        4643,
        2129,
        1399,
        719,
        787,
        881,
        7879,
        499,
        4721,
        3187,
        3203,
        7333,
        3527,
        7451,
        5399,
        1733,
        3583,
        3863,
        661,
        4591,
        257,
        7717,
        3877,
        7691,
        4597,
        6701
      ],
      [
        397,
        137,
        1009,
        181,
        881,
        379,
        107,
        919,
        229,
        1019,
        809,
        359,
        17,
        409,
        179,
        13,
        37,
        431,
        199,
        257,
        929,
        197,
        859,
        503,
        127,
        29
      ]
    ],
    "Ut": 26
  },
  "encode_samples": {
    "": "MDA18904b7c0-4a21-11f1-9913-3b6933000000AAAAAA==AAAAAA==",
    "a": "MDA18904b7c0-4a21-11f1-9913-3b6933000000Mg==6Le+Qw==GtW+DQ==",
    "hello": "MDA18904b7c0-4a21-11f1-9913-3b6933000000ORJPDDQ=NhCmhg==ZsTDug==",
    "Привет мир!": "MDA18904b7c0-4a21-11f1-9913-3b693300000036ran8OQ1brZvMi2QMKi37fekU4=sUikNw==tNPmPQ==",
    "{\"a\":1,\"b\":\"тест\",\"c\":[1,2,3]}": "MDA18904b7c0-4a21-11f1-9913-3b6933000000TEdEOndeTGldTmccyYPYjs+O2oBrY3UOK3xAbUNddVhAHQ==USbhDA==yWrXsQ==",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx": "MDA18904b7c0-4a21-11f1-9913-3b6933000000SSVbGD0tIEdzLC1yRTNVSUk3UyMJQl08FytJJVsYPS0gR3MsLXJFM1VJSTdTIwlCXTwXK0klWxg9LSBHcywtckUzVUlJN1MjCUJdPBcrSSVbGD0tIEdzLC1yRTNVSUk3UyMJQl08FytJJVsYPS0gR3MsLXJFM1VJSTdTIwlCXTwXK0klWxg9LSBHcywtckUzVUlJN1MjCUJdPBcrSSVbGD0tIEdzLC1yRTNVSUk3UyMJQl08FytJJVsYPS0gR3MsLXJFM1VJSTdTIwlCXTwXK0klWxg9LSBHcywtckUzVUlJN1MjCUJdPBcrSSVbGD0tIEdzLC1yRTNVSUk3UyMJQl08FytJJVsYPS0gR3MsLXJFM1VJSTdTIwlCXTwXK0klWxg9LSBHcywtckUzVUlJN1MjCUJdPBcrSSVbGD0tIEdzLC1yRTNVSUk3UyMJQl08FytJJVsYPS0gR3MsLXJFM1VJSTdTIwlCXTwXK0klWxg9LSBHcywtckUzVUlJN1MjCUJdPBcrSSVbGD0tIEdzLC1yRTNVSUk3UyMJQl08FytJJVsYPS0gR3MsLXJFM1VJSTdTIwlCXTwXK0klWxg9LSBHcywtckUzVUlJN1MjCUJdPBcrSSVbGD0tIEdzLC1yRTNVSUk3UyMJQl08FytJJVsYPS0=CrLOUQ==QC5sUw==",
    "{\"screen\":{\"width\":1920,\"height\":1080},\"ua\":\"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\"}": "MDA18904b7c0-4a21-11f1-9913-3b6933000000TEdWezcaDT0dZjAcRCRBRTlZFVRCdBVoORs2FkoIOU9aeCtkXXdxVVIya3F1cHhETjALFHhaEUhdVXh4LGdNRjYpUklpNxNZaHgZZTdsQR1PfRwaChpkKFwveGoLfH9Xe25RHjIQQ0s9Fk59XXQNMmYjVhoQI09APiQKVDt4E2xFW3dVe2smGwlBZFtiLXxhEH9rPA==aTiUWA==AIy0nw==",
    "😀": "MDA18904b7c0-4a21-11f1-9913-3b693300000084+wrA==BU21RA==ZFt7kw==",
    "a😀b": "MDA18904b7c0-4a21-11f1-9913-3b6933000000MvKqkKN6tEKthA==ILsyoQ==",
    "𝄞": "MDA18904b7c0-4a21-11f1-9913-3b6933000000842tig==GrEBFA==Sr5GHA==",
    "𐍈": "MDA18904b7c0-4a21-11f1-9913-3b693300000084CltA==N3+cXw==S95C7A==",
    "a\ud800b": "MDA18904b7c0-4a21-11f1-9913-3b6933000000Mg8=noNIbQ==PBZbHw==",
    "\udc00x": "MDA18904b7c0-4a21-11f1-9913-3b69330000008JCLgiU=tz48IQ==nIecCw==",
    "п́й": "MDA18904b7c0-4a21-11f1-9913-3b6933000000worVoMOR3oLMdw==uZmFuw==",
    "😀😀😀": "MDA18904b7c0-4a21-11f1-9913-3b693300000084+wrPKoibPziK64Q6+5wA==CaAhUQ==",
    "😀x\ud83d": "MDA18904b7c0-4a21-11f1-9913-3b693300000084+wrFs=/Wjevw==R9n+dA=="
  },
  "encode_samples_v004": {
    "": "MDA0AAAAAA==",
    "a": "MDA0Wg==WbxXZw==",
    "hello": "MDA0YXApWSY=h6cX8w==",
    "Привет мир!": "MDA0wpDTg82bxrXagMKJSdWL3L3Pkz4=ahNR8A==",
    "{\"a\":1,\"b\":\"тест\",\"c\":[1,2,3]}": "MDA0dC0eD2lIVRF1R1dr3avCgMaiyJNdH0E6dWVoQml1JT4aag==ayjgmg==",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx": "MDA0cQs1ZS8XKWcTJR1JbWFZRztrH09TKw0RPUNxCzVlLxcpZxMlHUltYVlHO2sfT1MrDRE9Q3ELNWUvFylnEyUdSW1hWUc7ax9PUysNET1DcQs1ZS8XKWcTJR1JbWFZRztrH09TKw0RPUNxCzVlLxcpZxMlHUltYVlHO2sfT1MrDRE9Q3ELNWUvFylnEyUdSW1hWUc7ax9PUysNET1DcQs1ZS8XKWcTJR1JbWFZRztrH09TKw0RPUNxCzVlLxcpZxMlHUltYVlHO2sfT1MrDRE9Q3ELNWUvFylnEyUdSW1hWUc7ax9PUysNET1DcQs1ZS8XKWcTJR1JbWFZRztrH09TKw0RPUNxCzVlLxcpZxMlHUltYVlHO2sfT1MrDRE9Q3ELNWUvFylnEyUdSW1hWUc7ax9PUysNET1DcQs1ZS8XKWcTJR1JbWFZRztrH09TKw0RPUNxCzVlLxcpZxMlHUltYVlHO2sfT1MrDRE9Q3ELNWUvFylnEyUdSW1hWUc7ax9PUysNET1DcQs1ZS8XKWcTJR1JbWFZRztrH09TKw0RPUNxCzVlLxcpZxMlHUltYVlHO2sfT1MrDRE9Q3ELNWUvFylnEyUdSW1hWUc7ax9PUysNET1DcQs1ZS8XKWcTJR1JbWFZRztrH09TKw0RPUNxCzVlLxc=ww/UyQ==",
    "{\"screen\":{\"width\":1920,\"height\":1080},\"ua\":\"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\"}": "MDA0dC0wUCl8Fl01XyBrbFJFQysVWQgUXT09XzNedCRVKzljIENdTU4hC1YwXS1BJEotdn0xLChAYx1PPwkgRGA9HV5XVkdba1cNOmFBOl0MaXspUg58Ezp8IUx+KCAPenETRyIjf1pdaWNldChST14WUn4cRmk4UVM+MFhOCA1hO0Frcyc7VUAYfRJhfFRSfCwXFH1dcA==JAN2Tg==",
    "😀": "MDA08oKqiQ==LxahOQ==",
    "a😀b": "MDA0WvGBp7FP++yqnA==",
    "𝄞": "MDA08oCWpw==g7cBZw==",
    "𐍈": "MDA08bOfkQ==qVfbkA==",
    "a\ud800b": "MDA0Wm0=Mo66xA==",
    "\udc00x": "MDA08JCGjQs=zxEeWA==",
    "п́й": "MDA0wrDOhM2cCmZKDQ==",
    "😀😀😀": "MDA08oKqifCbqrXzu6274KSVzg==",
    "😀x\ud83d": "MDA08oKqiTU=25u1Bw=="
  }
}
```

---

## Приложение B. Python-порты шифровальщиков (fl_encode.py, fl_encode_v004.py)

Полные рабочие файлы; запуск: `python3 fl_encode.py` (нужен `fl_constants.json` рядом —
см. Приложение A) → печатает «ALL MATCH» на 16 семплах.

### B.1. `fl_encode.py` — версия 005 (класс `kn`, тело POST /api/fl)

```python
"""
Python-порт кодировщика версии 005 (тело POST /api/fl) из бандла 413 (модуль 825).

JS-эталон: probe_encode.js -> fl_constants.json (массивы vn/wn/Sn/Cn/yn, CRC32 table, Vi,
хелперы Di, эталонные encode() на семплах).

Схема (из kn.encode / kn.Ht бандла):
    encode(s) = b64("005") + VI + b64(data) + b64(~e32) + b64(~n32)
    где data, n, e, i = Ht(s, n=-1, e=-1, i=0).

    Ht — поблочное «шифрование» каждого UTF-16 code unit через таблицы vn/wn/Sn/Cn/yn
    (сдвиг в альтернативную кодовую область) + двойной CRC32-аккумулятор (n, e).

Внимание, JS-семантика:
  * символы строки обрабатываются по UTF-16 code units (не code points!);
  * все битовые операции — 32-битные; в Python маскируем & 0xFFFFFFFF после каждого шага;
  * >>> — беззнаковый сдвиг; >> — знаковый (для наших значений ≥0 совпадает);
  * NaN из charCodeAt за границами: сравнения с NaN = false, арифметика даёт NaN,
    но битовые & превращают NaN в 0 (ветка при этом выполняется);
  * i инкрементируется в заголовке цикла (i++, g++) на КАЖДОЙ итерации; ветки-пропуски
    делают i-- (нетто 0). i % 26 — индекс в таблицах vn/wn/Sn/Cn/yn;
  * n обновляется от ВЫХОДНЫХ байтов, e — от ВХОДНЫХ code units; e — чистый
    CRC2-аккумулятор и нигде не инкрементируется.

Зависимости: только стандартная библиотека.
"""

import base64
import json
import os

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
M32 = 0xFFFFFFFF


def _load_constants() -> dict:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fl_constants.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _utf16_units(s: str) -> list[int]:
    """UTF-16 code units строки (как t.charCodeAt(g) в JS).

    Астральные символы раскладываются в суррогатную пару; одинокие суррогаты
    (в т.ч. из JSON-ключей с \\uD800) остаются как есть — как в JS.
    """
    units = []
    for ch in s:
        cp = ord(ch)
        if cp < 0x10000:
            units.append(cp)
        else:
            cp -= 0x10000
            units.append(0xD800 + (cp >> 10))
            units.append(0xDC00 + (cp & 0x3FF))
    return units


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class FLEncoderV5:
    def __init__(self, constants: dict):
        kn = constants["kn"]
        self.table: list[int] = kn["table"]  # CRC32 (256 значений, uint32)
        self.vn = [int(x) for x in constants["arrays"]["vn"]]
        self.wn = [int(x) for x in constants["arrays"]["wn"]]
        self.Sn = [int(x) for x in constants["arrays"]["Sn"]]
        self.Cn = [int(x) for x in constants["arrays"]["Cn"]]
        self.yn = [int(x) for x in constants["arrays"]["yn"]]
        self.VI: str = kn["Vi"]  # "8904b7c0-4a21-11f1-9913-3b6933000000"
        self.version: str = kn["version"]  # "005"

    # -- вспомогательные -----------------------------------------------------

    def _vt(self, t: int) -> str:
        """Vt: 4 байта big-endian uint32 -> b64."""
        t &= M32
        return _b64(bytes([(t >> 24) & 0xFF, (t >> 16) & 0xFF, (t >> 8) & 0xFF, t & 0xFF]))

    def _crc(self, acc: int, byte: int) -> int:
        """Один шаг CRC32-аккумулятора (n = n>>>8 ^ table[255&(n^byte)])."""
        return (((acc & M32) >> 8) ^ self.table[(acc ^ byte) & 0xFF]) & M32

    # -- кодировщик ----------------------------------------------------------

    def _ht(self, s: str) -> tuple[bytes, int, int, int]:
        """Точная транскрипция kn.Ht(t, -1, -1, 0).

        Возвращает (данные, n_акк, e_акк, i_индекс) как в JS: [v.join(""), n, e, i].
        """
        units = _utf16_units(s)
        n = M32  # -1
        e = M32  # -1
        i = 0
        v = bytearray()
        g = 0
        ln = len(units)
        while g < ln:
            m = units[g]
            if m < 8:
                # управляющий байт: символ пропускается; i-- в теле + i++ внизу = нетто 0
                i -= 1
            elif m < 128:
                r = 8 + (m - 8 + self.vn[i % 26]) % 120
                n = self._crc(n, r)
                e = self._crc(e, m)
                v.append(r)
            elif m < 2048:
                r = 128 + (m - 128 + self.wn[i % 26]) % 1920
                a = (r >> 6) | 192
                c = (r & 63) | 128
                n = self._crc(self._crc(n, a), c)
                h = (m >> 6) | 192
                f = (m & 63) | 128
                e = self._crc(self._crc(e, h), f)
                v.append(a)
                v.append(c)
            elif m < 55296:
                # 3 байта (обычные BMP-символы)
                r = 2048 + (m - 2048 + self.Sn[i % 26]) % 53248
                a = (r >> 12) | 224
                c = ((r >> 6) & 63) | 128
                u = (63 & r) | 128
                n = self._crc(self._crc(self._crc(n, a), c), u)
                h = (m >> 12) | 224
                f = ((m >> 6) & 63) | 128
                l = (63 & m) | 128
                e = self._crc(self._crc(self._crc(e, h), f), l)
                v.append(a)
                v.append(c)
                v.append(u)
            elif m < 56320:
                # high surrogate. JS: W = t.charCodeAt(g+1); вне строки NaN -> оба
                # сравнения (56320 > NaN, NaN >= 57344) false -> ветка пустая.
                nxt = units[g + 1] if g + 1 < ln else None
                if nxt is not None and not (56320 <= nxt < 57344):
                    # JS: i--; continue -> заголовок цикла делает i++, g++ => нетто 0
                    g += 1
                    continue
                # иначе: конец строки или next — low surrogate: ничего не выводим,
                # i и g инкрементируются внизу (пара обработается на low surrogate)
            elif m < 57344:
                # low surrogate: комбинируем с предыдущим high surrogate
                prev = units[g - 1] if g - 1 >= 0 else None
                if prev is not None and not (55296 <= prev < 56320):
                    # JS: i--; continue -> заголовок цикла делает i++, g++ => нетто 0
                    g += 1
                    continue
                if prev is None:
                    # JS: W = charCodeAt(-1) = NaN -> условия false, ветка выполняется,
                    # но арифметика с NaN даёт 0 после битовых &
                    W = 0
                    hi = 0
                else:
                    W = prev
                    hi = 1023 & (55296 + ((W - 55296) + self.Cn[(i - 1) % 26]) % 1024)
                lo = 56320 + ((m - 56320) + self.Cn[i % 26]) % 1024
                r = 65536 + ((hi << 10) | (1023 & lo))
                a = (r >> 18) | 240
                c = ((r >> 12) & 63) | 128
                u = ((r >> 6) & 63) | 128
                sb = (63 & r) | 128  # 4-й байт (в JS: s — не путать с параметром)
                n = self._crc(self._crc(self._crc(self._crc(n, a), c), u), sb)
                p = 65536 + (((1023 & W) << 10) | (1023 & m))
                h = (p >> 18) | 240
                f = (63 & (p >> 12)) | 128
                l = ((p >> 6) & 63) | 128
                d = (63 & p) | 128
                e = self._crc(self._crc(self._crc(self._crc(e, h), f), l), d)
                v.append(a)
                v.append(c)
                v.append(u)
                v.append(sb)
            else:
                # m >= 57344 (приватная зона/выше)
                r = 57344 + ((m - 57344) + self.yn[i % 26]) % 8192
                a = (r >> 12) | 224
                c = ((r >> 6) & 63) | 128
                u = (63 & r) | 128
                n = self._crc(self._crc(self._crc(n, a), c), u)
                h = (m >> 12) | 224
                f = ((m >> 6) & 63) | 128
                l = 128 | (63 & m)
                e = self._crc(self._crc(self._crc(e, h), f), l)
                v.append(a)
                v.append(c)
                v.append(u)
            i += 1
            g += 1
        return bytes(v), n, e, i

    # -- публичный API --------------------------------------------------------

    def encode(self, s: str) -> str:
        """Полное тело POST /api/fl (версия 005): b64(ver) + VI + b64(data) + 2 CRC."""
        data, n, e, _ = self._ht(s)
        return (
            _b64(self.version.encode("ascii"))
            + self.VI
            + _b64(data)
            + self._vt((-1 ^ e) & M32)
            + self._vt((-1 ^ n) & M32)
        )


if __name__ == "__main__":
    enc = FLEncoderV5(_load_constants())
    expected = _load_constants()["encode_samples"]
    ok = True
    for s in expected:
        got = enc.encode(s)
        exp = expected[s]
        match = got == exp
        if not match:
            ok = False
            print(f"MISMATCH for {s[:40]!r}:\n  py: {got}\n  js: {exp}")
        else:
            print(f"OK ({len(s)} ch): {got[:60]}...")
    print("\nALL MATCH" if ok else "\nFAILED")

```

### B.2. `fl_encode_v004.py` — версия 004 (класс `I`, кука `__zzatgib-w-hh`)

```python
"""
Python-порт кодировщика версии 004 (класс `I`, модуль __zzatgib-w-hh) из бандла 413.

JS-эталон: probe_encode.js -> fl_constants.json (v004.version/table/key/Ut,
encode_samples_v004).

Схема (из I.encode / I.Ht бандла):
    encode(s) = b64("004") + b64(data) + b64(4 байта BE: ~n & 0xFFFFFFFF)
    где data, n, e = Ht(s, n=-1, e=0).

Отличия от v005 (kn):
  * НЕТ Vi-префикса и НЕТ второй контрольной суммы (e);
  * e — счётчик итераций (индекс в таблицах key[0..4], e % 26), стартует с 0;
  * единственный CRC-аккумулятор n обновляется ТОЛЬКО от выходных байтов
    (в суррогатной ветке — только от закодированных a,c,u,d, без «настоящего»
    code point p);
  * таблицы сдвига: key[0] (1 байт), key[1] (2 байта), key[2] (3 байта BMP),
    key[3] (m >= 57344), key[4] (суррогаты).

Внимание, JS-семантика:
  * символы строки обрабатываются по UTF-16 code units (не code points!);
  * все битовые операции — 32-битные; в Python маскируем & 0xFFFFFFFF;
  * NaN из charCodeAt за границами: сравнения с NaN = false, арифметика даёт NaN,
    но битовые & превращают NaN в 0 (ветка при этом выполняется);
  * e инкрементируется в заголовке цикла (e++, h++) на КАЖДОЙ итерации;
    ветки-пропуски делают e-- (нетто 0).

Зависимости: только стандартная библиотека.
"""

import base64
import json
import os

M32 = 0xFFFFFFFF


def _load_constants() -> dict:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fl_constants.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _utf16_units(s: str) -> list[int]:
    """UTF-16 code units строки (как t.charCodeAt(g) в JS).

    Астральные символы раскладываются в суррогатную пару; одинокие суррогаты
    (в т.ч. из JSON-ключей с \\uD800) остаются как есть — как в JS.
    """
    units = []
    for ch in s:
        cp = ord(ch)
        if cp < 0x10000:
            units.append(cp)
        else:
            cp -= 0x10000
            units.append(0xD800 + (cp >> 10))
            units.append(0xDC00 + (cp & 0x3FF))
    return units


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class FLEncoderV4:
    def __init__(self, constants: dict):
        v4 = constants["v004"]
        self.table: list[int] = [int(x) for x in v4["table"]]  # CRC32 (256 значений)
        self.key: list[list[int]] = [[int(x) for x in row] for row in v4["key"]]
        self.Ut: int = v4["Ut"]  # 26
        self.version: str = v4["version"]  # "004"

    # -- вспомогательные -----------------------------------------------------

    def _vt(self, t: int) -> str:
        """Vt: 4 байта big-endian uint32 -> b64."""
        t &= M32
        return _b64(bytes([(t >> 24) & 0xFF, (t >> 16) & 0xFF, (t >> 8) & 0xFF, t & 0xFF]))

    def _crc(self, acc: int, byte: int) -> int:
        """Один шаг CRC32-аккумулятора (n = n>>>8 ^ table[255&(n^byte)])."""
        return (((acc & M32) >> 8) ^ self.table[(acc ^ byte) & 0xFF]) & M32

    # -- кодировщик ----------------------------------------------------------

    def _ht(self, s: str) -> tuple[bytes, int, int]:
        """Точная транскрипция I.Ht(t, -1, 0).

        Возвращает (данные, n_акк, e_счётчик) как в JS: [l.join(""), n, e].
        """
        units = _utf16_units(s)
        n = M32  # -1
        e = 0  # счётчик итераций/индекс в key (в v004 стартует с 0!)
        v = bytearray()
        h = 0
        ln = len(units)
        while h < ln:
            f = units[h]
            if f < 8:
                # управляющий байт: символ пропускается; e-- в теле + e++ внизу = нетто 0
                e -= 1
            elif f < 128:
                r = 8 + (f - 8 + self.key[0][e % self.Ut]) % 120
                n = self._crc(n, r)
                v.append(r)
            elif f < 2048:
                r = 128 + (f - 128 + self.key[1][e % self.Ut]) % 1920
                a = (r >> 6) | 192
                c = (r & 63) | 128
                n = self._crc(self._crc(n, a), c)
                v.append(a)
                v.append(c)
            elif f < 55296:
                r = 2048 + (f - 2048 + self.key[2][e % self.Ut]) % 53248
                a = (r >> 12) | 224
                c = ((r >> 6) & 63) | 128
                u = (63 & r) | 128
                n = self._crc(self._crc(self._crc(n, a), c), u)
                v.append(a)
                v.append(c)
                v.append(u)
            elif f < 56320:
                # high surrogate. JS: s = t.charCodeAt(h+1); вне строки NaN ->
                # оба сравнения (56320 > NaN, NaN >= 57344) false -> ветка пустая.
                nxt = units[h + 1] if h + 1 < ln else None
                if nxt is not None and not (56320 <= nxt < 57344):
                    # JS: e--; continue -> заголовок цикла делает e++, h++ => нетто 0
                    h += 1
                    continue
            elif f < 57344:
                # low surrogate: комбинируем с предыдущим high surrogate.
                # В v004 n обновляется ТОЛЬКО от закодированных байтов a,c,u,d
                # (без «настоящего» code point, как в v005).
                prev = units[h - 1] if h - 1 >= 0 else None
                if prev is not None and not (55296 <= prev < 56320):
                    # JS: e--; continue -> заголовок цикла делает e++, h++ => нетто 0
                    h += 1
                    continue
                if prev is None:
                    # JS: s = charCodeAt(-1) = NaN -> условия false, ветка
                    # выполняется, но арифметика с NaN даёт 0 после битовых &
                    hi = 0
                else:
                    hi = 1023 & (55296 + ((prev - 55296) + self.key[4][(e - 1) % self.Ut]) % 1024)
                o = 56320 + ((f - 56320) + self.key[4][e % self.Ut]) % 1024
                r = 65536 + ((hi << 10) | (1023 & o))
                a = (r >> 18) | 240
                c = ((r >> 12) & 63) | 128
                u = ((r >> 6) & 63) | 128
                d = (63 & r) | 128
                n = self._crc(self._crc(self._crc(self._crc(n, a), c), u), d)
                v.append(a)
                v.append(c)
                v.append(u)
                v.append(d)
            else:
                # f >= 57344 (приватная зона/выше)
                r = 57344 + ((f - 57344) + self.key[3][e % self.Ut]) % 8192
                a = (r >> 12) | 224
                c = ((r >> 6) & 63) | 128
                u = (63 & r) | 128
                n = self._crc(self._crc(self._crc(n, a), c), u)
                v.append(a)
                v.append(c)
                v.append(u)
            e += 1
            h += 1
        return bytes(v), n, e

    # -- публичный API --------------------------------------------------------

    def encode(self, s: str) -> str:
        """Полное тело (v004, __zzatgib-w-hh): b64(ver) + b64(data) + b64(~n)."""
        data, n, _ = self._ht(s)
        return (
            _b64(self.version.encode("ascii"))
            + _b64(data)
            + self._vt((-1 ^ n) & M32)
        )


if __name__ == "__main__":
    constants = _load_constants()
    enc = FLEncoderV4(constants)
    expected = constants["encode_samples_v004"]
    ok = True
    for s in expected:
        got = enc.encode(s)
        exp = expected[s]
        match = got == exp
        if not match:
            ok = False
            print(f"MISMATCH for {s[:40]!r}:\n  py: {got}\n  js: {exp}")
        else:
            print(f"OK ({len(s)} ch): {got[:60]}...")
    print("\nALL MATCH" if ok else "\nFAILED")

```

---

## Приложение C. `gib.py` — подпись fgssc и декодер string table бандла 413

Полный рабочий файл: формула `fgssc` (§2.2), кастомный base64-декодер `_b64_decode_custom`
и RC4 `_rc4` (точные транскрипции `KhYRzU` из бандла), извлечение и ротация string table
(`extract_string_table`, `rotate_table` с checksum 707452), `decode_bundle_strings`.
Запуск: `python3 gib.py bundles/413.2b730bc58fc45025.js` → печатает декодированные
`ce`, `prefix_alphabet`, `base64_alphabet`, затем ждёт `gssc` на stdin и печатает `fgssc`.

```python
"""
Reference-реализация gib-протокола hh.ru (анти-бот заголовки).

Всё проверено на живых парах (gssc, fgssc) из реального браузера 2026-08-02:
    fgssc = prefix(4 случайных символа) + SHA1hex(ce + gssc + prefix)[4:]

Зависимости: только стандартная библиотека (hashlib, random, base64).
"""

import base64
import hashlib
import random
import string
import re

# ---------------------------------------------------------------------------
# 1. Формула fgssc (проверена)
# ---------------------------------------------------------------------------

CE = "shgkla34ty3gg354g34wf"  # из string table бандла 413 (ko("9lAG", 1837))
PREFIX_ALPHABET = string.ascii_lowercase + string.ascii_uppercase + string.digits  # 62 символа


def make_fgssc(gssc: str) -> str:
    """Генерирует значение fgssc для текущего gssc (куки gsscgib-w-hh).

    >>> f = make_fgssc("5YOXawb8Wx1DmV6wE4T0l0FAUyYLNq1sScoLQ0j...")
    >>> len(f) == 40
    """
    prefix = "".join(random.choice(PREFIX_ALPHABET) for _ in range(4))
    digest = hashlib.sha1((CE + gssc + prefix).encode("utf-8")).hexdigest()
    return prefix + digest[4:]


# ---------------------------------------------------------------------------
# 2. Декодер string table бандла i.hh.ru/shared/413.2b730bc58fc45025.js
#    (для дальнейшего реверса: ce, алфавиты, любые строки бандла)
#
#    Схема: module 825 содержит
#      function t(e,i){var r=n(); return t=function(n,i){o=r[n-330]; return RC4(b64(o), i)}, t(e,i)}
#      function n(){var t=[...586 строк...]; return (n=function(){return t})()}
#      (function(n){ rotate until checksum 707452 })(n)
#    Таблица при загрузке ротируется; t() кэширует результат по ключу n+r[0].
# ---------------------------------------------------------------------------


def _b64_decode_custom(t: str) -> str:
    """Точная транскрипция base64-декодера бандла (KhYRzU, часть 1):
    символ -> индекс алфавита (тело цикла), затем в inc-части:
    n = o%4 ? 64*n+e : e; o++; если (o-1)%4 != 0: i += chr(255 & (n >> ((-2*o)&6))).
    Финал: percent-encode каждого байта + decodeURIComponent (= UTF-8 decode)."""
    alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
    i = ""
    n = 0
    o = 0
    a = 0
    while True:
        e = t[a] if a < len(t) else ""
        a += 1
        if e == "":
            break
        e = alpha.find(e)
        if e == -1:  # ~e == 0 -> inc-часть пропускается
            continue
        if o % 4:
            n = 64 * n + e
        else:
            n = e
        old = o
        o += 1
        if old % 4:
            shift = (-2 * o) & 6
            i += chr(0xFF & (n >> shift))
    return i.encode("latin-1").decode("utf-8", errors="replace")


def _rc4(data: str, key: str) -> str:
    """RC4-поток из KhYRzU: KSA по ключу, затем PRGA: chr(ord(c) ^ s[(s[i]+s[o])%256])."""
    k = key.encode("utf-8")
    s = list(range(256))
    o = 0
    for i in range(256):
        o = (o + s[i] + k[i % len(k)]) % 256
        s[i], s[o] = s[o], s[i]
    out = []
    i = 0
    o = 0
    for c in data:
        i = (i + 1) % 256
        o = (o + s[i]) % 256
        s[i], s[o] = s[o], s[i]
        out.append(chr(ord(c) ^ s[(s[i] + s[o]) % 256]))
    return "".join(out)


def extract_string_table(bundle_text: str) -> list[str]:
    """Вырезает массив строк из 'function n(){var t=[...];return(...)}'."""
    start = bundle_text.index("function n(){var t=[") + len("function n(){var t=[")
    end = bundle_text.index("];return", start)
    src = bundle_text[start:end]
    return [m.replace('\\"', '"').replace("\\\\", "\\") for m in re.findall(r'"((?:[^"\\]|\\.)*)"', src)]


def rotate_table(arr: list[str]) -> None:
    """Применяет checksum-ротацию (707452) к таблице in-place."""
    cache = {}

    def tdec(n: int, key: str) -> str:
        o = arr[n - 330]
        if o is None:
            return ""
        ck = (n, arr[0])
        if ck in cache:
            return cache[ck]
        dec = _rc4(_b64_decode_custom(o), key)
        cache[ck] = dec
        return dec

    # e(name, offset) = t(offset - -530, name)
    def expr() -> float:
        v = 0
        v += int(tdec(150 + 530, "dcEE")) / 1
        v += -int(tdec(-54 + 530, "Gs7^")) / 2
        v += int(tdec(-138 + 530, "$Lqo")) / 3
        v += -int(tdec(210 + 530, "IgsC")) / 4 * (-int(tdec(205 + 530, "$*!b")) / 5)
        v += -int(tdec(285 + 530, "@fdD")) / 6 * (-int(tdec(98 + 530, "*^*G")) / 7)
        v += -int(tdec(263 + 530, "^1Cz")) / 8
        v += -int(tdec(134 + 530, "Hxl0")) / 9
        return v

    target = 707452
    rotations = 0
    while rotations < 20000:
        if abs(expr() - target) < 1e-6:
            return
        arr.append(arr.pop(0))
        rotations += 1
        if rotations % 700 == 0:
            cache.clear()
    raise RuntimeError("rotation did not converge")


def decode_bundle_strings(bundle_text: str, samples: dict[str, tuple[int, str]]) -> dict[str, str]:
    """Декодирует строки из бандла по образцам {имя: (n, key)} через t(n, key)."""
    arr = extract_string_table(bundle_text)
    rotate_table(arr)
    cache = {}

    def tdec(n: int, key: str) -> str:
        ck = (n, arr[0])
        if ck in cache:
            return cache[ck]
        dec = _rc4(_b64_decode_custom(arr[n - 330]), key)
        cache[ck] = dec
        return dec

    return {name: tdec(n, key) for name, (n, key) in samples.items()}


# Известные адреса строк в бандле 413 (через ko(name, offset) = t(offset - 925, name)):
#   ce        = t(912, "9lAG")   # ko("9lAG", 1837)
#   alphabet  = t(783, "@fdD")   # ko("@fdD", 1708) — префиксы fgssc
#   z         = t(335, "!jr8")   # ko("!jr8", 1260) — base64-алфавит
if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "413.js"
    with open(path) as f:
        bundle = f.read()
    res = decode_bundle_strings(
        bundle,
        {
            "ce": (912, "9lAG"),
            "prefix_alphabet": (783, "@fdD"),
            "base64_alphabet": (335, "!jr8"),
        },
    )
    print(res)
    gssc = input("gssc (кука gsscgib-w-hh): ").strip()
    if gssc:
        print("fgssc =", make_fgssc(gssc))

```

---

*Конец досье. Составлено 2026-08-04 на основе данных исследования 2026-08-02…2026-08-04.*
