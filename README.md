# CF Domain Scanner

Инструмент для поиска Cloudflare-доменов, пригодных для **CDN VLESS fronting** в условиях российского ТСПУ.

Скрипт находит домены, через которые трафик проходит без блокировки — их можно использовать как `sni` и `host` в конфигурации VLESS/Xray с транспортом `ws` или `grpc` поверх Cloudflare.

---

## Два варианта скрипта

| | `cf_scanner.py` | `cf_scanner_lite.py` |
|---|---|---|
| **Зависимости** | `aiohttp aiodns httpx` | `aiohttp aiodns` |
| **GET / проверка** | ✓ | ✓ |
| **X-Pad ТСПУ-тест** | ✓ агрессивный (~72 КБ) | ✗ |
| **TLS / MITM-тест** | ✓ | ✓ |
| **Точность** | Высокая | Средняя |
| **Скорость** | Медленнее | Быстрее |

**`cf_scanner.py`** — основной вариант. Проводит активный ТСПУ-тест через нарастающую серию HEAD-запросов с мусорными заголовками, перекрывающую весь диапазон обрыва ТСПУ (1–69 КБ). Подходит для точного поиска доменов, устойчивых к DPI.

**`cf_scanner_lite.py`** — облегчённый вариант. Без теста X-Pad, только GET и TLS. Удобен если `httpx` недоступен, или нужна быстрая первичная фильтрация. Может давать ложноположительные результаты — некоторые найденные домены могут быть заблокированы ТСПУ.

> Запускать **с домашней машины в РФ** (под ТСПУ) — только тогда проверки имеют смысл. С VPS за рубежом ТСПУ не виден и результаты неточны.

---

## Как это работает

### Этапы проверки (`cf_scanner.py`)

**1. Резолвинг**
Домен резолвится через Quad9 (`9.9.9.9`) напрямую — в обход провайдерской подмены DNS. IP сверяется с официальными диапазонами Cloudflare.

**2. GET /**
Запрос к корню домена через HTTPS:
- Наличие заголовка `CF-Ray` или `Server: cloudflare`
- HTTP статус < 500
- Отсутствие CF JS Challenge (сайт не требует капчи)
- Отсутствие редиректа на блок-страницу провайдера (`warning.rt.ru`, `rkn.gov.ru` и др.)
- Ответ за 3 секунды

**3. X-Pad keepalive** *(только `cf_scanner.py`)*
Серия HEAD-запросов через одно keepalive-соединение с нарастающим мусором в заголовке `X-Pad` (суммарно ~72 КБ). Это заведомо больше диапазона ТСПУ (1–69 КБ). Если соединение обрывается в этом диапазоне — домен заблокирован ТСПУ. Метод работает независимо от размера сайта.

**4. TLS**
Новое TCP-соединение с реальной проверкой сертификата. Детектирует:
- Подмену сертификата провайдером (MITM)
- SNI-блокировку
- Блокировку TLS handshake

Домен считается **живым** только если прошёл все этапы.

---

## Требования

- Python 3.10+
- Запуск с домашней машины в РФ (под ТСПУ)

---

## Установка

**Полная версия (`cf_scanner.py`):**
```bash
pip install aiohttp aiodns httpx
```

**Lite версия (`cf_scanner_lite.py`):**
```bash
pip install aiohttp aiodns
```

Если `pip` ругается на систему:
```bash
pip install aiohttp aiodns httpx --break-system-packages
```

На Windows убедитесь что Python добавлен в PATH:
```
python --version
```

---

## Использование

### Проверить один домен

```bash
python cf_scanner.py check --domain example.com
```

```bash
python cf_scanner_lite.py check --domain example.com
```

Пример вывода (`cf_scanner.py`):
```
────────────────────────────────────────────────────────────
Домен:        example.com
IP:           104.21.44.100
CF IP:        ✓ Да
CF определён: ray
CF-Ray:       abc123-SVO
Server:       cloudflare
HTTP статус:  200
Байт получено:12800 (12 КБ)
Время:        0.41s

── Результаты проверок ──
  GET /       ✓ CF определён (ray), HTTP 200
  X-Pad       ✓ ТСПУ не обнаружен
  TLS         ✓ Сертификат валиден, нет MITM/SNI-блок

── Итог ──
  ✓ ЖИВОЙ — домен подходит для CDN VLESS fronting
────────────────────────────────────────────────────────────
```

Пропустить TLS-проверку (быстрее, если MITM маловероятен):
```bash
python cf_scanner.py check --domain example.com --skip-tls
```

Использовать другой DNS (например, Cloudflare):
```bash
python cf_scanner.py check --domain example.com --dns 1.1.1.1
```

---

### Сканировать топ-лист

Скачивает топ-1М доменов и проверяет выборку. Первый запуск скачает список (~5–10 МБ). Последующие — используют кеш (`cache_tranco.csv` и т.д.) 24 часа.

**Случайная выборка 10 000 доменов из Tranco (рекомендуется):**
```bash
python cf_scanner.py tranco --limit 10000 --random
```

**Первые 5 000 (не случайные):**
```bash
python cf_scanner.py tranco --limit 5000
```

**Другой источник:**
```bash
python cf_scanner.py tranco --source umbrella --limit 10000 --random
python cf_scanner.py tranco --source majestic --limit 20000 --random
python cf_scanner.py tranco --source crux --limit 10000 --random
```

**С кастомным именем выходного файла:**
```bash
python cf_scanner.py tranco --limit 10000 --random --output scan_results
```

**Без TLS-проверки (быстрее):**
```bash
python cf_scanner.py tranco --limit 10000 --random --skip-tls
```

**Снизить параллельность (при слабом интернете):**
```bash
python cf_scanner.py tranco --limit 10000 --random --concurrency 10
```

---

### Проверить свой список доменов

```bash
python cf_scanner.py file --file mylist.txt
```

Случайная выборка из файла:
```bash
python cf_scanner.py file --file mylist.txt --limit 500 --random
```

Формат файла — один домен на строку, строки с `#` игнорируются:
```
# мой список CF доменов
example.com
static.canva.com
assets.example.org
```

---

## Все параметры

### `check`

| Параметр | По умолчанию | Описание |
|---|---|---|
| `--domain` | обязателен | Домен для проверки |
| `--dns` | `9.9.9.9` | DNS сервер для резолвинга |
| `--skip-tls` | выкл | Пропустить TLS-проверку |

### `tranco`

| Параметр | По умолчанию | Описание |
|---|---|---|
| `--source` | `tranco` | Источник: `tranco`, `umbrella`, `majestic`, `crux` |
| `--limit` | `10000` | Сколько доменов проверить |
| `--random` | выкл | Случайная выборка вместо топа |
| `--concurrency` | `30` | Параллельных проверок одновременно |
| `--output` | `results` | Базовое имя выходных файлов (без расширения) |
| `--dns` | `9.9.9.9` | DNS сервер |
| `--skip-tls` | выкл | Пропустить TLS-проверку |

### `file`

| Параметр | По умолчанию | Описание |
|---|---|---|
| `--file` | обязателен | Путь к файлу со списком доменов |
| `--limit` | нет | Ограничить количество доменов |
| `--random` | выкл | Случайная выборка |
| `--concurrency` | `30` | Параллельных проверок |
| `--output` | `results` | Базовое имя выходных файлов |
| `--dns` | `9.9.9.9` | DNS сервер |
| `--skip-tls` | выкл | Пропустить TLS-проверку |

---

## Выходные файлы

После сканирования создаются два файла:

**`results.txt`** — только живые домены, по одному на строку. Готов к прямому использованию:
```
example.com
static.canva.com
assets.cloudflare-site.com
```

**`results.log`** — детальная информация по каждому живому домену:
```
[2026-03-06 14:23:01] example.com          ip=104.21.44.100    status=200 bytes=12KB elapsed=0.41s cf=ray xpad=ok tls=ok
[2026-03-06 14:23:04] static.canva.com     ip=104.18.32.7      status=403 bytes=3KB  elapsed=0.28s cf=server xpad=ok tls=ok
```

Мёртвые домены нигде не сохраняются. Файлы перезаписываются атомарно через `.tmp` — при Ctrl+C данные не теряются.

---

## Консольный вывод

Во время сканирования живые домены выводятся сразу при нахождении:

```
✓ example.com                                 (200, 12KB, 0.4s, ray)
✓ static.canva.com                            (403, 3KB, 0.3s, server)
[14:23:05] Прогресс: 100/5000, живых CF: 7
✓ assets.some-site.com                        (200, 89KB, 1.1s, ray)
```

Мёртвые домены в консоль не выводятся.

---

## Коды ошибок в логах

Скрипт помечает причину смерти домена коротким кодом. Расшифровка:

| Код | Причина |
|---|---|
| `dns_fail` | Домен не резолвится |
| `not_cf_ip` | IP не принадлежит Cloudflare |
| `not_cf` | Нет CF-Ray и Server: cloudflare в ответе |
| `http_5xx` | Сервер вернул 5xx ошибку |
| `http_451` | Сайт заблокирован по закону (451) |
| `cf_challenge` | CF требует решения JS Challenge / капчи |
| `isp_block_redirect` | Редирект на блок-страницу провайдера |
| `isp_block_body` | Тело ответа содержит маркеры блокировки |
| `empty_response` | Сервер ответил 0 байт |
| `tspu_cut:NKB` | ТСПУ оборвал соединение на N КБ (таймаут) |
| `tspu_rst:NKB` | ТСПУ оборвал соединение на N КБ (RST) |
| `tspu_slow:NKB` | ТСПУ замедляет соединение на N КБ |
| `tls_mitm` | Сертификат подменён провайдером (MITM) |
| `tls_mitm_selfsigned` | Провайдер подставляет самоподписанный сертификат |
| `tls_mitm_unknown_ca` | Неизвестный CA — вероятный MITM |
| `tls_mitm_hostname` | Несоответствие имени хоста в сертификате |
| `tls_cert_expired` | Истёкший сертификат (домен не обслуживается) |
| `sni_block` | SNI-блокировка провайдером |
| `tls_handshake_block` | TLS handshake заблокирован |
| `tls_dpi_eof` | DPI оборвал TLS-соединение |
| `tls_timeout` | TLS соединение не установлено за таймаут |
| `tls_rst` | TCP RST во время TLS handshake |
| `timeout:0KB` | Соединение зависло (не ТСПУ-диапазон) |
| `refused` | Соединение отклонено |

---

## Использование результатов в Xray / V2Ray

Техника называется **clean IP fronting**: вы физически коннектитесь к IP чистого CF-домена (из результатов сканера), но Cloudflare внутри своей сети маршрутизирует запрос на ваш Workers/Pages домен по заголовку `Host`.

ТСПУ видит соединение к чистому домену → пропускает. Cloudflare доставляет трафик на ваш воркер.

```json
{
  "outbounds": [{
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 443,
        "users": [{ "id": "ВАШ_UUID", "encryption": "none" }]
      }]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {
        "serverName": "ВАШ_WORKER_ИЛИ_PAGES_ДОМЕН"
      },
      "wsSettings": {
        "host": "ВАШ_WORKER_ИЛИ_PAGES_ДОМЕН",
        "path": "/ВАШ_ПУТЬ"
      }
    }
  }]
}
```

| Поле | Значение | Откуда |
|---|---|---|
| `address` | `example.com` | Домен из `results.txt` сканера (TCP коннект) |
| `serverName` | `your.workers.dev` | Ваш CF Worker или Pages домен (SNI) |
| `host` в wsSettings | `your.workers.dev` | Ваш CF Worker или Pages домен (HTTP Host) |
| `path` | `/ВАШ_ПУТЬ` | Путь, настроенный в вашем воркере |

---

## Советы

**Оптимальный запуск для поиска доменов:**
```bash
python cf_scanner.py tranco --limit 10000 --random --concurrency 30
```
Случайная выборка лучше топа — топовые домены (google.com, youtube.com) часто заблокированы или под капчей. Середина списка содержит много полезных CF-доменов.

**Если нужно больше результатов — комбинируйте источники:**
```bash
python cf_scanner.py tranco --source umbrella --limit 20000 --random
python cf_scanner.py tranco --source majestic --limit 20000 --random
```
Разные источники дают разные домены.

**Параллельность:**
Дефолт `--concurrency 30` — безопасное значение. При слабом интернете снизьте до 10–15. При хорошем канале можно поднять до 50, но X-Pad тест создаёт нагрузку (~72 КБ на каждый параллельный домен).

**`--skip-tls` когда использовать:**
Если нужно быстро прогнать большой список и MITM у провайдера маловероятен. Ускоряет каждую проверку примерно на 0.5–1 с.

**Lite для первичной фильтрации:**
Если список большой, можно сначала прогнать `cf_scanner_lite.py --skip-tls` для быстрой фильтрации CF-доменов, а потом результат `results.txt` прогнать через основной `cf_scanner.py file`:
```bash
python cf_scanner_lite.py tranco --limit 50000 --random --skip-tls --output pre
python cf_scanner.py file --file pre.txt --concurrency 20
```

**Обновление кеша:**
Файлы `cache_tranco.csv`, `cache_umbrella.csv` и т.д. создаются рядом со скриптом. Удалите для принудительного обновления, или подождите 24 часа.

---

## Зависимости

| Пакет | Зачем | Версия |
|---|---|---|
| `aiohttp` | Асинхронные HTTP-запросы (GET /) | любая |
| `aiodns` | Резолвинг через конкретный DNS-сервер (Quad9) | любая |
| `httpx` | X-Pad keepalive тест (только `cf_scanner.py`) | любая |

---

## Совместимость

- Windows, Linux, macOS
- Python 3.10+
- На Windows используется `WindowsSelectorEventLoopPolicy` автоматически