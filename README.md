# CF Domain Scanner

Инструмент для поиска доменов, проксированных через Cloudflare, доступных из РФ.
Используется для настройки CDN fronting в VLESS/Xray конфигурациях.

## Зачем это нужно

Роскомнадзор блокирует домены, но не может заблокировать IP Cloudflare целиком — за ними стоят миллионы легальных сайтов. CDN fronting позволяет подключаться к серверу через чужой CF-домен: трафик выглядит как обращение к разрешённому сайту, а CF перенаправляет его дальше.

Проблема в том, что не все CF-домены одинаково доступны. Этот сканер автоматически находит те, которые работают.

## Установка

```
pip install aiohttp
```

Python 3.10+, работает на Windows и Linux.

---

## Режимы работы

### `scan` — полный автопилот ⭐

Самый удобный режим, делает всё автоматически:

1. Скачивает топ-лист (Tranco или Umbrella)
2. Проверяет все домены из выборки на CF и доступность (**Фаза 1**)
3. Для каждого найденного CF-домена собирает поддомены через crt.sh и соседей по IP через reverse IP lookup (**Фаза 2**)
4. Проверяет все новые домены из Фазы 2
5. Сохраняет объединённый результат

```bash
# Базовый запуск: топ-5000 доменов
python cf_scanner.py scan --limit 5000

# Случайные 5000 из миллиона — лучше для поиска незаблокированных
python cf_scanner.py scan --limit 5000 --random

# Chrome UX Report — реальная статистика Chrome
python cf_scanner.py scan --source crux --limit 5000 --random

# Majestic Million
python cf_scanner.py scan --source majestic --limit 5000 --random

# Только топ-лист, без поиска поддоменов (быстрее)
python cf_scanner.py scan --limit 10000 --no-subdomains
```

Параметры:
- `--source` — `tranco` (default), `umbrella`, `crux`, `majestic`
- `--limit` — сколько доменов взять из топ-листа (default: 5000)
- `--random` — случайная выборка вместо первых N
- `--concurrency` — параллельность (default: 100)
- `--no-subdomains` — пропустить Фазу 2
- `--output` — файл результатов (default: `results_scan.json`)

Пример вывода:
```
[10:00:01] АВТОСКАНИРОВАНИЕ
[10:00:01]   Источник:      tranco
[10:00:01]   Доменов:       5000 (случайные)
...
[10:00:01] [Фаза 1] Скачиваем топ-лист и ищем CF-домены...
[10:00:12] Случайная выборка: 5000 из 1000000 доменов
  [1] [CF] OK cloudflare.com                               104.21.55.23       HTTP=200
  [1] [CF] OK discord.com                                  162.159.136.232    HTTP=200
...
[10:02:30] [Фаза 1] Найдено 312 рабочих CF-доменов

[10:02:30] [Фаза 2] Собираем поддомены/соседей для 312 CF-доменов...
  → cloudflare.com (104.21.55.23)
  crt.sh: нашёл 47 поддоменов
  HackerTarget нашёл 1842 доменов на 104.21.55.23
...
[10:05:10] [Фаза 2] Новых доменов для проверки: 28450
  [2] [CF] OK blog.cloudflare.com                          104.21.55.23       HTTP=200
...
════════════════════════════════════════════
ИТОГО:
  Фаза 1 — топ-лист:  проверено 5000, CF=312
  Фаза 2 — поддомены: проверено 28450, CF=1205
  Всего рабочих CF:   1517
  Файл:               results_scan.json
════════════════════════════════════════════
```

---

### `check` — проверить один домен

```bash
python cf_scanner.py check --domain example.com
```

```
──────────────────────────────────────────────────
Домен:        example.com
IP:           104.21.55.23
CF IP:        Да
CF заголовки: Да
Server:       cloudflare
CF-Ray:       8a3f1c2d4e5b6789-FRA
HTTP статус:  200
Доступен:     Да
Итог:         CLOUDFLARE (подходит)
──────────────────────────────────────────────────
```

---

### `tranco` — сканировать только топ-лист

Без автоматического поиска поддоменов. Удобно если нужна быстрая первичная разведка.

```bash
# Топ-5000 из Tranco
python cf_scanner.py tranco --limit 5000

# Случайные 5000 из миллиона
python cf_scanner.py tranco --limit 5000 --random

# Chrome UX Report — данные реального использования в браузере Chrome
python cf_scanner.py tranco --source crux --limit 5000 --random

# Umbrella с высокой параллельностью
python cf_scanner.py tranco --source umbrella --limit 10000 --concurrency 150 --random

# Majestic Million — на основе обратных ссылок
python cf_scanner.py tranco --source majestic --limit 5000 --random
```

Параметры:
- `--source` — источник списка (default: `tranco`):
  - `tranco` — агрегированный топ-лист, обновляется ежедневно
  - `umbrella` — Cisco Umbrella, на основе DNS-запросов
  - `crux` — Chrome UX Report, реальная статистика пользователей Chrome от Google
  - `majestic` — Majestic Million, на основе обратных ссылок
- `--limit` — сколько доменов (default: 10000)
- `--random` — случайная выборка вместо топ-N
- `--concurrency` — параллельных запросов (default: 100)
- `--output` — файл (default: `results_tranco.json`)

Каждый источник имеет несколько зеркал — если основной URL недоступен (заблокирован или timeout), автоматически пробуется следующий зеркальный URL с GitHub.

**Топ vs случайные:** первые N доменов — крупнейшие сайты (Google, Meta, Amazon), они чаще заблокированы или имеют нестандартную CF конфигурацию. Случайная выборка из всего миллиона даёт больше шансов найти обычные сайты малого бизнеса на CF, которые РКН не трогал.

---

### `subdomain` — поддомены конкретного домена

Если уже есть рабочий CF-домен, этот режим найдёт все его поддомены и соседей по IP.

Источники:
- **crt.sh** — Certificate Transparency logs (все домены, получавшие TLS сертификат)
- **HackerTarget** — reverse IP lookup (все домены на том же CF IP), бесплатно, ~100 req/день
- **RapidDNS** — автоматический fallback если HackerTarget исчерпал лимит

```bash
python cf_scanner.py subdomain --domain example.com
python cf_scanner.py subdomain --domain example.com --concurrency 100
```

Параметры:
- `--domain` — домен (обязательно)
- `--concurrency` — параллельность (default: 50)
- `--output` — файл (default: `results_subdomains.json`)

---

### `cfip` — сканировать IP-подсети Cloudflare

Перебирает IP из официальных CF-диапазонов, делает reverse DNS (PTR-запись) и проверяет найденные домены. Медленно, но находит домены которых нет в топ-листах.

```bash
# Конкретный диапазон, первые 500 IP
python cf_scanner.py cfip --range 104.16.0.0/20 --limit 500

# Случайные 1000 IP из большого диапазона
python cf_scanner.py cfip --range 104.16.0.0/13 --limit 1000 --random

# Интерактивный выбор диапазона
python cf_scanner.py cfip
```

Без `--range` покажет список всех CF-диапазонов с размерами для выбора.

Параметры:
- `--range` — CIDR (опционально)
- `--limit` — макс. IP для проверки (default: 1000)
- `--random` — случайные IP из диапазона вместо первых N
- `--concurrency` — параллельность (default: 50)
- `--output` — файл (default: `results_cfip.json`)

> PTR-записей у CF IP мало — у большинства IP их нет вообще. Этот режим полезен как дополнение, не как основной.

---

### `file` — проверить свой список

```bash
# Все домены из файла
python cf_scanner.py file --file mylist.txt

# Первые 500
python cf_scanner.py file --file mylist.txt --limit 500

# Случайные 500 из файла
python cf_scanner.py file --file mylist.txt --limit 500 --random
```

Формат файла — один домен на строку, строки с `#` игнорируются:
```
# мои кандидаты
cloudflare.com
workers.dev
discord.com
```

Параметры:
- `--file` — путь к файлу (обязательно)
- `--limit` — лимит доменов (опционально)
- `--random` — случайная выборка
- `--concurrency` — параллельность (default: 100)
- `--output` — файл результатов (default: `results_file.json`)

---

## Формат результатов

Все режимы сохраняют JSON:

```json
{
  "total_checked": 5000,
  "cf_accessible": 312,
  "domains": [
    {
      "domain": "example.com",
      "ip": "104.21.55.23",
      "cf_ip": true,
      "cf_headers": true,
      "http_ok": true,
      "status": 200,
      "server": "cloudflare",
      "cf_ray": "8a3f...-FRA",
      "is_cf": true
    }
  ]
}
```

В `domains` попадают только домены где `is_cf=true` и `http_ok=true`.

Извлечь только список доменов:

```bash
# Linux / macOS
python3 -c "import json; [print(d['domain']) for d in json.load(open('results_scan.json'))['domains']]"

# Windows PowerShell
(Get-Content results_scan.json | ConvertFrom-Json).domains | ForEach-Object { $_.domain }
```

---

## Как определяется Cloudflare

Домен считается CF если выполняется хотя бы одно:
1. **CF IP** — IP входит в официальные диапазоны Cloudflare (`cloudflare.com/ips-v4`)
2. **CF заголовки** — ответ содержит заголовок `cf-ray` или `server: cloudflare`

Доступность: HTTP статус < 500 (200, 301, 302, 403, 404 — всё считается доступным, главное что сервер отвечает).

---

## Справочник: источники данных

### Топ-листы доменов

| Источник | Флаг | URL | Размер |
|---|---|---|---|
| Tranco | `--source tranco` | https://tranco-list.eu/top-1m.csv.zip | ~10 MB |
| Cisco Umbrella | `--source umbrella` | http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip | ~10 MB |

### Источники поддоменов (режимы `subdomain` и `scan`)

| Источник | Что даёт | Лимит |
|---|---|---|
| crt.sh | Все поддомены из

---

## Рекомендуемый порядок действий

1. **Запустить автоскан** — `scan --limit 5000 --random`, подождать 10-30 минут
2. **Проверить результат** — открыть `results_scan.json`, посмотреть найденные домены
3. **Проверить доступность из РФ** — сканер проверяет с вашей машины. Если запускаете не из РФ — дополнительно проверить через [check-host.net](https://check-host.net) или похожие сервисы
4. **Использовать в конфиге** — найденный домен прописать как `host` / `sni` в настройках VLESS/Xray

---

## Справочник источников

### Топ-листы доменов

| Источник | `--source` | Основа данных | Зеркало (fallback) |
|---|---|---|---|
| Tranco | `tranco` | Агрегат нескольких списков | github.com/adysec/top_1m_domains |
| Cisco Umbrella | `umbrella` | DNS-запросы через резолверы Cisco | github.com/adysec/top_1m_domains |
| Chrome UX Report | `crux` | Реальные посещения в браузере Chrome | github.com/zakird/crux-top-lists |
| Majestic Million | `majestic` | Количество обратных ссылок | github.com/adysec/top_1m_domains |

Если основной URL недоступен или вернул таймаут — скрипт автоматически пробует GitHub-зеркало.

### Источники поддоменов (режимы `subdomain` и `scan`)

| Источник | Что даёт | Лимит |
|---|---|---|
| crt.sh | Все поддомены из Certificate Transparency logs | Без лимита |
| HackerTarget | Все домены на том же IP (reverse IP lookup) | ~100 запросов/день бесплатно |
| RapidDNS | То же, автоматический fallback если HackerTarget исчерпан | Без лимита, парсинг HTML |

### Cloudflare IP диапазоны (актуальны на момент написания)

```
103.21.244.0/22      103.22.200.0/22      103.31.4.0/22
104.16.0.0/13        104.24.0.0/14        108.162.192.0/18
131.0.72.0/22        141.101.64.0/18      162.158.0.0/15
172.64.0.0/13        173.245.48.0/20      188.114.96.0/20
190.93.240.0/20      197.234.240.0/22     198.41.128.0/17
```

Актуальный список всегда: https://www.cloudflare.com/ips-v4

---

## Параметр concurrency

| Ситуация | Рекомендация |
|---|---|
| Мобильный / слабый интернет | 30–50 |
| Обычный домашний | 100–150 |
| Хороший канал | 200–300 |
| VPS | 300–500 |

При слишком высоком значении начнут падать таймауты — результаты будут неточными.