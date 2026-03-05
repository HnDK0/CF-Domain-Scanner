#!/usr/bin/env python3
"""
CF Domain Scanner — поиск доменов через Cloudflare для CDN fronting (VLESS)

Установка зависимостей:
  pip install aiohttp

Примеры запуска:
  python cf_scanner.py check --domain example.com
  python cf_scanner.py tranco --limit 5000
  python cf_scanner.py tranco --limit 5000 --random
  python cf_scanner.py subdomain --domain example.com
  python cf_scanner.py cfip --range 104.16.0.0/20 --limit 1000
  python cf_scanner.py file --file mylist.txt
  python cf_scanner.py scan --limit 3000 --random
"""

import asyncio
import aiohttp
import argparse
import json
import random
import re
import socket
import ipaddress
import sys
import os
import io
import zipfile
import urllib.request
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# Cloudflare IP диапазоны (https://www.cloudflare.com/ips/)
# ─────────────────────────────────────────────────────────────────────────────

CF_IP_RANGES_V4 = [
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
]


# ─────────────────────────────────────────────────────────────────────────────
# Утилиты
# ─────────────────────────────────────────────────────────────────────────────

def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def is_cf_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in CF_IP_RANGES_V4:
            if addr in ipaddress.ip_network(cidr):
                return True
    except ValueError:
        pass
    return False


async def resolve(domain: str):
    loop = asyncio.get_event_loop()
    try:
        info = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
        return info[0][4][0] if info else None
    except Exception:
        return None


async def check_domain(session: aiohttp.ClientSession, domain: str, timeout: int = 8) -> dict:
    result = {
        "domain": domain,
        "ip": None,
        "cf_ip": False,
        "cf_headers": False,
        "http_ok": False,
        "status": None,
        "server": None,
        "cf_ray": None,
        "is_cf": False,
    }

    ip = await resolve(domain)
    if not ip:
        return result

    result["ip"] = ip
    result["cf_ip"] = is_cf_ip(ip)

    try:
        async with session.get(
            f"https://{domain}",
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        ) as resp:
            result["status"] = resp.status
            result["http_ok"] = resp.status < 500
            h = dict(resp.headers)
            server = h.get("server", h.get("Server", ""))
            result["server"] = server
            result["cf_ray"] = h.get("cf-ray") or h.get("CF-Ray")
            result["cf_headers"] = "cloudflare" in server.lower() or bool(result["cf_ray"])
    except Exception:
        pass

    result["is_cf"] = result["cf_ip"] or result["cf_headers"]
    return result


def print_result(r: dict, prefix: str = ""):
    status = r.get("status") or "---"
    ip = r.get("ip") or "no-resolve"
    cf = "[CF]" if r.get("is_cf") else "    "
    ok = "OK" if r.get("http_ok") else "  "
    ray = f" ray={r['cf_ray']}" if r.get("cf_ray") else ""
    print(f"  {prefix}{cf} {ok} {r['domain']:<45} {ip:<18} HTTP={status}{ray}", flush=True)


def save_results(results: list, output: str):
    cf_domains = [r for r in results if r.get("is_cf") and r.get("http_ok")]
    with open(output, "w", encoding="utf-8") as f:
        json.dump({
            "total_checked": len(results),
            "cf_accessible": len(cf_domains),
            "domains": cf_domains,
        }, f, indent=2, ensure_ascii=False)
    log(f"Сохранено в {output}: {len(cf_domains)} рабочих CF-доменов из {len(results)} проверенных")


# ─────────────────────────────────────────────────────────────────────────────
# Скачивание топ-листов
# ─────────────────────────────────────────────────────────────────────────────

# Для каждого источника — список URL в порядке приоритета (fallback цепочка).
# Если первый не отвечает — автоматически пробуется следующий.
SOURCES = {
    "tranco": [
        "https://tranco-list.eu/top-1m.csv.zip",
        # GitHub зеркало, обновляется ежедневно
        "https://github.com/adysec/top_1m_domains/raw/main/tranco.zip",
    ],
    "umbrella": [
        "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
        "https://github.com/adysec/top_1m_domains/raw/main/cisco-umbrella.zip",
    ],
    "majestic": [
        # Majestic Million — колонка 2 (GlobalRank, TldRank, Domain, ...)
        "https://downloads.majestic.com/majestic_million.csv",
        "https://github.com/adysec/top_1m_domains/raw/main/majestic.zip",
    ],
    "crux": [
        # Chrome UX Report — самый актуальный, данные Google Chrome
        # Формат: origin,rank  где origin = "https://example.com"
        "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz",
    ],
}


def _fetch_url(url: str, timeout: int = 45) -> bytes:
    log(f"  Загружаем: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _parse_zip(data: bytes, domain_col: int = 1) -> list:
    """Парсит zip с CSV внутри."""
    z = zipfile.ZipFile(io.BytesIO(data))
    lines = z.read(z.namelist()[0]).decode(errors="ignore").splitlines()
    result = []
    for line in lines:
        parts = line.split(",")
        if len(parts) > domain_col:
            d = parts[domain_col].strip().lower().strip('"')
            if d and "." in d and not d.startswith("#"):
                result.append(d)
    return result


def _parse_csv(data: bytes, domain_col: int = 2, skip_header: bool = True) -> list:
    """Парсит plain CSV без архива."""
    lines = data.decode(errors="ignore").splitlines()
    if skip_header and lines:
        lines = lines[1:]
    result = []
    for line in lines:
        parts = line.split(",")
        if len(parts) > domain_col:
            d = parts[domain_col].strip().lower().strip('"')
            if d and "." in d:
                result.append(d)
    return result


def _parse_gz_csv(data: bytes) -> list:
    """Парсит gzip CSV для CrUX. origin = 'https://example.com' → 'example.com'."""
    import gzip
    lines = gzip.decompress(data).decode(errors="ignore").splitlines()
    result = []
    for line in lines[1:]:  # пропускаем заголовок
        parts = line.split(",")
        if parts:
            raw = parts[0].strip().lower().strip('"')
            raw = raw.replace("https://", "").replace("http://", "").rstrip("/")
            if raw and "." in raw:
                result.append(raw)
    return result


def download_list(source: str, limit: int, use_random: bool) -> list:
    urls = SOURCES.get(source)
    if not urls:
        log(f"Неизвестный источник: {source}. Доступны: {', '.join(SOURCES)}")
        return []

    log(f"Скачиваем {source} top-1M...")
    all_domains = []

    for url in urls:
        try:
            data = _fetch_url(url)

            if source == "crux":
                all_domains = _parse_gz_csv(data)
            elif source == "majestic" and not url.endswith(".zip"):
                all_domains = _parse_csv(data, domain_col=2, skip_header=True)
            else:
                all_domains = _parse_zip(data, domain_col=1)

            if all_domains:
                log(f"  Успешно: {len(all_domains)} доменов")
                break
            else:
                log("  Файл скачан, но домены не распарсились — пробуем следующий...")
        except Exception as e:
            log(f"  Ошибка ({e}) — пробуем следующий источник...")
            continue

    if not all_domains:
        log(f"Все источники для '{source}' недоступны")
        return []

    if use_random:
        selected = random.sample(all_domains, min(limit, len(all_domains)))
        log(f"Случайная выборка: {len(selected)} из {len(all_domains)} доменов")
    else:
        selected = all_domains[:limit]
        log(f"Топ-{len(selected)} из {len(all_domains)} доменов")

    return selected


# ─────────────────────────────────────────────────────────────────────────────
# Общий движок сканирования
# ─────────────────────────────────────────────────────────────────────────────

async def scan_domains(domains: list, concurrency: int, output: str, prefix: str = "") -> list:
    """
    Проверяет список доменов. Если output=None — не сохраняет в файл.
    Возвращает список всех результатов.
    """
    log(f"Проверяем {len(domains)} доменов, параллельность={concurrency}")
    results = []
    sem = asyncio.Semaphore(concurrency)
    done = 0
    cf_found = 0

    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:

        async def worker(domain):
            nonlocal done, cf_found
            async with sem:
                r = await check_domain(session, domain)
                done += 1
                if r["is_cf"] and r["http_ok"]:
                    cf_found += 1
                    print_result(r, prefix=prefix)
                if done % 500 == 0:
                    log(f"Прогресс: {done}/{len(domains)}, CF найдено: {cf_found}")
                results.append(r)

        await asyncio.gather(*[worker(d) for d in domains])

    if output:
        save_results(results, output)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Поиск поддоменов (переиспользуется в subdomain и scan)
# ─────────────────────────────────────────────────────────────────────────────

async def fetch_crtsh(session: aiohttp.ClientSession, domain: str) -> list:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    log(f"  crt.sh: сертификаты для *.{domain} ...")
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=40)) as resp:
            data = await resp.json(content_type=None)
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    subs.add(name)
        log(f"  crt.sh нашёл {len(subs)} поддоменов")
        return list(subs)
    except Exception as e:
        log(f"  crt.sh ошибка: {e}")
        return []


async def fetch_hackertarget(session: aiohttp.ClientSession, ip: str) -> list:
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    log(f"  HackerTarget reverse IP для {ip} ...")
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            text = await resp.text()
        if "error" in text.lower() or "no records" in text.lower():
            log(f"  HackerTarget: {text.strip()}")
            return []
        domains = [line.strip() for line in text.splitlines() if line.strip() and "." in line]
        log(f"  HackerTarget нашёл {len(domains)} доменов на {ip}")
        return domains
    except Exception as e:
        log(f"  HackerTarget ошибка: {e}")
        return []


async def fetch_rapiddns(session: aiohttp.ClientSession, ip: str) -> list:
    url = f"https://rapiddns.io/sameip/{ip}?full=1"
    log(f"  RapidDNS reverse IP для {ip} (fallback) ...")
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=30),
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        ) as resp:
            text = await resp.text()
        domains = re.findall(r'<td>([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})</td>', text)
        domains = list(set(domains))
        log(f"  RapidDNS нашёл {len(domains)} доменов на {ip}")
        return domains
    except Exception as e:
        log(f"  RapidDNS ошибка: {e}")
        return []


async def collect_subdomains(domain: str, ip: str, session: aiohttp.ClientSession,
                             seen_ips: set) -> set:
    """
    Собирает поддомены и соседей по IP для одного домена.
    seen_ips — уже обработанные IP, чтобы не дублировать reverse IP запросы.
    """
    found = set([domain])

    # crt.sh — всегда
    crt = await fetch_crtsh(session, domain)
    found.update(crt)

    # Reverse IP — один раз на уникальный IP
    if ip and ip not in seen_ips:
        seen_ips.add(ip)
        ht = await fetch_hackertarget(session, ip)
        if ht:
            found.update(ht)
        else:
            rd = await fetch_rapiddns(session, ip)
            found.update(rd)

    return found


# ─────────────────────────────────────────────────────────────────────────────
# Режим: check
# ─────────────────────────────────────────────────────────────────────────────

async def mode_check(args):
    domain = args.domain.strip()
    log(f"Проверяем {domain}...")
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        r = await check_domain(session, domain, timeout=10)

    print(f"\n{'─' * 50}")
    print(f"Домен:        {r['domain']}")
    print(f"IP:           {r['ip'] or 'не резолвится'}")
    print(f"CF IP:        {'Да' if r['cf_ip'] else 'Нет'}")
    print(f"CF заголовки: {'Да' if r['cf_headers'] else 'Нет'}")
    print(f"Server:       {r['server'] or '—'}")
    print(f"CF-Ray:       {r['cf_ray'] or '—'}")
    print(f"HTTP статус:  {r['status'] or 'нет соединения'}")
    print(f"Доступен:     {'Да' if r['http_ok'] else 'Нет'}")
    print(f"Итог:         {'CLOUDFLARE (подходит)' if r['is_cf'] else 'Не Cloudflare'}")
    print(f"{'─' * 50}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Режим: tranco
# ─────────────────────────────────────────────────────────────────────────────

async def mode_tranco(args):
    domains = download_list(args.source, args.limit, args.random)
    if not domains:
        log("Не удалось загрузить домены")
        return
    await scan_domains(domains, args.concurrency, args.output)


# ─────────────────────────────────────────────────────────────────────────────
# Режим: subdomain
# ─────────────────────────────────────────────────────────────────────────────

async def mode_subdomain(args):
    domain = args.domain.lower().strip()
    ip = await resolve(domain)
    seen_ips = set()

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        all_subs = await collect_subdomains(domain, ip, session, seen_ips)

    log(f"Итого уникальных доменов для проверки: {len(all_subs)}")
    await scan_domains(list(all_subs), args.concurrency, args.output)


# ─────────────────────────────────────────────────────────────────────────────
# Режим: scan — полный автопилот
#
#  Фаза 1: скачать топ-лист → проверить все домены → выбрать CF-домены
#  Фаза 2: для каждого CF-домена → crt.sh + reverse IP → собрать новые домены
#          (уникальные IP не дублируются)
#  Итог:   объединить результаты обеих фаз → сохранить
# ─────────────────────────────────────────────────────────────────────────────

async def mode_scan(args):
    log("=" * 60)
    log("АВТОСКАНИРОВАНИЕ")
    log(f"  Источник:      {args.source}")
    log(f"  Доменов:       {args.limit} ({'случайные' if args.random else 'топ'})")
    log(f"  Параллельность:{args.concurrency}")
    log(f"  Поддомены:     {'нет (--no-subdomains)' if args.no_subdomains else 'да'}")
    log(f"  Результат:     {args.output}")
    log("=" * 60)

    # ── Фаза 1 ───────────────────────────────────────────────────────────
    log("\n[Фаза 1] Скачиваем топ-лист и ищем CF-домены...")
    domains = download_list(args.source, args.limit, args.random)
    if not domains:
        log("Не удалось загрузить домены")
        return

    phase1_results = await scan_domains(domains, args.concurrency, output=None, prefix="[1] ")
    cf_found_p1 = [r for r in phase1_results if r["is_cf"] and r["http_ok"]]
    log(f"\n[Фаза 1] Найдено {len(cf_found_p1)} рабочих CF-доменов")

    if not cf_found_p1 or args.no_subdomains:
        save_results(phase1_results, args.output)
        return

    # ── Фаза 2 ───────────────────────────────────────────────────────────
    log(f"\n[Фаза 2] Собираем поддомены/соседей для {len(cf_found_p1)} CF-доменов...")

    seen_ips = set()
    all_extra = set()

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for r in cf_found_p1:
            log(f"\n  → {r['domain']} ({r['ip']})")
            extra = await collect_subdomains(r["domain"], r["ip"], session, seen_ips)
            all_extra.update(extra)

    already_checked = {r["domain"] for r in phase1_results}
    new_domains = list(all_extra - already_checked)
    log(f"\n[Фаза 2] Новых доменов для проверки: {len(new_domains)}")

    if not new_domains:
        save_results(phase1_results, args.output)
        return

    phase2_results = await scan_domains(new_domains, args.concurrency, output=None, prefix="[2] ")

    # ── Итог ─────────────────────────────────────────────────────────────
    all_results = phase1_results + phase2_results
    save_results(all_results, args.output)

    cf_p2 = [r for r in phase2_results if r["is_cf"] and r["http_ok"]]
    cf_total = len(cf_found_p1) + len(cf_p2)

    log(f"\n{'=' * 60}")
    log(f"ИТОГО:")
    log(f"  Фаза 1 — топ-лист:  проверено {len(phase1_results)}, CF={len(cf_found_p1)}")
    log(f"  Фаза 2 — поддомены: проверено {len(phase2_results)}, CF={len(cf_p2)}")
    log(f"  Всего рабочих CF:   {cf_total}")
    log(f"  Файл:               {args.output}")
    log(f"{'=' * 60}")


# ─────────────────────────────────────────────────────────────────────────────
# Режим: cfip
# ─────────────────────────────────────────────────────────────────────────────

def reverse_dns(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


async def scan_cfip_range(ip_range: str, limit: int, use_random: bool, concurrency: int, output: str):
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        log(f"Неверный CIDR: {ip_range}")
        return

    hosts = list(network.hosts())

    if use_random:
        hosts = random.sample(hosts, min(limit, len(hosts)))
        log(f"Случайная выборка: {len(hosts)} IP из {network.num_addresses:,} в {ip_range}")
    else:
        hosts = hosts[:limit]
        log(f"Первые {len(hosts)} IP из {network.num_addresses:,} в {ip_range}")

    sem = asyncio.Semaphore(concurrency)
    found_domains = set()
    done = 0
    loop = asyncio.get_event_loop()

    async def rdns_worker(ip):
        nonlocal done
        async with sem:
            domain = await loop.run_in_executor(None, reverse_dns, str(ip))
            done += 1
            if done % 100 == 0:
                log(f"  rDNS: {done}/{len(hosts)}, доменов: {len(found_domains)}")
            if domain:
                found_domains.add(domain)
                log(f"  PTR {ip} -> {domain}")

    await asyncio.gather(*[rdns_worker(ip) for ip in hosts])
    log(f"Reverse DNS завершён. Найдено {len(found_domains)} доменов. Проверяем HTTP...")

    if found_domains:
        await scan_domains(list(found_domains), concurrency, output)
    else:
        log("Доменов через reverse DNS не найдено. Попробуйте другой диапазон.")


async def mode_cfip(args):
    ip_range = args.range
    if not ip_range:
        print("\nДоступные CF IP-диапазоны:")
        for i, r in enumerate(CF_IP_RANGES_V4):
            net = ipaddress.ip_network(r)
            print(f"  [{i:2d}] {r:<22} ({net.num_addresses:>9,} адресов)")
        print()
        choice = input("Введите номер или свой CIDR: ").strip()
        try:
            ip_range = CF_IP_RANGES_V4[int(choice)]
        except (ValueError, IndexError):
            ip_range = choice

    await scan_cfip_range(ip_range, args.limit, args.random, args.concurrency, args.output)


# ─────────────────────────────────────────────────────────────────────────────
# Режим: file
# ─────────────────────────────────────────────────────────────────────────────

async def mode_file(args):
    if not os.path.exists(args.file):
        log(f"Файл не найден: {args.file}")
        return
    with open(args.file, encoding="utf-8") as f:
        all_domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if args.random and args.limit:
        domains = random.sample(all_domains, min(args.limit, len(all_domains)))
        log(f"Случайная выборка: {len(domains)} из {len(all_domains)} доменов")
    elif args.limit:
        domains = all_domains[:args.limit]
        log(f"Первые {len(domains)} из {len(all_domains)} доменов")
    else:
        domains = all_domains
        log(f"Загружено {len(domains)} доменов из {args.file}")

    await scan_domains(domains, args.concurrency, args.output)


# ─────────────────────────────────────────────────────────────────────────────
# Точка входа
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CF Domain Scanner — поиск CF-доменов для VLESS CDN fronting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python cf_scanner.py check --domain example.com
  python cf_scanner.py tranco --limit 5000
  python cf_scanner.py tranco --limit 5000 --random
  python cf_scanner.py tranco --source umbrella --limit 10000 --random
  python cf_scanner.py subdomain --domain example.com
  python cf_scanner.py cfip --range 104.16.0.0/20 --limit 500 --random
  python cf_scanner.py file --file mylist.txt --limit 500 --random
  python cf_scanner.py scan --limit 3000
  python cf_scanner.py scan --limit 5000 --random --source umbrella
  python cf_scanner.py scan --limit 5000 --no-subdomains
        """
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # check
    p = sub.add_parser("check", help="Проверить один домен")
    p.add_argument("--domain", required=True)

    # tranco
    p = sub.add_parser("tranco", help="Сканировать топ-лист (tranco/umbrella/majestic/crux)")
    p.add_argument("--source", choices=["tranco", "umbrella", "majestic", "crux"], default="tranco")
    p.add_argument("--limit", type=int, default=10000, help="Сколько доменов (default: 10000)")
    p.add_argument("--random", action="store_true", help="Случайная выборка вместо топ-N")
    p.add_argument("--concurrency", type=int, default=100)
    p.add_argument("--output", default="results_tranco.json")

    # subdomain
    p = sub.add_parser("subdomain", help="Найти поддомены домена (crt.sh + reverse IP)")
    p.add_argument("--domain", required=True)
    p.add_argument("--concurrency", type=int, default=50)
    p.add_argument("--output", default="results_subdomains.json")

    # cfip
    p = sub.add_parser("cfip", help="Сканировать IP-подсети Cloudflare (reverse DNS)")
    p.add_argument("--range", default=None, help="CIDR, например 104.16.0.0/20")
    p.add_argument("--limit", type=int, default=1000, help="Макс. IP (default: 1000)")
    p.add_argument("--random", action="store_true", help="Случайные IP из диапазона")
    p.add_argument("--concurrency", type=int, default=50)
    p.add_argument("--output", default="results_cfip.json")

    # file
    p = sub.add_parser("file", help="Проверить список доменов из файла")
    p.add_argument("--file", required=True)
    p.add_argument("--limit", type=int, default=None, help="Лимит (опционально)")
    p.add_argument("--random", action="store_true", help="Случайная выборка из файла")
    p.add_argument("--concurrency", type=int, default=100)
    p.add_argument("--output", default="results_file.json")

    # scan
    p = sub.add_parser("scan", help="Автоскан: топ-лист → CF-домены → поддомены → результат")
    p.add_argument("--source", choices=["tranco", "umbrella", "majestic", "crux"], default="tranco")
    p.add_argument("--limit", type=int, default=5000, help="Доменов из топ-листа (default: 5000)")
    p.add_argument("--random", action="store_true", help="Случайная выборка из топ-листа")
    p.add_argument("--concurrency", type=int, default=100)
    p.add_argument("--no-subdomains", action="store_true", dest="no_subdomains",
                   help="Пропустить фазу поиска поддоменов (только топ-лист)")
    p.add_argument("--output", default="results_scan.json")

    args = parser.parse_args()

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    dispatch = {
        "check":     mode_check,
        "tranco":    mode_tranco,
        "subdomain": mode_subdomain,
        "cfip":      mode_cfip,
        "file":      mode_file,
        "scan":      mode_scan,
    }
    asyncio.run(dispatch[args.mode](args))


if __name__ == "__main__":
    main()