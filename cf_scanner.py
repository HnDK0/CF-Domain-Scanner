#!/usr/bin/env python3
"""
CF Domain Scanner — поиск доменов через Cloudflare для CDN fronting (VLESS)

Установка зависимостей:
  pip install aiohttp

Примеры запуска:
  python cf_scanner.py check --domain example.com
  python cf_scanner.py tranco --limit 5000 --concurrency 150
  python cf_scanner.py subdomain --domain example.com
  python cf_scanner.py cfip --range 104.16.0.0/20 --limit 1000
  python cf_scanner.py file --file mylist.txt
"""

import asyncio
import aiohttp
import argparse
import json
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


def print_result(r: dict):
    status = r.get("status") or "---"
    ip = r.get("ip") or "no-resolve"
    cf = "[CF]" if r.get("is_cf") else "    "
    ok = "OK" if r.get("http_ok") else "  "
    ray = f" ray={r['cf_ray']}" if r.get("cf_ray") else ""
    print(f"  {cf} {ok} {r['domain']:<45} {ip:<18} HTTP={status}{ray}", flush=True)


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
# Общий движок сканирования
# ─────────────────────────────────────────────────────────────────────────────

async def scan_domains(domains: list, concurrency: int, output: str):
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
                    print_result(r)
                if done % 500 == 0:
                    log(f"Прогресс: {done}/{len(domains)}, CF найдено: {cf_found}")
                results.append(r)

        await asyncio.gather(*[worker(d) for d in domains])

    save_results(results, output)


# ─────────────────────────────────────────────────────────────────────────────
# Режим: check — одиночная проверка домена
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
# Режим: tranco — сканирование топ-листа
# ─────────────────────────────────────────────────────────────────────────────

def download_list(source: str, limit: int) -> list:
    urls = {
        "tranco": "https://tranco-list.eu/top-1m.csv.zip",
        "umbrella": "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
    }
    url = urls[source]
    log(f"Скачиваем {source} top-1M (~10MB)...")
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            data = r.read()
        z = zipfile.ZipFile(io.BytesIO(data))
        lines = z.read(z.namelist()[0]).decode().splitlines()
        domains = []
        for line in lines[:limit]:
            parts = line.split(",")
            if len(parts) >= 2:
                domains.append(parts[1].strip().lower())
        log(f"Загружено {len(domains)} доменов")
        return domains
    except Exception as e:
        log(f"Ошибка загрузки: {e}")
        return []


async def mode_tranco(args):
    domains = download_list(args.source, args.limit)
    if not domains:
        log("Не удалось загрузить домены")
        return
    await scan_domains(domains, args.concurrency, args.output)


# ─────────────────────────────────────────────────────────────────────────────
# Режим: subdomain — поиск поддоменов через crt.sh + reverse IP lookup
# ─────────────────────────────────────────────────────────────────────────────

async def fetch_crtsh(session: aiohttp.ClientSession, domain: str) -> list:
    """
    Certificate Transparency logs — все поддомены которые когда-либо
    получали TLS-сертификат. Очень полный источник.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    log(f"crt.sh: запрашиваем сертификаты для *.{domain} ...")
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=40)) as resp:
            data = await resp.json(content_type=None)
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    subs.add(name)
        log(f"crt.sh нашёл {len(subs)} поддоменов")
        return list(subs)
    except Exception as e:
        log(f"crt.sh ошибка: {e}")
        return []


async def fetch_hackertarget_reverseip(session: aiohttp.ClientSession, ip: str) -> list:
    """
    HackerTarget Reverse IP — возвращает все домены на данном IP.
    Бесплатный API без ключа, лимит ~100 запросов/день.
    На одном CF IP обычно тысячи доменов — это золотая жила.
    """
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    log(f"HackerTarget reverse IP: ищем домены на {ip} ...")
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            text = await resp.text()
        # API возвращает домены построчно, или "error" / "API count exceeded"
        if "error" in text.lower() or "no records" in text.lower():
            log(f"HackerTarget: {text.strip()}")
            return []
        domains = [line.strip() for line in text.splitlines() if line.strip() and "." in line]
        log(f"HackerTarget нашёл {len(domains)} доменов на IP {ip}")
        return domains
    except Exception as e:
        log(f"HackerTarget ошибка: {e}")
        return []


async def fetch_rapiddns_reverseip(session: aiohttp.ClientSession, ip: str) -> list:
    """
    RapidDNS — альтернатива HackerTarget для reverse IP lookup.
    Используется как fallback если HackerTarget вернул ошибку лимита.
    """
    url = f"https://rapiddns.io/sameip/{ip}?full=1"
    log(f"RapidDNS reverse IP: ищем домены на {ip} ...")
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=30),
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        ) as resp:
            text = await resp.text()
        # Парсим домены из HTML таблицы — они в тегах <td>
        import re
        domains = re.findall(r'<td>([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})</td>', text)
        domains = list(set(domains))
        log(f"RapidDNS нашёл {len(domains)} доменов на IP {ip}")
        return domains
    except Exception as e:
        log(f"RapidDNS ошибка: {e}")
        return []


async def mode_subdomain(args):
    domain = args.domain.lower().strip()
    all_subs = set([domain])

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:

        # 1. crt.sh — Certificate Transparency
        crt_subs = await fetch_crtsh(session, domain)
        all_subs.update(crt_subs)

        # 2. Резолвим IP базового домена и делаем reverse IP lookup
        ip = await resolve(domain)
        if ip:
            log(f"IP домена {domain}: {ip}")
            if is_cf_ip(ip):
                log("IP в диапазоне Cloudflare — делаем reverse IP lookup")

                # Пробуем HackerTarget
                ht_domains = await fetch_hackertarget_reverseip(session, ip)
                if ht_domains:
                    all_subs.update(ht_domains)
                else:
                    # Fallback — RapidDNS
                    rd_domains = await fetch_rapiddns_reverseip(session, ip)
                    all_subs.update(rd_domains)
            else:
                log(f"IP {ip} не в диапазоне CF — reverse IP lookup пропускаем")
        else:
            log(f"Не удалось резолвить {domain}")

    log(f"Итого уникальных доменов для проверки: {len(all_subs)}")
    await scan_domains(list(all_subs), args.concurrency, args.output)


# ─────────────────────────────────────────────────────────────────────────────
# Режим: cfip — сканирование IP подсетей Cloudflare через reverse DNS
# ─────────────────────────────────────────────────────────────────────────────

def reverse_dns(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


async def scan_cfip_range(ip_range: str, limit: int, concurrency: int, output: str):
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        log(f"Неверный CIDR: {ip_range}")
        return

    hosts = list(network.hosts())
    if limit:
        hosts = hosts[:limit]

    log(f"Сканируем {len(hosts)} IP в диапазоне {ip_range} (reverse DNS)")

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
                log(f"  rDNS прогресс: {done}/{len(hosts)}, доменов: {len(found_domains)}")
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

    await scan_cfip_range(ip_range, args.limit, args.concurrency, args.output)


# ─────────────────────────────────────────────────────────────────────────────
# Режим: file — проверить свой список доменов
# ─────────────────────────────────────────────────────────────────────────────

async def mode_file(args):
    if not os.path.exists(args.file):
        log(f"Файл не найден: {args.file}")
        return
    with open(args.file, encoding="utf-8") as f:
        domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
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
  python cf_scanner.py tranco --limit 5000 --concurrency 150
  python cf_scanner.py tranco --source umbrella --limit 10000
  python cf_scanner.py subdomain --domain example.com
  python cf_scanner.py cfip --range 104.16.0.0/20 --limit 500
  python cf_scanner.py file --file mylist.txt --output my_results.json
        """
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # check
    p = sub.add_parser("check", help="Проверить один домен")
    p.add_argument("--domain", required=True)

    # tranco
    p = sub.add_parser("tranco", help="Сканировать топ-лист Tranco или Umbrella")
    p.add_argument("--source", choices=["tranco", "umbrella"], default="tranco")
    p.add_argument("--limit", type=int, default=10000, help="Сколько доменов (default: 10000)")
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
    p.add_argument("--concurrency", type=int, default=50)
    p.add_argument("--output", default="results_cfip.json")

    # file
    p = sub.add_parser("file", help="Проверить список доменов из файла")
    p.add_argument("--file", required=True)
    p.add_argument("--concurrency", type=int, default=100)
    p.add_argument("--output", default="results_file.json")

    args = parser.parse_args()

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    dispatch = {
        "check": mode_check,
        "tranco": mode_tranco,
        "subdomain": mode_subdomain,
        "cfip": mode_cfip,
        "file": mode_file,
    }
    asyncio.run(dispatch[args.mode](args))


if __name__ == "__main__":
    main()
