#!/usr/bin/env python3
"""
CF Domain Scanner — поиск CF-доменов для CDN VLESS fronting в РФ

Установка зависимостей:
  pip install aiohttp aiodns

Примеры:
  python cf_scanner.py check --domain example.com
  python cf_scanner.py tranco --limit 5000 --random
  python cf_scanner.py tranco --source umbrella --limit 10000
  python cf_scanner.py file --file mylist.txt
"""

import asyncio
import aiohttp
import argparse
import random
import ssl
import ipaddress
import sys
import os
import io
import gzip
import zipfile
import time
import errno
import socket
import urllib.request
from datetime import datetime
from typing import Optional, Tuple, List

# ─────────────────────────────────────────────────────────────────────────────
# Конфигурация
# ─────────────────────────────────────────────────────────────────────────────

CF_IP_RANGES_V4 = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13",   "104.24.0.0/14",   "108.162.192.0/18",
    "131.0.72.0/22",   "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13",   "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22","198.41.128.0/17",
]

# Таймауты
TOTAL_TIMEOUT    = 3.0   # максимум на GET /
CONNECT_TIMEOUT  = 3.0

# ТСПУ: диапазон обрыва (по данным dpi-detector актуально на 2025-2026)
TSPU_MIN_KB = 1
TSPU_MAX_KB = 69

# DNS для резолвинга — Quad9, обходит локальный фейк DNS
DEFAULT_DNS = "9.9.9.9"

# Маркеры CF JS Challenge в теле ответа
CF_CHALLENGE_MARKERS = [
    b"_cf_chl_rt_tk", b"cf_chl_prog", b"__cf_chl_f_tk",
    b"chl-store", b"jschl_vc", b"cf_chl_bypass",
    b"cf-challenge-running", b"cdn-cgi/challenge-platform",
]
CF_CHALLENGE_PEEK = 8 * 1024  # читаем первые 8 КБ для детекта challenge

# Маркеры блок-страниц провайдера
BLOCK_MARKERS_URL = [
    "warning.rt.ru", "blocked", "access-denied", "eais",
    "zapret-info", "rkn.gov.ru", "mvd.ru", "nap.gov.ru",
]
BLOCK_MARKERS_BODY = [
    b"blocked", b"\xd0\xb7\xd0\xb0\xd0\xb1\xd0\xbb\xd0\xbe\xd0\xba\xd0\xb8\xd1\x80\xd0\xbe\xd0\xb2\xd0\xb0\xd0\xbd",  # заблокирован
    b"rkn.gov.ru", b"eais.rkn.gov.ru", b"warning.rt.ru",
    b"zapret-info", b"\xd1\x80\xd0\xbe\xd1\x81\xd0\xba\xd0\xbe\xd0\xbc\xd0\xbd\xd0\xb0\xd0\xb4\xd0\xb7\xd0\xbe\xd1\x80",  # роскомнадзор
]

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)

# Кеш топ-листов
CACHE_MAX_AGE_HOURS = 24

# Источники топ-листов
SOURCES = {
    "tranco": [
        "https://tranco-list.eu/top-1m.csv.zip",
        "https://github.com/adysec/top_1m_domains/raw/main/tranco.zip",
    ],
    "umbrella": [
        "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
        "https://github.com/adysec/top_1m_domains/raw/main/cisco-umbrella.zip",
    ],
    "majestic": [
        "https://downloads.majestic.com/majestic_million.csv",
        "https://github.com/adysec/top_1m_domains/raw/main/majestic.zip",
    ],
    "crux": [
        "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz",
    ],
}

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


async def resolve(domain: str, dns_server: str = DEFAULT_DNS) -> Optional[str]:
    """Резолвит домен через указанный DNS-сервер (UDP, нативная реализация)."""
    try:
        import aiodns
        import warnings
        resolver = aiodns.DNSResolver(nameservers=[dns_server])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            result = await resolver.query(domain, "A")
        return result[0].host if result else None
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Классификатор ошибок (адаптировано из dpi-detector)
# ─────────────────────────────────────────────────────────────────────────────

# Windows errno коды
WSAECONNRESET   = 10054
WSAECONNREFUSED = 10061
WSAETIMEDOUT    = 10060
WSAENETUNREACH  = 10051
WSAEHOSTUNREACH = 10065
WSAECONNABORTED = 10053


def _find_cause(exc: Exception, target_type: type, max_depth: int = 10) -> Optional[Exception]:
    current = exc
    for _ in range(max_depth):
        if isinstance(current, target_type):
            return current
        nxt = current.__cause__ or current.__context__
        if nxt is None:
            break
        current = nxt
    return None


def _get_errno(exc: Exception, max_depth: int = 10) -> Optional[int]:
    current = exc
    for _ in range(max_depth):
        if isinstance(current, OSError) and current.errno is not None:
            return current.errno
        nxt = current.__cause__ or current.__context__
        if nxt is None:
            break
        current = nxt
    return None


def _collect_text(exc: Exception, max_depth: int = 10) -> str:
    parts = []
    current = exc
    for _ in range(max_depth):
        parts.append(str(current).lower())
        nxt = current.__cause__ or current.__context__
        if nxt is None:
            break
        current = nxt
    return " | ".join(parts)


def classify_error(exc: Exception, bytes_read: int = 0) -> str:
    """Возвращает короткую строку-метку для типа ошибки."""
    full = _collect_text(exc)
    en   = _get_errno(exc)

    if isinstance(exc, asyncio.TimeoutError) or "timeout" in full:
        kb = bytes_read // 1024
        if TSPU_MIN_KB <= kb <= TSPU_MAX_KB:
            return f"tspu_cut:{kb}KB"
        return f"timeout:{kb}KB"

    if _find_cause(exc, ConnectionResetError) or en in (errno.ECONNRESET, WSAECONNRESET):
        kb = bytes_read // 1024
        if TSPU_MIN_KB <= kb <= TSPU_MAX_KB:
            return f"tspu_rst:{kb}KB"
        return f"rst:{kb}KB"

    if _find_cause(exc, ConnectionAbortedError) or en in (getattr(errno, "ECONNABORTED", 103), WSAECONNABORTED):
        return "abort"

    if _find_cause(exc, ConnectionRefusedError) or en in (errno.ECONNREFUSED, WSAECONNREFUSED):
        return "refused"

    ssl_err = _find_cause(exc, ssl.SSLError)
    if ssl_err:
        msg = str(ssl_err).lower()
        if "certificate" in msg or "verify" in msg:
            return "tls_mitm"
        if "unrecognized_name" in msg or "unrecognized name" in msg:
            return "sni_block"
        if "handshake" in msg or "eof" in msg:
            return "tls_dpi"
        return "tls_err"

    if "ssl" in full or "tls" in full:
        if "certificate" in full or "verify" in full:
            return "tls_mitm"
        if "unrecognized" in full:
            return "sni_block"
        return "tls_err"

    return f"err:{type(exc).__name__}"


# ─────────────────────────────────────────────────────────────────────────────
# Проверка домена
# ─────────────────────────────────────────────────────────────────────────────

async def _step1_get(
    session: aiohttp.ClientSession,
    domain: str,
) -> dict:
    """
    Шаг 1: GET / — определяем CF, статус, детект блок-страниц и challenge.
    Таймаут: TOTAL_TIMEOUT секунд на весь ответ.
    Возвращает dict с полями: is_cf, cf_detection, status, bytes_received,
    dead (bool), dead_reason (str), server, cf_ray.
    """
    r = {
        "is_cf": False, "cf_detection": None,
        "status": None, "bytes_received": 0,
        "dead": False, "dead_reason": "",
        "server": "", "cf_ray": None,
    }

    try:
        timeout = aiohttp.ClientTimeout(total=TOTAL_TIMEOUT, connect=CONNECT_TIMEOUT)
        async with session.get(
            f"https://{domain}",
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
            ssl=False,
        ) as resp:
            r["status"] = resp.status
            headers = dict(resp.headers)
            r["server"]  = headers.get("server", headers.get("Server", "")).lower()
            r["cf_ray"]  = headers.get("cf-ray") or headers.get("CF-Ray")

            # Определяем CF
            if r["cf_ray"]:
                r["cf_detection"] = "ray"
            elif "cloudflare" in r["server"]:
                r["cf_detection"] = "server+ip"

            if not r["cf_detection"]:
                r["dead"] = True
                r["dead_reason"] = "not_cf"
                return r

            if resp.status >= 500:
                r["dead"] = True
                r["dead_reason"] = f"http_{resp.status}"
                return r

            # Проверяем блок-страницу провайдера через Location
            location = headers.get("location", "").lower()
            if any(m in location for m in BLOCK_MARKERS_URL):
                r["dead"] = True
                r["dead_reason"] = "isp_block_redirect"
                return r

            if resp.status == 451:
                r["dead"] = True
                r["dead_reason"] = "http_451"
                return r

            # cf-mitigated: challenge
            cf_mitigated = headers.get("cf-mitigated", "").lower()
            if cf_mitigated == "challenge":
                r["dead"] = True
                r["dead_reason"] = "cf_challenge"
                return r

            # Читаем тело: нам нужно до 65 КБ или до EOF
            LIMIT = 65 * 1024
            body_peek = bytearray()
            bytes_read = 0
            hard_error = False
            server_eof = False

            try:
                async for chunk in resp.content.iter_chunked(4096):
                    bytes_read += len(chunk)
                    if len(body_peek) < CF_CHALLENGE_PEEK:
                        body_peek.extend(chunk)
                    if bytes_read >= LIMIT:
                        # Скачали 65 КБ — хватит
                        break
                else:
                    server_eof = True
            except Exception as e:
                hard_error = True
                err_label = classify_error(e, bytes_read)
                r["bytes_received"] = bytes_read
                r["dead"] = True
                r["dead_reason"] = err_label
                return r

            r["bytes_received"] = bytes_read

            # Детект CF Challenge по телу
            if any(m in body_peek for m in CF_CHALLENGE_MARKERS):
                r["dead"] = True
                r["dead_reason"] = "cf_challenge"
                return r

            # Детект блок-страницы провайдера в теле (только если маленький ответ)
            if bytes_read < 16 * 1024:
                for m in BLOCK_MARKERS_BODY:
                    if m in body_peek:
                        r["dead"] = True
                        r["dead_reason"] = "isp_block_body"
                        return r

            # Если сервер сам закрыл и это 0 байт — подозрительно
            if server_eof and bytes_read == 0:
                r["dead"] = True
                r["dead_reason"] = "empty_response"
                return r

            r["is_cf"] = True
            return r

    except Exception as e:
        err_label = classify_error(e, 0)
        r["dead"] = True
        r["dead_reason"] = err_label
        return r



async def _step3_tls(domain: str) -> Tuple[bool, str]:
    """
    Шаг 3: TLS-проверка — детект MITM, SNI-блокировки, TLS version блокировок.
    Новое TCP-соединение с реальной проверкой сертификата.

    Возвращает (ok: bool, reason: str).
    """
    loop = asyncio.get_event_loop()
    try:
        ctx = ssl.create_default_context()
        # Проверяем сертификат по-настоящему
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                domain, 443,
                ssl=ctx,
                server_hostname=domain,
            ),
            timeout=CONNECT_TIMEOUT,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, ""

    except ssl.SSLCertVerificationError as e:
        msg = str(e).lower()
        if "expired" in msg:
            return False, "tls_cert_expired"
        if "self" in msg or "self-signed" in msg:
            return False, "tls_mitm_selfsigned"
        if "unknown ca" in msg or "unable to get" in msg:
            return False, "tls_mitm_unknown_ca"
        if "hostname" in msg or "mismatch" in msg:
            return False, "tls_mitm_hostname"
        return False, f"tls_cert_fail"

    except ssl.SSLError as e:
        msg = str(e).lower()
        if "unrecognized_name" in msg or "unrecognized name" in msg:
            return False, "sni_block"
        if "handshake" in msg:
            return False, "tls_handshake_block"
        if "eof" in msg or "unexpected" in msg:
            return False, "tls_dpi_eof"
        return False, f"tls_err"

    except asyncio.TimeoutError:
        return False, "tls_timeout"

    except OSError as e:
        en = e.errno
        if en in (errno.ECONNRESET, WSAECONNRESET):
            return False, "tls_rst"
        if en in (errno.ECONNREFUSED, WSAECONNREFUSED):
            return False, "tls_refused"
        return False, f"tls_oserr:{en}"

    except Exception as e:
        # Прочие ошибки не считаем блокировкой — TLS мог упасть по другой причине
        return True, f"tls_skip:{type(e).__name__}"


async def check_domain(
    session: aiohttp.ClientSession,
    domain: str,
    dns_server: str = DEFAULT_DNS,
    skip_tls: bool = False,
) -> dict:
    """
    Полная проверка домена: резолвинг → GET / → TLS.
    Возвращает dict с результатами.
    """
    result = {
        "domain":        domain,
        "ip":            None,
        "cf_ip":         False,
        "cf_detection":  None,
        "status":        None,
        "server":        "",
        "bytes_received": 0,
        "alive":         False,
        "dead_reason":   "",
        # детали по шагам
        "tls_ok":        None,
        "tls_reason":    "",
        "elapsed":       0.0,
    }

    t_start = time.time()

    # ── Резолвинг ──────────────────────────────────────────────────────────────
    ip = await resolve(domain, dns_server)
    if not ip:
        result["dead_reason"] = "dns_fail"
        result["elapsed"] = time.time() - t_start
        return result

    result["ip"] = ip
    result["cf_ip"] = is_cf_ip(ip)

    if not result["cf_ip"]:
        result["dead_reason"] = "not_cf_ip"
        result["elapsed"] = time.time() - t_start
        return result

    # ── Шаг 1: GET / ──────────────────────────────────────────────────────────
    s1 = await _step1_get(session, domain)
    result.update({
        "cf_detection":   s1["cf_detection"],
        "status":         s1["status"],
        "server":         s1["server"],
        "cf_ray":         s1.get("cf_ray"),
        "bytes_received": s1["bytes_received"],
    })

    if s1["dead"]:
        result["dead_reason"] = s1["dead_reason"]
        result["elapsed"] = time.time() - t_start
        return result

    if not s1["is_cf"]:
        result["dead_reason"] = "not_cf"
        result["elapsed"] = time.time() - t_start
        return result

    # ── Шаг 2: TLS ────────────────────────────────────────────────────────────
    if not skip_tls:
        tls_ok, tls_reason = await _step3_tls(domain)
        result["tls_ok"]     = tls_ok
        result["tls_reason"] = tls_reason

        if not tls_ok:
            result["dead_reason"] = tls_reason
            result["elapsed"] = time.time() - t_start
            return result

    result["alive"]   = True
    result["elapsed"] = time.time() - t_start
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Вывод результатов
# ─────────────────────────────────────────────────────────────────────────────

def fmt_result(r: dict) -> str:
    """Форматирует живой домен для консоли."""
    kb = r["bytes_received"] // 1024
    t  = r["elapsed"]
    det = r.get("cf_detection") or ""
    return f"✓ {r['domain']:<45} ({r['status']}, {kb}KB, {t:.1f}s, {det})"


class ResultWriter:
    """Пишет результаты в .txt и .log файлы, атомарно через .tmp."""

    def __init__(self, output_base: str):
        # output_base: например "results" → results.txt + results.log
        base = output_base.rsplit(".", 1)[0] if "." in os.path.basename(output_base) else output_base
        self.txt_path = base + ".txt"
        self.log_path = base + ".log"
        self._domains: List[str] = []
        self._log_lines: List[str] = []
        self.total_checked = 0
        self.total_alive   = 0

    def add(self, r: dict):
        self.total_checked += 1
        if not r["alive"]:
            return
        self.total_alive += 1
        self._domains.append(r["domain"])
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        kb = r["bytes_received"] // 1024
        self._log_lines.append(
            f"[{ts}] {r['domain']:<45} ip={r['ip']:<18} "
            f"status={r['status']} bytes={kb}KB "
            f"elapsed={r['elapsed']:.2f}s "
            f"cf={r.get('cf_detection','')} "

            f"tls={'ok' if r['tls_ok'] else r.get('tls_reason','skip')}"
        )
        self._flush()

    def _flush(self):
        self._write_atomic(self.txt_path, "\n".join(self._domains) + "\n" if self._domains else "")
        self._write_atomic(self.log_path, "\n".join(self._log_lines) + "\n" if self._log_lines else "")

    @staticmethod
    def _write_atomic(path: str, content: str):
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(tmp, path)
        except Exception as e:
            log(f"[!] Ошибка записи {path}: {e}")

    def finalize(self):
        self._flush()
        log(
            f"Сохранено: {self.txt_path} ({self.total_alive} доменов), "
            f"{self.log_path} (детали). "
            f"Проверено: {self.total_checked}, живых: {self.total_alive}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Движок сканирования
# ─────────────────────────────────────────────────────────────────────────────

async def scan_domains(
    domains: List[str],
    concurrency: int,
    writer: ResultWriter,
    dns_server: str = DEFAULT_DNS,
    skip_tls: bool = False,
) -> List[dict]:
    log(f"Проверяем {len(domains)} доменов, параллельность={concurrency}")

    results   = []
    sem       = asyncio.Semaphore(concurrency)
    done      = 0
    alive     = 0
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)

    async with aiohttp.ClientSession(connector=connector) as session:

        async def worker(domain: str):
            nonlocal done, alive
            async with sem:
                r = await check_domain(session, domain, dns_server=dns_server, skip_tls=skip_tls)
                done += 1
                if r["alive"]:
                    alive += 1
                    print(fmt_result(r), flush=True)
                if done % 100 == 0:
                    log(f"Прогресс: {done}/{len(domains)}, живых CF: {alive}")
                writer.add(r)
                results.append(r)

        try:
            await asyncio.gather(*[worker(d) for d in domains])
        except (asyncio.CancelledError, KeyboardInterrupt):
            log(f"Прервано. Проверено: {done}/{len(domains)}, живых: {alive}")
            writer.finalize()
            raise

    writer.finalize()
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Кеш и загрузка топ-листов
# ─────────────────────────────────────────────────────────────────────────────

def _cache_path(source: str) -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, f"cache_{source}.csv")


def _cache_is_fresh(source: str) -> bool:
    path = _cache_path(source)
    if not os.path.exists(path):
        return False
    age_hours = (time.time() - os.path.getmtime(path)) / 3600
    return age_hours < CACHE_MAX_AGE_HOURS


def _load_from_cache(source: str) -> List[str]:
    path = _cache_path(source)
    log(f"Загружаем из кеша: {path}")
    with open(path, encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    log(f"Из кеша загружено {len(lines)} доменов")
    return lines


def _save_to_cache(source: str, domains: List[str]):
    path = _cache_path(source)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(domains))
        log(f"Кеш сохранён: {path} ({len(domains)} доменов)")
    except Exception as e:
        log(f"[!] Не удалось сохранить кеш: {e}")


def _fetch_url(url: str, timeout: int = 45) -> bytes:
    log(f"  Загружаем: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _parse_zip(data: bytes, domain_col: int = 1) -> List[str]:
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


def _parse_csv(data: bytes, domain_col: int = 2, skip_header: bool = True) -> List[str]:
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


def _parse_gz_csv(data: bytes) -> List[str]:
    lines = gzip.decompress(data).decode(errors="ignore").splitlines()
    result = []
    for line in lines[1:]:
        parts = line.split(",")
        if parts:
            raw = parts[0].strip().lower().strip('"')
            raw = raw.replace("https://", "").replace("http://", "").rstrip("/")
            if raw and "." in raw:
                result.append(raw)
    return result


def download_list(source: str, limit: int, use_random: bool) -> List[str]:
    # Сначала проверяем кеш
    if _cache_is_fresh(source):
        all_domains = _load_from_cache(source)
    else:
        log(f"Скачиваем {source} top-1M (кеш устарел или отсутствует)...")
        all_domains = []
        urls = SOURCES.get(source, [])

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
                    _save_to_cache(source, all_domains)
                    break
                else:
                    log("  Файл скачан, но домены не распарсились — пробуем следующий...")
            except Exception as e:
                log(f"  Ошибка ({e}) — пробуем следующий источник...")

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
# Режимы
# ─────────────────────────────────────────────────────────────────────────────

async def mode_check(args):
    domain = args.domain.strip().lower()
    log(f"Проверяем {domain}...")

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        r = await check_domain(session, domain, dns_server=args.dns, skip_tls=args.skip_tls)

    sep = "─" * 60
    print(f"\n{sep}")
    print(f"Домен:        {r['domain']}")
    print(f"IP:           {r['ip'] or 'не резолвится'}")
    print(f"CF IP:        {'✓ Да' if r['cf_ip'] else '✗ Нет'}")
    print(f"CF определён: {r.get('cf_detection') or '—'}")
    print(f"CF-Ray:       {r.get('cf_ray') or '—'}")
    print(f"Server:       {r['server'] or '—'}")
    print(f"HTTP статус:  {r['status'] or 'нет соединения'}")
    print(f"Байт получено:{r['bytes_received']} ({r['bytes_received']//1024} КБ)")
    print(f"Время:        {r['elapsed']:.2f}s")

    print(f"\n── Результаты проверок ──")
    # Шаг 1
    if r.get("cf_detection"):
        print(f"  GET /       ✓ CF определён ({r['cf_detection']}), HTTP {r['status']}")
    else:
        print(f"  GET /       ✗ {r['dead_reason']}")

    # Шаг 2
    if r["tls_ok"] is True:
        print(f"  TLS         ✓ Сертификат валиден, нет MITM/SNI-блок")
    elif r["tls_ok"] is False:
        print(f"  TLS         ✗ {r['tls_reason']}")
    else:
        print(f"  TLS         — (пропущен или не дошли)")

    print(f"\n── Итог ──")
    if r["alive"]:
        print(f"  ✓ ЖИВОЙ — домен подходит для CDN VLESS fronting")
    else:
        print(f"  ✗ МЁРТВЫЙ — причина: {r['dead_reason']}")
    print(f"{sep}\n")


async def mode_tranco(args):
    domains = download_list(args.source, args.limit, args.random)
    if not domains:
        log("Не удалось загрузить домены")
        return
    writer = ResultWriter(args.output)
    await scan_domains(
        domains, args.concurrency, writer,
        dns_server=args.dns, skip_tls=args.skip_tls,
    )


async def mode_file(args):
    if not os.path.exists(args.file):
        log(f"Файл не найден: {args.file}")
        return
    with open(args.file, encoding="utf-8") as f:
        all_domains = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if args.random and args.limit:
        domains = random.sample(all_domains, min(args.limit, len(all_domains)))
        log(f"Случайная выборка: {len(domains)} из {len(all_domains)}")
    elif args.limit:
        domains = all_domains[:args.limit]
        log(f"Первые {len(domains)} из {len(all_domains)}")
    else:
        domains = all_domains
        log(f"Загружено {len(domains)} доменов из {args.file}")

    writer = ResultWriter(args.output)
    await scan_domains(
        domains, args.concurrency, writer,
        dns_server=args.dns, skip_tls=args.skip_tls,
    )


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
  python cf_scanner.py tranco --limit 5000 --random
  python cf_scanner.py tranco --source umbrella --limit 10000
  python cf_scanner.py file --file mylist.txt
  python cf_scanner.py file --file mylist.txt --skip-tls
        """,
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # ── check ──────────────────────────────────────────────────────────────────
    p = sub.add_parser("check", help="Проверить один домен")
    p.add_argument("--domain", required=True)
    p.add_argument("--dns",      default=DEFAULT_DNS, help=f"DNS сервер (default: {DEFAULT_DNS})")
    p.add_argument("--skip-tls", action="store_true", dest="skip_tls",
                   help="Пропустить TLS-проверку (быстрее, но не детектирует MITM)")

    # ── tranco ─────────────────────────────────────────────────────────────────
    p = sub.add_parser("tranco", help="Сканировать топ-лист")
    p.add_argument("--source",      choices=list(SOURCES), default="tranco")
    p.add_argument("--limit",       type=int, default=10000)
    p.add_argument("--random",      action="store_true")
    p.add_argument("--concurrency", type=int, default=30)
    p.add_argument("--output",      default="results.txt")
    p.add_argument("--dns",         default=DEFAULT_DNS)
    p.add_argument("--skip-tls",    action="store_true", dest="skip_tls")

    # ── file ───────────────────────────────────────────────────────────────────
    p = sub.add_parser("file", help="Проверить список доменов из файла")
    p.add_argument("--file",        required=True)
    p.add_argument("--limit",       type=int, default=None)
    p.add_argument("--random",      action="store_true")
    p.add_argument("--concurrency", type=int, default=30)
    p.add_argument("--output",      default="results.txt")
    p.add_argument("--dns",         default=DEFAULT_DNS)
    p.add_argument("--skip-tls",    action="store_true", dest="skip_tls")

    args = parser.parse_args()

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    dispatch = {
        "check":  mode_check,
        "tranco": mode_tranco,
        "file":   mode_file,
    }

    try:
        asyncio.run(dispatch[args.mode](args))
    except KeyboardInterrupt:
        print("\n[!] Остановлено пользователем. Результаты сохранены.", flush=True)
    except Exception as e:
        print(f"\n[!] Ошибка: {e}", flush=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()