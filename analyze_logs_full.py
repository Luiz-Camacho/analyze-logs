#!/usr/bin/env python3
"""
analyze_logs_modified_v3.py
Versão:
- HTTP Status por IP: apenas 30 primeiros
- Adiciona "Total de IPs únicos"
- Hits suspeitos: apenas top 10 IPs
- IP SUSPEITO PRINCIPAL: mostra top 5
- Remove contexto e sugestões de bloqueio
"""

import re
import os
import gzip
from collections import defaultdict, Counter
from datetime import datetime

LOG_LINE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
)

SUSPICIOUS_PATTERNS = [
    r'/wp-login\.php',
    r'/wp-admin\b',
    r'/xmlrpc\.php',
    r'/phpmyadmin\b',
    r'/administrator\b',
    r'/admin\b',
    r'/login\b',
    r'/wp-login\b',
    r'/vendor\b',
    r'/\.env\b',
]
SUSPICIOUS_RE = re.compile("|".join(SUSPICIOUS_PATTERNS), re.IGNORECASE)

def open_log(path):
    if path.endswith('.gz'):
        return gzip.open(path, 'rt', encoding='utf-8', errors='replace')
    return open(path, 'r', encoding='utf-8', errors='replace')

def parse_line(line):
    m = LOG_LINE_RE.search(line)
    if m:
        return m.groupdict()
    return None

def http_status_per_ip(path):
    ip_status = defaultdict(Counter)
    totals = Counter()
    with open_log(path) as f:
        for line in f:
            p = parse_line(line)
            if not p:
                continue
            ip = p['ip']
            status = p['status']
            ip_status[ip][status] += 1
            totals[ip] += 1
    return ip_status, totals

def endpoints_per_ip(path):
    ip_endpoints = defaultdict(Counter)
    with open_log(path) as f:
        for line in f:
            p = parse_line(line)
            if not p: continue
            ip = p['ip']
            req = p.get('request') or '-'
            parts = req.split()
            if len(parts) >= 2:
                method, path_qs = parts[0], parts[1]
                path_only = path_qs.split('?')[0]
                key = f"{method} {path_only}"
            else:
                key = req
            ip_endpoints[ip][key] += 1
    return ip_endpoints

def suspicious_hits_per_ip(path):
    ip_susp = defaultdict(Counter)
    totals = Counter()
    with open_log(path) as f:
        for line in f:
            p = parse_line(line)
            if not p: continue
            ip = p['ip']
            req = p.get('request') or ''
            m = SUSPICIOUS_RE.search(req)
            if m:
                matched = m.group(0)
                ip_susp[ip][matched] += 1
                totals[ip] += 1
    return ip_susp, totals

def build_report(path):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = f"Relatório automático de logs\nArquivo: {path}\nGerado: {now}\n\n"
    sections = [header]

    # HTTP Status por IP
    ip_status, totals = http_status_per_ip(path)
    if not ip_status:
        sections.append("Nenhuma linha analisável encontrada.\n")
        return "".join(sections)

    all_codes = sorted({code for counts in ip_status.values() for code in counts.keys()})
    sections.append("=== HTTP Status por IP (top 30) ===\n")
    header_line = "IP".ljust(18) + "  " + "  ".join(code.rjust(5) for code in all_codes) + "   TOTAL\n"
    sections.append(header_line)
    sections.append("-" * (len(header_line) + 10) + "\n")
    for ip, _ in totals.most_common(30):
        counts = ip_status[ip]
        line = ip.ljust(18) + "  "
        for code in all_codes:
            line += f"{counts.get(code,0):5d}  "
        line += f"  {totals[ip]:6d}\n"
        sections.append(line)
    sections.append("\n")

    # Total de IPs únicos
    total_ips = len(totals)
    sections.append(f"=== Total de IPs únicos ===\n{total_ips}\n\n")

    # Endpoints por IP (top 10)
    ip_endpoints = endpoints_per_ip(path)
    sections.append("=== Endpoints por IP (top 10 IPs) ===\n")
    for ip, _ in totals.most_common(10):
        sections.append(f"{ip}\n")
        for req, cnt in ip_endpoints[ip].most_common(10):
            sections.append(f"  {cnt:5d}  {req}\n")
        sections.append("\n")

    # Hits em endpoints suspeitos
    ip_susp, susp_totals = suspicious_hits_per_ip(path)
    sections.append("=== Hits em endpoints suspeitos (top 10) ===\n")
    if susp_totals:
        for ip, cnt in susp_totals.most_common(10):
            sections.append(f"{ip}  total_suspeitos={cnt}\n")
            for match, mc in ip_susp[ip].most_common():
                sections.append(f"    {mc:5d}  {match}\n")
            sections.append("\n")
    else:
        sections.append("Nenhum endpoint suspeito detectado.\n\n")

    # Top 5 suspeitos
    suspects = []
    login_counts = Counter()
    with open_log(path) as f:
        for line in f:
            if "POST /login" in line or "POST /wp-login.php" in line:
                p = parse_line(line)
                if p:
                    login_counts[p['ip']] += 1
    if login_counts:
        suspects = [ip for ip, _ in login_counts.most_common(5)]
    else:
        suspects = [ip for ip, _ in totals.most_common(5)]

    sections.append("=== IPs SUSPEITOS PRINCIPAIS (top 5) ===\n")
    for ip in suspects:
        sections.append(f"{ip}\n")
        for req, cnt in ip_endpoints[ip].most_common(20):
            sections.append(f"  {cnt:5d}  {req}\n")
        sections.append("\n")

    sections.append("Fim do relatório.\n")
    return "".join(sections)

def automatic_run_and_export(path, out_dir=None):
    report_text = build_report(path)
    print(report_text)
    if not out_dir:
        out_dir = os.getcwd()
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    out_path = os.path.join(out_dir, f"relatorio_{ts}.txt")
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(report_text)
    print(f"\nRelatório exportado para: {out_path}")

def main():
    path = input("Arquivo de log > ").strip()
    if not path or not os.path.exists(path):
        print("Arquivo não encontrado:", path)
        return
    automatic_run_and_export(path)

if __name__ == '__main__':
    main()

