#!/usr/bin/env python3
import base64
import re
import time
import urllib.request

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
}
REQUEST_TIMEOUT = 30

RULE_FILES = (
    "cn.list",
    "gfw.list",
    "hk-broker.list",
    "telegram.list",
    "linkedin.list",
)
TEMPLATE_FILE = "base.tpl"
OUTPUT_FILE = "shadowrocket.conf"

PROXY_TYPES = ("proxy", "direct")
AUTO_PROXY_SKIP_PREFIXES = ("!", "@@", "[AutoProxy")
HOSTNAME_PATTERN = re.compile(r"^[\w.-]+$")
INCLUDE_PATTERN = re.compile(r"^#include (.+)$")


def read_file(filename: str) -> str:
    with open(filename, "r", encoding="utf-8") as f:
        return f.read()


def write_file(filename: str, content: str) -> None:
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)


def download_content(url: str) -> str:
    request = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        return response.read().decode("utf-8")


def get_web_rule(url: str, encoding: str = "raw") -> str:
    content = download_content(url)
    if encoding == "base64":
        return base64.b64decode(content).decode("utf-8").replace("\\n", "\n")
    return content


def format_rule(domain: str, proxy_type: str) -> str:
    return f"DOMAIN-SUFFIX,{domain},{proxy_type}"


def clear_format(content: str) -> list[str]:
    rules = []
    for row in content.splitlines():
        row = row.strip()
        if not row or row.startswith(AUTO_PROXY_SKIP_PREFIXES):
            continue
        row = re.sub(r"^\|?https?://", "", row)
        row = re.sub(r"^\|\|", "", row)
        rules.append(row.lstrip(".*").rstrip("/^*"))
    return rules


def filtrate_rules(rules: list[str]) -> tuple[set[str], list[str]]:
    hostnames = set()
    unhandled = []
    for rule in rules:
        hostname = rule.split("/", 1)[0]
        if HOSTNAME_PATTERN.match(hostname):
            hostnames.add(hostname)
        else:
            unhandled.append(rule)
    return hostnames, unhandled


def handle_auto_proxy(content: str, proxy_type: str, excludes: set[str]) -> str:
    hostnames, unhandled = filtrate_rules(clear_format(content))
    print("unhandled rules:\n--------")
    print("\n".join(unhandled))
    print("--------\n")
    lines = [format_rule(h, proxy_type) for h in hostnames if h not in excludes]
    return "\n".join(sorted(lines))


def handle_domains(content: str, proxy_type: str, excludes: set[str]) -> str:
    seen = set()
    lines = []
    for domain in content.splitlines():
        if domain.startswith("#"):
            lines.append(domain)
            continue
        if domain.count(".") > 1:
            domain = domain.strip(".")
        if domain in excludes or domain in seen:
            continue
        seen.add(domain)
        lines.append(format_rule(domain, proxy_type))
    return "\n".join(sorted(lines))


def handle_surge(content: str, proxy_type: str, excludes: set[str]) -> str:
    lines = []
    for line in content.splitlines():
        if line.startswith("#"):
            lines.append(line)
            continue
        parts = line.split(",")
        if len(parts) < 2:
            continue
        rule_type, domain, *options = parts
        if domain in excludes:
            continue
        suffix = f",{options[0]}" if options else ""
        lines.append(f"{rule_type},{domain},{proxy_type}{suffix}")
    return "\n".join(lines)


FORMAT_HANDLERS = {
    "AutoProxy": handle_auto_proxy,
    "domains": handle_domains,
    "surge": handle_surge,
}


def update_rule_file(filename: str) -> None:
    """Regenerate a rule file from the source declared in its header:

    #web <format> <proxy|direct> [raw|base64]
    #<url>
    #ignore <domain>[,<domain>...]   (optional, repeatable)
    """
    lines = read_file(filename).splitlines()
    if len(lines) < 2:
        return
    parts = lines[0].lstrip("#").split()
    if len(parts) < 3 or parts[0] != "web":
        return
    fmt, proxy_type = parts[1], parts[2]
    encoding = parts[3] if len(parts) >= 4 else "raw"
    url = lines[1].lstrip("#")

    if proxy_type not in PROXY_TYPES:
        raise ValueError(f"invalid proxy type: {proxy_type}")
    handler = FORMAT_HANDLERS.get(fmt)
    if handler is None:
        raise ValueError(f"unknown format: {fmt}")

    header = lines[:2]
    excludes = set()
    for line in lines[2:]:
        if not line.startswith("#ignore"):
            break
        header.append(line)
        excludes.update(d.strip() for d in line.removeprefix("#ignore").split(","))

    content = handler(get_web_rule(url, encoding), proxy_type.upper(), excludes)
    write_file(filename, "\n".join(header) + "\n\n" + content + "\n")


def update_all_rule_files() -> None:
    for filename in RULE_FILES:
        print(f"update rule start: {filename}")
        update_rule_file(filename)
        print(f"update rule finish: {filename}")


def expand_includes(content: str) -> str:
    lines = []
    for line in content.splitlines():
        match = INCLUDE_PATTERN.match(line)
        if match:
            lines.append(read_file(match.group(1)))
            lines.append("\n")
        else:
            lines.append(line)
    return "\n".join(lines)


def main() -> None:
    update_all_rule_files()
    content = expand_includes(read_file(TEMPLATE_FILE))
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    write_file(OUTPUT_FILE, f"# update at {timestamp}\n\n{content}")
    print("Done!")


if __name__ == "__main__":
    main()
