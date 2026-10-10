#!/usr/bin/env python3
import base64
import re
import time
import urllib.request
from dataclasses import dataclass, field

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
}
REQUEST_TIMEOUT = 30

RULE_FILES = (
    "ai.list",
    "gfw.list",
    "hk-broker.list",
    "linkedin.list",
    "telegram.list",
    "cn.list",
)

PROXY_TYPES = ("proxy", "direct")
RULE_TYPES = ("DOMAIN-SUFFIX", "DOMAIN", "DOMAIN-KEYWORD", "IP-CIDR", "IP-ASN")
AUTO_PROXY_SKIP_PREFIXES = ("!", "@@", "[AutoProxy")
URL_SCHEME_PATTERN = re.compile(r"^\|?https?://")
DOMAIN_ANCHOR_PATTERN = re.compile(r"^\|\|")
IP_CIDR_COLON_PATTERN = re.compile(r"^ip-cidr:", re.IGNORECASE)
HOSTNAME_PATTERN = re.compile(r"^[\w.-]+$")


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


def print_unhandled_lines(lines: list[str]) -> None:
    if not lines:
        return
    print("unhandled rules:\n--------")
    print("\n".join(lines))
    print("--------\n")


def normalize_auto_proxy_rules(content: str) -> list[str]:
    rules = []
    for row in content.splitlines():
        row = row.strip()
        if not row or row.startswith(AUTO_PROXY_SKIP_PREFIXES):
            continue
        row = URL_SCHEME_PATTERN.sub("", row)
        row = DOMAIN_ANCHOR_PATTERN.sub("", row)
        rules.append(row.lstrip(".*").rstrip("/^*"))
    return rules


def split_hostnames(rules: list[str]) -> tuple[set[str], list[str]]:
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
    hostnames, unhandled = split_hostnames(normalize_auto_proxy_rules(content))
    print_unhandled_lines(unhandled)
    lines = [format_rule(h, proxy_type) for h in hostnames if h not in excludes]
    return "\n".join(sorted(lines))


def handle_domains(content: str, proxy_type: str, excludes: set[str]) -> str:
    seen = set()
    lines = []
    for line in content.splitlines():
        if not line.strip():
            continue
        if line.startswith("#"):
            lines.append(line)
            continue
        domain = line.strip(".") if line.count(".") > 1 else line
        if domain in excludes or domain in seen:
            continue
        seen.add(domain)
        lines.append(format_rule(domain, proxy_type))
    return "\n".join(lines)


def handle_surge(content: str, proxy_type: str, excludes: set[str]) -> str:
    lines = []
    unhandled = []
    for line in content.splitlines():
        if not line.strip():
            continue
        if line.startswith("#"):
            lines.append(line)
            continue
        line = IP_CIDR_COLON_PATTERN.sub("IP-CIDR,", line)
        parts = line.split(",")
        if len(parts) < 2:
            unhandled.append(line)
            continue
        rule_type, domain, *options = parts
        if domain in excludes:
            continue
        if rule_type not in RULE_TYPES:
            unhandled.append(line)
            continue
        suffix = f",{options[0]}" if options else ""
        lines.append(f"{rule_type},{domain},{proxy_type}{suffix}")
    print_unhandled_lines(unhandled)
    return "\n".join(lines)


FORMAT_HANDLERS = {
    "AutoProxy": handle_auto_proxy,
    "domains": handle_domains,
    "surge": handle_surge,
}


@dataclass
class RuleSource:
    """Source declared in a rule file header:

    #web <format> <proxy|direct> [raw|base64]
    #<url>
    #ignore <domain>[,<domain>...]   (optional, repeatable)
    """

    fmt: str
    proxy_type: str
    encoding: str
    url: str
    header: list[str]
    excludes: set[str] = field(default_factory=set)


def parse_rule_source(lines: list[str]) -> RuleSource | None:
    if len(lines) < 2:
        return None
    parts = lines[0].lstrip("#").split()
    if len(parts) < 3 or parts[0] != "web":
        return None
    fmt, proxy_type = parts[1], parts[2]
    if proxy_type not in PROXY_TYPES:
        raise ValueError(f"invalid proxy type: {proxy_type}")
    if fmt not in FORMAT_HANDLERS:
        raise ValueError(f"unknown format: {fmt}")

    source = RuleSource(
        fmt=fmt,
        proxy_type=proxy_type,
        encoding=parts[3] if len(parts) >= 4 else "raw",
        url=lines[1].lstrip("#"),
        header=lines[:2],
    )
    for line in lines[2:]:
        if not line.startswith("#ignore"):
            break
        source.header.append(line)
        source.excludes.update(d.strip() for d in line.removeprefix("#ignore").split(","))
    return source


def update_rule_file(filename: str) -> None:
    source = parse_rule_source(read_file(filename).splitlines())
    if source is None:
        return
    handler = FORMAT_HANDLERS[source.fmt]
    content = handler(
        get_web_rule(source.url, source.encoding),
        source.proxy_type.upper(),
        source.excludes,
    )
    write_file(filename, "\n".join(source.header) + "\n\n" + content + "\n")


def update_all_rule_files() -> None:
    for filename in RULE_FILES:
        print(f"update rule start: {filename}")
        update_rule_file(filename)
        print(f"update rule finish: {filename}")


def update_shadowrocket_config():
    tpl = read_file("shadowrocket.tpl")
    rules = []
    for file in RULE_FILES:
        rules.append(read_file(file))
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    content = tpl.format(rules="\n".join(rules).lstrip(), update_at=timestamp)
    write_file("shadowrocket.conf", content)


def convert_to_clash_rule_set(rule: str) -> tuple[str, str]:
    proxy_rules = []
    direct_rules = []
    unhandled_rules = []
    for line in rule.splitlines():
        line = line.strip()
        if line == "" or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 3:
            unhandled_rules.append(line)
            continue
        rule_type, domain, proxy_type, *options = parts
        option = f",{options[0]}" if options else ""
        clash_rule_line = f"  - {rule_type},{domain}{option}"
        if proxy_type == "DIRECT":
            direct_rules.append(clash_rule_line)
        elif proxy_type == "PROXY":
            proxy_rules.append(clash_rule_line)
        else:
            unhandled_rules.append(line)
            continue
    print_unhandled_lines(unhandled_rules)
    return ("\n".join(proxy_rules), "\n".join(direct_rules))


def update_clash_config():
    tpl = read_file("clash.tpl")
    direct_rules: list[str] = []
    proxy_rules: list[str] = []
    for file in RULE_FILES:
        proxy, direct = convert_to_clash_rule_set(read_file(file))
        proxy_rules.append(proxy)
        direct_rules.append(direct)

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    write_file("clash_direct.yaml", tpl.format(rules="\n".join(direct_rules).lstrip(), update_at=timestamp))
    write_file("clash_proxy.yaml", tpl.format(rules="\n".join(proxy_rules).lstrip(), update_at=timestamp))


def main() -> None:
    update_all_rule_files()
    update_shadowrocket_config()
    update_clash_config()
    print("Done!")


if __name__ == "__main__":
    main()
