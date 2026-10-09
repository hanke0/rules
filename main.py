#!/usr/bin/env python3
import time
import re
import base64
import urllib.request

# Define your custom HTTP headers
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
}

def download_content(url: str) -> str:
    request = urllib.request.Request(url, headers=headers)
    response = urllib.request.urlopen(request)
    if response.status != 200:
        raise Exception('error in request %s\n\treturn code: %d' % (url, response.status) )
    return response.read().decode('utf-8')

# ruleType for raw or base64
def get_web_rule(rules_url: str, ruleType: str ='raw') -> str:
    content = download_content(rules_url)
    if ruleType == 'base64':
        rule = base64.b64decode(content) \
                .decode("utf-8") \
                .replace('\\n', '\n')
    else:
        rule = content
    return rule


def clear_format(rule: str) -> list[str]:
    rules = []

    rule = rule.split('\n')
    for row in rule:
        row = row.strip()

        # 注释 直接跳过
        if row == '' or row.startswith('!') or row.startswith('@@') or row.startswith('[AutoProxy'):
            continue

        # 清除前缀
        row = re.sub(r'^\|?https?://', '', row)
        row = re.sub(r'^\|\|', '', row)
        row = row.lstrip('.*')

        # 清除后缀
        row = row.rstrip('/^*')

        rules.append(row)

    return rules


def filtrate_rules(rules: list[str]) -> tuple[list[str], list[str]]:
    ret = []
    unhandled_rules = []

    for rule in rules:
        rule0 = rule

        # only hostname
        if '/' in rule:
            split_ret = rule.split('/')
            rule = split_ret[0]

        if not re.match(r'^[\w.-]+$', rule):
            unhandled_rules.append(rule0)
            continue

        ret.append(rule)

    ret = list(set(ret))
    ret.sort()

    return ret, unhandled_rules


def handle_auto_proxy(rule: str, proxyType: str) -> str:
    rules = clear_format(rule)
    rules, unhandled_rules = filtrate_rules(rules)
    print("unhandled rules:\n--------")
    print("\n".join(unhandled_rules))
    print("--------\n")
    rules = list(set(rules))
    lines = []
    for rule in rules:
        lines.append(f"DOMAIN-SUFFIX,{rule},{proxyType}")
    lines.sort()
    return "\n".join(lines)

def handle_rule_set(rule: str, proxyType: str) -> str:
    rules = set()
    for line in split_uncomment_lines(rule):
        rules.add(f"DOMAIN-SUFFIX,{line.strip('.')},{proxyType}")
    rules = list(rules)
    rules.sort()
    return "\n".join(rules)

def read_file(filename: str) -> str:
    with open(filename, "r", encoding="utf-8") as f:
        return f.read()

def get_manual_rules(filename: str) -> iter[str]:
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f.readlines():
            line = line.strip()
            if line.startswith("#") or line == "":
                continue
            yield line

def split_uncomment_lines(content: str = '') -> iter[str]:
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#") or line == "":
            continue
        yield line

def handle_include(content: str) -> str:
    return "\n".join(_handle_include(content))

include_pattern = re.compile(r'^#include (.+)$')

def _handle_include(content: str) -> iter[str]:
    for line in content.splitlines():
        ma = include_pattern.match(line)
        if not ma:
            yield line
            continue
        filename = ma.group(1)
        yield read_file(filename)
        yield "\n"

def update_rule_file(filename: str):
    lines = read_file(filename).splitlines()
    if len(lines) < 2:
        return
    parts = lines[0].lstrip("#").split()
    if len(parts) < 3:
        return
    if parts[0] != 'web':
        return
    fmt = parts[1]
    proxyType = parts[2]
    ruleFmt = "raw"
    if len(parts) >= 4:
        ruleFmt = parts[3]
    url = lines[1].lstrip('#')

    if proxyType != "proxy" and proxyType != "direct":
        raise ValueError(f"invalid proxy type: {proxyType}")

    proxyType = proxyType.upper()
    content = get_web_rule(url, ruleFmt)
    if fmt == "AutoProxy":
        content = handle_auto_proxy(content, proxyType)
    elif fmt == "rule-set":
        content = handle_rule_set(content, proxyType)
    else:
        raise ValueError(f"unknown format: {fmt}")

    with open(filename, 'w', encoding="utf-8") as f:
        f.write(lines[0])
        f.write("\n")
        f.write(lines[1])
        f.write("\n\n")
        f.write(content)
        f.write("\n")

def update_all_rule_files() -> None:
    files = (
        "cn.list",
        "gfw.list",
        "hk-broker.list",
        "telegram.list",
    )
    for file in files:
        print(f"update rule start: {file}")
        update_rule_file(file)
        print(f"update rule finish: {file}")

def main():
    update_all_rule_files()
    fmt = read_file("base.tpl")
    content = handle_include(fmt)
    with open("shadowrocket.conf", "w", encoding="utf-8") as f:
        f.write(f"# update at {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(content)

    print("Done!")

if __name__ == '__main__':
    main()
