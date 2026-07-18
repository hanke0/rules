import time
import re
import base64
import urllib.request

def download_content(url):
    response = urllib.request.urlopen(url)
    if response.status != 200:
        raise Exception('error in request %s\n\treturn code: %d' % (url, response.status) )
    return response.read().decode('utf-8')

# ruleType for raw or base64
def get_rule(rules_url, ruleType='raw'):
    content = download_content(rules_url)
    if ruleType == 'base64':
        rule = base64.b64decode(content) \
                .decode("utf-8") \
                .replace('\\n', '\n')
    else:
        rule = content
    return rule


def clear_format(rule):
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


def filtrate_rules(rules, excludes=[]):
    ret = []
    unhandle_rules = []

    for rule in rules:
        rule0 = rule

        # only hostname
        if '/' in rule:
            split_ret = rule.split('/')
            rule = split_ret[0]

        if not re.match(r'^[\w.-]+$', rule):
            unhandle_rules.append(rule0)
            continue

        if rule in excludes:
            continue

        ret.append(rule)

    ret = list(set(ret))
    ret.sort()

    return ret, unhandle_rules

def read_file(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return f.read()

def get_manual_rules(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f.readlines():
            line = line.strip()
            if line.startswith("#") or line == "":
                continue
            yield line

def split_uncomment_lines(content = ''):
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#") or line == "":
            continue
        yield line

def proxy_rules():
    rule = get_rule(rules_url='https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt', ruleType='base64')
    rule += "\n".join(get_manual_rules("include.txt"))
    rules = clear_format(rule)
    excludes = list(get_manual_rules("excludes.txt"))
    rules, unhandle_rules = filtrate_rules(rules, excludes)
    print("unhandled rules:\n--------")
    print("\n".join(unhandle_rules))
    print("--------\n")
    rules = list(set(rules))
    lines = []
    for rule in rules:
        lines.append(f"DOMAIN-SUFFIX,{rule},PROXY")
    return "\n".join(lines)

def direct_rules():
    rule = get_rule('https://raw.githubusercontent.com/mawenjian/china-cdn-domain-whitelist/refs/heads/master/china-top-website-whitelist.txt')
    lines = []
    for line in split_uncomment_lines(rule):
        lines.append(f"DOMAIN-SUFFIX,{line.strip('.')},DIRECT")
    return "\n".join(lines)

def main():
    proxy = proxy_rules()
    direct = direct_rules()
    fmt = read_file("base.txt")
    with open("shadowrocket.conf", "w", encoding="utf-8") as f:
        f.write(f"# update at {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        content = fmt.format(direct=direct, proxy=proxy)
        f.write(content)

    print("Done!")

main()
