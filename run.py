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

        if not re.match('^[\w.-]+$', rule):
            unhandle_rules.append(rule0)
            continue

        if rule in excludes:
            continue

        ret.append(rule)

    ret = list( set(ret) )
    ret.sort()

    return ret, unhandle_rules

def getURLs(url):
    r = requests.get(url)
    return r.text.split("\n")[:-1]

def get_manual_rules(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f.readlines():
            line = line.strip()
            if line.startswith("#") or line == "":
                continue
            yield line

def main():
    rule = get_rule(rules_url='https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt', ruleType='base64')
    rule += "\n".join(get_manual_rules("include.txt"))
    rules = clear_format(rule)
    excludes = list(get_manual_rules("excludes.txt"))

    rules, unhandle_rules = filtrate_rules(rules, excludes)
    rules = list(set(rules))

    with open("gfw.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(rules))

    with open("gfw_unhandle.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(unhandle_rules))

if __name__ == "__main__":
    main()
