# Last Modified: {update_at}

# Usage: add bellow content in your clash.yaml
#rule-providers:
#  direct:
#    behavior: "classical"
#    type: http
#    url: "https://raw.githubusercontent.com/hanke0/rules/refs/heads/main/clash_direct.yaml"
#    format: 'yaml'
#    interval: 3600
#    path: ./direct.yaml
#  proxy:
#    behavior: "classical"
#    type: http
#    url: "https://raw.githubusercontent.com/hanke0/rules/refs/heads/main/clash_proxy.yaml"
#    format: 'yaml'
#    interval: 3600
#    path: ./proxy.yaml
#
#rules:
#  - RULE-SET,direct,REJECT
#  - RULE-SET,proxy,PROXY

payload:
{rules}
