
# -*- coding:utf-8 -*-
#/**********************************************************************/
#/*           The Author          :    Gerron Jo (zzydog)              */
#/*           Codding Time        :    2017/03/03,18:04:20             */
#/**********************************************************************/
#
# Description :
#     pacgen is a python script which converts the gfwlist to pac file.
# There are two types of rules in the generated pac file, one is domain
# rule, the other is keyword rule.
#
# Here is the domain rule format:
# domain : [opcode, params, return]
# e.g. 'google.com' : [1, '/account', proxy]
# It means return the proxy if '/account' can be found in the url.
#
# Here is the keyword rule format:
# [opcode, params, return] -> It's an array object for javascript.
#
# Opcode -> |
#      0 -> check if it's the host ifself
#      1 -> check ip range (for domain name)
#      2 -> check domain level (for domain name)
#      3 -> search sub-string in the url (use 'indexOf')
#      4 -> search for a shell pattern in the url (shExpMatch)
#      5 -> search for a regx pattern in the url (RegExp.test)
# Return -> |
#      0 -> null      -> default
#      5 -> drop      -> drop the request (block malware sites)
#      2 -> proxy     -> connect with the proxy
#      1 -> direct    -> return directly (local gateway)
#      3 -> random    -> select from the proxylist randomly 
#      4 -> anonymous -> connect with the anonymous proxy (i2p or tor)
#

from datetime import datetime
from urllib.parse import urlparse
from argparse import ArgumentParser
import sys, json, gzip, base64, string, urllib.request

_pacfile = 'https://rawgit.com/zzydog/iepro/master/pacgen.pac'
_gfwlist = 'https://rawgit.com/gfwlist/gfwlist/master/gfwlist.txt'
_template = """
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
"""

#----------------------------------------------------------------------
def command():
    """"""
    parser = ArgumentParser()

    parser.add_argument(
        '-o', '--output', required=True,
        dest='output', default='pacgen.pac',  metavar='PAC FILE', 
        help="specify the location to store the generated pac file"
    )

    parser.add_argument(
        '--proxy-drop', 
        dest='drop', default='PROXY 0.0.0.0:9999', 
        type=lambda s: str(s).upper(), metavar='DROP HOST', 
        help="specify the proxy server to handle the request you drop"
    )
    parser.add_argument(
        '--proxy-tunnel', 
        dest='proxy', 
        default=['PROXY 127.0.0.1:8080', 'SOCKS 127.0.0.1:1080'], 
        type=lambda s: str(s).upper(), metavar='PROXY HOST', nargs='+',
        help="specify the proxy server (at least two proxies: http+socks)", 
    )
    parser.add_argument(
        '--proxy-direct', 
        dest='direct', default='DIRECT', 
        type=lambda s: str(s).upper(), metavar='LOCAL HOST',
        help="specify the local host to connect to the internet directly", 
    )

    parser.add_argument(
        '--proxy-list', 
        dest='proxy_url', default=None, type=str,
        help="specify the proxy list url address", metavar='PROXY LIST URL'
    )
    parser.add_argument(
        '--proxy-file', 
        dest='proxy_file', default=None, type=str,
        help="specify the proxy list file location", metavar='PROXY LIST FILE'
    )

    parser.add_argument(
        '--gfwlist-url', 
        dest='gfwlist_url', default='default', type=str,
        help="specify the gfwlist url address", metavar='GFWLIST URL'
    )
    parser.add_argument(
        '--gfwlist-file', 
        dest='gfwlist_file', default=None, type=str,
        help="specify the gfwlist file location", metavar="GFWLIST FILE"
    )
    parser.add_argument(
        '--userlist-url', 
        dest='userlist_url', default=None, type=str,
        help="specify the userlist url address", metavar='USERLIST URL'
    )
    parser.add_argument(
        '--userlist-file', 
        dest='userlist_file', default=None, type=str,        
        help="specify the userlist file location", metavar='USERLIST FILE'
    )
    return parser.parse_args()


#----------------------------------------------------------------------
def getlist(listurl=None):
    """"""
    agent = 'Mozilla/5.0 (Windows NT 6.1; Trident/7.0) like Gecko'
    reffer = 'https://www.google.com/'
    request = urllib.request.Request(listurl)
    request.add_header('Accept', '*/*')
    request.add_header('Referer', reffer)
    request.add_header('User-Agent', agent)
    request.add_header('Accept-Language', 'en-US')
    request.add_header('Accept-Encoding', 'gzip, deflate')
    resp = urllib.request.urlopen(request)
    gfwlist = resp.read(); charset = 'utf-8'
    encoding = resp.headers.get('Content-Encoding')
    if encoding == 'gzip': gfwlist = gzip.decompress(gfwlist)
    try:
        ctype = self._headers.get('Content-Type')
        for item in ctype.split(';'):
            k, v = item.split('=')
            if k.strip().lower() == 'charset': charset = v.strip(); break
    except: pass
    try:
        return base64.b64decode(
            gfwlist.decode(charset)).decode('utf-8')
    except LookupError: 
        if charset == 'utf-8': raise
        else:
            try:
                return base64.b64decode(
                    gfwlist.decode('utf-8')).decode('utf-8')
            except: 
                raise ValueError("Can not decode the payload with 'utf-8'")
    except Exception: 
        raise ValueError("Can not decode the gfwlist with '{}'".format(charset))


#----------------------------------------------------------------------
def gfwlist(data, direct=1, proxy=2):
    """"""
    domains = {}
    keywords = set()
    select = domain = rule = None

    for rule in data.splitlines():
        # '.google.com' -> 'google.com'
        rule = rule.strip() # strip first

        if not rule: continue   # empty rule
        rule = '*' + rule if rule[0] == '.' else rule

        # '/.../' -> regular expression ()
        if rule[0] == rule[-1] == '/': 
            keywords.add((5, rule[1:-1], proxy)); continue
        # '\...\' -> regular expression ()
        if rule[0] == rule[-1] == '\\': 
            keywords.add((5, rule[1:-1], proxy)); continue

        # [AutoProxy 0.2.9] -> version section
        if rule[0] == '[' and rule[-1] == ']':
            print("[pacgen] gfwlist vers: {}".format(rule))
            continue
        # ! Checksum: zCCNfRC2esEetsQhBgrang ->comments
        if rule.startswith('!'): 
            print("[pacgen] gfwlist info: {}".format(rule.strip()))
            continue

        if rule.startswith('||'):       # ||www.google*.com
            rule = rule.lstrip('| '); select = proxy; flag = '||'
        elif rule.startswith('|'):      # |https://www.google*.com
            rule = rule.lstrip('| '); select = proxy; flag = '|'
        elif rule.startswith('@@||'):   # @@||www.google*.com
            rule = rule.lstrip('@| '); select = direct; flag = '@|'
        elif rule.startswith('@@|'):    # @@|https://www.google*.com
            rule = rule.lstrip('@| '); select = direct; flag = '@@|'
        else:
            rule = rule.lstrip(); select = proxy; flag = None # default


        # Note: here we support endswith -> google.com|
        def ruleexp(rule):
            if '*' in rule:
                if rule.endswith('|') is False:
                    return 4, '*' + rule.strip('*') + '*'
                else:
                    return 4, '*' + rule.lstrip('*').rstrip('|')
            else: return 3, rule.rstrip('|')

        # Extract the domain part
        rule = rule.replace('%2F', '/')
        scheme, domain, *arg = urlparse(rule)
        if domain: remain = ''.join(arg)
        else: domain, _, remain = rule.partition('/')

        # It's definitely a keyword
        if '.' not in domain: 
            keywords.add((*ruleexp(rule), select)); continue

        # Find the domain without '*'
        pos = domain.rfind('*')
        if pos < 0: parent = domain; strip = ''
        else:
            pos = domain.find('.', pos)
            strip = domain; parent = None
            if pos >= 0 and pos < len(domain)-1: 
                parent = domain[pos+1:]; strip = domain[:pos]

        # here, we can't extract the domain, so we save
        # it as a keyword. e.g. google*.c*
        if parent is None: 
            keywords.add((*ruleexp(rule), select))
        elif scheme or remain:
            domains.setdefault(
                parent, set()).add((*ruleexp(rule), select))
        else: 
            # ipv*.google.com -> ipv (not empty)
            if strip.strip('*.'):
                domains.setdefault(
                    parent, set()).add((*ruleexp(rule), select))
            # *.*.*.google.com -> '' (it's empty)
            elif '*' in domain:
                # range -> 0 ~ 32767 (0x7fff)
                lvl = domain.count('.') & 0x7f | 0x7f00
                domains.setdefault(parent, set()).add((2, lvl, select))
            # google.com
            else:
                domains.setdefault(parent, set()).add((0, None, select))

    # optimization
    for metalist in domains.values():
        force_proxy = force_direct = False
        proxy_set = set(); direct_set = set()
        while len(metalist):
            meta = metalist.pop()
            if meta == (0, None, proxy): force_proxy = True
            elif meta == (0, None, direct): force_direct = True
            elif meta[2] == proxy: proxy_set.add(meta)
            elif meta[2] == direct: direct_set.add(meta)
        if force_proxy is True: metalist.add((0, None, proxy))
        else: metalist.update(proxy_set)
        if force_direct is True: metalist.add((0, None, direct))
        else: metalist.update(direct_set)

    return domains, keywords


#----------------------------------------------------------------------
def pymain(args):
    """"""
    domains = {}; keywords = []; proxies = []

    try:
        # check the proxy infomation.
        if not args.drop:
            raise ValueError("'--proxy-drop' can't be empty!")
        if not args.proxy:
            raise ValueError("'--proxy-tunnel can't be empty!")
        else: args.proxy = '; '.join(args.proxy)
        if not args.direct:
            raise ValueError("'--proxy-direct can't be empty!")
    except Exception as exc: 
        print("[pacgen proxy] {}".format(exc)); print('crash'); return

    try:
        # load user list
        if args.userlist_file:
            with open(args.userlist_file) as file:
                domains = json.loads(file.read()) ##
        elif args.userlist_url:
            domains = json.loads(getlist(args.userlist_url))
    except Exception as exc: 
        print("[pacgen userlist] {}".format(exc)); print('crash'); return

    try:
        # now load gfw list
        _domains = _keywords = None
        if args.gfwlist_file:
            with open(args.gfwlist_file) as file:
                _domains, _keywords = gfwlist(file.read())
        elif args.gfwlist_url: 
            _domains, _keywords = gfwlist(getlist(args.gfwlist_url))
        if _keywords is not None: 
            _keywords.update(keywords); keywords = _keywords
        if _domains is not None:
            for k, m in domains.items(): _domains[k].update(m)
            domains = dict([(k,list(m)) for k,m in _domains.items()])
    except Exception as exc: 
        print("[pacgen gfwlist] {}.".format(exc)); print('crash'); return

    try:
        # now load the proxy list
        if args.proxy_file:
            with open(args.proxy_file) as file:
                proxies = [s.strip() for s in file.readlines()]
        elif args.proxy_url:
            proxies = [
                s.strip() for s in getlist(args.proxy_url).splitlines()]
    except Exception as exc: 
        print("[pacgen proxylist] {}.".format(exc)); print('crash'); return

    try:
        if not args.output:
            raise ValueError("you must specify the pac file location!")
        with open(args.output, 'w+') as file:
            # here, we try to beautify the js code.
            proxylist = "[\n" + ",\n".join([
                "\t{}".format(json.dumps(proxy)) for proxy in proxies
            ]) + "\n]"
            domainlist = "{\n" + ",\n".join([
                "\t{}: {}".format(
                    json.dumps(d),json.dumps(m)) for d,m in domains.items()
            ]) + "\n}"
            keywordlist = "[\n" + ",\n".join([
                "\t{}".format(json.dumps(keyword)) for keyword in keywords
            ]) + "\n]"
            # extract the template (gzip + base64).
            template = gzip.decompress(
                base64.b64decode(_template)).decode('utf-8')
            drop = json.dumps(args.drop)
            proxy = json.dumps(args.proxy)
            direct = json.dumps(args.direct)
            file.write(
                string.Template(template).substitute(
                    gentime=str(datetime.now()),
                    drop=drop, proxy=proxy, direct=direct, 
                    proxylist=proxylist, domainlist=domainlist, keywordlist=keywordlist,
                )
            )
    except Exception as exc: 
        print("[pacgen generator] {}.".format(exc)); print('crash'); return

    print("[pacgen task] done, generate the pac file successfully, now exit")
    
    
if __name__ == '__main__':  pymain(command())