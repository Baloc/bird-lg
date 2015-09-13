#!/usr/bin/env python3
#
# Copyright (c) 2012 Mehdi Abaakouk
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
###

import json
import logging
import random
import re
import subprocess
from collections import defaultdict
from functools import cmp_to_key
from logging.handlers import TimedRotatingFileHandler

import memcache
import pydot_ng as pydot
import requests
from flask import Flask, render_template, jsonify, redirect, session, request, abort, Response
from dns.exception import DNSException
from dns.resolver import NXDOMAIN
from requests.compat import unquote

from toolbox import mask_is_valid, ipv6_is_valid, ipv4_is_valid, resolve, get_asname_from_whois, resolve_ptr

app = Flask(__name__)
app.config.from_pyfile('lg.cfg')
app.secret_key = app.config['SESSION_KEY']
app.debug = app.config.get('DEBUG', False)

file_handler = TimedRotatingFileHandler(filename=app.config['LOG_FILE'], when='midnight')
file_handler.setLevel(getattr(logging, app.config['LOG_LEVEL'].upper()))
app.logger.addHandler(file_handler)

memcache_server = app.config.get('MEMCACHE_SERVER', '127.0.0.1:11211')
memcache_expiration = int(app.config.get('MEMCACHE_EXPIRATION', '1296000'))  # 15 days by default
mc = memcache.Client([memcache_server])


def get_asn_from_as(n):
    asn_zone = app.config.get('ASN_ZONE', 'asn.cymru.com')
    try:
        data = resolve("AS%s.%s" % (n, asn_zone), 'TXT').replace('\'', '').replace('"', '')
    except DNSException:
        return " " * 5
    return [field.strip() for field in data.split("|")]


def enrich_text(plain):
    """
    Enriches text output by adding html links to `whois` objects
    :param plain: plain text
    :return: html enriched text
    """

    if type(plain) is str:
        plain = plain.split('\n')

    enriched = []
    for line in plain:
        line = line.strip()

        # don't interpret the following lines
        #   Neighbor caps:    refresh AS4
        #   Session:          external AS4
        if line.startswith(('Neighbour caps:', 'Session:')):
            continue

        # add links to the as numbers
        #   BGP.as_path: 65038 49009
        #   Neighbor AS:      64858
        if line.startswith(('BGP.as_path:', 'Neighbor AS:')):
            enriched.append(re.sub(r'(\d+)', r'<a href="/whois/\1" class="whois">\1</a>', line))
        else:
            # Domain?
            line = re.sub(r'([a-zA-Z0-9\-]*\.([a-zA-Z]{2,3}){1,2})(\s|$)',
                          r'<a href="/whois/\1" class="whois">\1</a>\3', line)

            # ASN12345
            line = re.sub(r'AS(\d+)', r'<a href="/whois/\1" class="whois">AS\1</a>', line)

            # TODO: where does this appear?
            line = line.replace(' unreachable ', '\n', 1)

            # IPv4 address
            line = re.sub(r'(\d+\.\d+\.\d+\.\d+)', r'<a href="/whois/\1" class="whois">\1</a>', line)

            # IPv6 address
            line = re.sub(r'(^|\s+)(([a-f\d]{0,4}:){3,10}[a-f\d]{0,4})',
                          r'\1<a href="/whois/\2" class="whois">\2</a>', line, re.I)

            # TODO: date/time? where does this appear?
            hosts = '/'.join(request.path.split('/')[2:])
            line = re.sub(r'\[(\w+)\s+((|\d\d\d\d-\d\d-\d\d\s)(|\d\d:)\d\d:\d\d|\w\w\w\d\d)',
                          r'[<a href="/detail/%s?q=\1">\1</a> \2' % hosts, line)

            enriched.append(line)

    return '\n'.join(enriched)


def set_session(request_type, hosts, proto, request_args):
    """ Store all data from user in the user session """
    session.permanent = True
    session.update({
        'request_type': request_type,
        'hosts': hosts,
        'proto': proto,
        'request_args': request_args,
    })
    history = session.get('history', [])

    # erase old format history
    if not isinstance(history, list):
        history = []

    key = (hosts, proto, request_type, request_args)
    if key in history:
        del history[history.index(key)]
    history.insert(0, key)
    session['history'] = history[:20]


def whois_command(query):
    cmd = ['whois']

    # use a custom whois server, defaults to settings in /etc/whois.conf
    if app.config.get('WHOIS_SERVER', False):
        cmd.extend(["-h", app.config.get('WHOIS_SERVER')])

    cmd.append(query)

    return subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0].decode('utf-8', 'ignore')


def bird_command(host, proto, query):
    """
    Alias to bird_proxy for bird service
    """
    return bird_proxy(host, proto, 'bird', query)


def bird_proxy(host, proto, service, query):
    """
    Retrieve data from a remote lgproxy instance
    :param host: remote address
    :param proto: internet protocol version
    :param service: bird/ping/traceroute
    :param query: service-specific parameters
    :return: tuple containing status and response
    """

    path = None
    if proto == 'ipv6':
        path = '{}6'.format(service)
    elif proto == 'ipv4':
        path = service

    port = app.config['PROXY'].get(host, False)

    if not port:
        return False, 'Invalid host: "{}"'.format(host)
    elif not path:
        return False, 'Invalid proto: "{}"'.format(proto)
    else:
        url = 'http://{host}:{port}/{endpoint}'.format(host=app.config['ROUTER_IP'][host][0],
                                                       port=port,
                                                       endpoint=path)
        params = {'quote': query}
        try:
            response = requests.get(url, params=params)
            result = response.text
            status = response.status_code == 200
        except IOError:
            result = "Failed retreive url: %s" % url
            status = False

        return status, result


@app.context_processor
def inject_commands():
    commands = [
        ('ping', 'ping ...'),
        ('traceroute', 'traceroute ...'),
        ('summary', 'show protocols'),
        ('detail', 'show protocols ... all'),
        ('prefix', 'show route for ...'),
        ('prefix_detail', 'show route for ... all'),
        ('prefix_bgpmap', 'show route for ... (bgpmap)'),
        ('where', 'show route where net ~ [ ... ]'),
        ('where_detail', 'show route where net ~ [ ... ] all'),
        ('where_bgpmap', 'show route where net ~ [ ... ] (bgpmap)'),
        ('adv', 'show route ...'),
        ('adv_bgpmap', 'show route ... (bgpmap)'),
    ]
    commands_dict = {cmd: tooltip for cmd, tooltip in commands}

    return dict(commands=commands, commands_dict=commands_dict)


@app.context_processor
def inject_all_host():
    return dict(all_hosts='+'.join(app.config['PROXY'].keys()))


@app.route('/')
def hello():
    return redirect("/summary/{routers}/ipv4".format(routers='+'.join(app.config['PROXY'].keys())))


@app.errorhandler(500)
def error_page(text):
    return render_template('error.html', errors=[text]), 500


@app.errorhandler(400)
def incorrect_request(_):
        return render_template('error.html', warnings=['The server could not understand the request']), 400


@app.errorhandler(404)
def page_not_found(_):
        return render_template('error.html', warnings=['The requested URL was not found on the server.']), 404


def get_query_string():
    return unquote(request.args.get('q', '').strip())


@app.route('/whois')
def whois():
    query = get_query_string()
    if not query:
        abort(400)

    try:
        asn = int(query)
        query = "AS{}".format(asn)
    except ValueError:
        match = re.match(r'[\w\d-]*\.(?P<domain>[\d\w-]+\.[\d\w-]+)$', query)
        if match:
            query = match.groupdict()['domain']

    response = whois_command(query).replace('\n', '<br>')
    return jsonify(output=response, title=query)


SUMMARY_UNWANTED_PROTOS = ['Kernel', 'Static', 'Device']


@app.route('/summary/<routers>')
@app.route('/summary/<routers>/<proto>')
def summary(routers, proto='ipv4'):

    set_session('summary', routers, proto, '')
    command = 'show protocols'

    summary = {}
    errors = []
    for router in routers.split("+"):
        ret, res = bird_command(router, proto, command)
        res = res.split("\n")

        if ret is False:
            errors.append("%s" % res)
            continue

        if len(res) <= 1:
            errors.append("%s: bird command failed with error, %s" % (router, "\n".join(res)))
            continue

        data = []
        for line in res[1:]:
            line = line.strip()
            if line and (line.split() + [""])[1] not in SUMMARY_UNWANTED_PROTOS:
                split = line.split()
                if len(split) >= 5:
                    props = dict()
                    props['name'] = split[0]
                    props['proto'] = split[1]
                    props['table'] = split[2]
                    props['state'] = split[3]
                    props['since'] = split[4]
                    props['info'] = ' '.join(split[5:]) if len(split) > 5 else ''
                    data.append(props)
                else:
                    app.logger.warning("couldn't parse: {}".format(line))

        summary[router] = data

    return render_template('summary.html', summary=summary, command=command, errors=errors)


@app.route('/detail/<routers>/<proto>')
def detail(routers, proto):
    protocol = get_query_string()

    if not protocol:
        abort(400)

    set_session('detail', routers, proto, protocol)
    command = 'show protocols all {protocol}'.format(protocol=protocol)

    detail = {}
    errors = []
    for host in routers.split('+'):
        ret, res = bird_command(host, proto, command)
        res = res.splitlines()

        if ret is False:
            errors.append("%s" % res)
            continue

        if len(res) <= 1:
            errors.append("%s: bird command failed with error, %s" % (host, "\n".join(res)))
            continue

        detail[host] = {"status": res[1], "description": enrich_text(res[2:])}

    return render_template('detail.html', detail=detail, command=command, errors=errors)


@app.route('/ping/<routers>/<proto>')
def ping(routers, proto):
    host = get_query_string()

    if not host:
        abort(400)

    set_session("ping", routers, proto, host)

    if proto == "ipv6" and not ipv6_is_valid(host):
        try:
            host = resolve(host, "AAAA")
        except DNSException:
            return error_page("%s is unresolvable or invalid for %s" % (host, proto))
    if proto == "ipv4" and not ipv4_is_valid(host):
        try:
            host = resolve(host, "A")
        except DNSException:
            return error_page("%s is unresolvable or invalid for %s" % (host, proto))

    errors = []
    infos = {}
    for host in routers.split("+"):
        status, resultat = bird_proxy(host, proto, "ping", host)
        if status is False:
            errors.append("%s" % resultat)
            continue

        infos[host] = enrich_text(resultat)
    return render_template('ping.html', infos=infos, errors=errors)


@app.route('/traceroute/<routers>/<proto>')
def traceroute(routers, proto):
    host = get_query_string()

    if not host:
        abort(400)

    set_session('traceroute', routers, proto, host)

    if proto == 'ipv6' and not ipv6_is_valid(host):
        try:
            host = resolve(host, 'AAAA')
        except DNSException:
            return error_page("Unable to resolve host \"{host}\" (AAAA).".format(host=host))
    elif proto == 'ipv4' and not ipv4_is_valid(host):
        try:
            host = resolve(host, 'A')
        except DNSException:
            return error_page("Unable to resolve host \"{host}\" (A).".format(host=host))
    else:
        abort(400)

    errors = []
    infos = {}
    for host in routers.split("+"):
        status, response = bird_proxy(host, proto, 'traceroute', host)
        if not status:
            errors.append(response)
            continue

        infos[host] = enrich_text(response)

    return render_template('traceroute.html', infos=infos, errors=errors)


@app.route('/adv/<routers>/<proto>')
def show_route_filter(routers, proto):
    return show_route('adv', routers, proto)


@app.route('/adv_bgpmap/<routers>/<proto>')
def show_route_filter_bgpmap(routers, proto):
    return show_route('adv_bgpmap', routers, proto)


@app.route('/where/<routers>/<proto>')
def show_route_where(routers, proto):
    return show_route('where', routers, proto)


@app.route('/where_detail/<routers>/<proto>')
def show_route_where_detail(routers, proto):
    return show_route('where_detail', routers, proto)


@app.route('/where_bgpmap/<routers>/<proto>')
def show_route_where_bgpmap(routers, proto):
    return show_route('where_bgpmap', routers, proto)


@app.route('/prefix/<routers>/<proto>')
def show_route_for(routers, proto):
    return show_route('prefix', routers, proto)


@app.route('/prefix_detail/<routers>/<proto>')
def show_route_for_detail(routers, proto):
    return show_route('prefix_detail', routers, proto)


@app.route('/prefix_bgpmap/<routers>/<proto>')
def show_route_for_bgpmap(routers, proto):
    return show_route('prefix_bgpmap', routers, proto)


def get_as_name(asn):
    """return a string that contain the as number following by the as name

    It's the use whois database informations
    # Warning, the server can be blacklisted from ripe is too many requests are done
    """
    if not asn:
        return "AS?????"

    if not asn.isdigit():
        return asn.strip()

    name = get_asname_from_whois(whois_command('AS' + asn)).replace(' ', '\r', 1)
    return "AS%s | %s" % (asn, name)


def get_as_number_from_protocol_name(host, proto, protocol):
    ret, res = bird_command(host, proto, "show protocols all {protocol}".format(protocol=protocol))
    match = re.search('Neighbor AS:\s*(\d*)', res)
    if match:
        return match.group(1)
    else:
        return "?????"


@app.route('/bgpmap/')
def show_bgpmap():
    """return a bgp map in a png file, from the json tree in q argument"""
    params = get_query_string()

    if not params:
        abort(400)

    params = json.loads(params)

    graph = pydot.Dot('BGPMAP', graph_type='digraph')

    nodes = {}
    edges = {}

    def escape(label):
        label = label.replace('&', '&amp;')
        label = label.replace('>', '&gt;')
        label = label.replace('<', '&lt;')
        return label

    def add_node(asn, **kwargs):
        if asn not in nodes:
            kwargs['label'] = '<<TABLE CELLBORDER="0" BORDER="0" CELLPADDING="0" CELLSPACING="0"><TR><TD ALIGN="CENTER">' + escape(kwargs.get("label", get_as_name(asn))).replace("\r", "<BR/>") + "</TD></TR></TABLE>>"
            nodes[asn] = pydot.Node(asn, style="filled", fontsize="10", **kwargs)
            graph.add_node(nodes[asn])

        return nodes[asn]

    def add_edge(prev_asn, asn, **kwargs):
        kwargs['splines'] = 'true'
        force = kwargs.get('force', False)

        edge_tuple = (prev_asn, asn)
        if force or edge_tuple not in edges:
            edge = pydot.Edge(*edge_tuple, **kwargs)
            graph.add_edge(edge)
            edges[edge_tuple] = edge
        elif 'label' in kwargs and kwargs['label']:
            edge = edges[edge_tuple]

            label_without_star = kwargs['label'].replace('*', '')
            labels = edge.get_label().split('\r')
            if "{}*".format(label_without_star) not in labels:
                labels = [kwargs['label']] + [label for label in labels if not label.startswith(label_without_star)]
                labels = sorted(labels, key=cmp_to_key(lambda x, y: x.endswith('*') and -1 or 1))

                label = escape('\r'.join(labels))
                edge.set_label(label)

        return edges[edge_tuple]

    for host, asmaps in params.iteritems():
        add_node(host,
                 label="{host}\r{domain}".format(host=host.upper(), domain=app.config['DOMAIN'].upper()),
                 shape='box', fillcolor='#F5A9A9')

        as_number = app.config['AS_NUMBER'].get(host, None)
        if as_number:
            node = add_node(as_number, fillcolor='#F5A9A9')
            edge = add_edge(as_number, nodes[host])
            edge.set_color('red')
            edge.set_style('bold')

    # colors = [ "#009e23", "#1a6ec1" , "#d05701", "#6f879f", "#939a0e", "#0e9a93", "#9a0e85", "#56d8e1" ]
    previous_as = None
    hosts = params.keys()
    for host, asmaps in params.iteritems():
        first = True
        for asmap in asmaps:
            previous_as = host
            color = "#%x" % random.randint(0, 16777215)

            hop = False
            hop_label = ''
            for asn in asmap:
                if asn == previous_as:
                    continue

                if not hop:
                    if app.config.get('BIRD_HAS_FULL_VIEW', False):
                        hop = True
                        hop_label = ''
                        continue
                    elif asn not in hosts:
                        hop_label = asn
                        if first:
                            hop_label += '*'
                        continue
                    else:
                        hop_label = ''

                add_node(asn, fillcolor=(first and '#F5A9A9' or 'white'))
                if hop_label:
                    edge = add_edge(nodes[previous_as], nodes[asn], label=hop_label, fontsize='7')
                else:
                    edge = add_edge(nodes[previous_as], nodes[asn], fontsize='7')

                hop_label = ''

                if first:
                    edge.set_style('bold')
                    edge.set_color('red')
                elif edge.get_color() != 'red':
                    edge.set_style('dashed')
                    edge.set_color(color)

                previous_as = asn

            first = False

    if previous_as:
        node = add_node(previous_as)
        node.set_shape('box')

    # return Response("<pre>" + graph.create_dot() + "</pre>")
    return Response(graph.create_png(), mimetype='image/png')


def build_as_tree_from_raw_bird_ouput(host, proto, text):
    """Extract the as path from the raw bird "show route all" command"""

    path = None
    paths = []
    net_dest = None

    re_via = re.compile(r'(.*)via\s+([0-9a-fA-F:\.]+)\s+on.*\[(\w+)\s+')
    re_unreachable = re.compile(r'(.*)unreachable\s+\[(\w+)\s+')

    for line in text:
        line = line.strip()

        expr = re_via.search(line)
        if expr:
            if path:
                path.append(net_dest)
                paths.append(path)
                path = None

            if expr.group(1).strip():
                net_dest = expr.group(1).strip()

            peer_ip = expr.group(2).strip()
            peer_protocol_name = expr.group(3).strip()
            # Check if via line is a internal route
            for rt_host, rt_ips in app.config["ROUTER_IP"].iteritems():
                # Special case for internal routing
                if peer_ip in rt_ips:
                    path = [rt_host]
                    break
            else:
                # ugly hack for good printing
                path = [peer_protocol_name]
                # path = ["%s\r%s" % (peer_protocol_name, get_as_name(get_as_number_from_protocol_name(host, proto, peer_protocol_name)))]

        expr2 = re_unreachable.search(line)
        if expr2:
            if path:
                path.append(net_dest)
                paths.append(path)
                path = None

            if expr2.group(1).strip():
                net_dest = expr2.group(1).strip()

        if line.startswith("BGP.as_path:"):
            path.extend(line.replace("BGP.as_path:", "").strip().split(" "))

    if path:
        path.append(net_dest)
        paths.append(path)

    return paths


def build_as_tree_from_full_view(host, proto, res):
    re_chunk_start = re.compile(r'(.*)unreachable\s+\[(.*)\s+.*\s+from\s+(.*)\].*\(.*\)\s\[.*\]')
    dest_subnet = None
    raw = defaultdict(dict)

    for line in res:
        line = line.strip()
        expr = re_chunk_start.search(line)

        if expr:
            # Beginning of the BGP reply chunk
            if not dest_subnet:
                dest_subnet = expr.group(1).strip()

            router_tag = expr.group(2).strip()
            router_ip = expr.group(3).strip()

            try:
                router_ip = resolve_ptr(router_ip)
            except NXDOMAIN:
                # If PTR record can't be found, IP will do too
                pass

        elif line.startswith('BGP.as_path:'):
            # BGP AS path
            line = line.replace('BGP.as_path:', '')
            line = line.strip()
            path = [router_tag, ]
            for as_num in line.split(' '):
                if as_num:
                    path.append(as_num)

            path_tag = '+'.join(path[1:])

            if path_tag not in raw:
                raw[path_tag] = list()

            raw[path_tag].append(dict(router_tag=router_tag, router_ip=router_ip, path=path))

        elif line.startswith('BGP.community:'):
            # BGP community
            line = line.replace('BGP.community:', '')
            line = line.strip()
            raw[path_tag][-1]['community'] = line.split(' ')

        elif line.startswith('BGP.cluster_list:'):
            # BGP cluster size
            line = line.replace('BGP.cluster_list:', '')
            line = line.strip()
            raw[path_tag][-1]['cluster_size'] = len(line.split(' '))

    for path_tag in raw:
        raw[path_tag] = iter(raw[path_tag])

    result = defaultdict(list)
    exhausted_tags = set()
    existing_paths_num = len(raw)
    if len(raw) > app.config.get('MAX_PATHS', 10):
        max_paths = existing_paths_num
    else:
        max_paths = app.config.get('MAX_PATHS', 10)
    path_count = 0

    while path_count < max_paths:
        for path_tag in sorted(raw, key=lambda x: x.count('+')):
            if path_tag in exhausted_tags:
                continue

            try:
                path = next(raw[path_tag])
            except StopIteration:
                exhausted_tags.add(path_tag)
                continue

            result[path['router_ip']].append(path['path'])
            result[path['router_ip']][-1].append(dest_subnet)

            path_count += 1
            if path_count == max_paths:
                break

        if path_count == max_paths or len(exhausted_tags) == existing_paths_num:
            break

    return result


def show_route(request_type, hosts, proto):
    expression = get_query_string()
    if not expression:
        abort(400)

    set_session(request_type, hosts, proto, expression)

    bgpmap = request_type.endswith('bgpmap')

    all = (request_type.endswith("detail") and " all" or "")
    if bgpmap:
        all = " all"

    if request_type.startswith("adv"):
        command = "show route " + expression.strip()
        if bgpmap and not command.endswith("all"):
            command = command + " all"
    elif request_type.startswith("where"):
        command = "show route where net ~ [ " + expression + " ]" + all
    else:
        mask = ""
        if len(expression.split("/")) == 2:
            expression, mask = (expression.split("/"))

        if not mask and proto == "ipv4":
            mask = "32"
        if not mask and proto == "ipv6":
            mask = "128"
        if not mask_is_valid(mask):
            return error_page("mask %s is invalid" % mask)

        if proto == "ipv6" and not ipv6_is_valid(expression):
            try:
                expression = resolve(expression, "AAAA")
            except DNSException:
                return error_page("%s is unresolvable or invalid for %s" % (expression, proto))
        if proto == "ipv4" and not ipv4_is_valid(expression):
            try:
                expression = resolve(expression, "A")
            except DNSException:
                return error_page("%s is unresolvable or invalid for %s" % (expression, proto))

        if mask:
            expression += "/" + mask

        command = "show route for " + expression + all

    detail = {}
    errors = []
    for host in hosts.split("+"):
        ret, res = bird_command(host, proto, command)
        res = res.split("\n")

        if ret is False:
            errors.append("%s" % res)
            continue

        if len(res) <= 1:
            errors.append("%s: bird command failed with error, %s" % (host, "\n".join(res)))
            continue

        if bgpmap:
            if app.config.get('BIRD_HAS_FULL_VIEW', False):
                detail = build_as_tree_from_full_view(host, proto, res)
            else:
                detail[host] = build_as_tree_from_raw_bird_ouput(host, proto, res)
        else:
            detail[host] = enrich_text(res)

    if bgpmap:
        detail = json.dumps(detail)

    return render_template((bgpmap and 'bgpmap.html' or 'route.html'), detail=detail, command=command, expression=expression, errors=errors)


if __name__ == "__main__":
    app.run(app.config.get('BIND_IP', '::'), app.config.get('BIND_PORT', 12020))
