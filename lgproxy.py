#!/usr/bin/env python3
#
# Copyright (c) 2006-2012 Mehdi Abaakouk
# Copyright (c) 2015 Martin Weinelt
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


import sys
import logging
from logging.handlers import TimedRotatingFileHandler
import subprocess
from functools import wraps

from flask import Flask, request, abort
from requests.compat import unquote

from bird import BirdSocket

# Flask App
app = Flask(__name__)
app.debug = app.config.get('DEBUG', False)
app.config.from_pyfile('lgproxy.cfg')

# Logging
file_handler = TimedRotatingFileHandler(filename=app.config['LOG_FILE'], when='midnight')
app.logger.setLevel(getattr(logging, app.config['LOG_LEVEL'].upper()))
app.logger.addHandler(file_handler)


@app.before_request
def access_log_before(*args, **kwargs):
    app.logger.debug("[%s] request %s, %s", request.remote_addr, request.url,
                     "|".join(["%s:%s" % (k, v) for k, v in request.headers.items()]))


@app.after_request
def access_log_after(response, *args, **kwargs):
    app.logger.debug("[%s] reponse %s, %s", request.remote_addr, request.url, response.status_code)
    return response


def check_acl(func):
    """
    Check ACL for whitelisted IP addresses
    """

    @wraps(func)
    def decorator():
        if not app.config['ACCESS_LIST']:
            app.logger.warning("IP Whitelist not configured, denying access.")
            abort(423)  # Locked / Unconfigured
        elif request.remote_addr not in app.config['ACCESS_LIST']:
            app.logger.warning("Remote address (%s) not in IP whitelist.", request.remote_addr)
            abort(401)  # IP not whitelisted

    return decorator


def check_features():
    features = app.config.get('FEATURES', [])
    if features and request.endpoint not in features:
        app.logger.warning("Requested endpoint not in FEATURES: %s", request.endpoint)
        abort(401)


@app.route("/ping")
@app.route("/ping6")
@check_acl
def ping():
    check_features()

    cmd = []
    if request.path == '/ping':
        cmd.append('ping')
        if app.config.get('IPV4_SOURCE', ''):
            cmd.extend(['-I', app.config.get('IPV4_SOURCE')])
    else:
        cmd.append('ping6')
        if app.config.get('IPV6_SOURCE', ''):
            cmd.extend(['-I', app.config.get('IPV6_SOURCE')])

    options = ['-c4', '-i1', '-w5']
    cmd.extend(options)

    query = unquote(request.args.get('q', ''))
    cmd.extend(query)

    result = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0].decode('utf-8', 'ignore').replace('\n',
                                                                                                              '<br>')
    return result


@app.route("/traceroute")
@app.route("/traceroute6")
@check_acl
def traceroute():
    check_features()

    cmd = []
    if sys.platform.startswith('freebsd') or sys.platform.startswith('netbsd') or sys.platform.startswith('openbsd'):
        traceroute4 = ['traceroute']
        traceroute6 = ['traceroute6']
    else:  # For Linux
        traceroute4 = ['traceroute', '-4']
        traceroute6 = ['traceroute', '-6']

    if request.path == '/traceroute6':
        cmd.append(traceroute6)
        if app.config.get('IPV6_SOURCE', ''):
            cmd.extend(['-s', app.config.get('IPV6_SOURCE')])
    else:
        cmd.append(traceroute4)
        if app.config.get('IPV4_SOURCE', ''):
            cmd.extend(['-s', app.config.get('IPV4_SOURCE')])

    if sys.platform.startswith('freebsd') or sys.platform.startswith('netbsd'):
        options = ['-a', '-q1', '-w1', '-m15']
    elif sys.platform.startswith('openbsd'):
        options = ['-A', '-q1', '-w1', '-m15']
    else:  # For Linux
        options = ['-A', '-q1', '-N32', '-w1', '-m15']
    cmd.extend(options)

    query = unquote(request.args.get('q', ''))
    cmd.append(query)

    result = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0].decode('utf-8', 'ignore').replace('\n',
                                                                                                              '<br>')
    return result


@app.route('/bird')
@app.route('/bird6')
@check_acl
def bird():
    check_features()

    if request.path == '/bird':
        sock = BirdSocket(file=app.config.get('BIRD_SOCKET', '/run/bird/bird.ctl'))
    elif request.path == '/bird6':
        sock = BirdSocket(file=app.config.get('BIRD6_SOCKET', '/run/bird/bird6.ctl'))
    else:
        abort(400)
        return  # unnecessary, but makes for a more obvious control flow

    query = unquote(request.args.get('q', ''))

    status, result = sock.cmd(query)
    sock.close()

    # FIXME: use status
    return result


if __name__ == '__main__':
    app.logger.info('lgproxy start')
    app.run(app.config.get('BIND_IP', '::'), app.config.get('BIND_PORT', 12021))
