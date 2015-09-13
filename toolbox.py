#
# Copyright (c) 2006 Mehdi Abaakouk
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


import socket
import pickle
import re

from dns import resolver, reversename
from flask import Flask

resolver = resolver.Resolver()
resolver.timeout = 0.5
resolver.lifetime = 1

app = Flask(__name__)
app.config.from_pyfile('lg.cfg')


def resolve(name, rrtype):
    return str(resolver.query(name, rrtype)[0])


def resolve_ptr(ip_addr):
    ptr = str(resolve(reversename.from_address(ip_addr), 'PTR')).lower()
    ptr = ptr.replace(app.config.get('ROUTER_NAME_REMOVE', ''), '')
    return ptr


asname_regex = re.compile("(ASName|as-name):\s+(?P<name>\S+)")


def get_asname_from_whois(data):
    result = asname_regex.search(data)
    if not result:
        return 'UNKNOWN-AS'
    return result.groupdict()['name']


def mask_is_valid(netmask):
    if not netmask:
        return True
    try:
        mask = int(netmask)
        return 1 <= mask <= 128
    except ValueError:
        return False


def ipv4_is_valid(addr):
    try:
        socket.inet_pton(socket.AF_INET, addr)
        return True
    except socket.error:
        return False


def ipv6_is_valid(addr):
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except socket.error:
        return False


def save_cache_pickle(filename, data):
    with open(filename, 'wb') as output:
        pickle.dump(data, output)


def load_cache_pickle(filename, default=None):
    try:
        pkl_file = open(filename, 'rb')
    except IOError:
        return default
    try:
        data = pickle.load(pkl_file)
    except IOError:
        data = default

    pkl_file.close()

    return data
