from flask import Flask, jsonify, request, make_response
import socket

XOR_AUTOKEY_CIPHER_START_KEY = 171
TPLINK_DEFAULT_PORTNUM = 9999
TCP_RECV_BUFFER_SIZE = 2048

HTTP_STATUS_NOT_FOUND = 404
HTTP_STATUS_BAD_REQUEST = 400
HTTP_STATUS_OK = 200

version = 1.0
app = Flask(__name__)

# Initial Smart Plug Commands
commands = {
    'info'     : '{"system":{"get_sysinfo":{}}}',
    'on'       : '{"system":{"set_relay_state":{"state":1}}}',
    'off'      : '{"system":{"set_relay_state":{"state":0}}}',
    'wlanscan' : '{"netif":{"get_scaninfo":{"refresh":0}}}',
    'time'     : '{"time":{"get_time":{}}}',
    'reboot'   : '{"system":{"reboot":{"delay":1}}}',
    'reset'    : '{"system":{"reset":{"delay":1}}}',
    'internal' : 'test'
}

# XXX default me to "empty" so I can have a script take care of starting this
#     and handling network (arp) scans
devices = [
    {
        # XXX worth adding 'owner' so that one person can't mess with another?
        # how do we track owner? avoid copy/paste attack if possible
        # how about the time stuff?
        'ipaddr': u'192.168.1.31',
        'macaddr': u'50:c7:bf:05:a5:40',
        'port': TPLINK_DEFAULT_PORTNUM,
        'name': u'tv-lr'
    },
    {
        'ipaddr': u'192.168.1.100',
        'macaddr': u'2c:60:0c:6b:58:a1',
        'port': TPLINK_DEFAULT_PORTNUM,
        'name': u'fake1'
    },
]


# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key = 171
def encrypt(string):
    key = XOR_AUTOKEY_CIPHER_START_KEY
    result = b"\0\0\0\0"
    for i in string:
        a = key ^ ord(i)
        key = a
        result += a.to_bytes(1, byteorder='little')
    return result


def decrypt(bytes):
    key = XOR_AUTOKEY_CIPHER_START_KEY
    result = ""
    for i in bytes:
        a = key ^ i
        key = i
        result += chr(a)
    return result


def run_command(name, ipaddr, cmd, port):
    try:
        sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_tcp.connect((ipaddr, port))
        sock_tcp.send(encrypt(cmd))
        data = sock_tcp.recv(TCP_RECV_BUFFER_SIZE)
        sock_tcp.close()
    except socket.error:
        return "failed"
    return decrypt(data[4:])


def sanitize_name(name):
    if name is not None:
        if len(name) != 0:
            # XXX checks - allow upper, lower, number, dash, underscore only
            return name
    return None


def sanitize_ipv4_address(address):
    if address is not None:
        if len(address) != 0:
            # XXX checks - valid hex chars and dots
            return address
    return None


def sanitize_mac_address(address):
    if address is not None:
        if len(address) != 0:
            # XXX checks - valid hex chars and colons
            return address
    return None


def sanitize_command(cmd):
    if cmd is not None:
        if len(cmd) != 0:
            cmd_str = ""
            try:
                cmd_str = commands[cmd]
            except KeyError:
                cmd_str = None
            return cmd_str
    return None


@app.route('/iot', methods=['GET'])
def device_list():
    return jsonify({'devices': devices})


@app.route('/iot', methods=['POST'])
def device_add():
    # get the name first since names must be unique
    name = sanitize_name(request.values.get("name"))
    if name is None:
        return make_response(jsonify({'error': 'Name Parameter error'}),
                             HTTP_STATUS_BAD_REQUEST)
    dev = [dev for dev in devices if dev['name'] == name]
    if len(dev) != 0:
        return make_response(jsonify({'error': 'Name already exists'}),
                             HTTP_STATUS_BAD_REQUEST)

    ip = sanitize_ipv4_address(request.values.get("ipaddr"))
    if ip is None:
        return make_response(jsonify({'error': 'IP Address Parameter error'}),
                             HTTP_STATUS_BAD_REQUEST)

    mac = sanitize_mac_address(request.values.get("macaddr"))
    if mac is None:
        return make_response(jsonify({'error': 'MAC Address Parameter error'}),
                             HTTP_STATUS_BAD_REQUEST)

    port = request.values.get("port")
    if port is None:
        port = TPLINK_DEFAULT_PORTNUM

    # looks good - add it
    print("Add:", "name=", name, " ipaddr=", ip, " macaddr=", mac)
    newdev = {}
    newdev["name"] = name
    newdev["ipaddr"] = ip
    newdev["macaddr"] = mac
    newdev["port"] = port
    devices.append(newdev)
    return make_response(jsonify({'status': 'Added'}), HTTP_STATUS_OK)


@app.route('/iot', methods=['DELETE'])
def device_delete():
    # delete by name since a device can have more than one ip per mac
    name = sanitize_name(request.values.get("name"))
    if name is None:
        return make_response(jsonify({'error': 'Name Parameter error'}),
                             HTTP_STATUS_BAD_REQUEST)
    dev = [dev for dev in devices if dev['name'] == name]
    if len(dev) == 0:
        return make_response(jsonify({'error': 'Not found'}),
                             HTTP_STATUS_NOT_FOUND)
    print("Del:", "name=", name, "dev:", dev)
    devices.remove(dev[0])
    return make_response(jsonify({'status': 'Deleted'}), HTTP_STATUS_OK)


@app.route('/iot/<string:devname>', methods=['GET'])
def try_run_command(devname):
    dev = [dev for dev in devices if dev['name'] == devname]
    if len(dev) == 0:
        return make_response(jsonify({'error': 'Not found'}),
                             HTTP_STATUS_NOT_FOUND)
    cmd = sanitize_command(request.values.get("cmd"))
    if cmd is None:
        return make_response(jsonify({'error': 'Command Parameter error'}),
                             HTTP_STATUS_BAD_REQUEST)
    return run_command(devname, dev[0]['ipaddr'], cmd, dev[0]['port'])


@app.errorhandler(HTTP_STATUS_NOT_FOUND)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}),
                         HTTP_STATUS_NOT_FOUND)


# XXX pass in an optional address to bind to
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

