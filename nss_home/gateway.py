import json
import logging
import socket
import struct
import threading

from .constants import *

module_logger = logging.getLogger('nss_home.gateway')


class Gateway:
    def __init__(self):
        self.gateway_info: GatewayInfo = None
        self._handlers = []
        self._listener = None
        self._token = None
        self._logger = logging.getLogger('nss_home.gateway.Gateway')
        self._gateway_discovery()

    def _gateway_discovery(self):
        self._logger.info("Starting gateway discovery")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10)
        ttl = struct.pack('b', 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        self._logger.debug(GATEWAY_DISCOVERY_COMMAND)
        sock.sendto(GATEWAY_DISCOVERY_COMMAND.encode(), (MULTICAST_GROUP, GATEWAY_DISCOVERY_PORT))
        try:
            data, address = sock.recvfrom(1024)
            self._logger.debug(data.decode())
            self.gateway_info = GatewayInfo(json.loads(data))
            self._logger.info("Found gateway on ip {}".format(self.gateway_info.ip))
        except socket.timeout:
            self._logger.error("Failed to find gateway after 10 seconds")
        finally:
            sock.close()

    def _get_server_address(self):
        return self.gateway_info.ip, GATEWAY_COMMANDS_PORT

    def _start_events_listening(self):
        if not self._listener:
            self._listener = threading.Thread(target=self._event_listener)
            self._listener.start()

    def _event_listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', GATEWAY_COMMANDS_PORT))
        group = socket.inet_aton(MULTICAST_GROUP)
        mreq = struct.pack('4sL', group, socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        while len(self._handlers) > 0:
            data, address = sock.recvfrom(1024)
            self._logger.debug(data.decode())
            data = json.loads(data)
            if data['cmd'] == "heartbeat" and data['model'] == 'gateway':
                self._token = data['token']
            else:
                for handler in self._handlers:
                    handler(data)

    def get_devices_list(self) -> list:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        message = '{"cmd" : "get_id_list"}'
        self._logger.debug(message)
        sock.sendto(message.encode(), self._get_server_address())
        data, address = sock.recvfrom(1024)
        self._logger.debug(data)
        return json.loads(json.loads(data)["data"])

    def get_device_status(self, device_id):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        message = '{{"cmd":"read","sid":"{}"}}'.format(device_id)
        self._logger.debug(message)
        sock.sendto(message.encode(), self._get_server_address())
        data, address = sock.recvfrom(1024)
        self._logger.debug(data)
        return json.loads(data)

    # def set_device_status(self, device_id, command):

    def set_events_handler(self, handler):
        self._handlers.append(handler)
        self._start_events_listening()

    def remove_events_handler(self, handler):
        self._handlers.remove(handler)


class GatewayInfo:
    def __init__(self, gateway_whois_response):
        self.ip = gateway_whois_response['ip']
        self.sid = gateway_whois_response['sid']
        self.model = gateway_whois_response['model']
        self.proto_version = gateway_whois_response['proto_version']
