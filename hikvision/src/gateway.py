import os
import logging
import socket
from datetime import timedelta, datetime

import requests

from pyftpdlib.handlers import FTPHandler, logger
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer

# Read environment variables
ALLOWED_REMOTE_IP = os.getenv('ALLOWED_REMOTE_IP', None)
FTP_USERNAME = os.getenv('FTP_USERNAME', 'ftp')
FTP_PASSWORD = os.getenv('FTP_PASSWORD', 'ftp')
FTP_HOMEDIR = os.getenv('FTP_HOMEDIR', '/tmp')
FTP_PERM = os.getenv('FTP_PERM', 'elradfmwMT')
FTP_HOST = os.getenv('FTP_HOST', '0.0.0.0')
FTP_PORT = int(os.getenv('FTP_PORT', 21))

TRIGGER_MODE = os.getenv('TRIGGER_MODE', 'http')
TRIGGER_TIMEOUT_SECONDS = int(os.getenv('TRIGGER_TIMEOUT_SECONDS', 10))

TRIGGER_TCP_HOST = os.getenv('TRIGGER_TCP_HOST', None)
TRIGGER_TCP_PORT = os.getenv('TRIGGER_TCP_PORT', None)
TRIGGER_TCP_PAYLOAD = os.getenv('TRIGGER_TCP_PAYLOAD', '1')  # type: str

TRIGGER_HTTP_URL = os.getenv('TRIGGER_HTTP_URL', None)
TRIGGER_HTTP_URL_EXPECTED_STATUS = int(os.getenv('TRIGGER_HTTP_URL_EXPECTED_STATUS', 200))

logging.basicConfig(level=logging.INFO)

# from pyftpdlib.log import config_logging
# config_logging(level=logging.DEBUG)


class EventServer(FTPServer):
    last_trigger = None


class EventHandler(FTPHandler):
    def on_connect(self):
        if ALLOWED_REMOTE_IP and self.remote_ip != ALLOWED_REMOTE_IP:
            self.log(f'{self.remote_ip} is not allowed to connect.', logger.warning)
            self.close()

    def on_disconnect(self):
        # do something when client disconnects
        pass

    def on_login(self, username):
        # do something when user login
        pass

    def on_logout(self, username):
        # do something when user logs out
        pass

    def on_file_sent(self, file):
        # do something when a file has been sent
        pass

    def on_file_received(self, file):
        # do something when a file has been received
        self.log(f'on_file_received: {file}', logger.debug)

        try:
            self.trigger()
        finally:
            os.remove(file)

    def on_incomplete_file_sent(self, file):
        # do something when a file is partially sent
        pass

    def on_incomplete_file_received(self, file):
        # remove partially uploaded files
        os.remove(file)

    def trigger_http(self):
        if not TRIGGER_HTTP_URL:
            self.log('trigger_http: TRIGGER_HTTP_URL not set!', logger.warning)
            return

        self.log('trigger_http: triggering endpoint...', logger.warning)
        self.log(f'trigger_http: TRIGGER: {TRIGGER_HTTP_URL}', logger.debug)

        # Trigger endpoint
        r = requests.get(TRIGGER_HTTP_URL)
        if r.status_code != TRIGGER_HTTP_URL_EXPECTED_STATUS:
            self.logerror(
                f'trigger_http: Unexpected HTTP status when triggering url: {TRIGGER_HTTP_URL}, status: {r.status_code}, '
                f'expected: {TRIGGER_HTTP_URL_EXPECTED_STATUS}')

    def trigger_tcp(self):
        if not TRIGGER_TCP_HOST:
            self.log('trigger_tcp: TRIGGER_TCP_HOST not set!', logger.warning)
            return

        if not TRIGGER_TCP_PORT:
            self.log('trigger_tcp: TRIGGER_TCP_PORT not set!', logger.warning)
            return

        self.log('trigger_tcp: triggering port...', logger.warning)
        self.log(f'trigger_tcp: TRIGGER: {TRIGGER_TCP_HOST}:{TRIGGER_TCP_PORT}', logger.debug)
        self.log(f'trigger_tcp: SENDING PAYLOAD: "{TRIGGER_TCP_PAYLOAD}"', logger.debug)

        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((TRIGGER_TCP_HOST, int(TRIGGER_TCP_PORT)))
            s.sendall(TRIGGER_TCP_PAYLOAD.encode('utf-8'))
            # data = s.recv(1024)
        finally:
            if s:
                s.close()
            # print('Received', repr(data))

    def trigger(self):
        if self.server.last_trigger and self.server.last_trigger + timedelta(
                seconds=TRIGGER_TIMEOUT_SECONDS) > datetime.utcnow():
            self.log('prevented re-triggering (timeout).', logger.warning)
            return

        # Store last trigger time
        self.server.last_trigger = datetime.utcnow()

        try:
            if TRIGGER_MODE == 'http':
                self.trigger_http()
            elif TRIGGER_MODE == 'tcp':
                self.trigger_tcp()
        except Exception as e:
            self.logerror(f'trigger: error: {e}')


if __name__ == '__main__':
    authorizer = DummyAuthorizer()
    authorizer.add_user(username=FTP_USERNAME, password=FTP_PASSWORD, homedir=FTP_HOMEDIR, perm=FTP_PERM)
    # authorizer.add_anonymous(homedir='.')

    handler = EventHandler
    handler.authorizer = authorizer
    handler.permit_foreign_addresses = True
    server = EventServer((FTP_HOST, FTP_PORT), handler)

    server.serve_forever()

