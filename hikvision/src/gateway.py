import os
import logging
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

TRIGGER_HTTP_URL = os.getenv('TRIGGER_HTTP_URL', None)
TRIGGER_HTTP_URL_TIMEOUT_SECONDS = int(os.getenv('TRIGGER_HTTP_URL_TIMEOUT_SECONDS', 10))
TRIGGER_HTTP_URL_EXPECTED_STATUS = int(os.getenv('TRIGGER_HTTP_URL_EXPECTED_STATUS', 200))

logging.basicConfig(level=logging._nameToLevel[os.getenv('LOG_LEVEL', 'WARNING')])


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
            if not TRIGGER_HTTP_URL:
                return

            if self.server.last_trigger and self.server.last_trigger + timedelta(
                    seconds=TRIGGER_HTTP_URL_TIMEOUT_SECONDS) > datetime.utcnow():
                self.log('prevented re-triggering (timeout).', logger.warning)
                return

            self.log('triggering endpoint...', logger.warning)
            self.log(f'on_file_received: TRIGGER: {TRIGGER_HTTP_URL}', logger.debug)

            # Store last trigger time
            self.server.last_trigger = datetime.utcnow()

            # Trigger endpoint
            r = requests.get(TRIGGER_HTTP_URL)
            if r.status_code != TRIGGER_HTTP_URL_EXPECTED_STATUS:
                self.logerror(
                    f'Unexpected HTTP status when triggering url: {TRIGGER_HTTP_URL}, status: {r.status_code}, '
                    f'expected: {TRIGGER_HTTP_URL_EXPECTED_STATUS}')
        finally:
            os.remove(file)

    def on_incomplete_file_sent(self, file):
        # do something when a file is partially sent
        pass

    def on_incomplete_file_received(self, file):
        # remove partially uploaded files
        os.remove(file)


if __name__ == '__main__':
    authorizer = DummyAuthorizer()
    authorizer.add_user(username=FTP_USERNAME, password=FTP_PASSWORD, homedir=FTP_HOMEDIR, perm=FTP_PERM)
    # authorizer.add_anonymous(homedir='.')

    handler = EventHandler
    handler.authorizer = authorizer
    handler.permit_foreign_addresses = True
    server = EventServer((FTP_HOST, FTP_PORT), handler)

    server.serve_forever()

