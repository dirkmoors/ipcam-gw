from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer, ThreadedFTPServer
from pyftpdlib.authorizers import DummyAuthorizer


class MyHandler(FTPHandler):

    def on_connect(self):
        print("%s:%s connected" % (self.remote_ip, self.remote_port))

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
        print(f'file received: {file}')

    def on_incomplete_file_sent(self, file):
        # do something when a file is partially sent
        pass

    def on_incomplete_file_received(self, file):
        # remove partially uploaded files
        import os
        os.remove(file)


def main():
    authorizer = DummyAuthorizer()
    authorizer.add_user(username='ditchitallcam', password='DALLBR6w4ZD9ETAB', homedir='./media', perm='elradfmwMT')
    # authorizer.add_anonymous(homedir='.')

    handler = MyHandler
    handler.authorizer = authorizer
    server = FTPServer(('0.0.0.0', 25510), handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
