import socket

def send_msg(host, port, msg: bytes):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.sendall(msg)
        # data = s.recv(1024)
    finally:
        if s:
            s.close()
        # print('Received', repr(data))

if __name__ == '__main__':
    send_msg('192.168.0.11', 4999, b'Hello World')
