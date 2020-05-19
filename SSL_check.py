#！/usr/bin/env python 
from urllib3.contrib import pyopenssl
from datetime import datetime
from sys import argv
import idna
from socket import socket

class SSL_Check:
    def __init__(self, url):
        self.url = url

    @property
    def get_cert(self):
        sock = socket()
        sock.setblocking(True)
        sock.connect((self.url, 443),)
        ctx = pyopenssl.OpenSSL.SSL.Context(pyopenssl.OpenSSL.SSL.TLSv1_METHOD)
        ctx.check_hostname = False
        ctx.verify_mode = pyopenssl.OpenSSL.SSL.VERIFY_NONE

        sock_ssl = pyopenssl.OpenSSL.SSL.Connection(ctx, sock)
        sock_ssl.set_tlsext_host_name(idna.encode(self.url))
        sock_ssl.set_connect_state()
        sock_ssl.do_handshake()
        cert = sock_ssl.get_peer_certificate()
        sock_ssl.close()
        sock.close()
        return cert


    @property
    def get_str_time(self):
        cert = self.get_cert
        return cert.get_notAfter().decode()[0:-1]


    @property
    def get_ssl_time(self):
        ssl_time = datetime.strptime(self.get_str_time, '%Y%m%d%H%M%S')
        return (ssl_time-datetime.now()).days

if __name__ == '__main__':
    try:
        url = argv[1]
        ssl_check=SSL_Check(url)
        print(ssl_check.get_ssl_time)
    except Exception as e:
        print(e)

