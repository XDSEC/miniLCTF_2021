from gmssl import sm4 #https://github.com/duanhongyi/gmssl
import socketserver
import signal
import os
from base64 import *
import random
menu = '''1.enc;
2.dec;
3.getflag;
'''

XOR = lambda s1 , s2 : bytes([x1^x2 for x1,x2 in zip(s1,s2)])
def pad(m):
    padlen = 16 - len(m) % 16
    return m + padlen * bytes([padlen])
def unpad(m):
    return m[:-m[-1]]

def enc(iv , m , key):
    enc = sm4.CryptSM4(mode=sm4.SM4_ENCRYPT)
    enc.set_key(key = key , mode = sm4.SM4_ENCRYPT)
    c = enc.crypt_cbc(iv, m)
    return iv + c

def dec(iv , c , key):
    dec = sm4.CryptSM4(mode=sm4.SM4_DECRYPT)
    dec.set_key(key = key , mode = sm4.SM4_DECRYPT)
    m = dec.crypt_cbc(iv, c)
    return m

class server(socketserver.BaseRequestHandler):
    def _recv(self):
        data = self.request.recv(1024)
        return data.strip()

    def _send(self, msg, newline=True):
        if isinstance(msg , bytes):
            msg += b'\n'
        else:
            msg += '\n'
            msg = msg.encode()
        self.request.sendall(msg)

    def handle(self):
        signal.alarm(600)
        key = os.urandom(16)
        secret = os.urandom(random.randint(16 , 31))
        while 1:
            try:
                iv = os.urandom(16)
                self._send(menu)
                choice = self._recv()
                if choice == b'1':
                    self._send(b'your message:')
                    msg = b64decode(self._recv())
                    self._send(b64encode(enc(iv , msg + secret , key)))
                elif choice == b'2':
                    self._send('your ciphertext:')

                    c = b64decode(self._recv())
                    self._send('your iv:')
                    iv = b64decode(self._recv())

                    self._send(b64encode(dec(iv , c , key))[-1:])
                elif choice == b'3':
                    self._send('do you know my secret?')
                    guess = b64decode(self._recv())
                    if guess == secret:
                        self._send('congratulations')
                        self._send(os.getenv('FLAG'))
                    else:
                        self._send('I know you can\'t know it')
                        break
                else:
                    self._send('wrong!')
                    break
            except:
                pass



class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10001
    server = ForkedServer((HOST, PORT), server)
    server.allow_reuse_address = True
    server.serve_forever()
 