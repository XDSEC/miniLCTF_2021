import os
import signal
import socketserver
from random import randint

from coin import game

welcome = b'You may not know the concept of winning 578w with 20W. We usually only use two words to describe this kind of person: clod! I often say that Chen Daozai could win 3700w with 20 yuan. Today, it\'s not a problem for you to win from 20W to 500W!'


class server(socketserver.BaseRequestHandler):
    def _recv(self):
        data = self.request.recv(1024)
        return data.strip()

    def _send(self, msg, newline=True):
        if isinstance(msg, bytes):
            msg += b'\n'
        else:
            msg += '\n'
            msg = msg.encode()
        self.request.sendall(msg)

    def handle(self):
        signal.alarm(120)
        self._send(welcome)
        player_money = 200000
        self._send(b'what\'s your name')
        usrname = self._recv()
        cheat = []
        if usrname == b'lubenwei':
            while 1:
                self._send('op:')
                op = int(self._recv())
                if op == 0:
                    break
                self._send('params:')
                temp = [int(i) for i in self._recv().split(b' ')]
                cheat.append([op, temp])

        self._send(b'hi ' + usrname)
        while 1:
            if player_money > 5000000:
                self._send(b'ohhhhhhhhhhhhhhhhhhhhhhh, here is your flag')
                self._send(os.getenv('FLAG'))
                exit()
            elif player_money < 0:
                self._send(b'')
                exit()
            init_state = [0] * 4
            coin1 = randint(0, 1)
            coin2 = randint(0, 1)
            print(coin1)
            print(coin2)
            temp = coin1 * 2 + coin2
            init_state[temp] = 1
            servercoin = game(cheat, init_state)
            self._send('my coin is ' + str(servercoin) + ' your coin is?')
            playercoin = int(self._recv())
            if playercoin == coin2:
                self._send(b'oh, your are very lucky')
                player_money += 114514
            else:
                self._send(b'')
                player_money -= 1919810


class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10000
    server = ForkedServer((HOST, PORT), server)
    server.allow_reuse_address = True
    server.serve_forever()
