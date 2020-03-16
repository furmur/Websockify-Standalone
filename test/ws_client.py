#!/usr/bin/env python3

from websocket import create_connection
from base64 import b64encode, b64decode

ws = create_connection("ws://127.0.0.1:52525?host=127.0.0.1&port=5000")

s = "test"

print("Sending '{}'...".format(s))
ws.send(b64encode(s.encode('utf-8')))
print("Sent")

print("Receiving...")
result =  ws.recv()
print("Received '%s'" % result)

ws.close()
