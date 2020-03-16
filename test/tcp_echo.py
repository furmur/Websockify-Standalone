#!/usr/bin/env python3

import asyncio
import sys

async def handle_echo(reader, writer):
    try:
        while True:
            data = await reader.read(100)
            if not data:
                break
            addr = writer.get_extra_info('peername')
            print("Received %r from %r" % (data, addr))
        
            print("Send: %r" % data)
            writer.write(data)
            await writer.drain()
    except:
        print("got exception %r".format(sys.exc_info()))

    print("Close the client socket")
    writer.close()

loop = asyncio.get_event_loop()
coro = asyncio.start_server(handle_echo, '127.0.0.1', 5000, loop=loop)
server = loop.run_until_complete(coro)

# Serve requests until Ctrl+C is pressed
print('Serving on {}'.format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
