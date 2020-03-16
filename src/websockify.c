#include "stdlib.h"

#include "WebsocketBridge.h"

/*

$ python3 -m websockets 'ws://127.0.0.1:52525?host=127.0.0.1&port=5000'
Connected to ws://127.0.0.1:52525?host=127.0.0.1&port=5000.
> dGVzdA==
< (binary) 74657374

$ ./test/tcp_echo.py
Serving on ('127.0.0.1', 5000)
Received b'test' from ('127.0.0.1', 33450)
Send: b'test'

*/

int main(int argc, char **argv)
{
    start();
    return EXIT_SUCCESS;
}
