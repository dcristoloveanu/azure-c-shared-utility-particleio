// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stddef.h>
#include "application.h"
#include "tcpclient_c.h"

void log_serial(char* logline)
{
Serial.printf(logline);
Serial.printf("\r\n");
}

TCPCLIENT_HANDLE tcpclient_create(void)
{
    return new TCPClient();
}

void tcpclient_destroy(TCPCLIENT_HANDLE tcp_client)
{
	delete (TCPClient*)tcp_client;
}

int tcpclient_connect(TCPCLIENT_HANDLE tcp_client, const char *host, uint16_t port)
{
    return ((TCPClient*)tcp_client)->connect(host, port);
}

size_t tcpclient_write(TCPCLIENT_HANDLE tcp_client, const uint8_t *buffer, size_t size)
{
    return ((TCPClient*)tcp_client)->write(buffer, size);
}

int tcpclient_read(TCPCLIENT_HANDLE tcp_client, uint8_t *buffer, size_t size)
{
    return ((TCPClient*)tcp_client)->read(buffer, size);
}

int tcpclient_available(TCPCLIENT_HANDLE tcp_client)
{
    return ((TCPClient*)tcp_client)->available();
}

void tcpclient_stop(TCPCLIENT_HANDLE tcp_client)
{
    return ((TCPClient*)tcp_client)->stop();
}
