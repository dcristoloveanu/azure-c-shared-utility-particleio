// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef TCPCLIENT_C_H
#define TCPCLIENT_C_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	typedef void* TCPCLIENT_HANDLE;

	extern TCPCLIENT_HANDLE tcpclient_create(void);
    extern void tcpclient_destroy(TCPCLIENT_HANDLE tcp_client);
    extern int tcpclient_connect(TCPCLIENT_HANDLE tcp_client, const char *host, uint16_t port);
    extern size_t tcpclient_write(TCPCLIENT_HANDLE tcp_client, const uint8_t *buffer, size_t size);
    extern int tcpclient_read(TCPCLIENT_HANDLE tcp_client, uint8_t *buffer, size_t size);
    extern int tcpclient_available(TCPCLIENT_HANDLE tcp_client);
    extern void tcpclient_stop(TCPCLIENT_HANDLE tcp_client);

#ifdef __cplusplus
}
#endif

#endif /* TCPCLIENT_C_H */
