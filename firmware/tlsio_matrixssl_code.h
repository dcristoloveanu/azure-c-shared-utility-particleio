// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "tlsio.h"
#include "tlsio_matrixssl.h"
#include "socketio.h"

#include "httpsclient-particle/matrixsslApi.h"

typedef enum TLSIO_STATE_ENUM_TAG
{
    TLSIO_STATE_NOT_OPEN,
    TLSIO_STATE_OPENING_UNDERLYING_IO,
    TLSIO_STATE_IN_HANDSHAKE,
    TLSIO_STATE_OPEN,
    TLSIO_STATE_CLOSING,
    TLSIO_STATE_ERROR
} TLSIO_STATE_ENUM;

typedef struct TLS_IO_INSTANCE_TAG
{
    XIO_HANDLE socket_io;
    ON_BYTES_RECEIVED on_bytes_received;
    ON_IO_OPEN_COMPLETE on_io_open_complete;
    ON_IO_CLOSE_COMPLETE on_io_close_complete;
    ON_IO_ERROR on_io_error;
    void* on_bytes_received_context;
    void* on_io_open_complete_context;
    void* on_io_close_complete_context;
    void* on_io_error_context;
    LOGGER_LOG logger_log;
    TLSIO_STATE_ENUM tlsio_state;
    ON_SEND_COMPLETE on_send_complete;
    void* on_send_complete_callback_context;
    ssl_t* ssl;
    sslKeys_t *keys;
    unsigned char* trusted_certs;
    size_t trusted_certs_length;
    char* hostname;
} TLS_IO_INSTANCE;

static const IO_INTERFACE_DESCRIPTION tlsio_matrixssl_interface_description =
{
    tlsio_matrixssl_create,
    tlsio_matrixssl_destroy,
    tlsio_matrixssl_open,
    tlsio_matrixssl_close,
    tlsio_matrixssl_send,
    tlsio_matrixssl_dowork,
    tlsio_matrixssl_setoption
};

static void indicate_error(TLS_IO_INSTANCE* tls_io_instance)
{
    if (tls_io_instance->on_io_error != NULL)
    {
        tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
    }
}

static void indicate_open_complete(TLS_IO_INSTANCE* tls_io_instance, IO_OPEN_RESULT open_result)
{
    if (tls_io_instance->on_io_open_complete != NULL)
    {
        tls_io_instance->on_io_open_complete(tls_io_instance->on_io_open_complete_context, open_result);
    }
}

static void on_underlying_io_open_complete(void* context, IO_OPEN_RESULT open_result)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;

    if (open_result != IO_OPEN_OK)
    {
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        indicate_open_complete(tls_io_instance, IO_OPEN_ERROR);
    }
    else
    {
        tls_io_instance->tlsio_state = TLSIO_STATE_IN_HANDSHAKE;
    }
}

static void on_underlying_io_bytes_received(void* context, const unsigned char* buffer, size_t size)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;

    if ((tls_io_instance->tlsio_state != TLSIO_STATE_IN_HANDSHAKE) &&
        (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN))
    {
        /* error, discard bytes */
    }
    else
    {
        while (size > 0)
        {
            unsigned char is_error = 0;
            unsigned char* read_buffer;

            int32 bytes_to_be_read = matrixSslGetReadbuf(tls_io_instance->ssl, &read_buffer);
            if (bytes_to_be_read < 0)
            {
                /* error */
                is_error = 1;
            }
            else
            {
                unsigned char* decoded_bytes;
                uint32 decoded_bytes_length;
                int32 receive_result;

                size_t to_copy = size;
                if ((int32)to_copy > bytes_to_be_read)
                {
                    to_copy = bytes_to_be_read;
                }

                (void)memcpy(read_buffer, buffer, to_copy);
                receive_result = matrixSslReceivedData(tls_io_instance->ssl, to_copy, &decoded_bytes, &decoded_bytes_length);
                if (receive_result < 0)
                {
                    is_error = 1;
                }
                else
                {
                    if (receive_result == MATRIXSSL_HANDSHAKE_COMPLETE)
                    {
                        //printf("Handshake done\r\n");

                        /* indicate open complete */
                        tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
                        indicate_open_complete(tls_io_instance, IO_OPEN_OK);
                    }

                    if (decoded_bytes_length > 0)
                    {
                        //printf("Decoded %d bytes app data\r\n", (int)decoded_bytes_length);

                        /* indicate bytes up */
                        if (tls_io_instance->on_bytes_received != NULL)
                        {
                            tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, decoded_bytes, decoded_bytes_length);
                        }
                    }

                    size -= to_copy;
                    buffer += to_copy;
                }
            }

            if (is_error)
            {
                if (tls_io_instance->tlsio_state == TLSIO_STATE_IN_HANDSHAKE)
                {
                    tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
                    indicate_open_complete(tls_io_instance, IO_OPEN_ERROR);
                }
                else
                {
                    indicate_error(tls_io_instance);
                }

                break;
            }
        }
    }
}

static void on_underlying_io_error(void* context)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;

    switch (tls_io_instance->tlsio_state)
    {
    default:
    case TLSIO_STATE_NOT_OPEN:
    case TLSIO_STATE_ERROR:
        break;

    case TLSIO_STATE_OPENING_UNDERLYING_IO:
    case TLSIO_STATE_IN_HANDSHAKE:
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        indicate_open_complete(tls_io_instance, IO_OPEN_ERROR);
        break;

    case TLSIO_STATE_OPEN:
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        indicate_error(tls_io_instance);
        break;
    }
}

static void on_underlying_io_close_complete(void* context)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;

    if (tls_io_instance->tlsio_state == TLSIO_STATE_CLOSING)
    {
        if (tls_io_instance->on_io_close_complete != NULL)
        {
            tls_io_instance->on_io_close_complete(tls_io_instance->on_io_close_complete_context);
        }
    }
}

int tlsio_matrixssl_init(void)
{
    int result;

    if (matrixSslOpen() != PS_SUCCESS)
    {
        result = __LINE__;
    }
    else
    {
        result = 0;
    }

    return result;
}

void tlsio_matrixssl_deinit(void)
{
    matrixSslClose();
}

CONCRETE_IO_HANDLE tlsio_matrixssl_create(void* io_create_parameters, LOGGER_LOG logger_log)
{
    TLSIO_CONFIG* tls_io_config = io_create_parameters;
    TLS_IO_INSTANCE* result;

    if (tls_io_config == NULL)
    {
        result = NULL;
    }
    else
    {
        result = malloc(sizeof(TLS_IO_INSTANCE));
        if (result != NULL)
        {
            SOCKETIO_CONFIG socketio_config;

            socketio_config.hostname = tls_io_config->hostname;
            socketio_config.port = tls_io_config->port;
            socketio_config.accepted_socket = NULL;

            result->on_bytes_received = NULL;
            result->on_bytes_received_context = NULL;

            result->on_io_open_complete = NULL;
            result->on_io_open_complete_context = NULL;

            result->on_io_close_complete = NULL;
            result->on_io_close_complete_context = NULL;

            result->on_io_error = NULL;
            result->on_io_error_context = NULL;

            result->logger_log = logger_log;

            if (matrixSslNewKeys(&result->keys, NULL) != PS_SUCCESS)
            {
                free(result);
                result = NULL;
            }
            else
            {
                size_t hostname_length = strlen(tls_io_config->hostname);
                result->hostname = (char*)malloc(hostname_length + 1);
                if (result->hostname == NULL)
                {
                    free(result);
                    result = NULL;
                }
                else
                {
                    (void)memcpy(result->hostname, tls_io_config->hostname, hostname_length + 1);

                    /* load the cert */
                    const IO_INTERFACE_DESCRIPTION* socket_io_interface = socketio_get_interface_description();
                    if (socket_io_interface == NULL)
                    {
                        free(result->hostname);
                        free(result);
                        result = NULL;
                    }
                    else
                    {
                        result->socket_io = xio_create(socket_io_interface, &socketio_config, logger_log);
                        if (result->socket_io == NULL)
                        {
                            free(result->hostname);
                            free(result);
                            result = NULL;
                        }
                        else
                        {
                            result->on_send_complete = NULL;
                            result->on_send_complete_callback_context = NULL;
                            result->trusted_certs = NULL;
                            result->trusted_certs_length = 0;

                            result->tlsio_state = TLSIO_STATE_NOT_OPEN;
                        }
                    }
                }
            }
        }
    }

    return result;
}

void tlsio_matrixssl_destroy(CONCRETE_IO_HANDLE tls_io)
{
    if (tls_io != NULL)
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        xio_destroy(tls_io_instance->socket_io);

        if (tls_io_instance->hostname != NULL)
        {
            free(tls_io_instance->hostname);
        }

        if (tls_io_instance->trusted_certs != NULL)
        {
            free(tls_io_instance->trusted_certs);
        }

        matrixSslDeleteKeys(tls_io_instance->keys);

        free(tls_io);
    }
}

static int32 cert_validator_callback(ssl_t* ssl, psX509Cert_t* x509_cert, int32 alert)
{
    (void)ssl, x509_cert, alert;
    return 0;
}

static int32 extension_callback(ssl_t *ssl, unsigned short type, unsigned short len, void *data)
{
    (void)ssl, type, len, data;
    return 0;
}

int tlsio_matrixssl_open(CONCRETE_IO_HANDLE tls_io, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
{
    int result;

    if (tls_io == NULL)
    {
        result = __LINE__;
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if (tls_io_instance->tlsio_state != TLSIO_STATE_NOT_OPEN)
        {
            result = __LINE__;
        }
        else
        {
            tls_io_instance->on_bytes_received = on_bytes_received;
            tls_io_instance->on_bytes_received_context = on_bytes_received_context;

            tls_io_instance->on_io_open_complete = on_io_open_complete;
            tls_io_instance->on_io_open_complete_context = on_io_open_complete_context;

            tls_io_instance->on_io_error = on_io_error;
            tls_io_instance->on_io_error_context = on_io_error_context;

            if (matrixSslLoadRsaKeysMem(tls_io_instance->keys, NULL, 0, NULL, 0, tls_io_instance->trusted_certs, tls_io_instance->trusted_certs_length) < 0)
            {
                result = __LINE__;
            }
            else
            {
                tlsExtension_t* extension;

                if (matrixSslNewHelloExtension(&extension, NULL) < 0)
                {
                    result = __LINE__;
                }
                else
                {
                    unsigned char* ext_bytes;
                    int32 ext_bytes_count;

                    if (matrixSslCreateSNIext(NULL, tls_io_instance->hostname, strlen(tls_io_instance->hostname), &ext_bytes, &ext_bytes_count) < 0)
                    {
                        result = __LINE__;
                    }
                    else
                    {
                        if (matrixSslLoadHelloExtension(extension, ext_bytes, ext_bytes_count, EXT_SNI) < 0)
                        {
                            result = __LINE__;
                        }
                        else
                        {
                            int ret_code;
                            sslSessOpts_t session_options;

                            session_options.bufferPool = NULL;
                            session_options.maxFragLen = 0;
                            session_options.memAllocPtr = NULL;
                            session_options.ticketResumption = 0;
                            session_options.truncHmac = 0;
                            session_options.userPtr = tls_io_instance;
                            session_options.versionFlag = SSL_FLAGS_TLS_1_2;
                            ret_code = matrixSslNewClientSession(&tls_io_instance->ssl, tls_io_instance->keys, NULL, NULL, 0, cert_validator_callback,
                                NULL, extension, extension_callback, &session_options);

                            if (ret_code < 0)
                            {
                                result = __LINE__;
                            }
                            else
                            {
                                tls_io_instance->tlsio_state = TLSIO_STATE_OPENING_UNDERLYING_IO;

                                if (xio_open(tls_io_instance->socket_io, on_underlying_io_open_complete, tls_io_instance, on_underlying_io_bytes_received, tls_io_instance, on_underlying_io_error, tls_io_instance) != 0)
                                {
                                    matrixSslDeleteSession(tls_io_instance->ssl);
                                    tls_io_instance->ssl = NULL;
                                    tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
                                    result = __LINE__;
                                }
                                else
                                {
                                    result = 0;
                                }
                            }
                        }

                        psFree(ext_bytes, NULL);
                    }

                    matrixSslDeleteHelloExtension(extension);
                }
            }
        }
    }

    return result;
}

int tlsio_matrixssl_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
    int result = 0;

    if (tls_io == NULL)
    {
        result = __LINE__;
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if ((tls_io_instance->tlsio_state == TLSIO_STATE_NOT_OPEN) ||
            (tls_io_instance->tlsio_state == TLSIO_STATE_CLOSING))
        {
            result = __LINE__;
        }
        else
        {
            tls_io_instance->tlsio_state = TLSIO_STATE_CLOSING;
            tls_io_instance->on_io_close_complete = on_io_close_complete;
            tls_io_instance->on_io_close_complete_context = callback_context;

            if (xio_close(tls_io_instance->socket_io, on_underlying_io_close_complete, tls_io_instance) != 0)
            {
                result = __LINE__;
            }
            else
            {
                result = 0;
            }
        }
    }

    return result;
}

int tlsio_matrixssl_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;

    if (tls_io == NULL)
    {
        result = __LINE__;
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN)
        {
            result = __LINE__;
        }
        else
        {
            tls_io_instance->on_send_complete = on_send_complete;
            tls_io_instance->on_send_complete_callback_context = callback_context;

            while (size > 0)
            {
                size_t to_copy = size;
                unsigned char* write_bytes;
                int32 app_buffer_size = matrixSslGetWritebuf(tls_io_instance->ssl, &write_bytes, size);
                if (app_buffer_size <= 0)
                {
                    result = __LINE__;
                    break;
                }
                else
                {
                    if (to_copy > app_buffer_size)
                    {
                        to_copy = app_buffer_size;
                    }

                    (void)memcpy(write_bytes, buffer, to_copy);
                    size -= to_copy;
                    buffer = ((unsigned char*)buffer + to_copy);

                    int32 encoded_bytes = matrixSslEncodeWritebuf(tls_io_instance->ssl, to_copy);
                    if (encoded_bytes <= 0)
                    {
                        result = __LINE__;
                        break;
                    }
                    else
                    {
                        unsigned char* out_data;

                        /* send encoded data */
                        int32 out_data_length = matrixSslGetOutdata(tls_io_instance->ssl, &out_data);
                        if (out_data_length > 0)
                        {
                            if ((xio_send(tls_io_instance->socket_io, out_data, out_data_length, NULL, NULL) != 0) ||
                                (matrixSslSentData(tls_io_instance->ssl, out_data_length) < 0))
                            {
                                result = __LINE__;
                                break;
                            }
                            else
                            {
                            }
                        }
                    }
                }
            }

            result = 0;
        }
    }

    return result;
}

void tlsio_matrixssl_dowork(CONCRETE_IO_HANDLE tls_io)
{
    if (tls_io != NULL)
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if (tls_io_instance->tlsio_state == TLSIO_STATE_IN_HANDSHAKE)
        {
            unsigned char* out_data;

            /* send data to be sent out while in handshake */
            int32 out_data_length = matrixSslGetOutdata(tls_io_instance->ssl, &out_data);
            if (out_data_length > 0)
            {
                if ((xio_send(tls_io_instance->socket_io, out_data, out_data_length, NULL, NULL) != 0) ||
                    (matrixSslSentData(tls_io_instance->ssl, out_data_length) < 0))
                {
                    indicate_open_complete(tls_io_instance, IO_OPEN_ERROR);
                    tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
                }
                else
                {
                    //printf("Send %d bytes\r\n", (int)out_data_length);
                }
            }
        }

        if ((tls_io_instance->tlsio_state == TLSIO_STATE_IN_HANDSHAKE) ||
            (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN))
        {
            xio_dowork(tls_io_instance->socket_io);
        }
    }
}

const IO_INTERFACE_DESCRIPTION* tlsio_matrixssl_get_interface_description(void)
{
    return &tlsio_matrixssl_interface_description;
}

int tlsio_matrixssl_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
    int result;

    if (tls_io == NULL || optionName == NULL)
    {
        result = __LINE__;
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        if (strcmp("TrustedCerts", optionName) == 0)
        {
            uint32* certs = (uint32*)value;
            tls_io_instance->trusted_certs_length = *certs;
            tls_io_instance->trusted_certs = (unsigned char*)malloc(tls_io_instance->trusted_certs_length);
            if (tls_io_instance->trusted_certs == NULL)
            {
                result = __LINE__;
            }
            else
            {
                (void)memcpy(tls_io_instance->trusted_certs, certs + 1, tls_io_instance->trusted_certs_length);
                result = 0;
            }
        }
        else
        {
            result = xio_setoption(tls_io_instance->socket_io, optionName, value);
        }
    }

    return result;
}
