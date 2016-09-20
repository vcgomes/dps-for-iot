#include <assert.h>
#include <string.h>
#include <malloc.h>
#include <uv.h>
#include <dps/dps_dbg.h>
#include <dps/dps.h>
#include <dps/network.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);



#define MAX_READ_LEN   4096
#define MAX_WRITE_LEN  4096
#define MIN_READ_LEN      8

struct _DPS_NetContext {
    uv_udp_t socket;
    DPS_Node* node;
    DPS_OnReceive receiveCB;
    uint16_t readLen;
    char buffer[MAX_READ_LEN];
};

static void AllocBuffer(uv_handle_t* handle, size_t suggestedSize, uv_buf_t* buf)
{
    DPS_NetContext* netCtx = (DPS_NetContext*)handle->data;

    DPS_DBGTRACE();
    buf->len = sizeof(netCtx->buffer) - netCtx->readLen;
    buf->base = netCtx->buffer + netCtx->readLen;
}

static void HandleClosed(uv_handle_t* handle)
{
    DPS_DBGPRINT("Closed handle %p\n", handle);
    free(handle->data);
}

static void OnData(uv_udp_t* socket, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    size_t toRead;
    DPS_NetContext* netCtx = (DPS_NetContext*)socket->data;

    DPS_DBGTRACE();
    if (nread < 0) {
        netCtx->readLen = 0;
        DPS_ERRPRINT("OnData error %s\n", uv_err_name(nread));
        return;
    }
    if (!nread) {
        netCtx->readLen = 0;
        return;
    }
    if (!buf) {
        DPS_ERRPRINT("OnData no buffer\n");
        netCtx->readLen = 0;
        return;
    }
    if (!addr) {
        DPS_ERRPRINT("OnData no address\n");
        netCtx->readLen = 0;
        return;
    }
    toRead = netCtx->receiveCB(netCtx->node, addr, (uint8_t*)netCtx->buffer, nread);
    if (toRead == 0) {
        netCtx->readLen = 0;
    } else {
        netCtx->readLen += nread;
    }
}

DPS_NetContext* DPS_NetStart(DPS_Node* node, int port, DPS_OnReceive cb)
{
    int ret;
    DPS_NetContext* netCtx;
    struct sockaddr_in6 addr;

    netCtx = calloc(1, sizeof(*netCtx));
    if (!netCtx) {
        return NULL;
    }
    ret = uv_udp_init(DPS_GetLoop(node), &netCtx->socket);
    if (ret) {
        DPS_ERRPRINT("uv_tcp_init error=%s\n", uv_err_name(ret));
        free(netCtx);
        return NULL;
    }
    netCtx->node = node;
    netCtx->receiveCB = cb;
    netCtx->socket.data = netCtx;
    ret = uv_ip6_addr("::", port, &addr);
    if (ret) {
        goto ErrorExit;
    }
    ret = uv_udp_bind(&netCtx->socket, (const struct sockaddr*)&addr, 0);
    if (ret) {
        goto ErrorExit;
    }
    ret = uv_udp_recv_start(&netCtx->socket, AllocBuffer, OnData);
    if (ret) {
        goto ErrorExit;
    }
    return netCtx;

ErrorExit:

    DPS_ERRPRINT("Failed to start net netCtx: error=%s\n", uv_err_name(ret));
    uv_close((uv_handle_t*)&netCtx->socket, HandleClosed);
    return NULL;
}

uint16_t DPS_NetGetListenerPort(DPS_NetContext* netCtx)
{
    struct sockaddr_in6 addr;
    int len = sizeof(addr);

    if (!netCtx) {
        return 0;
    }
    if (uv_udp_getsockname(&netCtx->socket, (struct sockaddr*)&addr, &len)) {
        return 0;
    }
    DPS_DBGPRINT("Listener port = %d\n", ntohs(addr.sin6_port));
    return ntohs(addr.sin6_port);
}

void DPS_NetStop(DPS_NetContext* netCtx)
{
    if (netCtx) {
        uv_close((uv_handle_t*)&netCtx->socket, HandleClosed);
    }
}

#define MAX_BUFS 3

typedef struct {
    DPS_NetContext* netCtx;
    DPS_NodeAddress addr;
    uv_udp_send_t sendReq;
    uv_buf_t bufs[MAX_BUFS];
    size_t numBufs;
    DPS_NetSendComplete onSendComplete;
} NetSender;

static void OnSendComplete(uv_udp_send_t* req, int status)
{
    NetSender* sender = (NetSender*)req->data;
    DPS_Status dpsRet = DPS_OK;

    if (status) {
        DPS_ERRPRINT("OnSendComplete status=%s\n", uv_err_name(status));
        dpsRet = DPS_ERR_NETWORK;
    }
    sender->onSendComplete(sender->netCtx->node, (struct sockaddr*)&sender->addr, sender->bufs, sender->numBufs, dpsRet);
}

DPS_Status DPS_NetSend(DPS_NetContext* netCtx, uv_buf_t* bufs, size_t numBufs, const struct sockaddr* addr, DPS_NetSendComplete sendCompleteCB)
{
    int ret;
    size_t i;
    size_t len = 0;
    NetSender* sender;

    if (numBufs > MAX_BUFS) {
        return DPS_ERR_OVERFLOW;
    }
    for (i = 0; i < numBufs; ++i) {
        len += bufs[i].len;
    }
    if (len > MAX_WRITE_LEN) {
        return DPS_ERR_OVERFLOW;
    }
    DPS_DBGPRINT("DPS_NetSend total %zu bytes to %s\n", len, DPS_NetAddrText(addr));

    sender = malloc(sizeof(NetSender));
    if (!sender) {
        return DPS_ERR_RESOURCES;
    }

    sender->sendReq.data = sender;
    sender->onSendComplete = sendCompleteCB;
    memcpy(&sender->addr, addr, sizeof(sender->addr));
    sender->netCtx = netCtx;
    memcpy(sender->bufs, bufs, numBufs * sizeof(uv_buf_t));
    sender->numBufs = numBufs;

    ret = uv_udp_send(&sender->sendReq, &netCtx->socket, bufs, numBufs, addr, OnSendComplete);
    if (ret) {
        free(sender);
        return DPS_ERR_NETWORK;
    }
    return DPS_OK;
}

const char* DPS_NetAddrText(const struct sockaddr* addr)
{
    if (addr) {
        static char txt[INET6_ADDRSTRLEN + 8];
        uint16_t port;
        int ret;
        if (addr->sa_family == AF_INET6) {
            ret = uv_ip6_name((const struct sockaddr_in6*)addr, txt, sizeof(txt));
            port = ((const struct sockaddr_in6*)addr)->sin6_port;
        } else {
            ret = uv_ip4_name((const struct sockaddr_in*)addr, txt, sizeof(txt));
            port = ((const struct sockaddr_in*)addr)->sin_port;
        }
        if (ret) {
            return "Invalid address";
        }
        sprintf(txt + strlen(txt), "/%d", ntohs(port));
        return txt;
    } else {
        return "NULL";
    }
}
