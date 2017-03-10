/*
*******************************************************************
*
* Copyright 2016 Intel Corporation All rights reserved.
*
*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
*/

#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <alloca.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/synchronous.h>
#include <dps/event.h>

#include <uv.h>

#include <dps/private/cbor.h>

#include <systemd/sd-id128.h>

#include <linux/kd.h>
#include <sys/ioctl.h>

DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define DPS_PORT 3456
#define OUR_APPLICATION_ID SD_ID128_MAKE(e0,28,48,a5,53,9c,4a,e7,58,78,e9,8f,41,4b,f4,b6)
#define OIC_ENDPOINT_DEVICE_PREFIX "/oic/endpoint/"
#define OIC_ENDPOINT_ALL "/oic/endpoint/all"

typedef DPS_TxBuffer* (*ResourceMethodHandler)(const DPS_Publication *pub, DPS_RxBuffer *rx, void *data);

enum method {
    METHOD_CREATE,
    METHOD_DELETE,
    METHOD_NOTIFY,
    METHOD_RETRIEVE,
    METHOD_UPDATE,
    METHOD_UNKNOWN,
};

struct internal_resource {
    const char *path;
    ResourceMethodHandler retrieve;
};

struct resource {
    const char *path;
    const char * const rt[4];
    const char * const ifaces[4];
    ResourceMethodHandler retrieve, update, notify, delete, create;
    void *user_data;
};

struct map_entry {
    const char *key;
    void *value;
    size_t len;
};

static char device_id[SD_ID128_STRING_MAX];

static uint8_t buffer[2048];

static int counter;

static char topic_mine[sizeof(OIC_ENDPOINT_DEVICE_PREFIX) + SD_ID128_STRING_MAX];

static struct uv_timer_t counter_timer;

static DPS_Node* node;

static DPS_Publication *notification_pub;

#define STR_ENTRY(_key, _value) { .key = (_key), .value = (_value), .len =  strlen(_value) }

static DPS_TxBuffer *oicResRetrieve(const DPS_Publication *pub, DPS_RxBuffer *rx, void *data);

static DPS_TxBuffer *oic_d_retrieve(const DPS_Publication *pub, DPS_RxBuffer *rx, void *data);

static DPS_TxBuffer *oic_p_retrieve(const DPS_Publication *pub, DPS_RxBuffer *rx, void *data);

static DPS_TxBuffer *light_retrieve(const DPS_Publication *pub, DPS_RxBuffer *rx, void *data);

static DPS_TxBuffer *light_update(const DPS_Publication *pub, DPS_RxBuffer *rx, void *data);

static DPS_TxBuffer *counter_retrieve(const DPS_Publication *pub, DPS_RxBuffer *rx, void *data);

static DPS_TxBuffer *counter_notify(const DPS_Publication *pub, DPS_RxBuffer *rx, void *data);

static const struct internal_resource internal_resources[] = {
    { .path = "/oic/res",
      .retrieve = oicResRetrieve,
    },
    { },
};

static struct resource resources[] = {
    { .path = "/oic/d",
      .rt = { "oic.d.light", "oic.wd.d", NULL },
      .ifaces = { "oic.if.r", "oic.if.baseline", NULL },
      .retrieve = oic_d_retrieve,
    },
    { .path = "/oic/p",
      .rt = {  "oic.wk.p", NULL },
      .ifaces = { "oic.if.r", "oic.if.baseline", NULL },
      .retrieve = oic_p_retrieve,
    },
    { .path = "/light1",
      .rt = { "oic.r.switch.binary", "oic.r.light.brightness", NULL},
      .ifaces = { "oic.if.a", "oic.if.baseline", NULL },
      .retrieve = light_retrieve,
      .update = light_update,
    },
    { .path = "/light2",
      .rt = { "oic.r.switch.binary", "oic.r.light.brightness", NULL},
      .ifaces = { "oic.if.a", "oic.if.baseline", NULL },
      .retrieve = light_retrieve,
      .update = light_update,
    },
    { .path = "/light3",
      .rt = { "oic.r.switch.binary", "oic.r.light.brightness", NULL},
      .ifaces = { "oic.if.a", "oic.if.baseline", NULL },
      .retrieve = light_retrieve,
      .update = light_update,
    },
    { .path = "/light4",
      .rt = { "oic.r.switch.binary", "oic.r.light.brightness", NULL},
      .ifaces = { "oic.if.a", "oic.if.baseline", NULL },
      .retrieve = light_retrieve,
      .update = light_update,
    },
    { .path = "/counter",
      .rt = { "my.counter", NULL},
      .ifaces = { "oic.if.a", "oic.if.baseline", NULL },
      .retrieve = counter_retrieve,
      .notify = counter_notify,
    },
    { },
};

static bool strequal(const uint8_t *buf, size_t len, const char *str)
{
    size_t slen = strlen(str);

    if (len == slen && !memcmp(buf, str, slen)) {
        return true;
    }

    return false;
}

static DPS_Status emptyPayload(DPS_TxBuffer *tx)
{
    return CBOR_EncodeMap(tx, 0);
}

static DPS_Status encodeResult(DPS_TxBuffer *tx, int code, const char *device_id)
{
    DPS_Status ret;

    ret = CBOR_EncodeMap(tx, 2);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeMap failed: %s\n", DPS_ErrTxt(ret));
        return ret;;
    }

    ret = CBOR_EncodeString(tx, "code");
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    ret = CBOR_EncodeUint(tx, code);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeUint failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    ret = CBOR_EncodeString(tx, "di");
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    ret = CBOR_EncodeString(tx, device_id);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    return ret;
}

static DPS_Status encodeStringArray(DPS_TxBuffer *tx, const char * const *strarray)
{
    const char * const *str;
    DPS_Status ret;
    int num;

    num = 0;

    for (str = strarray; *str; str++) {
        num++;
    }

    ret = CBOR_EncodeArray(tx, num);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeArray failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    for (str = strarray; *str; str++) {
        ret = CBOR_EncodeString(tx, *str);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
            return ret;
        }
    }

    return ret;
}

static DPS_Status encodeResource(DPS_TxBuffer *tx, const struct resource *r)
{
    DPS_Status ret;

    ret = CBOR_EncodeMap(tx, 3);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeMap failed: %s\n", DPS_ErrTxt(ret));
        return ret;;
    }

    ret = CBOR_EncodeString(tx, "href");
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    ret = CBOR_EncodeString(tx, r->path);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    ret = CBOR_EncodeString(tx, "rt");
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    ret = encodeStringArray(tx, r->rt);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    ret = CBOR_EncodeString(tx, "if");
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    ret = encodeStringArray(tx, r->ifaces);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    return ret;
}

static DPS_Status encodeRepresentation(DPS_TxBuffer *tx, const struct resource *resource,
    const struct map_entry entries[])
{
    const struct map_entry *e;
    DPS_Status ret;
    int num = 0;

    for (e = entries; e->key; e++) {
        num++;
    }

    DPS_PRINT("encodeRepresentation %d\n", num);

    if (resource && resource->rt) {
        num++;
    }

    ret = CBOR_EncodeMap(tx, num);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeMap failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    if (resource->rt) {
        ret = CBOR_EncodeString(tx, "rt");
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
            return ret;
        }

        ret = encodeStringArray(tx, resource->rt);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
            return ret;
        }
    }

    for (e = entries; e->key; e++) {
        ret = CBOR_EncodeString(tx, e->key);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
            return ret;
        }

        ret = CBOR_EncodeString(tx, e->value);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
            return ret;
        }
    }

    return ret;
}

static DPS_Status encodeDeviceResources(DPS_TxBuffer *tx, const char *device_id,
    const struct resource resources[])
{
    const struct resource *r;
    DPS_Status ret;
    int links;

    ret = CBOR_EncodeMap(tx, 2);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeMap failed: %s\n", DPS_ErrTxt(ret));
        return ret;;
    }

    ret = CBOR_EncodeString(tx, "di");
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    ret = CBOR_EncodeString(tx, device_id);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    ret = CBOR_EncodeString(tx, "links");
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    links = 0;

    for (r = resources; r->path; r++) {
        links++;
    }

    ret = CBOR_EncodeArray(tx, links);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeArray failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    for (r = resources; r->path; r++) {
        ret = encodeResource(tx, r);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("encodeResource failed: %s\n", DPS_ErrTxt(ret));
            return ret;
        }
    }

    return ret;
}

static DPS_TxBuffer *oicResRetrieve(const DPS_Publication *pub, DPS_RxBuffer *rx, void *data)
{
    static uint8_t buffer[2048];
    DPS_Status ret;
    DPS_TxBuffer *tx;
    int r;

    tx = malloc(sizeof(DPS_TxBuffer));
    if (!tx) {
        return NULL;
    }

    ret = DPS_TxBufferInit(tx, buffer, sizeof(buffer));
    if (ret != DPS_OK) {
        goto error;
    }

    ret = encodeResult(tx, 200, device_id);
    if (ret != DPS_OK) {
        goto error;
    }

    ret = CBOR_EncodeArray(tx, 1);
    if (ret != DPS_OK) {
        goto error;
    }

    ret = encodeDeviceResources(tx, device_id, resources);
    if (ret != DPS_OK) {
        goto error;
    }

    return tx;

error:
    DPS_TxBufferFree(tx);
    free(tx);
    return NULL;
}

static DPS_TxBuffer *oic_d_retrieve(const DPS_Publication *pub, DPS_RxBuffer *rx, void *data)
{
    struct map_entry device[] = { STR_ENTRY("di", device_id),
                                  STR_ENTRY("n", "My Device"),
                                  STR_ENTRY("icv", "1.0.0"),
                                  STR_ENTRY("dmv", "1.0.0"),
                                  { }, };
    static uint8_t buffer[2048];
    DPS_Status ret;
    DPS_TxBuffer *tx;
    int r;

    tx = malloc(sizeof(DPS_TxBuffer));
    if (!tx) {
        return NULL;
    }

    ret = DPS_TxBufferInit(tx, buffer, sizeof(buffer));
    if (ret != DPS_OK) {
        goto error;
    }

    ret = encodeResult(tx, 200, device_id);
    if (ret != DPS_OK) {
        goto error;
    }

    ret = encodeRepresentation(tx, data, device);
    if (ret != DPS_OK) {
        goto error;
    }

    return tx;

error:
    DPS_TxBufferFree(tx);
    free(tx);
    return NULL;
}

static DPS_TxBuffer *oic_p_retrieve(const DPS_Publication *pub, DPS_RxBuffer *rx, void *data)
{
    struct map_entry device[] = { STR_ENTRY("pi", "54919CA5-4101-4AE4-595B-353C51AA983C"),
                                  STR_ENTRY("mnmn", "Acme, Inc"),
                                  { }, };
    static uint8_t buffer[2048];
    DPS_Status ret;
    DPS_TxBuffer *tx;
    int r;

    tx = malloc(sizeof(DPS_TxBuffer));
    if (!tx) {
        return NULL;
    }

    ret = DPS_TxBufferInit(tx, buffer, sizeof(buffer));
    if (ret != DPS_OK) {
        goto error;
    }

    ret = encodeResult(tx, 200, device_id);
    if (ret != DPS_OK) {
        goto error;
    }

    ret = encodeRepresentation(tx, data, device);
    if (ret != DPS_OK) {
        goto error;
    }

    return tx;

error:
    DPS_TxBufferFree(tx);
    free(tx);
    return NULL;
}

static DPS_TxBuffer *counter_retrieve(const DPS_Publication *pub, DPS_RxBuffer *rx, void *data)
{
    struct map_entry entries[] = { { .key = "value" },
                                   { } };
    char counter_str[48];
    static uint8_t buffer[2048];
    DPS_Status ret;
    DPS_TxBuffer *tx;
    int r;

    tx = malloc(sizeof(DPS_TxBuffer));
    if (!tx) {
        return NULL;
    }

    ret = DPS_TxBufferInit(tx, buffer, sizeof(buffer));
    if (ret != DPS_OK) {
        goto error;
    }

    ret = encodeResult(tx, 200, device_id);
    if (ret != DPS_OK) {
        goto error;
    }

    r = snprintf(counter_str, sizeof(counter_str), "%d", counter);
    if (r < 0) {
        goto error;
    }

    entries[0].value = counter_str;
    entries[0].len = r + 1;

    ret = encodeRepresentation(tx, data, entries);
    if (ret != DPS_OK) {
        goto error;
    }

    return tx;

error:
    DPS_TxBufferFree(tx);
    free(tx);
    return NULL;
}

static DPS_TxBuffer *counter_notify(const DPS_Publication *pub, DPS_RxBuffer *rx, void *data)
{
    struct resource *resource = data;
    const char *topics[2];
    char path[64];

    DPS_PRINT("[1] notification_pub %p\n", notification_pub);

    if (notification_pub) {
        DPS_DestroyPublication(notification_pub);
    }

    notification_pub = DPS_CreatePublication(node);

    DPS_PRINT("[2] notification_pub %p\n", notification_pub);

    snprintf(path, sizeof(path), "/oic/notification/resource%s", resource->path);

    topics[0] = topic_mine;
    topics[1] = path;

    DPS_PRINT("mine %s path %s\n", topic_mine, path);

    DPS_InitPublication(notification_pub, topics, 2, false, NULL, NULL);

    return counter_retrieve(pub, rx, data);
}

static DPS_TxBuffer *light_retrieve(const DPS_Publication *pub, DPS_RxBuffer *rx, void *data)
{
    const struct resource *resource = data;
    static uint8_t buffer[2048];
    DPS_Status ret;
    DPS_TxBuffer *tx;
    bool state = !!resource->user_data;
    int r;

    tx = malloc(sizeof(DPS_TxBuffer));
    if (!tx) {
        return NULL;
    }

    ret = DPS_TxBufferInit(tx, buffer, sizeof(buffer));
    if (ret != DPS_OK) {
        goto error;
    }

    ret = encodeResult(tx, 200, device_id);
    if (ret != DPS_OK) {
        goto error;
    }

    ret = CBOR_EncodeMap(tx, 2);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeMap failed: %s\n", DPS_ErrTxt(ret));
        goto error;
    }

    ret = CBOR_EncodeString(tx, "id");
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        goto error;
    }

    ret = CBOR_EncodeString(tx, "light switch id");
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        goto error;
    }

    ret = CBOR_EncodeString(tx, "value");
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        goto error;
    }

    ret = CBOR_EncodeBoolean(tx, state);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        goto error;
    }

    return tx;

error:
    DPS_TxBufferFree(tx);
    free(tx);
    return NULL;
}

static int parseStringMap(DPS_RxBuffer *rx, struct map_entry entries[])
{
    size_t num;
    DPS_Status ret;

    ret = CBOR_DecodeMap(rx, &num);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_DecodeMap failed: %s\n", DPS_ErrTxt(ret));
        return -EINVAL;
    }

    while (num--) {
        struct map_entry *e;
        char *key, *value;
        size_t keyLen, valueLen;

        ret = CBOR_DecodeString(rx, &key, &keyLen);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CBOR_DecodeString failed: %s\n", DPS_ErrTxt(ret));
            return -EINVAL;
        }

        ret = CBOR_DecodeString(rx, &value, &valueLen);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CBOR_DecodeString failed: %s\n", DPS_ErrTxt(ret));
            return -EINVAL;
        }

        for (e = entries; e->key; e++) {
            if (!memcmp(key, e->key, keyLen)) {
                e->value = value;
                e->len = valueLen;
                break;
            }
        }
    }

    return num + 1;
}

static DPS_TxBuffer *light_update(const DPS_Publication *pub, DPS_RxBuffer *rx, void *data)
{
    struct resource *resource = data;
    struct map_entry update[] = { { .key = "value" },
                                  { }, };
    static uint8_t buffer[2048];
    DPS_Status ret;
    DPS_TxBuffer *tx;
    int r;
    bool state = false;

    r = parseStringMap(rx, update);
    if (r < 0) {
        DPS_ERRPRINT("parseStringMap failed %d\n", r);
        return NULL;
    }

    if (strequal(update[0].value, update[0].len, "true")) {
        state = true;
    }

    DPS_PRINT("[update] state for %s is now %s\n", resource->path, state ? "ON" : "OFF");

    resource->user_data = (void *) state;

    tx = malloc(sizeof(DPS_TxBuffer));
    if (!tx) {
        return NULL;
    }

    ret = DPS_TxBufferInit(tx, buffer, sizeof(buffer));
    if (ret != DPS_OK) {
        goto error;
    }

    ret = encodeResult(tx, 200, device_id);
    if (ret != DPS_OK) {
        goto error;
    }

    ret = emptyPayload(tx);
    if (ret != DPS_OK) {
        goto error;
    }

    return tx;

error:
    DPS_TxBufferFree(tx);
    free(tx);
    return NULL;
}

static void print_buffer(const void *buffer, size_t len)
{
    size_t i;
    const char *p = buffer;

    fprintf(stderr, "buf[%zu] (%p): ", len, buffer);

    for (i = 0; i < len; i++) {
        fprintf(stderr, "%02X ", p[i]);
        if (i != 0 && !(i % 16)) {
            fprintf(stderr, "\n");
        }
    }
    fprintf(stderr, "\n");
}

static enum method str_to_method(const uint8_t *buf, size_t len)
{
    DPS_PRINT("[str_to_method] method %.*s\n", len, (char *) buf);

    if (strequal(buf, len, "retrieve")) {
        return METHOD_RETRIEVE;
    }

    if (strequal(buf, len, "create")) {
        return METHOD_CREATE;
    }

    if (strequal(buf, len, "update")) {
        return METHOD_UPDATE;
    }

    if (strequal(buf, len, "delete")) {
        return METHOD_DELETE;
    }

    if (strequal(buf, len, "notify")) {
        return METHOD_NOTIFY;
    }

    return METHOD_UNKNOWN;
}

static ResourceMethodHandler get_method_from_resource(const struct resource *resource, enum method method)
{
    switch (method) {
    case METHOD_RETRIEVE:
        return resource->retrieve;
    case METHOD_UPDATE:
        return resource->update;
    case METHOD_CREATE:
        return resource->create;
    case METHOD_DELETE:
        return resource->delete;
    case METHOD_NOTIFY:
        return resource->notify;
    default:
        return NULL;
    }

    return NULL;
}

static void OnPubMatchAll(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    struct map_entry params[] = { { .key = "operation" },
                                  { .key = "resource" },
                                  { .key = "query" },
                                  { } };
    const struct internal_resource *internal;
    struct map_entry *e;
    DPS_RxBuffer rx;
    DPS_Status ret;
    int r;

    CBOR_Dump("OnPubMatchAll", data, len);

    ret = DPS_RxBufferInit(&rx, data, len);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_RxBufferInit failed: %s\n", DPS_ErrTxt(ret));
        return;
    }

    r = parseStringMap(&rx, params);
    if (r < 0) {
        DPS_ERRPRINT("parseStringMap failed: %d\n", r);
        return;
    }

    for (internal = internal_resources; internal->path; internal++) {
        enum method method;

        if (!strequal(params[1].value, params[1].len, internal->path)) {
            continue;
        }

        method = str_to_method(params[0].value, params[0].len);

        DPS_PRINT("OnPubMatchAll %#x\n", method);

        if (internal->retrieve && method == METHOD_RETRIEVE) {
            DPS_TxBuffer *tx;

            tx = internal->retrieve(pub, &rx, (void *) internal);
            if (!tx) {
                continue;
            }

            DPS_AckPublication(pub, tx->base, tx->txPos - tx->base);
            free(tx);
            return;
        }
    }
}

static void OnPubMatchMine(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    struct map_entry params[] = { { .key = "operation" },
                                  { .key = "resource" },
                                  { .key = "query" },
                                  { } };
    struct resource *resource;
    struct map_entry *e;
    DPS_RxBuffer rx;
    DPS_Status ret;
    int r;

    CBOR_Dump("OnPubMatchMine", data, len);

    ret = DPS_RxBufferInit(&rx, data, len);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_RxBufferInit failed: %s\n", DPS_ErrTxt(ret));
        return;
    }

    r = parseStringMap(&rx, params);
    if (r < 0) {
        DPS_ERRPRINT("parseStringMap failed: %d\n", r);
        return;
    }

    for (resource = resources; resource->path; resource++) {
        enum method method;
        ResourceMethodHandler handler;
        DPS_TxBuffer *tx;

        if (!strequal(params[1].value, params[1].len, resource->path)) {
            continue;
        }

        method = str_to_method(params[0].value, params[0].len);
        handler = get_method_from_resource(resource, method);

        DPS_PRINT("OnPubMatchMine %#x handler %p\n", method, handler);

        if (!handler) {
            continue;
        }

        tx = handler(pub, &rx, (void *) resource);
        if (!tx) {
            continue;
        }

        DPS_AckPublication(pub, tx->base, tx->txPos - tx->base);
        free(tx);
        return;
    }
}

static void send_notification(uv_timer_t *handle)
{
    DPS_TxBuffer *tx;

    DPS_PRINT("send_notification %p pub %p\n", handle, notification_pub);

    counter++;

    if (!notification_pub) {
        return;
    }

    /* FIXME: do not use hardcoded indexes */
    tx = counter_retrieve(notification_pub, NULL, &resources[6]);
    if (!tx) {
        return;
    }

    DPS_Publish(notification_pub, tx->base, tx->txPos - tx->base, 0);
    free(tx);
    return;
}

int main(int argc, char** argv)
{
    sd_id128_t id;
    DPS_Subscription *sub;
    DPS_Event *nodeDestroyed;
    uv_loop_t *loop;
    uv_timer_t timer;
    int mcast = DPS_MCAST_PUB_ENABLE_SEND | DPS_MCAST_PUB_ENABLE_RECV;
    DPS_Status ret;
    const char *topics[1] = { OIC_ENDPOINT_ALL };
    char old_led_state;

    int r;

    sd_id128_get_machine_app_specific(OUR_APPLICATION_ID, &id);

    node = DPS_CreateNode(":", NULL, NULL);

    ret = DPS_StartNode(node, mcast, DPS_PORT);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_CreateNode failed: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    nodeDestroyed = DPS_CreateEvent();

    sub = DPS_CreateSubscription(node, topics, 1);
    ret = DPS_Subscribe(sub,OnPubMatchAll);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_Subscribe failed: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    snprintf(device_id, sizeof(device_id), SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(id));

    r = snprintf(topic_mine, sizeof(topic_mine), OIC_ENDPOINT_DEVICE_PREFIX "%s", device_id);
    if (r < 0) {
        DPS_ERRPRINT("snprintf failed\n");
        return 1;
    }

    topics[0] = topic_mine;

    sub = DPS_CreateSubscription(node, topics, 1);
    ret = DPS_Subscribe(sub,OnPubMatchMine);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_Subscribe failed: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    loop = DPS_GetLoop(node);

    r = uv_timer_init(loop, &timer);

    r = uv_timer_start(&timer, send_notification, 5 * 1000, 5 * 1000);

    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);

    return 0;
}
