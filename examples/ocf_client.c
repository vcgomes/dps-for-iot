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

#include <dps/private/cbor.h>
#include <dps/private/dps.h>

#include <systemd/sd-id128.h>

#define OIC_ENDPOINT_ALL "/oic/endpoint/all"
#define OIC_ENDPOINT_DEVICE_PREFIX "/oic/endpoint/"

#define DPS_PORT 3456
#define OUR_APPLICATION_ID SD_ID128_MAKE(e0,28,48,a5,53,9c,4a,e7,58,78,e9,8f,41,4b,f4,b6)

static uint8_t buffer[2048];

struct map_entry {
    const char *key;
    void *value;
    size_t len;
};

static DPS_Node* node;

#define STR_ENTRY(_key, _value) { .key = (_key), .value = (_value), .len =  strlen(_value) }

static DPS_Status emptyPayload(DPS_TxBuffer *tx)
{
    return CBOR_EncodeMap(tx, 0);
}

static bool strequal(const uint8_t *buf, size_t len, const char *str)
{
    size_t slen = strlen(str);

    if (len == slen && !memcmp(buf, str, slen)) {
        return true;
    }

    return false;
}

static DPS_Status buildRequest(DPS_TxBuffer *tx, const char *operation,
    const char *resource, const char *query)
{
    DPS_Status ret;
    int entries;

    if (!operation) {
        goto error;
    }

    entries = 1; /* Always have 'operation' in the map */

    if (resource) {
        entries++;
    }

    if (query) {
        entries++;
    }

    ret = CBOR_EncodeMap(tx, entries);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeMap failed: %s\n", DPS_ErrTxt(ret));
        goto error;
    }

    ret = CBOR_EncodeString(tx, "operation");
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        goto error;
    }

    ret = CBOR_EncodeString(tx, operation);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
        goto error;
    }

    if (resource) {
        ret = CBOR_EncodeString(tx, "resource");
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
            goto error;
        }

        ret = CBOR_EncodeString(tx, resource);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
            goto error;
        }
    }

    if (query) {
        ret = CBOR_EncodeString(tx, "query");
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
            goto error;
        }

        ret = CBOR_EncodeString(tx, query);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
            goto error;
        }
    }

    return DPS_OK;

error:
    return DPS_ERR_INVALID;
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
}

static DPS_Status parseResult(DPS_RxBuffer *rx, char **di,
    uint64_t *status)
{
    DPS_Status ret;
    size_t num;

    ret = CBOR_DecodeMap(rx, &num);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_DecodeMap failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    while (num--) {
        char *key;
        size_t keyLen, diLen;

        ret = CBOR_DecodeString(rx, &key, &keyLen);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CBOR_DecodeString failed: %s\n", DPS_ErrTxt(ret));
            return -EINVAL;
        }

        if (strequal(key, keyLen, "code")) {
            ret = CBOR_DecodeUint(rx, status);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("CBOR_DecodeString failed: %s\n", DPS_ErrTxt(ret));
                return ret;
            }
            continue;
        }

        if (strequal(key, keyLen, "di")) {
            ret = CBOR_DecodeString(rx, di, &diLen);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("CBOR_DecodeString failed: %s\n", DPS_ErrTxt(ret));
                return ret;
            }
            continue;
        }
    }

    return num == -1 ? DPS_OK : DPS_ERR_INVALID;
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

static bool matchStringArray(DPS_RxBuffer *rx, const char *match)
{
    DPS_Status ret;
    size_t num;
    bool result = false;

    ret = CBOR_DecodeArray(rx, &num);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_DecodeArray failed: %s\n", DPS_ErrTxt(ret));
        return false;
    }

    while (num--) {
        size_t len;
        char *s;

        ret = CBOR_DecodeString(rx, &s, &len);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CBOR_DecodeString failed: %s\n", DPS_ErrTxt(ret));
            return -EINVAL;
        }

        if (match && strequal(s, len, match)) {
            result = true;
        };
    }

    return result;
}

static DPS_Status encodeMap(DPS_TxBuffer *tx, const struct map_entry entries[])
{
    const struct map_entry *e;
    DPS_Status ret;
    int num = 0;

    for (e = entries; e->key; e++) {
        num++;
    }

    ret = CBOR_EncodeMap(tx, num);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeMap failed: %s\n", DPS_ErrTxt(ret));
        return ret;
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

static void onUpdateAck(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_ERRPRINT("onUpdate pub %p payload %p len %zu\n", pub, payload, len);
    CBOR_Dump("payload",  payload, len);
}

static void onDiscoverAck(DPS_Publication* pub, uint8_t* payload, size_t len)
{
    DPS_ERRPRINT("onDiscoverAck pub %p payload %p len %zu\n", pub, payload, len);
    CBOR_Dump("payload",  payload, len);
}

static DPS_Status AppendPairs(DPS_TxBuffer *tx, int argc, char *argv[])
{
    DPS_Status ret;
    int i;

    if (argc % 2) {
        return DPS_ERR_INVALID;
    }

    ret = CBOR_EncodeMap(tx, argc / 2);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("CBOR_EncodeMap failed: %s\n", DPS_ErrTxt(ret));
        return ret;
    }

    for (i = 0; i < argc; i++) {
        ret = CBOR_EncodeString(tx, argv[i]);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("CBOR_EncodeString failed: %s\n", DPS_ErrTxt(ret));
            return ret;
        }
    }

    return DPS_OK;
}

static void dump_publication(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    CBOR_Dump("payload", data, len);
}

int main(int argc, char** argv)
{
    sd_id128_t id;
    DPS_Status ret;
    DPS_Subscription *sub;
    DPS_Publication *pub;
    DPS_Event *nodeDestroyed;
    int mcast = DPS_MCAST_PUB_ENABLE_SEND | DPS_MCAST_PUB_ENABLE_RECV;
    const char topic_device[strlen(OIC_ENDPOINT_DEVICE_PREFIX) + SD_ID128_STRING_MAX];
    const char *topics[1] = { OIC_ENDPOINT_ALL };
    const char *all_notification_topic[1] = { "/oic/endpoint/a22b901124154b82b15b1d21d7ba3892" };
    int len, r;
    DPS_NodeAddress *addr;
    DPS_TxBuffer tx;

    sd_id128_get_machine_app_specific(OUR_APPLICATION_ID, &id);

    node = DPS_CreateNode(":", NULL, NULL);

    if (argc < 3) {
        fprintf(stderr, "Usage: ocf_client <update||retrieve||notify> <topic> <path> [[key] [value]]+\n");
        return 1;
    }

    ret = DPS_StartNode(node, DPS_MCAST_PUB_DISABLED, 0);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_CreateNode failed: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    addr = DPS_CreateAddress();

    ret = DPS_LinkTo(node, NULL, DPS_PORT, addr);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_LinkTo failed: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    nodeDestroyed = DPS_CreateEvent();

    sub = DPS_CreateSubscription(node, all_notification_topic, 1);
    ret = DPS_Subscribe(sub, dump_publication);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_Subscribe failed: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    pub = DPS_CreatePublication(node);

    topics[0] = argv[2];

    ret = DPS_InitPublication(pub, topics, 1, false, NULL,
        onDiscoverAck);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_InitPublication failed: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    ret = DPS_TxBufferInit(&tx, buffer, sizeof(buffer));
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_TxBufferInit failed: %s\n", DPS_ErrTxt(ret));
        return 1;
    }

    len = buildRequest(&tx, argv[1], argv[3], NULL);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("buildRequest failed: %s\n", DPS_ErrTxt(ret));
        return -EINVAL;
    }

    argc -= 4;
    argv += 4;

    ret = AppendPairs(&tx, argc, argv);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("emptyPayload failed: %s\n", DPS_ErrTxt(ret));
        return -EINVAL;
    }

    ret = DPS_Publish(pub, tx.base, tx.txPos - tx.base, 0);

    DPS_WaitForEvent(nodeDestroyed);
    DPS_DestroyEvent(nodeDestroyed);

    return 0;
}
