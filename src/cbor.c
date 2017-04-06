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

#include <dps/dbg.h>
#include <stdint.h>
#include <safe_lib.h>
#include <assert.h>
#include <dps/private/cbor.h>

/*
 * Debug control for this module
 */
DPS_DEBUG_CONTROL(DPS_DEBUG_ON);

#define CBOR_LEN1   24
#define CBOR_LEN2   25
#define CBOR_LEN4   26
#define CBOR_LEN8   27

#define CBOR_FALSE  (CBOR_OTHER | 20)
#define CBOR_TRUE   (CBOR_OTHER | 21)
#define CBOR_NULL   (CBOR_OTHER | 22)

static int Requires(uint64_t n)
{
    if (n < 24) {
        return 0;
    }
    if (n <= UINT8_MAX) {
        return 1;
    }
    if (n <= UINT16_MAX) {
        return 2;
    }
    if (n <= UINT32_MAX) {
        return 4;
    }
    return 8;
}

static DPS_Status EncodeUint(DPS_TxBuffer* buffer, uint64_t n, uint8_t maj)
{
    uint8_t* p = buffer->txPos;
    uint32_t lenReq = (uint32_t)Requires(n);

    if ((lenReq + 1) > DPS_TxBufferSpace(buffer)) {
        return DPS_ERR_OVERFLOW;
    }
    switch (lenReq) {
        case 0:
            *p++ = (uint8_t)(maj | n);
            break;
        case 1:
            *p++ = (uint8_t)(maj | CBOR_LEN1);
            *p++ = (uint8_t)(n);
            break;
        case 2:
            *p++ = (uint8_t)(maj | CBOR_LEN2);
            *p++ = (uint8_t)(n >> 8);
            *p++ = (uint8_t)(n);
            break;
        case 4:
            *p++ = (uint8_t)(maj | CBOR_LEN4);
            *p++ = (uint8_t)(n >> 24);
            *p++ = (uint8_t)(n >> 16);
            *p++ = (uint8_t)(n >> 8);
            *p++ = (uint8_t)(n);
            break;
        case 8:
            *p++ = (uint8_t)(maj | CBOR_LEN8);
            *p++ = (uint8_t)(n >> 56);
            *p++ = (uint8_t)(n >> 48);
            *p++ = (uint8_t)(n >> 40);
            *p++ = (uint8_t)(n >> 32);
            *p++ = (uint8_t)(n >> 24);
            *p++ = (uint8_t)(n >> 16);
            *p++ = (uint8_t)(n >> 8);
            *p++ = (uint8_t)(n);
    }
    buffer->txPos = p;
    return DPS_OK;
}

DPS_Status CBOR_EncodeLength(DPS_TxBuffer* buffer, uint64_t len, uint8_t maj)
{
    return EncodeUint(buffer, len, maj);
}

DPS_Status CBOR_Copy(DPS_TxBuffer* buffer, const uint8_t* data, size_t len)
{
    DPS_Status ret = DPS_OK;
    if (data) {
        if (memcpy_s(buffer->txPos, DPS_TxBufferSpace(buffer), data, len) != EOK) {
            ret = DPS_ERR_OVERFLOW;
        } else {
            buffer->txPos += len;
        }
    }
    return ret;
}

DPS_Status CBOR_DecodeBoolean(DPS_RxBuffer* buffer, int* i)
{
    if (DPS_RxBufferAvail(buffer) < 1) {
        return DPS_ERR_EOD;
    } else {
        uint8_t b = *buffer->rxPos++;
        if (b != CBOR_FALSE && b != CBOR_TRUE) {
            return DPS_ERR_INVALID;
        }
        *i = b & 1;
        return DPS_OK;
    }
}

/*
 * Byte length corresponding the various info encodings
 */
static const size_t IntLengths[] = { 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,3,5,9,0,0,0,0 };

static DPS_Status DecodeUint(DPS_RxBuffer* buffer, uint64_t* n, uint8_t* maj)
{
    size_t avail = DPS_RxBufferAvail(buffer);
    uint8_t* p = buffer->rxPos;
    uint8_t info;
    size_t len;

    if (avail < 1) {
        return DPS_ERR_EOD;
    }
    info = *p;
    *maj = info & 0xE0;
    info &= 0x1F;
    len = IntLengths[info];
    if (avail < len) {
        return DPS_ERR_EOD;
    }
    switch (len) {
    case 1:
        *n = info;
        break;
    case 2:
        *n = (uint64_t)p[1];
        break;
    case 3:
        *n = ((uint64_t)p[1] << 8) | (uint64_t)p[2];
        break;
    case 5:
        *n = ((uint64_t)p[1] << 24) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3]) << 8 | (uint64_t)p[4];
        break;
    case 9:
        *n = ((uint64_t)p[1] << 56) | ((uint64_t)p[2] << 48) | ((uint64_t)p[3] << 40) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 24) | ((uint64_t)p[6] << 16) | ((uint64_t)p[7] << 8) | (uint64_t)p[8];
        break;
    default:
        return DPS_ERR_INVALID;
    }
    buffer->rxPos += len;
    return DPS_OK;
}

DPS_Status CBOR_EncodeBoolean(DPS_TxBuffer* buffer, int i)
{
    if (DPS_TxBufferSpace(buffer) < 1) {
        return DPS_ERR_OVERFLOW;
    }
    *(buffer->txPos++) = i ? CBOR_TRUE : CBOR_FALSE;
    return DPS_OK;
}

DPS_Status CBOR_EncodeUint(DPS_TxBuffer* buffer, uint64_t n)
{
    return EncodeUint(buffer, n, CBOR_UINT);
}

DPS_Status CBOR_EncodeInt(DPS_TxBuffer* buffer, int64_t i)
{
    if (i >= 0) {
        return EncodeUint(buffer, (uint64_t)i, CBOR_UINT);
    } else {
        return EncodeUint(buffer, ~(uint64_t)i, CBOR_NEG);
    }
}

DPS_Status CBOR_EncodeBytes(DPS_TxBuffer* buffer, const uint8_t* data, size_t len)
{
    DPS_Status ret = EncodeUint(buffer, (uint32_t)len, CBOR_BYTES);
    if (ret == DPS_OK) {
        ret = CBOR_Copy(buffer, data, len);
    }
    return ret;
}

DPS_Status CBOR_ReserveBytes(DPS_TxBuffer* buffer, size_t len, uint8_t** ptr)
{
    DPS_Status ret = EncodeUint(buffer, (uint32_t)len, CBOR_BYTES);
    if (ret == DPS_OK) {
        if (DPS_TxBufferSpace(buffer) < len) {
            ret = DPS_ERR_OVERFLOW;
        } else {
            *ptr = buffer->txPos;
            buffer->txPos += len;
        }
    }
    return ret;
}

DPS_Status CBOR_StartWrapBytes(DPS_TxBuffer* buffer, size_t hintLen, uint8_t** ptr)
{
    DPS_Status ret;
    uint8_t* tmp;

    *ptr = buffer->txPos;
    ret = CBOR_ReserveBytes(buffer, hintLen, &tmp);
    if (ret == DPS_OK) {
        buffer->txPos = tmp;
    }
    return ret;
}

DPS_Status CBOR_EndWrapBytes(DPS_TxBuffer* buffer, uint8_t* wrapPtr)
{
    uint8_t maj;
    uint8_t* pos;
    uint64_t hint;
    size_t actual;
    int diff;
    DPS_RxBuffer rx;

    /*
     * Decode the original hint length
     */
    DPS_RxBufferInit(&rx, wrapPtr, CBOR_MAX_LENGTH);
    if ((DecodeUint(&rx, &hint, &maj) != DPS_OK) || (maj != CBOR_BYTES)) {
        return DPS_ERR_INVALID;
    }
    /*
     * See if the space needed to encode length changed
     */
    actual = buffer->txPos - rx.rxPos;
    diff = Requires(actual) - Requires(hint);
    if (diff && actual) {
        buffer->txPos = wrapPtr + Requires(actual);
        if (memmove_s(rx.rxPos + diff, DPS_TxBufferSpace(buffer), rx.rxPos, actual) != EOK) {
            return DPS_ERR_RESOURCES;
        }
    }
    /*
     * Rewind to write the actual length
     */
    buffer->txPos = wrapPtr;
    return CBOR_ReserveBytes(buffer, actual, &pos);
}


DPS_Status CBOR_EncodeString(DPS_TxBuffer* buffer, const char* str)
{
    DPS_Status ret;
    size_t len = strnlen_s(str, CBOR_MAX_STRING_LEN + 1);

    if (len > CBOR_MAX_STRING_LEN) {
        ret = DPS_ERR_OVERFLOW;
    } else {
        ret = EncodeUint(buffer, (uint32_t)len, CBOR_STRING);
    }
    if (ret == DPS_OK) {
        ret = CBOR_Copy(buffer, (uint8_t*)str, len);
    }
    return ret;
}

DPS_Status CBOR_EncodeArray(DPS_TxBuffer* buffer, size_t len)
{
    return EncodeUint(buffer, (uint32_t)len, CBOR_ARRAY);
}

DPS_Status CBOR_EncodeMap(DPS_TxBuffer* buffer, size_t len)
{
    return EncodeUint(buffer, (uint32_t)len, CBOR_MAP);
}

DPS_Status CBOR_EncodeTag(DPS_TxBuffer* buffer, uint64_t n)
{
    return EncodeUint(buffer, n, CBOR_TAG);
}

DPS_Status CBOR_DecodeUint(DPS_RxBuffer* buffer, uint64_t* n)
{
    uint8_t maj;
    DPS_Status ret;

    ret = DecodeUint(buffer, n, &maj);
    if ((ret == DPS_OK) && (maj != CBOR_UINT)) {
        ret = DPS_ERR_INVALID;
    }
    return ret;
}

DPS_Status CBOR_DecodeUint8(DPS_RxBuffer* buffer, uint8_t* n)
{
    uint64_t u64 = 0;
    uint8_t maj;
    DPS_Status ret;

    ret = DecodeUint(buffer, &u64, &maj);
    if ((ret == DPS_OK) && ((maj != CBOR_UINT) || (u64 > UINT8_MAX))) {
        ret = DPS_ERR_INVALID;
    }
    *n = (uint8_t)u64;
    return ret;
}

DPS_Status CBOR_DecodeUint16(DPS_RxBuffer* buffer, uint16_t* n)
{
    uint64_t u64 = 0;
    uint8_t maj;
    DPS_Status ret;

    ret = DecodeUint(buffer, &u64, &maj);
    if ((ret == DPS_OK) && ((maj != CBOR_UINT) || (u64 > UINT16_MAX))) {
        ret = DPS_ERR_INVALID;
    }
    *n = (uint16_t)u64;
    return ret;
}

DPS_Status CBOR_DecodeUint32(DPS_RxBuffer* buffer, uint32_t* n)
{
    uint64_t u64 = 0;
    uint8_t maj;
    DPS_Status ret;

    ret = DecodeUint(buffer, &u64, &maj);
    if ((ret == DPS_OK) && ((maj != CBOR_UINT) || (u64 > UINT32_MAX))) {
        ret = DPS_ERR_INVALID;
    }
    *n = (uint32_t)u64;
    return ret;
}

DPS_Status CBOR_DecodeInt(DPS_RxBuffer* buffer, int64_t* i)
{
    uint8_t maj;
    uint64_t n = 0;
    DPS_Status ret;

    ret = DecodeUint(buffer, &n, &maj);
    if (ret == DPS_OK) {
        if (maj == CBOR_UINT) {
            *i = (int64_t)n;
            if (*i < 0) {
                return DPS_ERR_INVALID;
            }
        } else if (maj == CBOR_NEG) {
            *i = (int64_t)(~n);
            if (*i > 0) {
                return DPS_ERR_INVALID;
            }
        } else {
            return DPS_ERR_INVALID;
        }
    }
    return ret;
}

DPS_Status CBOR_DecodeInt8(DPS_RxBuffer* buffer, int8_t* n)
{
    int64_t i64 = 0;
    DPS_Status ret = CBOR_DecodeInt(buffer, &i64);
    if ((ret == DPS_OK) && ((i64 < INT8_MIN) || (i64 > INT8_MAX))) {
        ret = DPS_ERR_INVALID;
    }
    *n = (int8_t)i64;
    return ret;
}

DPS_Status CBOR_DecodeInt16(DPS_RxBuffer* buffer, int16_t* n)
{
    int64_t i64 = 0;
    DPS_Status ret = CBOR_DecodeInt(buffer, &i64);
    if ((ret == DPS_OK) && ((i64 < INT16_MIN) || (i64 > INT16_MAX))) {
        ret = DPS_ERR_INVALID;
    }
    *n = (int16_t)i64;
    return ret;
}

DPS_Status CBOR_DecodeInt32(DPS_RxBuffer* buffer, int32_t* n)
{
    int64_t i64 = 0;
    DPS_Status ret = CBOR_DecodeInt(buffer, &i64);
    if ((ret == DPS_OK) && ((i64 < INT32_MIN) || (i64 > INT32_MAX))) {
        ret = DPS_ERR_INVALID;
    }
    *n = (int32_t)i64;
    return ret;
}

DPS_Status CBOR_DecodeBytes(DPS_RxBuffer* buffer, uint8_t** data, size_t* size)
{
    uint8_t maj;
    DPS_Status ret;
    uint64_t len;

    *data = NULL;
    *size = 0;
    ret = DecodeUint(buffer, &len, &maj);
    if (ret == DPS_OK) {
        if ((maj != CBOR_BYTES) || (len > DPS_RxBufferAvail(buffer))) {
            ret = DPS_ERR_INVALID;
        } else {
            if (len) {
                *data = buffer->rxPos;
                *size = len;
                buffer->rxPos += len;
            }
        }
    }
    return ret;
}

DPS_Status CBOR_DecodeString(DPS_RxBuffer* buffer, char** data, size_t* size)
{
    uint8_t maj;
    DPS_Status ret;
    uint64_t len;

    ret = DecodeUint(buffer, &len, &maj);
    if (ret == DPS_OK) {
        if ((maj != CBOR_STRING) || (len > DPS_RxBufferAvail(buffer))) {
            ret = DPS_ERR_INVALID;
        } else {
            *data = len ? (char*)buffer->rxPos : NULL;
            *size = len;
            buffer->rxPos += len;
        }
    }
    return ret;
}

DPS_Status CBOR_DecodeArray(DPS_RxBuffer* buffer, size_t* size)
{
    uint8_t maj;
    DPS_Status ret;
    uint64_t len;

    ret = DecodeUint(buffer, &len, &maj);
    if (ret == DPS_OK) {
        if (maj != CBOR_ARRAY) {
            ret = DPS_ERR_INVALID;
        } else {
            *size = len;
        }
    }
    return ret;
}

DPS_Status CBOR_DecodeMap(DPS_RxBuffer* buffer, size_t* size)
{
    uint8_t maj;
    DPS_Status ret;
    uint64_t len;

    ret = DecodeUint(buffer, &len, &maj);
    if (ret == DPS_OK) {
        if (maj != CBOR_MAP) {
            ret = DPS_ERR_INVALID;
        } else {
            *size = len;
        }
    }
    return ret;
}

DPS_Status CBOR_DecodeTag(DPS_RxBuffer* buffer, uint64_t* n)
{
    uint8_t maj;
    uint8_t* pos = buffer->rxPos;
    DPS_Status ret;

    ret = DecodeUint(buffer, n, &maj);
    if ((ret == DPS_OK) && (maj != CBOR_TAG)) {
        buffer->rxPos = pos;
        ret = DPS_ERR_INVALID;
    }
    return ret;
}

DPS_Status CBOR_Skip(DPS_RxBuffer* buffer, uint8_t* majOut, size_t* skipped)
{
    DPS_Status ret = DPS_OK;
    size_t avail = DPS_RxBufferAvail(buffer);
    uint8_t* startPos = buffer->rxPos;
    uint64_t len = 0;
    size_t size = 0;
    uint8_t* dummy;
    uint8_t info;
    uint8_t maj;

    if (avail < 1) {
        return DPS_ERR_EOD;
    }
    info = buffer->rxPos[0];
    maj = info & 0xE0;
    info &= 0x1F;

    switch (maj) {
    case CBOR_UINT:
    case CBOR_NEG:
    case CBOR_TAG:
        len = IntLengths[info];
        if (len == 0) {
            ret = DPS_ERR_INVALID;
        } else if (avail < len) {
            ret = DPS_ERR_EOD;
        } else {
            buffer->rxPos += len;
        }
        break;
    case CBOR_BYTES:
        ret = CBOR_DecodeBytes(buffer, &dummy, &size);
        break;
    case CBOR_STRING:
        ret = CBOR_DecodeString(buffer, (char**)&dummy, &size);
        break;
    case CBOR_ARRAY:
        ret = DecodeUint(buffer, &len, &maj);
        while ((ret == DPS_OK) && len--) {
            ret = CBOR_Skip(buffer, NULL, NULL);
        }
        break;
    case CBOR_MAP:
        ret = DecodeUint(buffer, &len, &maj);
        while ((ret == DPS_OK) && len--) {
            ret = CBOR_Skip(buffer, NULL, NULL);
            if (ret == DPS_OK) {
                ret = CBOR_Skip(buffer, NULL, NULL);
            }
        }
        break;
    case CBOR_OTHER:
        if (info < 20 || info > 22) {
            ret = DPS_ERR_INVALID;
        } else {
            buffer->rxPos += 1;
        }
        break;
    default:
        ret = DPS_ERR_INVALID;
    }
    if (skipped) {
        *skipped = buffer->rxPos - startPos;
    }
    if (majOut) {
        *majOut = maj;
    }
    return ret;
}

size_t _CBOR_SizeOfString(const char* s)
{
    size_t len = s ? strnlen_s(s, CBOR_MAX_STRING_LEN) + 1 : 0;
    return len + CBOR_SIZEOF_LEN(len);
}

DPS_Status DPS_ParseMapInit(CBOR_MapState* mapState, DPS_RxBuffer* buffer, const int32_t* keys, size_t numKeys)
{
    mapState->buffer = buffer;
    mapState->keys = keys;
    mapState->needKeys = numKeys;
    mapState->result = CBOR_DecodeMap(buffer, &mapState->entries);
    return mapState->result;
}

DPS_Status DPS_ParseMapNext(CBOR_MapState* mapState, int32_t* key)
{
    int32_t k = 0;

    if (mapState->result != DPS_OK) {
        return mapState->result;
    }
    mapState->result = DPS_ERR_MISSING;
    while (mapState->entries && mapState->needKeys) {
        --mapState->entries;
        mapState->result = CBOR_DecodeInt32(mapState->buffer, &k);
        if (mapState->result != DPS_OK) {
            break;
        }
        if (k == mapState->keys[0]) {
            ++mapState->keys;
            --mapState->needKeys;
            *key = k;
            break;
        }
        /*
         * Keys must be in ascending order
         */
        if (k > mapState->keys[0]) {
            mapState->result = DPS_ERR_MISSING;
            break;
        }
        /*
         * Skip map entries for keys we are not looking for
         */
        mapState->result = CBOR_Skip(mapState->buffer, NULL, NULL);
        if (mapState->result != DPS_OK) {
            break;
        }
    }
    if (mapState->result != DPS_OK) {
        return mapState->result;
    }
    if (mapState->needKeys) {
        /*
         * We expect there to be more entries
         */
        if (!mapState->entries) {
            mapState->result = DPS_ERR_MISSING;
        }
    }
    return mapState->result;
}

int DPS_ParseMapDone(CBOR_MapState* mapState)
{
    int32_t k;

    if (mapState->needKeys) {
        return DPS_FALSE;
    } else {
        while (mapState->entries) {
            /*
             * We have all the keys we need so skip all remaining entries
             */
            --mapState->entries;
            mapState->result = CBOR_DecodeInt32(mapState->buffer, &k);
            if (mapState->result == DPS_OK) {
                mapState->result = CBOR_Skip(mapState->buffer, NULL, NULL);
            }
            if (mapState->result != DPS_OK) {
                return DPS_FALSE;
            }
        }
        return DPS_TRUE;
    }
}

#ifndef NDEBUG
static DPS_Status Dump(DPS_RxBuffer* buffer, int in)
{
    static const char indent[] = "                                                            ";
    DPS_Status ret = DPS_OK;
    size_t size = 0;
    uint64_t len;
    uint8_t* dummy;
    uint8_t maj;
    uint64_t n;

    if (DPS_RxBufferAvail(buffer) < 1) {
        return DPS_ERR_EOD;
    }
    switch(buffer->rxPos[0] & 0xE0) {
    case CBOR_UINT:
        ret = DecodeUint(buffer, &n, &maj);
        DPS_PRINT("%.*suint:%zu\n", in, indent, n);
        break;
    case CBOR_NEG:
        ret = DecodeUint(buffer, &n, &maj);
        DPS_PRINT("%.*sint:-%zu\n", in, indent, n);
        break;
    case CBOR_TAG:
        ret = DecodeUint(buffer, &n, &maj);
        DPS_PRINT("%.*stag:%zu\n", in, indent, n);
        break;
    case CBOR_BYTES:
        ret = CBOR_DecodeBytes(buffer, &dummy, &size);
        DPS_PRINT("%.*sbstr: len=%zu\n", in, indent, size);
        break;
    case CBOR_STRING:
        ret = CBOR_DecodeString(buffer, (char**)&dummy, &size);
        DPS_PRINT("%.*sstring: \"%.*s\"\n", in, indent, (int)size, dummy);
        break;
    case CBOR_ARRAY:
        DPS_PRINT("%.*s[\n", in, indent);
        ret = DecodeUint(buffer, &len, &maj);
        while ((ret == DPS_OK) && len--) {
            ret = Dump(buffer, in + 2);
        }
        DPS_PRINT("%.*s]\n", in, indent);
        break;
    case CBOR_MAP:
        DPS_PRINT("%.*s{\n", in, indent);
        ret = DecodeUint(buffer, &len, &maj);
        while ((ret == DPS_OK) && len--) {
            ret = Dump(buffer, in + 2);
            if (ret == DPS_OK) {
                ret = Dump(buffer, in + 4);
            }
        }
        DPS_PRINT("%.*s}\n", in, indent);
        break;
    case CBOR_OTHER:
        if (buffer->rxPos[0] == CBOR_TRUE) {
            DPS_PRINT("%.*sTRUE\n", in, indent);
            ++buffer->rxPos;
            break;
        }
        if (buffer->rxPos[0] == CBOR_FALSE) {
            DPS_PRINT("%.*sFALSE\n", in, indent);
            ++buffer->rxPos;
            break;
        }
        if (buffer->rxPos[0] == CBOR_NULL) {
            DPS_PRINT("%.*sNULL\n", in, indent);
            ++buffer->rxPos;
            break;
        }
        ret = DPS_ERR_INVALID;
        break;
    default:
        ret = DPS_ERR_INVALID;
    }
    return ret;
}

void CBOR_Dump(const char* tag, uint8_t* data, size_t len)
{
    if (DPS_DEBUG_ENABLED()) {
        DPS_Status ret;
        DPS_RxBuffer tmp;

        if (tag) {
            DPS_PRINT("CBOR %s:\n", tag);
        }
        DPS_RxBufferInit(&tmp, data, len);
        while (DPS_RxBufferAvail(&tmp)) {
            ret = Dump(&tmp, 0);
            if (ret != DPS_OK) {
                DPS_ERRPRINT("Invalid CBOR at offset %d\n", (int)(tmp.rxPos - tmp.base));
                break;
            }
        }
    }
}
#endif

