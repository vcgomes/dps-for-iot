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

#ifndef _COAP_H
#define _COAP_H

#include <stdint.h>
#include <stddef.h>
#include <dps/private/dps.h>

#ifdef __cplusplus
extern "C" {
#endif

#define COAP_OVER_UDP   0
#define COAP_OVER_TCP   1

#define COAP_UDP_PORT   5683
#define COAP_TCP_PORT   5683

#define COAP_MCAST_ALL_NODES_LINK_LOCAL_6   "ff02::fd"
#define COAP_MCAST_ALL_NODES_LINK_LOCAL_4   "224.0.1.187"


#define COAP_VERSION          1

/*
 * Message types
 */
#define COAP_TYPE_CONFIRMABLE      0
#define COAP_TYPE_NON_CONFIRMABLE  1
#define COAP_TYPE_ACKNOWLEDGEMENT  2
#define COAP_TYPE_RESET            3

/*
 * Compose a code from a class and detail
 */
#define COAP_CODE(class_bits, detail_bits)  (((class_bits) << 5) | ((detail_bits) & 0x1F))

/*
 * Code classes
 */
#define COAP_REQUEST    0
#define COAP_SUCCESS    2
#define COAP_ERROR      4
#define COAP_SRV_ERROR  5

/*
 * Detail codes for class REQUEST
 */
#define COAP_GET      1
#define COAP_POST     2
#define COAP_PUT      3
#define COAP_DELETE   4

/*
 * Option identifiers
 */
#define COAP_OPT_IF_MATCH    1
#define COAP_OPT_URI_HOST    3
#define COAP_OPT_URI_PORT    7
#define COAP_OPT_URI_PATH   11
#define COAP_OPT_URI_QUERY  15

#define COAP_END_OF_OPTS   0xFF

typedef struct {
    uint8_t id;
    size_t len;
    const uint8_t* val;
} CoAP_Option;


typedef struct {
    uint8_t version;
    uint8_t type;
    uint8_t code;
    int16_t msgId;
    CoAP_Option *opts;
    uint16_t numOpts;
    uint8_t token[8];
    size_t tokenLen;
} CoAP_Parsed;


/**
 * Parses enough of the packet to determin the packet length. This is really only useful for COAP over TCP
 * because for COAP over UDP the UPD datagram size IS the packet size.
 *
 * @param protocol  UDP or TCP
 * @param buf       The buffer containing a CoAP packet
 * @param bufLen    The length of data in the buffer
 * @param pktLen    Returns the length of the packet
 *
 * @return   - DPS_OK if the packet size is known
 *           - DPS_ERR_EOD if there is not enought data in the buffer to determine the packet size
 */
DPS_Status CoAP_GetPktLen(int protocol, const uint8_t* buf, size_t bufLen, size_t* pktLen);

/*
 * Parse a CoAP packet from the buffer. The parsed contents hold pointer into
 * buffer so the buffer must not be freed until the parsed packet is no longer
 * needed.
 *
 * @param protocol  UDP or TCP
 * @param buf       The buffer containing a CoAP packet
 * @param bufLen    The length of the CoAP packet
 * @param coAP      Data structure to return the parsed CoAP packet
 * @param data      Returns a pointer to the CoAP payload
 * @param dataLen   Retuns the lenght of the CoAP payload
 *
 * @return  Returns DPS_OK if the packet was succesfully parsed or an error
 *          code if the packet was not succesfully parsed.
 */
DPS_Status CoAP_Parse(int protocol, const uint8_t* buf, size_t bufLen, CoAP_Parsed* coap, DPS_RxBuffer* payload);

/*
 * Free resources allocated for a parsed CoAP packet
 *
 * @param coap  A parsed packet.
 */
void CoAP_Free(CoAP_Parsed* coap);

/**
 * Compose a CoAP packet into a buffer.
 *
 * @param protocol   UDP or TCP - the serialization is different depeding on the underlying protocol
 * @param code       The CoAP command code
 * @param opts       CoAP options to serialize into the buffer
 * @param numOpts    The number of options to serialize
 * @param payloadLen The number of bytes in the payload
 * @param buf        The output buffer
 *
 * @return   Returns DPS_OK if the packet was composed on an error if the operation failed.
 */
DPS_Status CoAP_Compose(int protocol, uint8_t code, const CoAP_Option* opts, size_t numOpts, size_t payloadLen, DPS_TxBuffer* buf);

/*
 * Print a CoAP option to stdout
 */
void CoAP_DumpOpt(const CoAP_Option* opt);

#ifdef __cplusplus
}
#endif

#endif
