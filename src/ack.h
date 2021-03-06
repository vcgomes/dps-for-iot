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

#ifndef _ACK_H
#define _ACK_H

#include <stdint.h>
#include <stddef.h>
#include <dps/private/dps.h>
#include "node.h"


#ifdef __cplusplus
extern "C" {
#endif

/*
 * Acknowledgment packet queued to be sent on node loop
 */
typedef struct _PublicationAck {
    DPS_TxBuffer headers;
    DPS_TxBuffer payload;
    DPS_NodeAddress destAddr;
    uint32_t sequenceNum;
    DPS_UUID pubId;
    struct _PublicationAck* next;
} PublicationAck;

/*
 */
DPS_Status DPS_DecodeAcknowledgment(DPS_Node* node, DPS_NetEndpoint* ep, DPS_RxBuffer* buffer);

/*
 * Send an previously serialized acknowledgement
 *
 * @param node    The local node
 * @param ack     The acknowledgment to send
 * @param ackNode The remote node to send the acknowledgment to
 */
DPS_Status DPS_SendAcknowledgment(DPS_Node*node, PublicationAck* ack, RemoteNode* ackNode);

/*
 * Free resources associated with an acknowledgement
 *
 * @param ack   The acknowledgment to destroy.
 */
void DPS_DestroyAck(PublicationAck* ack);

#ifdef __cplusplus
}
#endif

#endif
