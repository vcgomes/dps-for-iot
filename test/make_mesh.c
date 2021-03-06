/*
 *******************************************************************
 *
 * Copyright 2017 Intel Corporation All rights reserved.
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <uv.h>
#include <dps/private/network.h>
#include <dps/dbg.h>
#include <dps/dps.h>
#include <dps/synchronous.h>
#include <dps/event.h>
#include "../src/node.h"

/*
 * This is just test code so to make it easy port numbers maps 1:1 into this array
 */
static uint16_t PortMap[UINT16_MAX];

/*
 * Maps node id's to DPS nodes
 */
static DPS_Node* NodeMap[UINT16_MAX];

/*
 * List of node id's from the input file
 */
static uint16_t NodeList[UINT16_MAX];

static void OnPubMatch(DPS_Subscription* sub, const DPS_Publication* pub, uint8_t* data, size_t len)
{
    static uint8_t AckFmt[] = "This is an ACK from %d";
    DPS_Status ret;
    const DPS_UUID* pubId = DPS_PublicationGetUUID(pub);
    uint32_t sn = DPS_PublicationGetSequenceNum(pub);
    size_t i;
    size_t numTopics;

    DPS_PRINT("Pub %s(%d) matches:\n", DPS_UUIDToString(pubId), sn);
    DPS_PRINT("  pub ");
    numTopics = DPS_PublicationGetNumTopics(pub);
    for (i = 0; i < numTopics; ++i) {
        if (i) {
            DPS_PRINT(" | ");
        }
        DPS_PRINT("%s", DPS_PublicationGetTopic(pub, i));
    }
    DPS_PRINT("\n");
    DPS_PRINT("  sub ");
    numTopics = DPS_SubscriptionGetNumTopics(sub);
    for (i = 0; i < numTopics; ++i) {
        if (i) {
            DPS_PRINT(" & ");
        }
        DPS_PRINT("%s", DPS_SubscriptionGetTopic(sub, i));
    }
    DPS_PRINT("\n");
    if (data) {
        DPS_PRINT("%.*s\n", (int)len, data);
    }

    if (DPS_PublicationIsAckRequested(pub)) {
        char ackMsg[sizeof(AckFmt) + 8];

        sprintf(ackMsg, AckFmt, DPS_GetPortNumber(DPS_PublicationGetNode(pub)));

        ret = DPS_AckPublication(pub, ackMsg, sizeof(ackMsg));
        if (ret != DPS_OK) {
            DPS_PRINT("Failed to ack pub %s\n", DPS_ErrTxt(ret));
        }
    }
}

typedef struct _LINK {
    uint16_t src;
    uint16_t dst;
    int muted;
    struct _LINK* next;
} LINK;

static LINK* links = NULL;

static LINK* HasLink(uint16_t src, uint16_t dst)
{
    LINK* l;
    for (l = links; l != NULL; l = l->next) {
        if (l->src == src && l->dst == dst) {
            return l;
        }
        if (l->dst == src && l->src == dst) {
            return l;
        }
    }
    return NULL;
}

static int IsNew(uint16_t n)
{
    LINK* l;
    for (l = links; l != NULL; l = l->next) {
        if (l->src == n || l->dst == n) {
            return 0;
        }
    }
    return 1;
}

static size_t NumArcs()
{
    size_t numArcs = 0;
    LINK* l;
    for (l = links; l != NULL; l = l->next) {
        ++numArcs;
    }
    return numArcs;
}

static LINK* AddLink(uint16_t src, uint16_t dst)
{
    LINK* l = HasLink(src, dst);
    if (!l) {
        l = calloc(1, sizeof(LINK));
        l->next = links;
        l->src = src;
        l->dst = dst;
        links = l;
    }
    return l;
}

static int StrArg(char* opt, char*** argp, int* argcp, const char** val)
{
    char** arg = *argp;
    int argc = *argcp;

    if (strcmp(*arg++, opt) != 0) {
        return 0;
    }
    if (!--argc) {
        return 0;
    }
    *val = *arg++;
    if (**val == '-') {
        DPS_PRINT("Value for option %s must be a string\n", opt);
        return 0;
    }
    *argp = arg;
    *argcp = argc;
    return 1;
}

static int IntArg(char* opt, char*** argp, int* argcp, int* val, int min, int max)
{
    char* p;
    char** arg = *argp;
    int argc = *argcp;

    if (strcmp(*arg++, opt) != 0) {
        return 0;
    }
    if (!--argc) {
        return 0;
    }
    *val = strtol(*arg++, &p, 10);
    if (*p) {
        return 0;
    }
    if (*val < min || *val > max) {
        DPS_PRINT("Value for option %s must be in range %d..%d\n", opt, min, max);
        return 0;
    }
    *argp = arg;
    *argcp = argc;
    return 1;
}

static uint16_t GetPort(DPS_NodeAddress* nodeAddr)
{
    const struct sockaddr* addr = (const struct sockaddr*)&nodeAddr->inaddr;
    if (addr->sa_family == AF_INET6) {
        return ntohs(((const struct sockaddr_in6*)addr)->sin6_port);
    } else {
        return ntohs(((const struct sockaddr_in*)addr)->sin_port);
    }
}

static size_t AddLinksForNode(DPS_Node* node)
{
    size_t numMuted = 0;
    RemoteNode* remote;
    uint16_t nodeId = PortMap[DPS_GetPortNumber(node)];

    for (remote = node->remoteNodes; remote != NULL; remote = remote->next) {
        uint16_t port = GetPort(&remote->ep.addr);
        uint16_t id = PortMap[port];
        if (NodeMap[id]) {
            LINK* link = AddLink(nodeId, id);
            if (remote->outbound.muted) {
                ++numMuted;
                link->muted = 1;
            }
        }
    }
    return numMuted;
}

static void MakeLinks(size_t* numNodes, size_t* numMuted)
{
    size_t i;

    *numMuted = 0;
    *numNodes = 0;

    /* Delete stale link info */
    while (links) {
        LINK* l = links;
        links = links->next;
        free(l);
    }
    for (i = 0; i < A_SIZEOF(NodeMap); ++i) {
        if (NodeMap[i]) {
            *numMuted += AddLinksForNode(NodeMap[i]);
            *numNodes += 1;
        }
    }
}

static void PrintSubgraph(FILE* f, int showMuted, uint16_t* kills, size_t numKills)
{
    static int g = 0;
    static int base = 0;
    static const char* style[] = {
        " [len=0.7]",
        " [color=red, style=dotted, len=1.5]"
    };
    LINK* l;
    size_t i;
    size_t numNodes = 0;
    size_t numArcs = 0;
    size_t numMuted = 0;
    int maxN = 0;

    MakeLinks(&numNodes, &numMuted);
    if (numMuted & 1) {
        DPS_ERRPRINT("Odd number of muted links - something went wrong\n");
    }

    fprintf(f, "subgraph cluster_%d {\n", g++);
    for (i = 0; i < numKills; ++i) {
        fprintf(f, "  %d[style=filled, fillcolor=yellow];\n", kills[i] + base);
    }
    for (l = links; l != NULL; l = l->next) {
        int src = l->src + base;
        int dst = l->dst + base;
        if (showMuted || (l->muted == 0)) {
            fprintf(f, "  %d -- %d%s;\n", src, dst, style[l->muted]);
            fprintf(f, "  %d[label=%d];\n", src, l->src);
            fprintf(f, "  %d[label=%d];\n", dst, l->dst);
            ++numArcs;
        }
        maxN  = (src > maxN) ? src : maxN;
        maxN  = (dst > maxN) ? dst : maxN;
    }
    fprintf(f, "  labelloc=t;\n");
    fprintf(f, "  label=\"Nodes=%d arcs=%d muted=%d\";\n", (int)numNodes, (int)NumArcs(), (int)(numMuted / 2));
    fprintf(f, "}\n");

    base += maxN + 1;
}

static void DumpLinks()
{
    LINK* l;
    for (l = links; l != NULL; l = l->next) {
        DPS_PRINT("   %d -> %d;\n", l->src, l->dst);
    }
}

static int ReadLinks(const char* fn)
{
    int numIds = 0;
    FILE* f;

    f = fopen(fn, "r");
    if (!f) {
        DPS_PRINT("Could not open file %s\n", fn);
        return 0;
    }
    while (1) {
        int ep1;
        int ep2;
        size_t n = 0;
        ssize_t len;
        char line[32];

        if (fgets(line, sizeof(line), f) == NULL) {
            break;
        }
        len = strnlen(line, sizeof(line));
        if (len != 0) {
            char* l = line;
            char* e;

            ep1 = strtol(l, &e, 10);
            if (l != e) {
                l = e;
                ep2 = strtol(l, &e, 10);
            }
            if (l == e) {
                DPS_PRINT("Link requires two nodes\n");
                goto ErrExit;
            }
            if (ep1 == ep2) {
                DPS_PRINT("Cannot link to self\n");
                goto ErrExit;

            }
            if (IsNew(ep1)) {
                NodeList[numIds++] = ep1;
            }
            if (IsNew(ep2)) {
                NodeList[numIds++] = ep2;
            }
            AddLink(ep1, ep2);
        }
    }
    fclose(f);
    return numIds;

ErrExit:

    fclose(f);
    return 0;
}

static void DumpMeshIds(uint16_t numIds)
{
    size_t i;
    for (i = 0; i < numIds; ++i) {
        uint16_t id = NodeList[i];
        DPS_Node* node = NodeMap[id];
        if (node) {
            DPS_PRINT("Node[%d] has meshId %08x (min=%08x)\n", id, UUID_32(&node->meshId), UUID_32(&node->minMeshId));
        }
    }
}

static void DumpPortMap(uint16_t numIds)
{
    size_t i;
    for (i = 0; i < numIds; ++i) {
        uint16_t id = NodeList[i];
        DPS_Node* node = NodeMap[id];
        DPS_PRINT("Node[%d] = %d\n", id, DPS_GetPortNumber(node));
    }
}

static void OnNodeDestroyed(DPS_Node* node, void* data)
{
    if (data) {
        DPS_PRINT("Node %d destroyed\n", *(uint16_t*)data);
    }
}

const LinkMonitorConfig FastLinkProbe = {
    .retries = 0,     /* Maximum number of retries following a probe failure */
    .probeTO = 1000,  /* Repeat rate for probes */
    .retryTO = 10     /* Repeat time for retries following a probe failure */
};

#define MAX_KILLS  16

int main(int argc, char** argv)
{
    FILE* dotFile = NULL;
    DPS_Status ret;
    char** arg = argv + 1;
    LINK* l;
    DPS_Event* sleeper;
    int numIds = 0;
    int numLinks = 0;
    int maxSubs = 1;
    int numSubs = 0;
    int numKills = 0;
    const char* inFn = NULL;
    const char* outFn = NULL;
    uint16_t killList[MAX_KILLS];
    size_t i;

    DPS_Debug = 0;

    while (--argc) {
        if (StrArg("-f", &arg, &argc, &inFn)) {
            continue;
        }
        if (StrArg("-o", &arg, &argc, &outFn)) {
            continue;
        }
        if (IntArg("-s", &arg, &argc, &maxSubs, 0, 10000)) {
            continue;
        }
        if (IntArg("-k", &arg, &argc, &numKills, 0, MAX_KILLS)) {
            continue;
        }
        if (strcmp(*arg, "-d") == 0) {
            ++arg;
            DPS_Debug = 1;
            continue;
        }
        if (IntArg("-n", &arg, &argc, &numIds, 2, UINT16_MAX)) {
            continue;
        }
    }
    if (inFn) {
        numIds = ReadLinks(inFn);
        if (numIds == 0) {
            return 1;
        }
        DumpLinks();
    } else {
        /*
         * TODO - do something useful here
         */
        DPS_PRINT("No input file\n");
        return 1;
    }
    /*
     * Start the nodes
     */
    for (i = 0; i < numIds; ++i) {
        DPS_Node* node = DPS_CreateNode("/.", NULL, NULL);
        ret = DPS_StartNode(node, DPS_FALSE, 0);
        if (ret != DPS_OK) {
            DPS_ERRPRINT("Failed to start node: %s\n", DPS_ErrTxt(ret));
            return 1;
        }
        PortMap[DPS_GetPortNumber(node)] = NodeList[i];
        NodeMap[NodeList[i]] = node;
        /*
         * Set fast link monitor probes so we don't
         * need to wait so long to detect disconnects.
         */
        node->linkMonitorConfig = FastLinkProbe;
    }
    DumpPortMap(numIds);

    sleeper = DPS_CreateEvent();
    /*
     * Wait for a short time while before trying to link
     */
    DPS_TimedWaitForEvent(sleeper, 2000);
    /*
     * Link the nodes
     */
    for (l = links; l != NULL; l = l->next) {
        DPS_NodeAddress* addr = DPS_CreateAddress();
        DPS_Node* src = NodeMap[l->src];
        DPS_Node* dst = NodeMap[l->dst];

        ret = DPS_LinkTo(src, NULL, DPS_GetPortNumber(dst), addr);
        if (ret == DPS_OK) {
            DPS_PRINT("Node %d connected to node %d\n", l->src, l->dst);
            ++numLinks;
        } else {
            DPS_ERRPRINT("Failed to link %d to %d returned %s\n", l->src, l->dst, DPS_ErrTxt(ret));
        }
        DPS_DestroyAddress(addr);
    }

    DPS_PRINT("%d nodes created %d links \n", numIds, numLinks);

    DPS_TimedWaitForEvent(sleeper, 100);
    /*
     * Add some subscriptions
     */
    while (maxSubs > 0) {
        for (i = 0; i < numIds && numSubs < maxSubs; ++i) {
            DPS_Node* node = NodeMap[NodeList[i]];
            if ((DPS_Rand() % 4) == 0) {
                DPS_Subscription* sub;
                char topic[] = "A";
                const char* topicList[] = { topic };

                topic[0] += DPS_Rand() % 26;
                sub = DPS_CreateSubscription(node, topicList, 1);
                if (!sub) {
                    DPS_ERRPRINT("CreateSubscribe failed\n");
                    break;
                }
                ret = DPS_Subscribe(sub, OnPubMatch);
                if (ret == DPS_OK) {
                    ++numSubs;
                } else {
                    DPS_ERRPRINT("Subscribe failed %s\n", DPS_ErrTxt(ret));
                }
                DPS_TimedWaitForEvent(sleeper, 1 + DPS_Rand() % 100);
            }
        }
        /*
         * Need to have at least one subscription
         */
        if (numSubs > 0) {
            maxSubs = 0;
        }
    }

    /*
     * Decide which nodes we are going to kill
     */
    for (i = 0; i < numKills; ++i) {
        uint16_t goner = NodeList[DPS_Rand() % numIds];
        if (NodeMap[goner]) {
            killList[i] = goner;
        }
    }

    DPS_TimedWaitForEvent(sleeper, 1000);

    DumpMeshIds(numIds);

    if (outFn) {
        dotFile = fopen(outFn, "w");
        if (!dotFile) {
            DPS_PRINT("Could not open %s for writing\n");
            dotFile = stdout;
        }
    }
    if (!dotFile) {
        dotFile = stdout;
    }

    fprintf(dotFile, "graph {\n");
    fprintf(dotFile, "  node[shape=circle, width=0.3, fontsize=10, margin=\"0.01,0.01\", fixedsize=true];\n");
    fprintf(dotFile, "  overlap=false;\n");
    fprintf(dotFile, "  splines=true;\n");

    fprintf(dotFile, "subgraph cluster_A {\n");
    PrintSubgraph(dotFile, 1, killList, numKills);
    PrintSubgraph(dotFile, 0, killList, numKills);
    fprintf(dotFile, "}\n");

    if (numKills > 0) {
        /*
         * Kill the nodes on the list
         */
        for (i = 0; i < numKills; ++i) {
            uint16_t goner = killList[i];
            if (NodeMap[goner]) {
                DPS_PRINT("Killing node %d\n", goner);
                DPS_DestroyNode(NodeMap[goner], OnNodeDestroyed, &killList[i]);
                NodeMap[goner] = NULL;
            }
        }

        DPS_TimedWaitForEvent(sleeper, 5000);

        fprintf(dotFile, "subgraph cluster_B {\n");
        PrintSubgraph(dotFile, 1, NULL, 0);
        PrintSubgraph(dotFile, 0, NULL, 0);
        fprintf(dotFile, "}\n");
    }

    fprintf(dotFile, "}\n");

    if (dotFile != stdout) {
        fclose(dotFile);
    }

    DPS_DestroyEvent(sleeper);

    for (i = 0; i < A_SIZEOF(NodeMap); ++i) {
        if (NodeMap[i]) {
            DPS_DestroyNode(NodeMap[i], OnNodeDestroyed, NULL);
            NodeMap[i] = NULL;
        }
    }

    return 0;
}
