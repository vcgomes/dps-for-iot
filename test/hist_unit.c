/*
 * Unit test for internal history APIs
 *
 */
#include <memory.h>
#include <assert.h>
#include <uv.h>
#include <dps.h>
#include <dps_dbg.h>
#include <stdlib.h>
#include "dps_uuid.h"
#include "dps_history.h"
#include "dps_internal.h"

extern void usleep(int);

extern void DPS_DumpHistory(DPS_History* history);

static DPS_History history;

#define NUM_PUBS   1000

int main()
{
    int i = 0;
    int j;
    uint32_t sn;
    DPS_UUID uuid[NUM_PUBS];
    DPS_NodeAddress addr;
    DPS_NodeAddress* addrPtr;

    DPS_Debug = 1;
    addr.inaddr.ss_family = AF_INET6;
    DPS_InitUUID();

#ifdef READABLE_UUIDS
    /* 
     * This makes debugging easier
     */
    memset(uuid, 0, sizeof(uuid));
    while (i < NUM_PUBS) {
        int n = rand() % NUM_PUBS;
        if (uuid[n].val64[0] == 0) {
            uuid[n].val64[0] = ++i;
        }
    }
#else
    for (i = 0; i < NUM_PUBS; ++i) {
        DPS_GenerateUUID(&uuid[i]);
    }
#endif
    /*
     * Add entries
     */
    DPS_PRINT("Add entries\n");
    for (i = 0; i < NUM_PUBS; ++i) {
        DPS_UpdatePubHistory(&history, &uuid[i], 1, 0, &addr);
    }
    /*
     * Check there are all there
     */
    DPS_PRINT("Check all entries present\n");
    for (i = 0; i < NUM_PUBS; ++i) {
        if (DPS_LookupPublisher(&history, &uuid[i], &sn, &addrPtr) != DPS_OK) {
            DPS_PRINT("Pub history lookup failed\n");
            return 1;
        }
    }
    /*
     * Remove some
     */
    DPS_PRINT("Remove some entries\n");
    for (i = 0; i < NUM_PUBS / 4; ++i) {
        if (DPS_DeletePubHistory(&history, &uuid[i]) != DPS_OK) {
            DPS_PRINT("Pub history delete failed\n");
            return 1;
        }
    }
    /*
     * Check remaining pubs are still there
     */
    DPS_PRINT("Check remaining entries\n");
    for (i = NUM_PUBS / 4; i < NUM_PUBS; ++i) {
        if (DPS_LookupPublisher(&history, &uuid[i], &sn, &addrPtr) != DPS_OK) {
            DPS_PRINT("Pub history lookup failed\n");
            return 1;
        }
    }
    /*
     * Put them back
     */
    DPS_PRINT("Replace removed entries\n");
    for (i = 0; i < NUM_PUBS / 4; ++i) {
        DPS_UpdatePubHistory(&history, &uuid[i], 1, 0, &addr);
    }
    /*
     * Check there are all there
     */
    DPS_PRINT("Check all entries present after replacement\n");
    for (i = 0; i < NUM_PUBS; ++i) {
        if (DPS_LookupPublisher(&history, &uuid[i], &sn, &addrPtr) != DPS_OK) {
            DPS_PRINT("Pub history lookup failed\n");
            return 1;
        }
    }
    /*
     * Protect some by setting a longer timeout
     */
    for (i = NUM_PUBS / 4; i < NUM_PUBS / 3; ++i) {
        DPS_UpdatePubHistory(&history, &uuid[i], 1, 20, &addr);
    }
    /*
     * Wait a while - default timeout is 10 seconds
     */
    DPS_PRINT("Wait for history to expire\n");
    usleep(12 * 1000000);
    /*
     * Expire the stale entries
     */
    DPS_FreshenHistory(&history);
    /*
     * Check protected entries are still there and others have expired
     */
    for (i = 0; i < NUM_PUBS; ++i) {
        DPS_Status ret = DPS_LookupPublisher(&history, &uuid[i], &sn, &addrPtr);
        if (i >= NUM_PUBS / 4 &&  i < NUM_PUBS / 3) {
            if (ret != DPS_OK) {
                DPS_PRINT("Pub history is missing\n");
                return 1;
            }
        } else {
            if (ret != DPS_ERR_MISSING) {
                DPS_PRINT("Pub history was not expired\n");
                return 1;
            }
            DPS_PRINT("Pub history %s expired\n", DPS_UUIDToString(&uuid[i]));
        }
    }
    DPS_HistoryFree(&history);

    DPS_PRINT("Unit test passed\n");

    return 0;

}