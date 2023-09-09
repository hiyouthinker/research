/*
 * BigBro @2023
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include <zookeeper_log.h>
#include <zookeeper.jute.h>
#include <zookeeper.h>

static zhandle_t *zkhandle = NULL;
static char zk_addr[] = "10.6.130.68:2181";
static int zk_timeout = 5;
static char level1_path[] = "/test";

static const char* state2String(int state)
{
    if (state == 0)
        return "CLOSED_STATE";
    if (state == ZOO_CONNECTING_STATE)
        return "CONNECTING_STATE";
    if (state == ZOO_ASSOCIATING_STATE)
        return "ASSOCIATING_STATE";
    if (state == ZOO_CONNECTED_STATE)
        return "CONNECTED_STATE";
    if (state == ZOO_EXPIRED_SESSION_STATE)
        return "EXPIRED_SESSION_STATE";
    if (state == ZOO_AUTH_FAILED_STATE)
        return "AUTH_FAILED_STATE";

    return "INVALID_STATE";
}

static void policy_watcher(zhandle_t* zh, int type, int state, const char* path, void* watcherCtx) 
{
	const clientid_t *zk_clientid = NULL;
	struct String_vector policy_children;
	int ret, i;

	if (type == ZOO_CREATED_EVENT)
		printf("%s created. not expected\n",  path);
	else if (type == ZOO_DELETED_EVENT)
		printf("%s deleted. not expected\n",  path);
	else if (type == ZOO_CHANGED_EVENT)
		printf("%s changed.\n", path);
	else if (type == ZOO_CHILD_EVENT) {
		char node[512], buffer[512];
		int buffer_len = sizeof(buffer);
		struct Stat stat;

		printf("znode %s children changed.\n",  path);

		sleep(10);

		ret = zoo_get_children(zkhandle, path, true, &policy_children);
		if (ret != ZOK) {
			printf("fail to call zoo_get_children: err=%d, msg=%s\n",  ret, zerror(ret));    
			return;
		}

		printf("set children watch %s ok\n", path);

		printf("%s: number of node: %d\n", path, policy_children.count);

#if 0
		for (i = 0; i < policy_children.count; i++)  {
			sprintf(node, "%s/%s", path, policy_children.data[i]);

			ret = zoo_get(zkhandle, node, false, buffer, &buffer_len, &stat);
			if (ret != ZOK) {
				printf("fail to get node %s, err= %d, msg=%s\n", node, ret, zerror(ret));
				continue;
			}
				printf("%s: content: %s\n", path, buffer);
		}			
#endif
	} else if (type == ZOO_SESSION_EVENT) {
		if (state == ZOO_EXPIRED_SESSION_STATE) {
			printf("zookeeper session expired\n");
			zookeeper_close(zkhandle);
			zkhandle = zookeeper_init(zk_addr, policy_watcher, zk_timeout, 0, NULL, 0);
			if (zkhandle != NULL) {
				printf("init zookeeper handler again ok");
			} else {
				printf("init zookeeper handler again failed");
			}
		} else if (state == ZOO_AUTH_FAILED_STATE)
			printf("zookeeper session auth failed\n");
		else if (state == ZOO_CONNECTING_STATE)
			printf("zookeeper session is connecting\n");
		else if (state == ZOO_ASSOCIATING_STATE)
			printf("zookeeper session is associating state\n");
		else if (state == ZOO_CONNECTED_STATE) {
			zk_clientid = zoo_client_id(zh);
			printf("connected to zookeeper server with clientid=%lu\n",  zk_clientid ->client_id);

			ret = zoo_get_children(zkhandle, level1_path, true, &policy_children);
			if (ret != ZOK) {
				printf("fail to call zoo_get_children: err=%d, msg=%s\n",  ret, zerror(ret));    
				return;
			}
			printf("set children watch %s ok\n", level1_path);

#if 0
			if (policy_children.count < 4) {
				for (i = 0; i < policy_children.count; i++)  {
					printf("%s: %s\n", policy_watch_path, policy_children.data[i]);
				}
			} else {
				printf("%s: number of node: %d\n", policy_watch_path, policy_children.count);
			}
#endif
			deallocate_String_vector(&policy_children); 
		} else if (state == ZOO_NOTWATCHING_EVENT) 
			printf("zookeeper session remove watch\n");
		else 
			printf("unknown session event state = %s, path = %s, ctxt=%s\n", state2String(state), path, (char *)watcherCtx);
	}
}

/*
 * gcc zk_test.c -o zk_test -I./include/zookeeper-c -L./lib/zookeeper-c -lzookeeper_mt -DTHREADED
 */
int main(int argc, char *argv[])
{
	zkhandle = zookeeper_init(zk_addr, policy_watcher, zk_timeout, 0, NULL, 0);
	if (!zkhandle) {
		printf("zookeeper_init error: %s\n", strerror(errno));
		return 0;
	}

	while (1) {
		sleep(2);
	}

	printf("Done\n");
	return 0;
}
