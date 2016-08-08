#include "questd.h"

struct ubus_auto_conn conn;

/*
* init functions
*/
void parse_args(int argc, char *argv[])
{
	if (argc != 1 || argv[1]) {
		printf("Parameters not supported.\n");
		return;
	}

	/* TODO add custom path for ubus socket */
	/* TODO add usage function */
}

void init_ubus(void)
{
	conn.cb = ubus_connect_cb;
	ubus_auto_connect(&conn);
}

/*
* (re)connect function(s)
*/
void ubus_connect_cb(struct ubus_context *ctx)
{
	int fd;

	printf("Connected to ubus as: %08x\n", ctx->local_id);

	/* set close-on-exec flag: do not share fd with child processes */
	/* fcntl is needed because libubus cannot do this */
	fd = ctx->sock.fd;
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
}

/*
* done/ending functions
*/
void done_ubus(void)
{
	/* if the re/connection to ubus is ongoing, there is nothing to clean */
	if (conn.timer.pending)
		return;

	/* disconnect from ubus */
	if (conn.ctx.local_id)
		printf("Disconnected from ubus. Was %08x\n",
			conn.ctx.local_id);
	ubus_shutdown(&conn.ctx);
}

void done_uloop(void)
{
	uloop_end(); /* this might trigger a segmentation fault in libubus */
	uloop_done();
}

/* register objects to ubus */
void add_objects(void)
{
	add_system_objects(&conn.ctx);
}


/*
* main function
*/
int main(int argc, char *argv[])
{

	parse_args(argc, argv);

	uloop_init();
	init_ubus();

	start_worker();
	add_objects();

	/* main loop */
	uloop_run();

	done_ubus();
	done_uloop();

	return 0;
}
