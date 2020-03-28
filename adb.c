/*
 * "Adb" backend.
 */

#include <stdio.h>
#include <stdlib.h>

#include "putty.h"

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#define ADB_MAX_BACKLOG 4096

typedef struct Adb Adb;
struct Adb {
	Socket* s;
	int state;
	size_t bufsize;
	Seat* seat;
	LogContext* logctx;
	Conf* conf;
	Plug plug;
	Backend backend;
};


static void adb_size(Backend* be, int width, int height);

static void c_write(Adb *adb, const void* buf, size_t len)
{
    size_t backlog = seat_stdout(adb->seat, buf, len);
    sk_set_frozen(adb->s, backlog > ADB_MAX_BACKLOG);
}

static void adb_log(Plug* plug, PlugLogType type, SockAddr* addr, int port,
	const char* error_msg, int error_code)
{
    Adb *adb = container_of(plug, Adb, plug);
    char addrbuf[256], *msg;

    sk_getaddr(addr, addrbuf, lenof(addrbuf));

    if (type == 0)
	msg = dupprintf("Connecting to %s port %d", addrbuf, port);
    else
	msg = dupprintf("Failed to connect to %s: %s", addrbuf, error_msg);

    logevent(adb->logctx, msg);
}

static int adb_closing(Plug* plug, const char* error_msg, int error_code,
	bool calling_back)
{
	Adb* adb = container_of(plug, Adb, plug);

    if (adb->s) {
        sk_close(adb->s);
        adb->s = NULL;
		seat_notify_remote_exit(adb->seat);
    }
    if (error_msg) {
	/* A socket error has occurred. */
	logevent(adb->logctx, error_msg);
	seat_connection_fatal(adb->seat, "%s", error_msg);
    }				       /* Otherwise, the remote side closed the connection normally. */
    return 0;
}

static int adb_receive(Plug* plug, int urgent, const char* data, size_t len)
{
	Adb* adb = container_of(plug, Adb, plug);
	if (adb->state==1) {
		if (data[0]=='O') { // OKAY
			sk_write(adb->s,"0006shell:",10);
			adb->state=2; // wait for shell start response
		} else {
			if (data[0]=='F') {
				char* d = (char*)smalloc(len+1);
				memcpy(d,data,len);
				d[len]='\0';
				seat_connection_fatal(adb->seat, "%s", d+8);
				sfree(d);
			} else {
				seat_connection_fatal(adb->seat, "Bad response");
			}
			return 0;
		}
	} else if (adb->state==2) {
		if (data[0]=='O') { //OKAY
			adb->state=3; // shell started, switch to terminal mode
		} else {
			if (data[0]=='F') {
				char* d = (char*)smalloc(len+1);
				memcpy(d,data,len);
				d[len]='\0';
				seat_connection_fatal(adb->seat, "%s", d+8);
				sfree(d);
			} else {
				seat_connection_fatal(adb->seat, "Bad response");
			}
			return 0;
		}
	} else {
		c_write(adb, data, len);
	}
    return 1;
}

static void adb_sent(Plug* plug, size_t bufsize)
{
	Adb* adb = container_of(plug, Adb, plug);
    adb->bufsize = bufsize;
}

/*
 * Called to set up the adb connection.
 * 
 * Returns an error message, or NULL on success.
 *
 * Also places the canonical host name into `realhost'. It must be
 * freed by the caller.
 */
//(void *frontend_handle, void **backend_handle,
//	 Conf *conf, const char *host, int port,
//	 char **realhost, int nodelay, int keepalive) 
 /* void* frontend_handle, void** backend_handle,
Conf* cfg,
const  char* host, int port, char** realhost, int nodelay,
int keepalive */

static const PlugVtable Adb_plugvt = {
	.log = adb_log,
	.closing = adb_closing,
	.receive = adb_receive,
	.sent = adb_sent,
};

static const char *adb_init(const BackendVtable* vt, Seat* seat,
	Backend** backend_handle, LogContext* logctx,
	Conf* conf, const char* host, int port,
	char** realhost, bool nodelay, bool keepalive)
{

    SockAddr *addr;
    const char *err;
    Adb *adb;
	char sendhost[512];
	int addressfamily;
	char *loghost;

	seat_set_trust_status(seat, false);

    adb = snew(Adb);
    adb->plug.vt = &Adb_plugvt;
	adb->backend.vt = vt;
    adb->s = NULL;
	adb->state = 0;
    *backend_handle = &adb->backend;
	
    adb->conf = conf_copy(conf);
	adb->seat = seat;
	adb->logctx = logctx;
    /*
     * Try to find host.
     */
	addressfamily = conf_get_int(conf, CONF_addressfamily);
    {
	char *buf;
	buf = dupprintf("Looking up host \"%s\"%s", "localhost",
			(addressfamily == ADDRTYPE_IPV4 ? " (IPv4)" :
			 (addressfamily == ADDRTYPE_IPV6 ? " (IPv6)" :
			  "")));
	logevent(adb->logctx, buf);
	sfree(buf);
    }
    addr = name_lookup("localhost", port, realhost, conf, addressfamily, adb->logctx, "Telnet connection");
    if ((err = sk_addr_error(addr)) != NULL) {
	sk_addr_free(addr);
	return err;
    }

    if (port < 0)
	port = 5037;		       /* default adb port */

    /*
     * Open socket.
     */
    adb->s = new_connection(addr, *realhost, port, false, true, nodelay, keepalive,
			     &adb->plug, conf);
    if ((err = sk_socket_error(adb->s)) != NULL)
	return err;
	loghost = conf_get_str(conf, CONF_loghost);
    if (loghost) {
	char *colon;

	sfree(*realhost);
	*realhost = dupstr(loghost);
	colon = strrchr(*realhost, ':');
	if (colon) {
	    /*
	     * FIXME: if we ever update this aspect of ssh.c for
	     * IPv6 literal management, this should change in line
	     * with it.
	     */
	    *colon++ = '\0';
	}
    }

	/* send initial data to adb server */
	
	sprintf_s(sendhost,512,"%04xhost:%s",strlen(host)+5,host);

	sk_write(adb->s,sendhost,strlen(host)+9);
	adb->state = 1;
    return NULL;
}

static void adb_free(Backend* be)
{
	Adb* adb = container_of(be, Adb, backend);
    if (adb->s)
	sk_close(adb->s);
    sfree(adb);
}

/*
 * Stub routine (we don't have any need to reconfigure this backend).
 */
static void adb_reconfig(Backend* be, Conf* conf)
{
}

/*
 * Called to send data down the adb connection.
 */
static int adb_send(Backend* be, const char* buf, size_t len)
{
	Adb* adb = container_of(be, Adb, backend);

    if (adb->s == NULL)
	return 0;

    adb->bufsize = sk_write(adb->s, buf, len);

    return adb->bufsize;
}

/*
 * Called to query the current socket sendability status.
 */
static int adb_sendbuffer(Backend* be)
{
	Adb* adb = container_of(be, Adb, backend);
    return adb->bufsize;
}

/*
 * Called to set the size of the window
 */
static void adb_size(Backend* be, int width, int height)
{
    /* Do nothing! */
    return;
}

/*
 * Send adb special codes.
 */
static void adb_special(Backend* be, SessionSpecialCode code, int arg)
{
    /* Do nothing! */
    return;
}

/*
 * Return a list of the special codes that make sense in this
 * protocol.
 */
static const SessionSpecial *adb_get_specials(Backend* be)
{
    return NULL;
}

static bool adb_connected(Backend* be)
{
	Adb* adb = container_of(be, Adb, backend);
    return adb->s != NULL;
}

static bool adb_sendok(Backend* be)
{
    return true;
}

static void adb_unthrottle(Backend* be, size_t backlog)
{
	Adb* adb = container_of(be, Adb, backend);
    sk_set_frozen(adb->s, backlog > ADB_MAX_BACKLOG);
}

static bool adb_ldisc(Backend* be, int option)
{
    // Don't allow line discipline options
    return false;
}

static void adb_provide_ldisc(Backend* be, Ldisc* ldisc)
{
    /* This is a stub. */
}

static void adb_provide_logctx(void *handle, void *logctx)
{
    /* This is a stub. */
}

static int adb_exitcode(Backend* be)
{
	Adb* adb = container_of(be, Adb, backend);
    if (adb->s != NULL)
        return -1;                     /* still connected */
    else
        /* Exit codes are a meaningless concept in the Adb protocol */
        return 0;
}

/*
 * cfg_info for Adb does nothing at all.
 */
static int adb_cfg_info(Backend* be)
{
    return 0;
}

const BackendVtable adb_backend = {
	.init = adb_init,
	.free = adb_free,
	.reconfig = adb_reconfig,
	.send = adb_send,
	.sendbuffer = adb_sendbuffer,
	.size = adb_size,
	.special = adb_special,
	.get_specials = adb_get_specials,
	.connected = adb_connected,
	.exitcode = adb_exitcode,
	.sendok = adb_sendok,
	.ldisc_option_state = adb_ldisc,
	.provide_ldisc = adb_provide_ldisc,
	.unthrottle = adb_unthrottle,
	.cfg_info = adb_cfg_info,
	.id = "adb",
	.displayname = "ADB",
	.protocol = PROT_ADB,
	.default_port = 5037,
};
