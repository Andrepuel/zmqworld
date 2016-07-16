module zmq;

import deimos.zmq.zmq;
import std.exception : enforce;

public import deimos.zmq.zmq : ZMQ_PAIR, ZMQ_PUB, ZMQ_SUB, ZMQ_REQ, ZMQ_REP, ZMQ_DEALER, ZMQ_ROUTER, ZMQ_PULL, ZMQ_PUSH, ZMQ_XPUB, ZMQ_XSUB, ZMQ_STREAM, ZMQ_AFFINITY;
public import deimos.zmq.zmq : ZMQ_IDENTITY, ZMQ_SUBSCRIBE, ZMQ_UNSUBSCRIBE, ZMQ_RATE, ZMQ_RECOVERY_IVL, ZMQ_SNDBUF, ZMQ_RCVBUF, ZMQ_RCVMORE, ZMQ_FD, ZMQ_EVENTS, ZMQ_TYPE, ZMQ_LINGER, ZMQ_RECONNECT_IVL, ZMQ_BACKLOG, ZMQ_RECONNECT_IVL_MAX, ZMQ_MAXMSGSIZE, ZMQ_SNDHWM, ZMQ_RCVHWM, ZMQ_MULTICAST_HOPS, ZMQ_RCVTIMEO, ZMQ_SNDTIMEO, ZMQ_LAST_ENDPOINT, ZMQ_ROUTER_MANDATORY, ZMQ_TCP_KEEPALIVE, ZMQ_TCP_KEEPALIVE_CNT, ZMQ_TCP_KEEPALIVE_IDLE, ZMQ_TCP_KEEPALIVE_INTVL, ZMQ_IMMEDIATE, ZMQ_XPUB_VERBOSE, ZMQ_ROUTER_RAW, ZMQ_IPV6, ZMQ_MECHANISM, ZMQ_PLAIN_SERVER, ZMQ_PLAIN_USERNAME, ZMQ_PLAIN_PASSWORD, ZMQ_CURVE_SERVER, ZMQ_CURVE_PUBLICKEY, ZMQ_CURVE_SECRETKEY, ZMQ_CURVE_SERVERKEY, ZMQ_PROBE_ROUTER, ZMQ_REQ_CORRELATE, ZMQ_REQ_RELAXED, ZMQ_CONFLATE, ZMQ_ZAP_DOMAIN, ZMQ_ROUTER_HANDOVER, ZMQ_TOS, ZMQ_CONNECT_RID, ZMQ_GSSAPI_SERVER, ZMQ_GSSAPI_PRINCIPAL, ZMQ_GSSAPI_SERVICE_PRINCIPAL, ZMQ_GSSAPI_PLAINTEXT, ZMQ_HANDSHAKE_IVL, ZMQ_SOCKS_PROXY, ZMQ_XPUB_NODROP;
public import deimos.zmq.zmq : ZMQ_DONTWAIT, ZMQ_SNDMORE;


__gshared void* zctx;
shared static this() {
    zctx = zmq_ctx_new();
    assert(zctx != null);
}

shared static ~this() {
    zmq_ctx_term(zctx);
    zctx = null;
}

struct CurveKey {
    char[41] pubkey;
    char[41] pvtkey;

    void fromRaw(const(void)[] raw) {
        enforce(raw.length == 32);
        ubyte[32] copy;
        copy[] = cast(ubyte[])raw;
        zmq_z85_encode(pubkey.ptr, copy.ptr, 32);
    }

    void create() {
        int rc = zmq_curve_keypair(pubkey.ptr, pvtkey.ptr);
        enforce(rc != -1);
    }

    @property void priv(const(char)[] input) {
        enforce(input.length == 40);
        pvtkey[0..40] = input;
    }

    @property const(char)[] priv() const {
        return pvtkey[0..40];
    }

    @property void pub(const(char)[] input) {
        enforce(input.length == 40);
        pubkey[0..40] = input;
    }

    @property const(char)[] pub() const {
        return pubkey[0..40];
    }
}

struct ZSocket {
    void* socket;

    @disable this(this);

    this(int type) {
        socket = zmq_socket(zctx, type);
        enforce(socket !is null);
    }

    ~this() {
        import std.algorithm : swap;

        if (socket is null) return;
        void* destroying;
        swap(destroying, socket);
        zmq_close(destroying);
    }

    void setsockopt(int opt, const(void)* value, size_t len) {
        int rc = zmq_setsockopt(socket, opt, value, len);
        enforce(rc != -1);
    }
    
    void setsockopt(int opt, int value) {
        setsockopt(opt, &value, int.sizeof);
    }

    void getsockopt(int opt, void* value, size_t* len) {
        int rc = zmq_getsockopt(socket, opt, value, len);
        enforce(rc != -1);
    }

    T getsockopt(T)(int opt) {
        T r;
        size_t len = T.sizeof;
        getsockopt(opt, &r, &len);
        enforce(len == T.sizeof);
        return r;
    }

    void curveServer(in CurveKey key) {
        setsockopt(ZMQ_CURVE_SERVER, 1);
        setsockopt(ZMQ_CURVE_SECRETKEY, key.pvtkey.ptr, 40);
    }

    void curveClient(in CurveKey server, in CurveKey key) {
        setsockopt(ZMQ_CURVE_SERVERKEY, server.pubkey.ptr, 40);
        setsockopt(ZMQ_CURVE_PUBLICKEY, key.pubkey.ptr, 40);
        setsockopt(ZMQ_CURVE_SECRETKEY, key.pvtkey.ptr, 40);
    }

    void bind(string addr) {
        import core.stdc.stdlib : alloca;
        char[] addrZ = (cast(char*)alloca(addr.length + 1))[0..addr.length+1];
        addrZ[0..$-1] = addr[];
        addrZ[$-1] = 0;
        int rc = zmq_bind(socket, addrZ.ptr);
        enforce(rc != -1);
    }

    void connect(string addr) {
        import core.stdc.stdlib : alloca;
        char[] addrZ = (cast(char*)alloca(addr.length + 1))[0..addr.length+1];
        addrZ[0..$-1] = addr[];
        addrZ[$-1] = 0;
        int rc = zmq_connect(socket, addrZ.ptr);
        enforce(rc != -1);
    }

    void send(const(void)[] data, int flags = 0) {
        int rc = zmq_send(socket, data.ptr, data.length, flags);
        enforce(rc != -1);
    }

    void[] recv(void[] data, bool* recvmore = null) {
        int rc = zmq_recv(socket, data.ptr, data.length, 0);
        enforce(rc != -1);
        if (recvmore !is null) {
            *recvmore = getsockopt!int(ZMQ_RCVMORE) > 0;
        }
        return data[0..rc];
    }

    void send(ref ZMessage msg, int flags = 0) {
        enforce(cast(bool) msg);
        int rc = zmq_msg_send(&msg.msg, socket, flags);
        enforce(rc != -1);
    }

    ZMessage recv(bool* recvmore = null) {
        ZMessage r = ZMessage(0);
        recv(r, recvmore);
        return r;
    }

    void recv(ref ZMessage msg, bool* recvmore = null) {
        enforce(cast(bool) msg);
        int rc = zmq_msg_recv(&msg.msg, socket, 0);
        if (recvmore !is null) {
            *recvmore = getsockopt!int(ZMQ_RCVMORE) > 0;
        }
        enforce(rc != -1);
    }
}

struct ZMessage {
    zmq_msg_t msg;

    @disable this(this);

    this(size_t size) {
        assert(!this);
        int rc;
        if (size == 0) {
            rc = zmq_msg_init(&msg);
        } else {
            rc = zmq_msg_init_size(&msg, size);
        }
        enforce(rc != -1);
        assert(this);
    }

    this(const(void)[] dataArg) {
        this(dataArg.length);
        data()[] = cast(ubyte[])dataArg;
    }

    ~this() {
        if (!this) return;
        zmq_msg_close(&msg);
        msg = zmq_msg_t.init;
    }

    ZMessage copy() {
        enforce(cast(bool) this);
        ZMessage r = ZMessage(0);
        int rc = zmq_msg_copy(&r.msg, &msg);
        enforce(rc != -1);
        return r;
    }

    ubyte[] data() {
        assert(this);
        return (cast(ubyte*)zmq_msg_data(&msg))[0..zmq_msg_size(&msg)];
    }

    bool opCast(T)() const
    if (is(T == bool))
    {
        return msg != zmq_msg_t.init;
    }
}

size_t recvFrames(ref ZSocket socket, ZMessage[] buf) {
    ZMessage[] result;
    bool more = true;
    size_t n;
    while (more && buf.length > 0) {
        buf[0] = ZMessage(0);
        socket.recv(buf[0], &more);
        ++n;
        buf = buf[1..$];
    }

    if (more) {
        while (more) {
            ZMessage garbage = ZMessage(0);
            socket.recv(garbage, &more);
            ++n;
        }
    }

    return n;
}

void sendFrames(ref ZSocket socket, ZMessage[] buf) {
    while (buf.length > 0) {
        socket.send(buf[0], buf.length > 1 ? ZMQ_SNDMORE : 0);
        buf = buf[1..$];
    }
}

class AuthError : Exception {
    this(in CurveKey k) {
        super((k.pub ~ " key reject.").idup);
    }
}

void installZap(bool delegate(in CurveKey ident) cb) {
    import core.thread;

    ZSocket zapReady = ZSocket(ZMQ_REP);
    zapReady.bind("inproc://zap_ready");

    auto a = new Thread(() {
        import core.stdc.stdlib;
        import std.algorithm : min;
        debug import std.stdio;

        scope (failure) abort();

        ZMessage msg_version = ZMessage("1.0");
        ZMessage msg_200 = ZMessage("200");
        ZMessage msg_400 = ZMessage("400");
        ZMessage msg_500 = ZMessage("500");

        ZSocket handler = ZSocket(ZMQ_REP);
        handler.bind("inproc://zeromq.zap.01");

        {
            ZSocket zapReadyNotify = ZSocket(ZMQ_REQ);
            zapReadyNotify.connect("inproc://zap_ready");
            ZMessage empty = ZMessage(0);
            zapReadyNotify.send(empty);
        }

        while (true) {
            ZMessage[7] request;
            auto requestN = handler.recvFrames(request);
            ZMessage[6] response;
            foreach(ref r; response) r = ZMessage(0);
            try {
                response[0] = msg_version.copy;
                if (request.length > 1) response[1] = request[1].copy;
                enforce(requestN >= 6);
                enforce((cast(char[])request[5].data) == "CURVE");
                enforce(requestN == 7);
                CurveKey key;
                key.fromRaw(request[6].data);
                if (!cb(key)) throw new AuthError(key);
                writeln("Accepting ", key.pub);
                response[2] = msg_200.copy;
                response[4] = ZMessage(key.pub);
            } catch(AuthError e) {
                debug stderr.writeln(e);
                response[2] = msg_400.copy;
                response[3] = ZMessage(e.msg[0..$.min(255)]);
            } catch(Exception e) {
                debug stderr.writeln(e);
                response[2] = msg_500.copy;
                response[3] = ZMessage(e.msg[0..$.min(255)]);
            }
            assert(response[2].data.length > 0);
            handler.sendFrames(response[]);
        }
    });

    a.isDaemon = true;
    a.start();
    zapReady.recv();
}
