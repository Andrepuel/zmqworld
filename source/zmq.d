module zmq;

import deimos.zmq.zmq;
import std.exception : enforce;

public import deimos.zmq.zmq : ZMQ_PAIR, ZMQ_PUB, ZMQ_SUB, ZMQ_REQ, ZMQ_REP, ZMQ_DEALER, ZMQ_ROUTER, ZMQ_PULL, ZMQ_PUSH, ZMQ_XPUB, ZMQ_XSUB, ZMQ_STREAM;

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

    void create() {
        int rc = zmq_curve_keypair(pubkey.ptr, pvtkey.ptr);
        enforce(rc != -1);
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

    void send(const(void)[] data) {
        int rc = zmq_send(socket, data.ptr, data.length, 0);
        enforce(rc != -1);
    }

    void[] recv(void[] data) {
        int rc = zmq_recv(socket, data.ptr, data.length, 0);
        enforce(rc != -1);
        return data[0..rc];
    }
}
