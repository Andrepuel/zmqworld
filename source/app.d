import std.stdio;
import deimos.zmq.zmq;
import std.exception : enforce;

void main() {
    auto zctx = zmq_ctx_new();
    assert(zctx != null);
    scope(exit) zmq_ctx_term(zctx);

    int rc;

    char[41] server_pubkey;
    char[41] server_privkey;
    rc = zmq_curve_keypair(server_pubkey.ptr, server_privkey.ptr);
    enforce(rc != -1);

    void* server = zmq_socket(zctx, ZMQ_PUSH);
    assert(server !is null);
    scope(exit) zmq_close(server);
    int one = 1;
    rc = zmq_setsockopt(server, ZMQ_CURVE_SERVER, &one, int.sizeof);
    enforce(rc != -1);
    rc = zmq_setsockopt(server, ZMQ_CURVE_SECRETKEY, server_privkey.ptr, 40);
    enforce(rc != -1);

    rc = zmq_bind(server, "tcp://*:9000");
    enforce(rc != -1);

    char[41] client_pubkey;
    char[41] client_privkey;
    rc = zmq_curve_keypair(client_pubkey.ptr, client_privkey.ptr);
    enforce(rc != -1);

    void* client = zmq_socket(zctx, ZMQ_PULL);
    assert(client !is null);
    scope(exit) zmq_close(client);
    rc = zmq_setsockopt(client, ZMQ_CURVE_PUBLICKEY, client_pubkey.ptr, 40);
    enforce(rc != -1);
    rc = zmq_setsockopt(client, ZMQ_CURVE_SECRETKEY, client_privkey.ptr, 40);
    enforce(rc != -1);
    rc = zmq_setsockopt(client, ZMQ_CURVE_SERVERKEY, server_pubkey.ptr, 40);
    enforce(rc != -1);

    rc = zmq_connect(client, "tcp://127.0.0.1:9000");
    enforce(rc != -1);

    rc = zmq_send(server, "some data".ptr, 9, 0);
    enforce(rc != -1);

    char[256] buf;
    rc = zmq_recv(client, buf.ptr, 256, 0);
    enforce(rc != -1);
    enforce(buf[0..rc] == "some data");

    writeln("Grasslands ok!");
}
