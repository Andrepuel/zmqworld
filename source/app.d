import std.stdio;
import zmq;

void main() {
    CurveKey serverKey;
    serverKey.create();

    ZSocket server = ZSocket(ZMQ_PUSH);
    server.curveServer(serverKey);
    server.bind("tcp://*:9000");

    CurveKey clientKey;
    clientKey.create();

    ZSocket client = ZSocket(ZMQ_PULL);
    client.curveClient(serverKey, clientKey);
    client.connect("tcp://127.0.0.1:9000");

    server.send("some data");
    char[256] buf;
    enforce((cast(char[])client.recv(buf)) == "some data");

    writeln("Grasslands ok!");
}
