import std.stdio;
import zmq;
import std.datetime;
import core.thread;
import std.conv;
import std.range;
import std.getopt;

void main() {
    import std.algorithm;
    import std.range;

    ZSocket toAgent = ZSocket(ZMQ_ROUTER);
    toAgent.bind("tcp://*:9000");

    ZSocket oneAgent = ZSocket(ZMQ_REQ);
    oneAgent.setsockopt(ZMQ_IDENTITY, "48091521119");
    oneAgent.connect("tcp://127.0.0.1:9000");
    oneAgent.send("hello");

    toAgent.recvFrames().ptrList.map!(x => cast(char[])x.data).writeln;
    ZMessage[3] send = [ZMessage("48091521119"), ZMessage(""), ZMessage("sup")];
    toAgent.sendFrames(send[]);

    oneAgent.recvFrames().ptrList.map!(x => cast(char[])x.data).writeln;
}

void main4() {
    installZap((x) {
        writeln("Accepting ", x.pub);
        return true;
    });

    CurveKey b;
    b.create();
    ZSocket server = ZSocket(ZMQ_REP);
    server.curveServer(b);
    server.bind("tcp://*:9000");

    CurveKey c;
    c.create();
    ZSocket client = ZSocket(ZMQ_REQ);
    client.curveClient(b, c);
    client.setsockopt(ZMQ_IDENTITY, c.pub.ptr, c.pub.length);
    client.connect("tcp://127.0.0.1:9000");

    client.send("sup moite");
    writeln("client sent");
    
    import std.algorithm;
    import std.range;

    ZMessage[5] buf;
    auto repN = server.recvFrames(buf);
    repN = repN > buf.length ? buf.length : repN;
    writeln(0.iota(repN).map!(x => (cast(ubyte[])buf[x].data).escape).join(" "));
    import deimos.zmq.zmq;
    import std.string;
    writeln(zmq_msg_gets(&buf[0].msg, "User-Id").fromStringz);
}

void main3(string[] args) {
    ZSocket client = ZSocket(ZMQ_REQ);
    client.setsockopt(ZMQ_IDENTITY, "puelusername:".ptr, "puelusername".length);
    client.connect("tcp://127.0.0.1:9001");

    ZSocket brokerClient = ZSocket(ZMQ_ROUTER);
    brokerClient.bind("tcp://*:9001");

    ZSocket brokerServer = ZSocket(ZMQ_DEALER);
    brokerServer.bind("tcp://*:9002");
 
    ZSocket server = ZSocket(ZMQ_REP);
    server.connect("tcp://127.0.0.1:9002");

    client.send([0]);

    char[128] buf;
    while (true) {
        bool more;
        auto data = cast(ubyte[])brokerClient.recv(buf, &more);
        writeln(data, " ", cast(char[])data);

        brokerServer.send(data, more ? ZMQ_SNDMORE : 0);
        if (!more) {
            writeln("End of data");
            break;
        }
    }
    auto data = cast(ubyte[])server.recv(buf);
    writeln(data);
}

void main2(string[] args) {
    string serverKeyStr;
    ushort serverPort = 9000;
    bool genkey;

    auto help = args.getopt("genkey", "Generate key pair for server", &genkey,
                            "serverkey", "Starts the server with the given key", &serverKeyStr,
                            "port|p", "Which ports the server listen to", &serverPort);

    if (help.helpWanted) {
        defaultGetoptPrinter("Client server clock distributed application", help.options);
    }

    if (genkey) {
        CurveKey gen;
        gen.create;
        writeln(gen.priv, ",", gen.pub);
    }

    if (serverKeyStr.length > 0) {
        CurveKey serverKey;
        serverKey.priv = serverKeyStr.split(",")[0];
        serverKey.pub = serverKeyStr.split(",")[1];
        writeln("tcp://localhost:", serverPort, ",", serverKey.pub);

        ZSocket server = ZSocket(ZMQ_PUSH);
        server.curveServer(serverKey);
        server.bind("tcp://*:" ~ serverPort.to!string);

        while (true) {
            Thread.sleep(1.seconds);
            server.send(Clock.currTime.to!string);
        }

        assert(false);
    }

    if (args.length == 1) return;

    CurveKey clientKey;
    clientKey.create();

    ZSocket client = ZSocket(ZMQ_PULL);

    foreach(each; args[1..$]) {
        string address = each.split(",")[0];
        string pubkey = each.split(",")[1];
        CurveKey serverKey;
        serverKey.pub = pubkey;
        client.curveClient(serverKey, clientKey);
        client.connect(address);
    }

    char[256] buf;
    while (true) {
        writeln(cast(const(char)[])client.recv(buf));
    }
}



string escape(const(ubyte[]) bytes) pure
{
    import std.format;
    string r = "\"";

    foreach(b; bytes)
    {
        if(b == '\a')
        {
            r ~= "\\a";
        }
        else if(b == '\b')
        {
            r ~= "\\b";
        }
        else if(b == '\f')
        {
            r ~= "\\f";
        }
        else if(b == '\n')
        {
            r ~= "\\n";
        }
        else if(b == '\r')
        {
            r ~= "\\r";
        }
        else if(b == '\t')
        {
            r ~= "\\t";
        }
        else if(b == '\v')
        {
            r ~= "\\v";
        }
        else if(b == '\\')
        {
            r ~= "\\\\";
        }
        else if(b == '\"')
        {
            r ~= "\\\"";
        }
        else if (b >= 32 && b <= 126)
        {
            r ~= cast(char)(b);
        }
        else
        {
            r ~= format("\\x%02x", cast(int)(b));
        }
    }

    r ~= "\"";
    return r;
}
