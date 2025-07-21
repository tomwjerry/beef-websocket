namespace WebsocketExample;

using System;
using Beef_Net;
using BeefWebsocket;
using BeefWebsocket.Server;
using sead;

class Program
{
    private static bool running = true;
    private static WebsocketServer server;

    public static int Main(String[] aArgs)
    {
        Beef_Net_Init();
        server = new WebsocketServer();
        server.Listen(80);
        server.OnTextRecieved.Add(new => MyRecvText);

        Console.OnCancel.Add(new => OnCancel);
        while (running)
        {
            server.CallAction();
        }
        
        server.Disconnect();
        delete server;
        return 0;
    }

    private static void OnCancel(Console.CancelKind cancelKind, ref bool terminate)
    {
        running = false;
    }

    private static void MyRecvText(Socket s, StringView msg)
    {
        Console.WriteLine(msg);
        String srvhello = "Hello from server!";
        Span<uint8> smsg = Span<uint8>((uint8*)srvhello.Ptr, srvhello.Length);
        server.SendResponse(s, .TextFrame, smsg);
    }
}
