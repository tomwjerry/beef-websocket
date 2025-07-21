namespace BeefWebsocket.Server;

using System;
using System.Collections;
using Beef_Net;
using Beef_Net.Connection;
using BeefCrypto;
using sead;

enum WebsocketState
{
    Disconnected,
    Connecting,
    AfterHanshake
}

enum WebsocketOPCodes : uint8
{
    ContinuationFrame = 0,
    TextFrame = 1,
    BinaryFrame = 2,
    // 3 - 7 Reserved
    ConnectionClose = 8,
    Ping = 9,
    Pong = 10
}

struct WSClientData : IDisposable
{
    public WebsocketState state;
    public Socket sock;
    public List<uint8> messageContinuation;
    public bool continueIsBinary;

    public this()
    {
        this = default;
        messageContinuation = new List<uint8>();
    }

    public void Dispose()
    {
        delete messageContinuation;
    }
}

class WebsocketServer : TcpConnection
{
    const int WEBSOCKET_FRAME_SIZE = 16000;
    protected SocketEvent _onWSReceive = new => OnWSReceive ~ delete _;
    protected Dictionary<Socket, WSClientData> _clients = new .() ~ delete _;
    public Event<delegate void(Socket, Span<uint8>)> OnBinaryRecieved  ~ _.Dispose();;
    public Event<delegate void(Socket, StringView)> OnTextRecieved  ~ _.Dispose();;
    public Event<delegate void(Socket)> OnClientPingRecieved  ~ _.Dispose();;
    public Event<delegate void(Socket)> OnServerPingAnswered  ~ _.Dispose();;
    public Event<delegate void(Socket)> OnWSDisconnect  ~ _.Dispose();;

    public this() : base()
    {
        OnReceive = _onWSReceive;
    }

    // Called when receive a message, after connect
    public void OnWSReceive(Socket aSocket)
    {
        WSClientData clientInfo;
        // First, see if we have the socket ovva here, if so check ets state
        if (_clients.ContainsKey(aSocket))
        {
            clientInfo = _clients.GetValue(aSocket);
        }
        else
        {
            clientInfo = WSClientData();
            clientInfo.sock = aSocket;
            clientInfo.state = .Connecting;
            _clients.Add(aSocket, clientInfo);
        }    
        // Get massage, max size will be the websocket frame size
        uint8[WEBSOCKET_FRAME_SIZE] frame = uint8[WEBSOCKET_FRAME_SIZE]();
        aSocket.Get(&frame, WEBSOCKET_FRAME_SIZE);

        // First we need to connect to websocket
        // We have at this point established TCP connection
        // but not yet performed the Websocket handshake
        if (clientInfo.state == .Connecting)
        {
            // Parse the request to string, we actually get a HTTP request here
            String aOutMsg = scope String();
            aOutMsg.Append((char8*)&frame, WEBSOCKET_FRAME_SIZE);

            // Will always be GET, otherwise ignore requests becuase it is not websocket stuff
            if (aOutMsg.StartsWith("GET", .OrdinalIgnoreCase))
            {
                // Here we can do other stuff, but be only care about the Sec-Websocket-Key
                int keyloc = aOutMsg.IndexOf("Sec-WebSocket-Key: ");
                keyloc += 19;
                StringView websockKey = aOutMsg.Substring(keyloc, aOutMsg.IndexOf('\r', keyloc) - keyloc);

                if (websockKey.Length < 4)
                {
                    return;
                }

                // Append magic value to the key
                String respKey = scope String(websockKey);
                // This is magic!
                respKey.Append("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                // Now, make a SHA1 computation of this
                SHA1Hash sha1 = SHA1.Hash(.((uint8*)respKey.Ptr, respKey.Length));
                // Then poot it in encoded string
                String encodedKey = scope String();
                Base64.Encode(Span<uint8>(&sha1.mHash, 20), encodedKey);

                // Now we need to be respondelble and send summit back
                // This tells client that we are doing websocket now!
                const String eol = "\r\n";
                String responseMessage = scope String("HTTP/1.1 101 Switching Protocols" + eol +
                    "Connection: Upgrade" + eol +
                    "Upgrade: websocket" + eol +
                    "Sec-WebSocket-Accept: ");
                responseMessage.Append(encodedKey);
                responseMessage.Append(eol);
                responseMessage.Append(eol);

                aSocket.SendMessage(responseMessage);

                // We can now blissfully assume we have shaked hands
                _clients[aSocket].state = .AfterHanshake;
            }
        }
        else if (clientInfo.state == .AfterHanshake)
        {
            // Here we needta figure out WHAT message we gut and maybe dispatch appropriate
            // events or something
            // We need to stich togheter continuation frames and so on
            // And of course decode messages
            bool fin = (frame[0] & 0b10000000) != 0;
            bool mask = (frame[1] & 0b10000000) != 0; // must be true, "All messages from the client to the server have this bit set"
            WebsocketOPCodes opcode = (WebsocketOPCodes)(frame[0] & 0b00001111);
            uint64 offset = 2;
            uint64 msgLen = frame[1] & 0b01111111;

            // Get the frame length, quite complicated
            // Som magic values, I forgot what it does, someting about a certain length then need to
            // do something special with the frame length parsing
            if (msgLen == 126)
            {
                // bytes are reversed because websocket will print them in Big-Endian, whereas
                // BitConverter will want them arranged in little-endian on windows
                msgLen = BitConverter.Convert<uint8[2], uint64>(uint8[] ( frame[3], frame[2] ));
                offset = 4;
            }
            else if (msgLen == 127)
            {
                // To test the below code, we need to manually buffer larger messages — since the NIC's autobuffering
                // may be too latency-friendly for this code to run (that is, we may have only some of the bytes in this
                // websocket frame available through client.Available).
                msgLen = BitConverter.Convert<uint8[8], uint64>(uint8[] ( frame[9], frame[8], frame[7], frame[6], frame[5], frame[4], frame[3], frame[2] ));
                offset = 10;
            }

            if (msgLen == 0)
            {
                return;
            }
            else if (mask)
            {
                uint8[] decoded = scope uint8[msgLen];
                uint8[4] masks = uint8[4] ( frame[offset], frame[offset + 1], frame[offset + 2], frame[offset + 3] );
                offset += 4;

                for (int i = 0; i < (int)msgLen && i < WEBSOCKET_FRAME_SIZE; ++i)
                {
                    decoded[i] = frame[(int)offset + i] ^ masks[i % 4];
                }

                // We are done! Dispatch the message
                if (fin || opcode == .Ping || opcode == .Pong || opcode == .ConnectionClose)
                {
                    List<uint8> wholeMsg = scope List<uint8>(decoded);
                    // Likely we have already stored message, now we can dispatch
                    if (opcode == .ContinuationFrame)
                    {
                        _clients[aSocket].messageContinuation.AddRange(decoded);
                        wholeMsg.Set(clientInfo.messageContinuation);
                        _clients[aSocket].messageContinuation.Clear();
                    }

                    // Dispatch...
                    switch (opcode)
                    {
                    case .BinaryFrame:
                        OnBinaryRecieved(aSocket, wholeMsg);
                        break;
                    case .TextFrame:
                        String textMessage = scope String();
                        textMessage.Append((char8*)wholeMsg.Ptr, wholeMsg.Count);
                        OnTextRecieved(aSocket, textMessage);
                        break;
                    case .Ping:
                        RespondToPing(aSocket);
                        break;
                    case .Pong:
                        RegisterPong(aSocket);
                        break;
                    case .ConnectionClose:
                        DisconnectClient(aSocket);
                        break;
                    default: break;
                    }
                }
                // Not done... We needta store the message temporary
                else
                {
                    if (opcode == .TextFrame)
                    {
                        _clients[aSocket].continueIsBinary = false;
                    }
                    else if (opcode == .BinaryFrame)
                    {
                        _clients[aSocket].continueIsBinary = true;
                    }

                    _clients[aSocket].messageContinuation.AddRange(decoded);
                }
            } 
        }
    }

    public void SendResponse(Socket receiver, WebsocketOPCodes messageType, Span<uint8>? msgData)
    {
        int payloadLen = 0;
        if (msgData.HasValue)
        {
            payloadLen = msgData.Value.Length;
        }

        int headerLen = 2;
        if (payloadLen >= 126 && payloadLen <= 65535)
        {
            headerLen += 2;
        }
        else if (payloadLen > 65535)
        {
            headerLen += 8;
        }

        int totalLen = headerLen + payloadLen;
        List<uint8> sendBytes = scope .(totalLen);

        // Byte 1: FIN bit set (1), RSV1-3 (0), and opcode
        sendBytes.Add((uint8)(0x80 | (uint8)messageType)); // FIN | opcode

        // Byte 2: MASK bit unset (server -> client) + payload length
        if (payloadLen < 126)
        {
            sendBytes.Add((uint8)payloadLen);
        }
        else if (payloadLen <= 65535)
        {
            sendBytes.Add(126);
            sendBytes.Add((uint8)((payloadLen >> 8) & 0xFF)); // High byte
            sendBytes.Add((uint8)(payloadLen & 0xFF));        // Low byte
        }
        else
        {
            sendBytes.Add(127);
            for (int i = 7; i >= 0; i--)
            {
                sendBytes.Add((uint8)((payloadLen >> (i * 8)) & 0xFF));
            }
        }

        // Append payload data (no masking)
        if (payloadLen > 0)
        {
            sendBytes.AddRange(msgData.Value);
        }

        // Send the frame to the client
        receiver.Send(sendBytes.Ptr, (int32)sendBytes.Count);
    }

    public void RespondToPing(Socket cliSock)
    {
        SendResponse(cliSock, .Pong, null);
        OnClientPingRecieved(cliSock);
    }

    public void RegisterPong(Socket cliSock)
    {
        OnServerPingAnswered(cliSock);
    }

    public void DisconnectClient(Socket cliSock)
    {
        // Send a disconnection frame (if client disconnects)
        OnWSDisconnect(cliSock);
    }
}
