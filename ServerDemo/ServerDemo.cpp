#include <iostream>


#include "./NetworkAPI.h";


int main()
{
    NetworkAPI::Init();

    auto Server = NetworkAPI::CreateServer("127.0.0.1", 8025, 65536);

    Server->Event_ConnectSuccess([](PNServerClient clientServer) -> bool {


        DEBUG_CLIENT_SERVER_CONNECT(clientServer);

        return true;

        });


    Server->Event_ServerRecv([Server](PNServerClient clientServer, char* dataBuffer, int byteRead) -> std::string {



        std::stringstream httpResponseStream;

        // Build the HTTP response manually
        httpResponseStream << "HTTP/1.1 200 OK\r\n"
            << "Content-Type: application/json\r\n"
            << "Connection: close\r\n"
            << "Server: custom-cpp-server\r\n"
            << "Content-Length: " << 191 << "\r\n"
            << "\r\n"
            << "{\n"
            << "  \"status\": \"success\",\n"
            << "  \"data\": {\n"
            << "    \"server\": {\n"
            << "      \"id\": \"6ba7b811-9dad-11d1-80b4-00c04fd430c8\",\n"
            << "      \"node\": \"Node-east-BM3P7W3\",\n"
            << "      \"cpu\": \"35%\",\n"
            << "      \"gpu\":  \"75%\"\n"
            << "    }\n"
            << "  }\n"
            << "}";


        std::string httpResponse = httpResponseStream.str();


        std::cout << "httpResponse : " << httpResponse << std::endl;


        // Server->DiscClient(clientServer);

        return std::string(httpResponse);

        });



    Server->WaitForDisconnect();
}

