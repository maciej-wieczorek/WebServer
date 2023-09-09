#include <iostream>
#include <vector>
#include <thread>
#include <algorithm>
#include <mutex>
#include <sstream>

#include "spdlog/spdlog.h" 

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <ws2tcpip.h>

std::string createHTTPResponse(const std::string& content)
{
    const std::string httpHeader{ "HTTP/1.1 200 OK\nContent-Type: text/html\n" };
    std::stringstream response;
    response << httpHeader;
    response << "Content-Length: " << content.size() << "\n\n";
    response << content;

    return response.str();
}

struct Client
{
    SOCKET socket;
    std::thread thread;
    std::string ipAddress;
    int port;

    void disconnect()
    {
        shutdown(socket, SD_SEND);
        closesocket(socket);

        SPDLOG_INFO("Disconnected: {}:{}", ipAddress, port);
    }
};

class Server
{
    static constexpr int WEB_SERVER_PORT = 80;
public:
    Server()
    {
        init();
    }
    ~Server()
    {
        m_serverRunning = false;

        closesocket(m_listenSocket);

        m_clientsMutex.lock();
        for (size_t i = 0; i < m_clients.size(); ++i)
        {
            m_clients[i].disconnect();
            m_clients[i].thread.join();
        }
        m_clientsMutex.unlock();

        WSACleanup();
    }

    void init()
    {

        WSADATA wsaData;
        int result;
    
        result = WSAStartup(MAKEWORD(2, 2), &wsaData);

        m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        sockaddr_in serverAddress;
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
        serverAddress.sin_port = htons(WEB_SERVER_PORT);

        result = bind(m_listenSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

        char serverIPAddress[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(serverAddress.sin_addr), serverIPAddress, INET_ADDRSTRLEN);
        SPDLOG_INFO("Created server on: {}:{}", serverIPAddress, ntohs(serverAddress.sin_port));
    }

    void run()
    {
        int result = listen(m_listenSocket, SOMAXCONN);

        acceptProc();
    }

    void acceptProc()
    {
        while (m_serverRunning)
        {
            sockaddr_in clientAddress;
            int clientAddressLength = sizeof(clientAddress);

            SOCKET clientSocket = accept(m_listenSocket, (struct sockaddr*)&clientAddress, &clientAddressLength);

            char clientIPAddress[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(clientAddress.sin_addr), clientIPAddress, INET_ADDRSTRLEN);
            int clientPort = ntohs(clientAddress.sin_port);

            SPDLOG_INFO("Connected: {}:{}", clientIPAddress, clientPort);

            m_clients.push_back(Client{ clientSocket,
                std::thread{ &Server::clientProc, this, clientSocket }, clientIPAddress, clientPort });
        }
    }

    void clientProc(SOCKET clientSocket)
    {
        std::string content{ "Hello World!" };
        std::string httpResponse = createHTTPResponse(content);
        send(clientSocket, httpResponse.c_str(), httpResponse.size(), 0);
        char buff[128];
        while (m_serverRunning)
        {
            // request/response loop
            int bytes = recv(clientSocket, buff, sizeof(buff), 0);
            if (bytes == 0)
            {
                removeClient(clientSocket);
                return;
            }
            else
            {
                //std::cout << buff;
            }
        }
    }

    void disconnectClient(SOCKET clientSocket)
    {
        shutdown(clientSocket, SD_SEND);
        closesocket(clientSocket);
    }

    void removeClient(SOCKET clientSocket)
    {
        m_clientsMutex.lock();

        auto find = std::find_if(m_clients.begin(), m_clients.end(),
            [&clientSocket](Client& client) { return client.socket == clientSocket; });
        if (find != m_clients.end())
        {
            find->disconnect();
            find->thread.detach();
            m_clients.erase(find);
        }

        m_clientsMutex.unlock();
    }

private:
    SOCKET m_listenSocket;
    std::vector<Client> m_clients;
    std::mutex m_clientsMutex;
    std::atomic<bool> m_serverRunning{ true };
};

int main()
{
    spdlog::set_level(spdlog::level::info);

    Server webServer;
    webServer.run();

    return 0;
}