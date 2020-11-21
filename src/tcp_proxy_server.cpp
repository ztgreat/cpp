#include <netdb.h>
#include <netinet/in.h>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <functional>
#include <motoro/util.hpp>
#include <motoro/upstream_server.hpp>
#include <utility>
#include "motoro/http_request_parser.hpp"
#include "motoro/http_response_parser.hpp"
#include "motoro/tcp_proxy_server.hpp"
#include "motoro/Buffer.h"

namespace motoro {

    tcp_client::tcp_client(std::string host, int port)
            : host(std::move(host)), port(port), socket_fd(-1), server_addr(), server(nullptr) {
        this->init();
    }

    tcp_client::~tcp_client() {
        if (this->socket_fd > 0) {
            shutdown(this->socket_fd, SHUT_RDWR);
            close(this->socket_fd);
        }
    }

    void tcp_client::init() {
        this->server = gethostbyname(this->host.c_str());
        if (this->server == nullptr) {
            this->socket_fd = -1;
            return;
        }
        memset((char *) &this->server_addr, 0, sizeof(this->server_addr));
        this->server_addr.sin_family = this->server->h_addrtype;
        this->server_addr.sin_port = htons(this->port);
        memcpy(&this->server_addr.sin_addr, (char *) this->server->h_addr, this->server->h_length);

        this->socket_fd = socket(this->server->h_addrtype, SOCK_STREAM, 0);
        if (this->socket_fd < 0) {
            return;
        }
        if (connect(this->socket_fd, (struct sockaddr *) &this->server_addr, sizeof(this->server_addr)) < 0) {
            close(this->socket_fd);
            this->socket_fd = -1;
            return;
        }
    }

    bool tcp_client::ok() const {
        return this->socket_fd > 0;
    }

    ssize_t tcp_client::recv(char *buffer, size_t len) const {

        return ::read(this->socket_fd, buffer, len);
    }

    ssize_t tcp_client::send(const char *str, size_t len) const {
        return ::send(this->socket_fd, str, len, MSG_NOSIGNAL);
    }

    std::string tcp_proxy_server::DEFAULT_HTTP_CONTENT = "HTTP/1.1 403 Forbidden\r\n"
                                                         "Content-Type: text/html; charset=UTF-8\r\n"
                                                         "Content-Length: 72\r\n"
                                                         "Connection: close\r\n"
                                                         "\r\n\r\n"
                                                         "<html>"
                                                         "<head><title>403</title></head>"
                                                         "<body>403 Forbidden</body>"
                                                         "</html>";

    std::string tcp_proxy_server::DEFAULT_TCP_CONTENT = "close";

    tcp_proxy_server::tcp_proxy_server(const std::string &host, int port, int timeout, size_t buffer_size,
                                       motoro::tcp_server::connection_t mode,
                                       int max_event_size)
            : http_lru_cache_size(1024), http_lru_cache_expires(300),
              enable_http_lru_cache(false), server(nullptr), mode(mode), clients(),
              default_content(tcp_proxy_server::DEFAULT_TCP_CONTENT), http_lru_cache(nullptr) {
        this->route_locators = new std::vector<motoro::route_locator *>();
        this->server = new tcp_server(host, port, timeout, buffer_size, max_event_size, mode);
    }

    tcp_proxy_server::~tcp_proxy_server() {
        if (this->http_lru_cache) {
            delete this->http_lru_cache;
        }

        if (this->server) {
            delete this->server;
        }

        for (auto it = this->route_locators->begin(); it != this->route_locators->end(); it++) {
            delete *it;
        }
        this->route_locators->clear();
        this->route_locators->shrink_to_fit();
        delete this->route_locators;
    }

    void tcp_proxy_server::run(const tcp_server::filter_handler_function &g) {

        tcp_server::handler_function f;

        f = std::bind(&tcp_proxy_server::tcp_work, this, std::cref(g), std::placeholders::_1, std::placeholders::_2,
                      std::placeholders::_3);

        auto fc = std::bind(&tcp_proxy_server::on_connect_close_function, this,
                            std::placeholders::_1);

        this->server->set_on_connect_close_function(fc);

        this->server->run(f);
    }

    void tcp_proxy_server::run(const tcp_server::filter_handler_function &f,
                               const std::function<bool(const motoro::request &)> &g) {
        if (this->enable_http_lru_cache) {
            this->http_lru_cache = new lru11::Cache<std::string, std::shared_ptr<std::pair<std::string, time_t>>>(
                    this->http_lru_cache_size);
        }

        tcp_server::handler_function ff;

        if (this->mode == motoro::tcp_server::connection_t::TCP) {
            ff = std::bind(&tcp_proxy_server::tcp_work, this, std::cref(f),
                           std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
        } else {
            ff = std::bind(&tcp_proxy_server::http_work, this, std::cref(f), std::cref(g),
                           std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
        }

        auto fc = std::bind(&tcp_proxy_server::on_connect_close_function, this,
                            std::placeholders::_1);


        this->server->set_on_connect_close_function(fc);

        this->server->run(ff);
    }

    void tcp_proxy_server::add_route_locators(motoro::route_locator *routeLocator) {
        this->route_locators->insert(this->route_locators->begin(), routeLocator);
    }


    void tcp_proxy_server::set_default_content(const std::string &str) {
        this->default_content = str;
    }

    void tcp_proxy_server::set_enable_http_lru_cache(bool b) {
        this->enable_http_lru_cache = b;
    }

    void tcp_proxy_server::set_http_lru_cache_size(size_t len) {
        this->http_lru_cache_size = len;
    }

    void tcp_proxy_server::set_http_lru_cache_expires(long long expires) {
        this->http_lru_cache_expires = expires;
    }

    std::string
    tcp_proxy_server::tcp_work(const tcp_server::filter_handler_function &f, const std::pair<char *, size_t> &input,
                               bool &keepalive, tcp_server::client_t &client) {
        keepalive = KEEPALIVE_CONNECTION;
        if (client.is_up_server) {
            // up_server_response
            std::shared_ptr<tcp_client> up_server = this->clients[client.client_request_id];
            if (up_server == nullptr) {
                std::cout << "tcp up_server is null" << std::endl;
                return "0";
            }
            return do_tcp_response(keepalive, client, up_server);
        }
        return do_tcp_request(f, input, keepalive, client);
    }


    std::string tcp_proxy_server::do_tcp_request(const tcp_server::filter_handler_function &f,
                                                 const std::pair<char *, size_t> &input, bool &keepalive,
                                                 tcp_server::client_t &client) {


        keepalive = KEEPALIVE_CONNECTION;
        size_t request_id;
        std::shared_ptr<std::pair<std::string, time_t>> output;

        if (!f(client)) {
            return "0";
        }

        std::hash<string> hash;
        request_id = client.sid;

        std::shared_ptr<tcp_client> cli = this->clients[request_id];
        //std::cout << "TCP: " << "client.sid:" << client.sid << ",client.port:" << client.port
        //          << ",up.server.size:" + std::to_string(this->clients.size()) << std::endl;
        bool is_old = true;
        if (cli == nullptr) {
            new_client:
            for (auto route : *(this->route_locators)) {
                motoro::upstream_server *upstreamServer = route->choseServer(nullptr);
                if (upstreamServer) {
                    cli = std::make_shared<tcp_client>(upstreamServer->server, upstreamServer->port);
                    break;
                }
            }
            if (cli == nullptr) {
                std::cout << "tcp.doRequest.cli: null,not found route" << std::endl;
                return "0";
            }
            this->server->set_nonblock(cli->socket_fd);
            this->clients[request_id] = cli;
            this->fd_to_upServer[cli->socket_fd] = request_id;
            is_old = false;
        }

        if (cli == nullptr) {
            std::cout << "tcp.doRequest.cli is null" << std::endl;
            return "0";
        }

        if (cli->ok()) {
            ssize_t send_ret = cli->send(input.first, input.second);
            if (send_ret > 0) {
                this->server->add_client(cli->socket_fd, cli->host, cli->port, true,
                                         client.client_sid,
                                         client.socket_fd,
                                         request_id);
                return "1";
            }
        }

        this->del_up_server(request_id);
        if (is_old) {
            goto new_client;
        }
        return "0";

    }

    std::string tcp_proxy_server::do_tcp_response(bool &keepalive,
                                                  tcp_server::client_t &client,
                                                  std::shared_ptr<tcp_client> up_server) {

        motoro::StringPiece piece = client.buffer.toStringPiece();

        size_t ret = send(client.client_socket_fd, piece.data(), piece.size(), MSG_NOSIGNAL);

        this->clean_request_context(client.client_socket_fd);
        this->clean_request_context(up_server->socket_fd);
        if (ret <= 0) {
            this->del_up_server(client.client_request_id);
            return "0";
        }
        return "1";
    }

    std::string tcp_proxy_server::do_http_response(bool &keepalive,
                                                   tcp_server::client_t &client,
                                                   std::shared_ptr<tcp_client> up_server) {

        motoro::response &res = client.res;
        motoro::http_response_parser res_parser(res);
        motoro::StringPiece piece = client.buffer.toStringPiece();
        bool success = res_parser.parse(piece.data(), piece.size());
        if (!success) {
            // 没解析成功，包错误
            this->clean_request_context(client.client_socket_fd);
            this->clean_request_context(up_server->socket_fd);
            this->del_up_server(client.client_request_id);
            return "0";
        }
        if (!res_parser.message_complete()) {
            // 包还没有接收完整，继续接收
            return "1";
        }

        std::shared_ptr<std::pair<std::string, time_t>> output;
        output = std::make_shared<std::pair<std::string, time_t>>();

        output->first.assign(piece.data(), piece.size());
        output->second = time(nullptr);
        auto i = res.headers.find("Connection");
        if (i == res.headers.end()) {
            this->del_up_server(client.client_request_id);
            auto p = output->first.find("\n");
            if (p != std::string::npos) {
                output->first.insert(p + 1, keepalive == KEEPALIVE_CONNECTION
                                            ? "Connection: keep-alive\r\n"
                                            : "Connection: close\r\n");
            }
        } else if (i->second == "close" && keepalive == KEEPALIVE_CONNECTION) {
            this->del_up_server(client.client_request_id);
            auto p = output->first.find("close");
            if (p != std::string::npos) {
                output->first.replace(p, 5, "keep-alive");
            }

        } else if (i->second == "keep-alive" && keepalive == CLOSE_CONNECTION) {
            keepalive = KEEPALIVE_CONNECTION;
            /*auto p = output->first.find("keep-alive");
                if (p != std::string::npos) {
                    output->first.replace(p, 10, "close");
                }*/
        }


        size_t ret = send(client.client_socket_fd, output->first.c_str(), output->first.size(), MSG_NOSIGNAL);

        this->clean_request_context(client.client_socket_fd);
        this->clean_request_context(up_server->socket_fd);

        if (ret <= 0) {
            this->del_up_server(client.client_request_id);
            return "0";
        }
        if (keepalive == CLOSE_CONNECTION) {
            this->del_up_server(client.client_request_id);
            return "1";
        }
        return "1";

    }

    void tcp_proxy_server::del_up_server(size_t client_request_id) {

        std::shared_ptr<tcp_client> cli = this->clients[client_request_id];
        if (cli == nullptr) {
            return;
        }
        this->server->del_client(cli->socket_fd);
        this->clients.erase(client_request_id);
        this->fd_to_upServer.erase(cli->socket_fd);
        shutdown(cli->socket_fd, SHUT_RDWR);
        close(cli->socket_fd);
    }

    void tcp_proxy_server::on_connect_close_function(int fd) {
        size_t upServerId = this->fd_to_upServer[fd];
        if (upServerId <= 0) {
            return;
        }
        this->clients.erase(upServerId);
        this->fd_to_upServer.erase(fd);
        //shutdown(fd, SHUT_RDWR);
        //close(fd);
    }

    void tcp_proxy_server::clean_request_context(int fd) {
        if (fd <= 0) {
            return;
        }
        this->server->clean_context(fd);
    }

    std::string tcp_proxy_server::do_http_request(const tcp_server::filter_handler_function &f,
                                                  const std::function<bool(const motoro::request &)> &g,
                                                  const std::pair<char *, size_t> &input, bool &keepalive,
                                                  tcp_server::client_t &client) {


        keepalive = KEEPALIVE_CONNECTION;
        size_t request_id;
        std::shared_ptr<std::pair<std::string, time_t>> output;

        if (!f(client)) {
            return "0";
        }
        motoro::request &req = client.req;

        motoro::http_request_parser req_parser(req);
        motoro::StringPiece piece = client.buffer.toStringPiece();
        bool success = req_parser.parse(piece.data(), piece.size());
        if (!success) {
            // 没解析成功，包错误
            return "0";
        }
        if (!req_parser.message_complete()) {
            // 包还没有接收完整，继续接收
            return "1";
        }

        req.client = client.ip;
        if (!g(req)) {
            return "0";
        }

        std::unordered_map<std::string, std::string>::const_iterator tmp_iterator;
        if ((tmp_iterator = req.headers.find("Connection")) != req.headers.end()) {
            if (tmp_iterator->second == "close") {
                keepalive = CLOSE_CONNECTION;
            }
        } else {
            keepalive = CLOSE_CONNECTION;
        }

        std::string tmp_str(req.method + req.uri + std::to_string(client.sid) + std::to_string(getpid()));
        //std::cout << "HTTP: " << "client.sid:" << client.sid << ",client.port:" << client.port
        //          << ",up.server.size:" + std::to_string(this->clients.size()) << std::endl;
        // todo 路由需要注意这里是否支持
        std::hash<string> hash;
        request_id = hash(req.param.empty() ? tmp_str : tmp_str.append("?").append(req.param));

        std::shared_ptr<tcp_client> cli = this->clients[request_id];
        bool is_old = true;
        if (cli == nullptr) {
            new_client:
            for (auto route : *(this->route_locators)) {
                motoro::upstream_server *upstreamServer = route->choseServer(&req);
                if (upstreamServer) {
                    cli = std::make_shared<tcp_client>(upstreamServer->server, upstreamServer->port);
                    break;
                }
            }

            if (cli == nullptr) {
                std::cout << "http.doRequest.cli: null,not found route" << std::endl;
                return "0";
            }
            this->server->set_nonblock(cli->socket_fd);
            this->clients[request_id] = cli;
            is_old = false;
        }

        if (cli == nullptr) {
            std::cout << "http.doRequest.cli: null" << std::endl;
            return "0";
        }

        if (cli->ok()) {
            ssize_t send_ret = cli->send(input.first, input.second);
            if (send_ret > 0) {
                this->server->add_client(cli->socket_fd, cli->host, cli->port,
                                         true,
                                         client.client_sid,
                                         client.socket_fd,
                                         request_id);
                return "1";
            }
        }

        this->del_up_server(request_id);
        if (is_old) {
            goto new_client;
        }
        return "0";

    }

    std::string tcp_proxy_server::http_work(const tcp_server::filter_handler_function &f,
                                            const std::function<bool(const motoro::request &)> &g,
                                            const std::pair<char *, size_t> &input, bool &keepalive,
                                            tcp_server::client_t &client) {


        if (client.is_up_server) {

            // up_server_response
            std::shared_ptr<tcp_client> up_server = this->clients[client.client_request_id];
            if (up_server == nullptr) {
                std::cout << "http.up_server is null" << std::endl;
                return "0";
            }
            return do_http_response(keepalive, client, up_server);
        }
        return do_http_request(f, g, input, keepalive, client);

    }

    void tcp_proxy_server::set_default_http_content() {
        this->default_content = tcp_proxy_server::DEFAULT_HTTP_CONTENT;
    }

    void tcp_proxy_server::set_shutdown(const tcp_server::shutdown_function &f) {
        this->server->set_shutdown(f);
    }
}
