#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <functional>
#include <iostream>
#include <mongols/util.hpp>
#include <mongols/upstream_server.hpp>

#include "mongols/http_request_parser.hpp"
#include "mongols/http_response_parser.hpp"
#include "lib/hash/hash_engine.hpp"
#include "mongols/tcp_proxy_server.hpp"
#include "mongols/version.hpp"
#include "mongols/Buffer.h"

namespace mongols {

    tcp_client::ctx_t tcp_client::ctx;
    const int tcp_client::ssl_session_ctx_id = 1;

    tcp_client::ctx_t::ctx_t()
            : ctx(0) {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        switch (openssl::version) {
            case openssl::version_t::SSLv23:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
                this->ctx = SSL_CTX_new(SSLv23_client_method());
#else
                this->ctx = SSL_CTX_new(TLS_client_method());
#endif
                break;
            case openssl::version_t::TLSv12:
                this->ctx = SSL_CTX_new(TLSv1_2_client_method());
                break;
            case openssl::version_t::TLSv13:
                this->ctx = SSL_CTX_new(TLSv1_2_client_method());
                break;
            default:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
                this->ctx = SSL_CTX_new(TLSv1_2_client_method());
#else
                this->ctx = SSL_CTX_new(TLS_client_method());
#endif
                break;
        }

        SSL_CTX_set_ecdh_auto(this->ctx, 1024);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        this->ctx->freelist_max_len = 0;
#endif
        SSL_CTX_set_mode(this->ctx,
                         SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_options(this->ctx, openssl::flags);

        SSL_CTX_set_session_cache_mode(this->ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
        SSL_CTX_sess_set_cache_size(this->ctx, 1);
    }

    tcp_client::ctx_t::~ctx_t() {
        if (this->ctx) {
            SSL_CTX_free(this->ctx);
        }
        EVP_cleanup();
    }

    SSL_CTX *tcp_client::ctx_t::get() {
        return this->ctx;
    }

    tcp_client::tcp_client(const std::string &host, int port, bool enable_openssl)
            : host(host), port(port), socket_fd(-1), server_addr(), server(0), enable_openssl(enable_openssl), ssl(0) {
        this->init();
    }

    tcp_client::~tcp_client() {
        if (this->ssl) {
            SSL_shutdown(this->ssl);
            SSL_free(this->ssl);
        }
        if (this->socket_fd > 0) {
            shutdown(this->socket_fd, SHUT_RDWR);
            close(this->socket_fd);
        }
    }

    void tcp_client::init() {
        this->server = gethostbyname(this->host.c_str());
        if (this->server == NULL) {
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
        if (this->enable_openssl) {
            this->ssl = SSL_new(tcp_client::ctx.get());
            if (this->ssl) {
                SSL_set_mode(this->ssl, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
                SSL_set_options(this->ssl, SSL_OP_NO_TICKET);
                SSL_set_fd(this->ssl, this->socket_fd);
                int ret = SSL_connect(this->ssl);
                if (ret <= 0) {
                    SSL_shutdown(this->ssl);
                    SSL_free(this->ssl);
                    this->ssl = 0;
                    close(this->socket_fd);
                    this->socket_fd = -1;
                }
            }
        }
    }

    bool tcp_client::ok() {
        return this->socket_fd > 0;
    }

    ssize_t tcp_client::recv(char *buffer, size_t len) {
        if (this->enable_openssl && this->ssl) {
            return SSL_read(this->ssl, buffer, len);
        }
        return ::read(this->socket_fd, buffer, len);
    }

    ssize_t tcp_client::send(const char *str, size_t len) {
        if (this->enable_openssl && this->ssl) {

            return SSL_write(this->ssl, str, len);
        }
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
                                       size_t thread_size, int max_event_size)
            : http_lru_cache_size(1024), http_lru_cache_expires(300),
              enable_http_lru_cache(false), enable_tcp_send_to_other(true), server(0), clients(),
              default_content(tcp_proxy_server::DEFAULT_TCP_CONTENT), http_lru_cache(0) {

        this->route_locators = new std::vector<mongols::route_locator *>();

        if (thread_size > 0) {
            this->server = new tcp_threading_server(host, port, timeout, buffer_size, thread_size, max_event_size);
        } else {
            this->server = new tcp_server(host, port, timeout, buffer_size, max_event_size);
        }
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

        f = std::bind(&tcp_proxy_server::work, this, std::cref(g), std::placeholders::_1, std::placeholders::_2,
                      std::placeholders::_3, std::placeholders::_4, std::placeholders::_5);

        this->server->run(f);
    }

    void tcp_proxy_server::run(const tcp_server::filter_handler_function &f,
                               const std::function<bool(const mongols::request &)> &g) {
        if (this->enable_http_lru_cache) {
            this->http_lru_cache = new lru11::Cache<std::string, std::shared_ptr<std::pair<std::string, time_t>>>(
                    this->http_lru_cache_size);
        }

        tcp_server::handler_function ff = std::bind(&tcp_proxy_server::http_work, this, std::cref(f), std::cref(g),
                                                    std::placeholders::_1, std::placeholders::_2, std::placeholders::_3,
                                                    std::placeholders::_4, std::placeholders::_5);

        this->server->run(ff);
    }

    void tcp_proxy_server::add_route_locators(mongols::route_locator *routeLocator) {
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

    bool tcp_proxy_server::set_openssl(const std::string &crt_file, const std::string &key_file, openssl::version_t v,
                                       const std::string &ciphers, long flags) {
        return this->server->set_openssl(crt_file, key_file, v, ciphers, flags);
    }

    void tcp_proxy_server::set_enable_blacklist(bool b) {
        this->server->set_enable_blacklist(b);
    }

    void tcp_proxy_server::set_enable_whitelist(bool b) {
        this->server->set_enable_whitelist(b);
    }

    void tcp_proxy_server::set_whitelist(const std::string &ip) {
        this->server->set_whitelist(ip);
    }

    void tcp_proxy_server::del_whitelist(const std::string &ip) {
        this->server->del_whitelist(ip);
    }

    void tcp_proxy_server::set_whitelist_file(const std::string &path) {
        this->server->set_whitelist_file(path);
    }

    void tcp_proxy_server::set_enable_security_check(bool b) {
        this->server->set_enable_security_check(b);
    }

    void tcp_proxy_server::set_enable_tcp_send_to_other(bool b) {
        this->enable_tcp_send_to_other = b;
    }

    std::string
    tcp_proxy_server::work(const tcp_server::filter_handler_function &f, const std::pair<char *, size_t> &input,
                           bool &keepalive, bool &send_to_other, tcp_server::client_t &client,
                           tcp_server::filter_handler_function &send_to_other_filter) {
        keepalive = KEEPALIVE_CONNECTION;
        send_to_other = this->enable_tcp_send_to_other;
        if (f(client)) {

            std::unordered_map<size_t, std::shared_ptr<tcp_client>>::iterator iter = this->clients.find(client.sid);
            std::shared_ptr<tcp_client> cli;
            bool is_old = false;
            if (iter == this->clients.end()) {
                new_client:
                for (auto route : *(this->route_locators)) {
                    mongols::upstream_server *upstreamServer = route->choseServer(nullptr);
                    if (upstreamServer) {
                        cli = std::make_shared<tcp_client>(upstreamServer->server, upstreamServer->port, false);
                        break;
                    }
                }
                this->clients[client.sid] = cli;
                is_old = false;
            } else {
                cli = iter->second;
                is_old = true;
            }

            if (cli->ok()) {
                ssize_t ret = cli->send(input.first, input.second);
                if (ret > 0) {
                    char buffer[this->server->get_buffer_size()];
                    ret = cli->recv(buffer, this->server->get_buffer_size());
                    if (ret > 0) {
                        return std::string(buffer, ret);
                    }
                }
            }
            this->clients.erase(client.sid);
            if (is_old) {
                goto new_client;
            }
        }
        return this->default_content;
    }

    std::string tcp_proxy_server::http_work(const tcp_server::filter_handler_function &f,
                                            const std::function<bool(const mongols::request &)> &g,
                                            const std::pair<char *, size_t> &input, bool &keepalive,
                                            bool &send_to_other, tcp_server::client_t &client,
                                            tcp_server::filter_handler_function &send_to_other_filter) {
        keepalive = KEEPALIVE_CONNECTION;
        send_to_other = false;
        std::shared_ptr<std::string> cache_key;
        std::shared_ptr<std::pair<std::string, time_t>> output;
        if (f(client)) {
            mongols::request req;
            mongols::http_request_parser parser(req);
            if (parser.parse(input.first, input.second)) {
                req.client = client.ip;
                if (g(req)) {
                    goto http_process;
                } else {
                    goto done;
                }
                http_process:
                std::unordered_map<std::string, std::string>::const_iterator tmp_iterator;
                if ((tmp_iterator = req.headers.find("Connection")) != req.headers.end()) {
                    if (tmp_iterator->second == "close") {
                        keepalive = CLOSE_CONNECTION;
                    }
                } else {
                    keepalive = CLOSE_CONNECTION;
                }
                if (this->enable_http_lru_cache && std::strcmp(req.method.c_str(), "GET") == 0) {
                    std::string tmp_str(req.method);
                    tmp_str.append(req.uri);
                    cache_key = std::make_shared<std::string>(std::move(
                            hash_engine::md5(req.param.empty() ? tmp_str : tmp_str.append("?").append(req.param))));
                    if (this->http_lru_cache->contains(*cache_key)) {
                        output = this->http_lru_cache->get(*cache_key);
                        if (difftime(time(0), output->second) > this->http_lru_cache_expires) {
                            this->http_lru_cache->remove(*cache_key);
                        } else {
                            return output->first;
                        }
                    }
                }

            } else {
                goto done;
            }

            std::unordered_map<size_t, std::shared_ptr<tcp_client>>::iterator iter = this->clients.find(client.sid);
            std::shared_ptr<tcp_client> cli;
            bool is_old = false;
            if (iter == this->clients.end()) {
                new_client:
                for (auto route : *(this->route_locators)) {
                    mongols::upstream_server *upstreamServer = route->choseServer(&req);
                    if (upstreamServer) {
                        cli = std::make_shared<tcp_client>(upstreamServer->server, upstreamServer->port, false);
                        break;
                    }
                }
                this->clients[client.sid] = cli;
                is_old = false;
            } else {
                cli = iter->second;
                is_old = true;
            }

            if (cli->ok()) {
                ssize_t send_ret = cli->send(input.first, input.second);
                if (send_ret > 0) {
                    mongols::net::Buffer buffer(2048);
                    ssize_t recv_ret = 0;
                    mongols::response res;
                    recv_ret = receiveClientData(cli, buffer, res);
                    if (recv_ret > 0) {
                        mongols::StringPiece piece = buffer.toStringPiece();
                        output = std::make_shared<std::pair<std::string, time_t>>();
                        output->first.assign(piece.data(), piece.size());
                        output->second = time(0);
                        auto i = res.headers.find("Connection");
                        if (i == res.headers.end()) {
                            this->clients.erase(client.sid);
                            auto p = output->first.find("\n");
                            if (p != std::string::npos) {
                                output->first.insert(p + 1, keepalive == KEEPALIVE_CONNECTION
                                                            ? "Connection: keep-alive\r\n"
                                                            : "Connection: close\r\n");
                            }
                        } else if (i->second == "close" && keepalive == KEEPALIVE_CONNECTION) {
                            this->clients.erase(client.sid);
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

                        if (res.status == 200 && this->enable_http_lru_cache &&
                            std::strcmp(req.method.c_str(), "GET") == 0) {
                            this->http_lru_cache->insert(*cache_key, output);
                        }
                        return output->first;
                    }
                }
            }
            this->clients.erase(client.sid);
            if (is_old) {
                goto new_client;
            }
        }
        done:
        return this->default_content;
    }

    void tcp_proxy_server::set_default_http_content() {
        this->default_content = tcp_proxy_server::DEFAULT_HTTP_CONTENT;
    }

    size_t tcp_proxy_server::receiveClientData(const std::shared_ptr<tcp_client> &cli, mongols::net::Buffer &buffer,
                                               mongols::response &res) {

        size_t ret = 0;
        char temp[this->server->get_buffer_size()];
        mongols::http_response_parser res_parser(res);
        again:
        size_t recv_ret = cli->recv(temp, this->server->get_buffer_size());
        if (recv_ret > 0) {
            ret += recv_ret;
            buffer.append(temp, recv_ret);
            mongols::StringPiece piece = buffer.toStringPiece();
            res_parser.parse(piece.data(), piece.size());
            if (!res_parser.message_complete()) {
                goto again;
            }
        }
        return ret;
    }


    void tcp_proxy_server::set_shutdown(const tcp_server::shutdown_function &f) {
        this->server->set_shutdown(f);
    }
}
