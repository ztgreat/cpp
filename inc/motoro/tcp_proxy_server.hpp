#ifndef CA0A8993_99AF_4891_B370_E8DB720B1705
#define CA0A8993_99AF_4891_B370_E8DB720B1705

#include <netdb.h>
#include <netinet/in.h>

#include <ctime>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "lib/LRUCache11.hpp"
#include "motoro/request.hpp"
#include "motoro/response.hpp"
#include "motoro/tcp_server.hpp"
#include "motoro/route_locator.hpp"
#include "motoro/Buffer.h"


namespace motoro {

    class tcp_client {
    public:
        tcp_client(std::string host = "127.0.0.1", int port = 8080);

        virtual ~tcp_client();

        bool ok() const;

        ssize_t send(const char *str, size_t len) const;

        ssize_t recv(char *buffer, size_t len) const;

    private:
        void init();

    public:
        std::string host;
        int port, socket_fd;
        struct sockaddr_in server_addr;
        struct hostent *server;
    };

    class tcp_proxy_server {
    public:
        tcp_proxy_server() = delete;

        tcp_proxy_server(const std::string &host, int port, int timeout = 5000, size_t buffer_size = 8192,
                         motoro::tcp_server::connection_t mode = motoro::tcp_server::connection_t::HTTP,
                         int max_event_size = 64);

        virtual ~tcp_proxy_server();

        void run(const tcp_server::filter_handler_function &);

        void run(const tcp_server::filter_handler_function &, const std::function<bool(const motoro::request &)> &);

        void set_default_content(const std::string &);

        void set_default_http_content();

        void set_enable_http_lru_cache(bool);

        void set_http_lru_cache_size(size_t);

        void set_http_lru_cache_expires(long long);

        void set_shutdown(const tcp_server::shutdown_function &);

        void add_route_locators(motoro::route_locator *);

    private:
        motoro::tcp_server::connection_t mode;
        size_t http_lru_cache_size;
        long long http_lru_cache_expires;
        bool enable_http_lru_cache;
        tcp_server *server;
        std::vector<route_locator *> *route_locators;
        std::unordered_map<size_t, std::unordered_map<size_t, std::shared_ptr<tcp_client> > > clients;
        std::unordered_map<size_t, size_t> fd_to_upServer;
        std::string default_content;
        lru11::Cache<std::string, std::shared_ptr<std::pair<std::string, time_t>>> *http_lru_cache;

        std::string
        tcp_work(const tcp_server::filter_handler_function &, const std::pair<char *, size_t> &, bool &,
                 tcp_server::client_t &);


        void del_up_server(size_t client_request_id, std::shared_ptr<tcp_client>);

        void on_connect_close_function(int fd);

        void clean_request_context(int fd);


        std::string do_tcp_request(const tcp_server::filter_handler_function &f,
                                   const std::pair<char *, size_t> &input, bool &keepalive,
                                   tcp_server::client_t &client);


        std::string do_tcp_response(bool &keepalive,
                                    tcp_server::client_t &client,
                                    std::shared_ptr<tcp_client>);

        std::string do_http_response(bool &keepalive,
                                     tcp_server::client_t &client,
                                     std::shared_ptr<tcp_client>);

        std::string do_http_request(const tcp_server::filter_handler_function &f,
                                    const std::function<bool(const motoro::request &)> &g,
                                    const std::pair<char *, size_t> &input, bool &keepalive,
                                    tcp_server::client_t &client);

        std::string
        http_work(const tcp_server::filter_handler_function &, const std::function<bool(const motoro::request &)> &,
                  const std::pair<char *, size_t> &, bool &, tcp_server::client_t &);

        static std::string DEFAULT_HTTP_CONTENT, DEFAULT_TCP_CONTENT;
    };
}

#endif /* CA0A8993_99AF_4891_B370_E8DB720B1705 */
