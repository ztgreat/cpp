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
#include "mongols/request.hpp"
#include "mongols/response.hpp"
#include "mongols/tcp_server.hpp"
#include "mongols/tcp_threading_server.hpp"
#include "mongols/route_locator.hpp"
#include "mongols/Buffer.h"


namespace mongols {

    class tcp_client {
    public:
        tcp_client(const std::string &host = "127.0.0.1", int port = 8080);

        virtual ~tcp_client();

        bool ok();

        ssize_t send(const char *str, size_t len);

        ssize_t recv(char *buffer, size_t len);

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
                         size_t thread_size = std::thread::hardware_concurrency(), int max_event_size = 64);

        virtual ~tcp_proxy_server();

        void run(const tcp_server::filter_handler_function &);

        void run(const tcp_server::filter_handler_function &, const std::function<bool(const mongols::request &)> &);

        void set_default_content(const std::string &);

        void set_enable_tcp_send_to_other(bool);

        void set_default_http_content();

        void set_enable_http_lru_cache(bool);

        void set_http_lru_cache_size(size_t);

        void set_http_lru_cache_expires(long long);

        void set_enable_blacklist(bool);

        void set_enable_whitelist(bool);

        void set_whitelist(const std::string &);

        void del_whitelist(const std::string &);

        void set_whitelist_file(const std::string &);

        void set_shutdown(const tcp_server::shutdown_function &);

        void add_route_locators(mongols::route_locator *);

    private:
        size_t http_lru_cache_size;
        long long http_lru_cache_expires;
        bool enable_http_lru_cache, enable_tcp_send_to_other;
        tcp_server *server;
        std::vector<route_locator *> *route_locators;
        std::unordered_map<std::string, std::shared_ptr<tcp_client>> clients;
        std::string default_content;
        lru11::Cache<std::string, std::shared_ptr<std::pair<std::string, time_t>>> *http_lru_cache;

        std::string work(const tcp_server::filter_handler_function &, const std::pair<char *, size_t> &, bool &, bool &,
                         tcp_server::client_t &, tcp_server::filter_handler_function &);


        void del_up_server(std::shared_ptr<std::string> client_request_id);

        void cleanHttpContext(int &fd);

        std::string doResponse(bool &keepalive,
                               tcp_server::client_t &client,
                               std::shared_ptr<tcp_client>);

        std::string doRequest(const tcp_server::filter_handler_function &f,
                              const std::function<bool(const mongols::request &)> &g,
                              const std::pair<char *, size_t> &input, bool &keepalive,
                              bool &send_to_other, tcp_server::client_t &client,
                              tcp_server::filter_handler_function &send_to_other_filter);

        std::string
        http_work(const tcp_server::filter_handler_function &, const std::function<bool(const mongols::request &)> &,
                  const std::pair<char *, size_t> &, bool &, bool &, tcp_server::client_t &,
                  tcp_server::filter_handler_function &);

        static std::string DEFAULT_HTTP_CONTENT, DEFAULT_TCP_CONTENT;
    };
}

#endif /* CA0A8993_99AF_4891_B370_E8DB720B1705 */
