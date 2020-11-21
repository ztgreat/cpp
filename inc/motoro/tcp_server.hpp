#ifndef C3200096_C7F1_4006_B373_7B88A1BB95E3
#define C3200096_C7F1_4006_B373_7B88A1BB95E3

#include <atomic>
#include <ctime>
#include <list>
#include <memory>
#include <netdb.h>
#include <queue>
#include <string>
#include <csignal>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>

#include "epoll.hpp"
#include "inotify.hpp"
#include "lib/LRUCache11.hpp"
#include "thread_pool.hpp"
#include "motoro/Buffer.h"
#include "motoro/request.hpp"
#include "response.hpp"

#define CLOSE_CONNECTION true
#define KEEPALIVE_CONNECTION false

namespace motoro {

    class tcp_server {
    public:
        enum connection_t {
            TCP = 0,
            HTTP = 1,
            WEBSOCKET = 2
        };

        class client_t {
        public:
            client_t();

            client_t(const std::string &ip, int port, size_t uid, size_t gid, bool, size_t client_sid,
                     size_t, int);

            virtual ~client_t() = default;

            connection_t type;
            std::string ip;
            int port;
            int socket_fd;
            time_t t;
            size_t sid, uid, u_size, count;
            std::list<size_t> gid;
            motoro::net::Buffer buffer;
            motoro::request req;
            motoro::response res;

            // only for up_server
            bool is_up_server;
            size_t client_request_id;
            int client_socket_fd;
            size_t client_sid;
        };

        typedef std::function<void(int)> setsockopt_function;
        typedef std::function<bool(const client_t &)> filter_handler_function;
        typedef std::function<std::string(
                const std::pair<char *, size_t> &, bool &, client_t &)>
                handler_function;
        typedef std::function<void(void)> shutdown_function;

        typedef std::function<void(int)> on_connect_close_function;

        static setsockopt_function setsockopt_cb;

    public:
        tcp_server() = delete;

        tcp_server(const std::string &host, int port, int timeout = 5000, size_t buffer_size = 8192,
                   int max_event_size = 64, connection_t mode = connection_t::HTTP);

        virtual ~tcp_server();

    public:
        virtual bool
        add_client(int, const std::string &, int);

        virtual bool
        add_client(int, const std::string &, int, bool, size_t client_sid,
                   int client_socket_fd,
                   size_t);

        virtual void del_client(int);

        virtual void clean_context(int);

        void set_nonblock(int fd);

        void run(const handler_function &);

        size_t get_buffer_size() const;

        void set_shutdown(const shutdown_function &);

        void set_on_connect_close_function(const tcp_server::on_connect_close_function &func);

        static int backlog;
        static size_t max_connection_limit;

        static size_t max_send_limit;
        static size_t max_connection_keepalive;

    private:
        std::string host;
        connection_t mode;
        int port, listenfd, max_event_size;
        bool server_is_ok;
        struct addrinfo server_hints;
        shutdown_function cleaning_fun;
        on_connect_close_function on_connect_close;
        std::shared_ptr<inotify> whitelist_inotify;
        static std::atomic_bool done;

        static void signal_normal_cb(int sig, siginfo_t *, void *);

        void main_loop(struct epoll_event *, const handler_function &, motoro::epoll &);

        static bool get_client_address(struct sockaddr_storage *, std::string &, int &);

    protected:
        class meta_data_t {
        public:
            meta_data_t();

            meta_data_t(const std::string &ip, int port, size_t uid, size_t gid, bool, size_t client_sid,
                        size_t,
                        int);

            virtual ~meta_data_t() = default;

        public:
            client_t client;
        };

        motoro::epoll *server_epoll;
        size_t buffer_size, thread_size, sid;
        int timeout;
        std::queue<size_t, std::list<size_t>> sid_queue;
        std::unordered_map<int, meta_data_t> clients;
        motoro::thread_pool<std::function<bool()>> *work_pool;

        virtual bool work(int, const handler_function &);
    };
}

#endif /* C3200096_C7F1_4006_B373_7B88A1BB95E3 */
