#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <csignal>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <vector>
#include <motoro/Buffer.h>
#include <netinet/tcp.h>
#include "tcp_server.hpp"
#include "util.hpp"

namespace motoro {

    std::atomic_bool tcp_server::done(true);
    int tcp_server::backlog = 511;
    size_t tcp_server::max_connection_limit = 30;
    size_t tcp_server::max_send_limit = 5;
    size_t tcp_server::max_connection_keepalive = 60;

    tcp_server::setsockopt_function tcp_server::setsockopt_cb = nullptr;

    void tcp_server::signal_normal_cb(int sig, siginfo_t *, void *) {
        tcp_server::done = false;
    }

    tcp_server::tcp_server(const std::string &host, int port, int timeout, size_t buffer_size, int max_event_size,
                           connection_t mode)
            : host(host), port(port), listenfd(0), max_event_size(max_event_size), mode(mode), server_is_ok(false),
              server_hints(),
              cleaning_fun(), whitelist_inotify(), server_epoll(0), buffer_size(buffer_size), thread_size(0), sid(0),
              timeout(timeout), sid_queue(), clients(), work_pool(0) {

        memset(&this->server_hints, 0, sizeof(this->server_hints));
        this->server_hints.ai_family = AF_UNSPEC;
        this->server_hints.ai_socktype = SOCK_STREAM;
        this->server_hints.ai_flags = AI_PASSIVE;

        struct addrinfo *server_info = 0;
        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &this->server_hints, &server_info) != 0) {
            perror("getaddrinfo error");
            return;
        } else {
            this->server_is_ok = true;
        }

        this->listenfd = socket(server_info->ai_family, server_info->ai_socktype, server_info->ai_protocol);

        int on = 1;
        setsockopt(this->listenfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));

        struct timeval send_timeout{}, recv_timeout{};
        send_timeout.tv_sec = this->timeout;
        send_timeout.tv_usec = 0;
        setsockopt(this->listenfd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));

        recv_timeout.tv_sec = this->timeout;
        recv_timeout.tv_usec = 0;
        setsockopt(this->listenfd, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));
        setsockopt(this->listenfd, SOL_SOCKET, MSG_ZEROCOPY, &on, sizeof(on));
        setsockopt(this->listenfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
        if (tcp_server::setsockopt_cb) {
            tcp_server::setsockopt_cb(this->listenfd);
        }

        bind(this->listenfd, server_info->ai_addr, server_info->ai_addrlen);

        freeaddrinfo(server_info);

        this->set_nonblock(this->listenfd);

        listen(this->listenfd, tcp_server::backlog);
    }

    tcp_server::~tcp_server() {
        if (this->work_pool) {
            delete this->work_pool;
        }
        if (this->cleaning_fun) {
            this->cleaning_fun();
        }
        if (this->listenfd) {
            close(this->listenfd);
        }
    }

    tcp_server::client_t::client_t()
            : type(tcp_server::connection_t::TCP), ip(), port(-1), t(time(0)), sid(0), uid(0), u_size(0), count(0),
              gid() {
        this->gid.push_back(0);
    }

    tcp_server::client_t::client_t(const std::string &ip, int port, size_t uid, size_t gid,
                                   size_t buffer_size,
                                   bool is_up_server, size_t client_sid, size_t client_request_id,
                                   int client_socket_fd)
            : type(tcp_server::connection_t::TCP), ip(ip), port(port), t(time(0)), sid(0), uid(uid), u_size(0),
              count(0), gid(), is_up_server(is_up_server), client_sid(client_sid), client_request_id(client_request_id),
              client_socket_fd(client_socket_fd) {
        this->gid.push_back(gid);
    }

    tcp_server::meta_data_t::meta_data_t()
            : client() {
    }

    tcp_server::meta_data_t::meta_data_t(const std::string &ip, int port, size_t uid, size_t gid,
                                         size_t buffer_size,
                                         bool is_up_server,
                                         size_t client_sid,
                                         size_t client_request_id, int client_socket_fd)
            : client(ip, port, uid, gid, buffer_size, is_up_server, client_sid, client_request_id, client_socket_fd) {
    }

    void tcp_server::run(const handler_function &g) {
        if (!this->server_is_ok) {
            perror("server error");
            return;
        }
        std::vector<int> sigs = multi_process::signals;

        struct sigaction act{};
        for (size_t i = 0; i < sigs.size(); ++i) {
            memset(&act, 0, sizeof(struct sigaction));
            sigemptyset(&act.sa_mask);
            act.sa_sigaction = tcp_server::signal_normal_cb;
            act.sa_flags = SA_SIGINFO;
            if (sigaction(sigs[i], &act, nullptr) < 0) {
                perror("sigaction error");
                return;
            }
        }
        motoro::epoll epoll(this->max_event_size, -1);
        if (!epoll.is_ready()) {
            perror("epoll error");
            return;
        }
        this->server_epoll = &epoll;
        if (!epoll.add(this->listenfd, EPOLLIN | EPOLLET)) {
            perror("epoll listen error");
            return;
        }
        if (this->whitelist_inotify) {
            int whitelist_fd = this->whitelist_inotify->get_fd();
            this->set_nonblock(whitelist_fd);
            if (!epoll.add(whitelist_fd, EPOLLIN | EPOLLET) || !this->whitelist_inotify->watch(IN_MODIFY)) {
                epoll.del(whitelist_fd);
                this->whitelist_inotify.reset();
            }
        }
        auto main_fun = std::bind(&tcp_server::main_loop, this, std::placeholders::_1, std::cref(g), std::ref(epoll));
        if (this->thread_size > 0) {
            this->work_pool = new motoro::thread_pool<std::function<bool()>>(this->thread_size);
        }
        while (tcp_server::done) {
            epoll.loop(main_fun);
        }
    }

    void tcp_server::set_shutdown(const shutdown_function &f) {
        this->cleaning_fun = f;
    }

    void tcp_server::set_on_connect_close_function(const tcp_server::on_connect_close_function &func) {
        this->on_connect_close = func;
    }

    void tcp_server::set_nonblock(int fd) {
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    bool
    tcp_server::add_client(int fd, const std::string &ip, int port) {
        std::shared_ptr<std::string> client_request_id(nullptr);
        return add_client(fd, ip, port, false, -1, -1, -1);
    }

    bool
    tcp_server::add_client(int fd, const std::string &ip, int port,
                           bool is_up_server,
                           size_t client_sid,
                           int client_socket_fd,
                           size_t client_request_id
    ) {


        bool add_result;
        if (this->mode == connection_t::HTTP) {
            add_result = this->server_epoll->add(fd, EPOLLIN | EPOLLRDHUP | EPOLLET);
        } else {
            add_result = this->server_epoll->add(fd, EPOLLIN | EPOLLRDHUP);
        }

        if (!add_result) {
            // 添加失败,重复了
            // return false;
        }

        this->clients[fd] = std::make_shared<meta_data_t>(
                meta_data_t(ip, port, 0, 0, this->buffer_size, is_up_server, client_sid, client_request_id,
                            client_socket_fd));

        std::shared_ptr<meta_data_t> metaData = this->clients[fd];
        if (this->sid_queue.empty()) {
            metaData->client.sid = this->sid = ((this->sid + 1) & SIZE_MAX);
        } else {
            metaData->client.sid = this->sid_queue.front();
            this->sid_queue.pop();
        }
        metaData->client.socket_fd = fd;
        this->clients[fd] = metaData;
        return true;
    }

    void tcp_server::del_client(int fd) {
        if (fd <= 0) {
            return;
        }
        this->clients[fd]->client.buffer.shrink();
        this->clients[fd]->client.req.clean();
        this->clients[fd]->client.res.clean();
        this->server_epoll->del(fd);
        this->sid_queue.push(this->clients.find(fd)->second->client.sid);
        this->clients.erase(fd);
        shutdown(fd, SHUT_RDWR);
        close(fd);

        if (this->on_connect_close) {
            this->on_connect_close(fd);
        }
    }

    void tcp_server::clean_context(int fd) {
        if (fd <= 0) {
            return;
        }
        if (this->clients[fd] == nullptr) {
            //std::cout << "clean_context:this->clients[fd] is null" << std::endl;
            return;
        }
        this->clients[fd]->client.buffer.shrink();
        this->clients[fd]->client.req.clean();
        this->clients[fd]->client.res.clean();
    }

    bool tcp_server::work(int fd, const handler_function &do_work) {
        motoro::net::Buffer &buffer = this->clients[fd]->client.buffer;

        char temp[this->buffer_size];
        bool repeatable = true;
        ev_recv:
        ssize_t ret = recv(fd, temp, this->buffer_size, MSG_WAITALL);
        if (ret < 0) {
            if (errno == EINTR) {
                if (repeatable) {
                    repeatable = false;
                    goto ev_recv;
                }
            } else if (errno == EAGAIN) {
                return false;
            }
            goto ev_error;

        } else if (ret > 0) {
            buffer.append(temp, ret);
            std::pair<char *, size_t> input;
            StringPiece stringPiece = buffer.toStringPiece();
            input.first = const_cast<char *>(stringPiece.data());
            input.second = stringPiece.size();

            bool keepalive = CLOSE_CONNECTION;
            if (this->clients[fd] == nullptr) {
                //std::cout << "work:this->clients[fd] is null" << std::endl;
                goto ev_error;
            }
            client_t &client = this->clients[fd]->client;
            client.u_size = this->clients.size();
            client.count++;

            std::string success = std::move(do_work(input, keepalive, client));

            if (std::strcmp(success.c_str(), "0") == 0) {
                goto ev_error;
            }
        } else {

            ev_error:
            this->del_client(fd);
            return false;
        }
        return true;
    }


    void tcp_server::main_loop(struct epoll_event *event, const handler_function &g, motoro::epoll &epoll) {
        if (event->data.fd == this->listenfd) {
            struct sockaddr_storage clientaddr{};
            socklen_t clilen = sizeof(clientaddr);
            std::string clientip;
            int clientport = 0;
            int connfd;
            do {
                connfd = accept(this->listenfd, (struct sockaddr *) &clientaddr, &clilen);
                if (connfd > 0) {
                    this->set_nonblock(connfd);
                    if (!motoro::tcp_server::get_client_address(&clientaddr, clientip, clientport)) {
                        shutdown(connfd, SHUT_RDWR);
                        close(connfd);
                        break;
                    }
                    if (!this->add_client(connfd, clientip, clientport)) {
                        this->del_client(connfd);
                        break;
                    }
                } else if (errno != EAGAIN) {
                    std::cout << "accept fail,error:" << errno << ":" << strerror(errno) << std::endl;
                }
            } while (connfd > 0);
        } else if (event->events & EPOLLIN) {
            if (this->whitelist_inotify && event->data.fd == this->whitelist_inotify->get_fd()) {
                this->whitelist_inotify->run();
            } else {
                this->work(event->data.fd, g);
            }
        } else {
            this->del_client(event->data.fd);
        }
    }

    size_t tcp_server::get_buffer_size() const {
        return this->buffer_size;
    }

    bool tcp_server::get_client_address(struct sockaddr_storage *address, std::string &ip, int &port) {
        if (address->ss_family == AF_INET) {
            auto *clientaddr_v4 = (struct sockaddr_in *) address;
            char clistr[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &clientaddr_v4->sin_addr, clistr, INET_ADDRSTRLEN)) {
                ip = clistr;
                port = ntohs(clientaddr_v4->sin_port);
                return true;
            }
        } else if (address->ss_family == AF_INET6) {
            auto *clientaddr_v6 = (struct sockaddr_in6 *) address;
            char clistr[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &clientaddr_v6->sin6_addr, clistr, INET6_ADDRSTRLEN)) {
                ip = clistr;
                port = ntohs(clientaddr_v6->sin6_port);
                return true;
            }
        }
        return false;
    }
}