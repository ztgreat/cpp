#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include "tcp_threading_server.hpp"
#include "util.hpp"

namespace motoro {

    tcp_threading_server::tcp_threading_server(const std::string &host, int port, int timeout, size_t buffer_size,
                                               size_t thread_size, int max_event_size)
            : tcp_server(host, port, timeout, buffer_size, max_event_size), main_mtx() {
        this->thread_size = (thread_size == 0 ? std::thread::hardware_concurrency() : thread_size);
    }

    void tcp_threading_server::set_whitelist(const std::string &ip) {
        std::lock_guard<std::mutex> lk(this->main_mtx);
        this->whitelist.push_back(ip);
    }

    void tcp_threading_server::del_whitelist(const std::string &ip) {
        std::lock_guard<std::mutex> lk(this->main_mtx);
        this->whitelist.remove(ip);
    }

    bool tcp_threading_server::read_whitelist_file(const std::string &path) {
        if (motoro::is_file(path)) {
            std::lock_guard<std::mutex> lk(this->main_mtx);
            this->whitelist.clear();
            std::ifstream input(path);
            if (input) {
                std::string line;
                while (std::getline(input, line)) {
                    motoro::trim(line);
                    if (!line.empty()) {
                        this->whitelist.push_back(line);
                    }
                }
                return true;
            }
        }
        return false;
    }

    bool tcp_threading_server::add_client(int fd, const std::string &ip, int port, bool is_up_server = false,
                                          size_t client_sid = -1,
                                          std::shared_ptr<std::string> client_request_id = nullptr,
                                          int client_socket_fd = -1) {
        std::lock_guard<std::mutex> lk(this->main_mtx);
        this->server_epoll->add(fd, EPOLLIN | EPOLLRDHUP | EPOLLET);
        auto pair = this->clients.insert(
                std::move(std::make_pair(fd, std::move(
                        meta_data_t(ip, port, 0, 0, is_up_server, client_sid,client_request_id, client_socket_fd)))));
        if (this->sid_queue.empty()) {
            pair.first->second.client.sid = ++this->sid;
        } else {
            pair.first->second.client.sid = this->sid_queue.front();
            this->sid_queue.pop();
        }
        return true;
    }

    void tcp_threading_server::del_client(int fd) {
        std::lock_guard<std::mutex> lk(this->main_mtx);
        this->server_epoll->del(fd);
        this->sid_queue.push(this->clients.find(fd)->second.client.sid);
        this->clients.erase(fd);
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }

    bool tcp_threading_server::send_to_other_client(int fd, int ffd, meta_data_t &meta_data, const std::string &str,
                                                    const filter_handler_function &h) {
        std::lock_guard<std::mutex> lk(this->main_mtx);
        if (ffd != fd && h(meta_data.client) &&
            send(ffd, str.c_str(), str.size(), MSG_NOSIGNAL) < 0) {
            this->del_client(ffd);
        }
        return false;
    }

    bool tcp_threading_server::send_to_all_client(int fd, const std::string &str, const filter_handler_function &h) {
        std::lock_guard<std::mutex> lk(this->main_mtx);
        for (auto &i : this->clients) {
            this->work_pool->submit(
                    std::bind(&tcp_threading_server::send_to_other_client, this, fd, i.first, std::ref(i.second), str,
                              h));
        }
        return false;
    }

    bool tcp_threading_server::check_blacklist(const std::string &ip) {
        std::lock_guard<std::mutex> lk(this->main_mtx);
        std::shared_ptr<black_ip_t> black_ip;
        if (this->blacklist.tryGet(ip, black_ip)) {
            double diff = difftime(time(0), black_ip->t);
            if (black_ip->disallow) {
                if (diff < tcp_server::backlist_timeout) {
                    return false;
                } else {
                    black_ip->disallow = false;
                    black_ip->count = 1;
                    black_ip->t = time(0);
                }
            }

            if ((diff == 0 && black_ip->count > tcp_server::max_connection_limit)
                || (diff > 0 && black_ip->count / diff > tcp_server::max_connection_limit)) {
                black_ip->t = time(0);
                black_ip->disallow = true;
                return false;
            } else {
                black_ip->count++;
            }
        } else {
            this->blacklist.insert(ip, std::make_shared<black_ip_t>());
        }
        return true;
    }

    bool tcp_threading_server::check_whitelist(const std::string &ip) {
        std::lock_guard<std::mutex> lk(this->main_mtx);
        return std::find(this->whitelist.begin(), this->whitelist.end(), ip) != this->whitelist.end();
    }

    bool tcp_threading_server::work(int fd, const handler_function &g) {
        char buffer[this->buffer_size];
        bool rereaded = false;
        ev_recv:
        ssize_t ret = recv(fd, buffer, this->buffer_size, MSG_WAITALL);
        if (ret == -1) {
            if (errno == EINTR) {
                if (!rereaded) {
                    rereaded = true;
                    goto ev_recv;
                }
            } else if (errno == EAGAIN) {
                return false;
            }
            goto ev_error;

        } else if (ret > 0) {
            std::pair<char *, size_t> input;
            input.first = &buffer[0];
            input.second = ret;
            std::string output;
            filter_handler_function send_to_other_filter = [](const tcp_server::client_t &) {
                return true;
            };
            bool keepalive = CLOSE_CONNECTION, send_to_all = false;
            {
                std::lock_guard<std::mutex> lk(this->main_mtx);
                tcp_server::client_t &client = this->clients[fd].client;
                client.u_size = this->clients.size();
                client.count++;
                output = std::move(g(input, keepalive, send_to_all, client, send_to_other_filter));
                if (output.empty()) {
                    return false;
                }
            }
            ret = send(fd, output.c_str(), output.size(), MSG_NOSIGNAL);
            if (ret > 0) {
                if (send_to_all) {
                    this->work_pool->submit(std::bind(&tcp_threading_server::send_to_all_client, this, fd, output,
                                                      send_to_other_filter));
                }
            }
            if (ret <= 0 || keepalive == CLOSE_CONNECTION) {
                goto ev_error;
            }

        } else {

            ev_error:
            this->del_client(fd);
        }
        return false;
    }
}