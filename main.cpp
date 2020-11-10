#include <unistd.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/prctl.h>

#include "inc/mongols/util.hpp"
#include "inc/mongols/tcp_proxy_server.hpp"

#include <cstring>
#include <iostream>
#include <functional>

int main(int, char**) {
    //    daemon(1, 0);
    auto f = [](const mongols::tcp_server::client_t & client) {
        return true;
    };

    auto h = [&](const mongols::request & req) {
        return true;
    };

    int port = 9099;
    const char* host = "127.0.0.1";
    mongols::tcp_proxy_server server(host, port, 5000, 8192, 0/*2*/);


    server.set_enable_http_lru_cache(true);
    server.set_http_lru_cache_expires(1);
    server.set_default_http_content();

    server.set_backend_server(host, 9090);
    //server.set_backend_server(host, 8889);


    server.run(f,h);

    std::function<void(pthread_mutex_t*, size_t*) > ff = [&](pthread_mutex_t* mtx, size_t * data) {
        server.run(f, h);
    };

    std::function<bool(int) > g = [&](int status) {
        std::cout << strsignal(WTERMSIG(status)) << std::endl;
        return false;
    };

    //mongols::multi_process main_process;
    //main_process.run(ff, g);
}