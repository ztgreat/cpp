#include <sys/wait.h>
#include "inc/motoro/util.hpp"
#include "inc/motoro/tcp_proxy_server.hpp"
#include <cstring>
#include <iostream>
#include <functional>
#include <motoro/route_predicate.hpp>
#include "inc/yaml-cpp/yaml.h"

int main(int, char **) {

    YAML::Node config = YAML::LoadFile("./config.yaml");

    const std::string host = config["server.host"].as<std::string>();
    int port = config["server.port"].as<std::int32_t>();
    const std::string mode = config["server.mode"].as<std::string>();
    int buffer_size = config["server.buffer.size"].as<std::int32_t>();

    const std::string worker_processes_str = config["server.worker.processes"].as<std::string>();
    unsigned int worker_processes = std::thread::hardware_concurrency();
    if (strcmp(worker_processes_str.c_str(), "auto") != 0) {
        worker_processes = std::stoi(worker_processes_str);
    }

    motoro::tcp_server::connection_t connection;
    if (strcmp(mode.c_str(), "TCP") == 0 || strcmp(mode.c_str(), "tcp") == 0) {
        connection = motoro::tcp_server::connection_t::TCP;
    } else {
        connection = motoro::tcp_server::connection_t::HTTP;
    }

    motoro::tcp_proxy_server server(host, port, 5000, buffer_size, connection);
    server.set_enable_http_lru_cache(false);
    server.set_default_http_content();

    const YAML::Node &routes = config["routes"];
    for (auto it = routes.begin(); it != routes.end(); ++it) {

        const YAML::Node &route = *it;
        auto routeLocator = new motoro::route_locator;
        auto *loadBalance = new motoro::load_balance;
        const YAML::Node &upServers = route["uri"];
        for (auto it2 = upServers.begin(); it2 != upServers.end(); ++it2) {
            const YAML::Node &upServer = *it2;
            std::string url = upServer.as<std::string>();

            std::string::size_type first_pos = url.find_first_of(':');

            // upstream
            if (first_pos == -1) {
                auto temp = new motoro::upstream_server(url, 80);
                loadBalance->add_upstream_server(temp);
            } else {
                auto temp = new motoro::upstream_server(url.substr(0, first_pos), std::stoi(
                        url.substr(first_pos + 1, url.length() - first_pos - 1)));
                loadBalance->add_upstream_server(temp);
            }
        }

        const YAML::Node &predicates = route["predicates"];
        for (auto it2 = predicates.begin(); it2 != predicates.end(); ++it2) {
            const YAML::Node &node_predicate = *it2;
            // predicate
            std::string predicate = node_predicate.as<std::string>();
            std::vector<std::string> temp = motoro::split(predicate, '=');

            if (temp.size() != 2) {
                continue;
            }
            if (std::strcmp(temp[0].c_str(), "path") == 0) {
                auto path_predicate = new motoro::route_predicate("path", temp[1]);
                routeLocator->addPredicate(path_predicate);
            }

        }
        routeLocator->setLoadBalance(loadBalance);
        server.add_route_locators(routeLocator);
    }

    auto f = [](const motoro::tcp_server::client_t &client) {
        return true;
    };

    auto h = [&](const motoro::request &req) {
        return true;
    };

    //server.run(f, h);

    std::function<void(pthread_mutex_t *, size_t *)> ff = [&](pthread_mutex_t *mtx, size_t *data) {
        server.run(f, h);
    };

    std::function<bool(int)> g = [&](int status) {
        std::cout << strsignal(WTERMSIG(status)) << std::endl;
        return false;
    };

    motoro::multi_process main_process;
    main_process.run(ff, g, worker_processes);
}

