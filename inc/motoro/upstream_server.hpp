#ifndef MOTORO_UPSTREAM_SERVER_HPP
#define MOTORO_UPSTREAM_SERVER_HPP

#include <string>

namespace motoro {

    class upstream_server {
    public:
        std::string server;
        int port;
    public:
        upstream_server() = delete;

        upstream_server(const std::string &, int port);

        virtual ~upstream_server() = default;
    };

}

#endif