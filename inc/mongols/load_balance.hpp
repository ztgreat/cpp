#ifndef MONGOLS_LOAD_BALANCE_HPP
#define MONGOLS_LOAD_BALANCE_HPP

#include <string>
#include <mongols/upstream_server.hpp>
#include <vector>

namespace mongols {

    class load_balance {
    public:
        std::vector<mongols::upstream_server> upstream_server_list;
    public:
        load_balance() = default;
        void add_upstream_server(upstream_server *upstreamServer) {
            upstream_server_list.insert(upstream_server_list.begin(), *upstreamServer);
        }
        virtual mongols::upstream_server *choseServer();
    };

}

#endif
