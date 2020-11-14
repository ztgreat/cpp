#ifndef MONGOLS_LOAD_BALANCE_HPP
#define MONGOLS_LOAD_BALANCE_HPP

#include <string>
#include <mongols/upstream_server.hpp>
#include <vector>

namespace mongols {

    class load_balance {
    public:
        std::vector<mongols::upstream_server *> *upstream_server_list;
    public:
        load_balance() {
            this->upstream_server_list = new std::vector<mongols::upstream_server *>();
        }

        ~load_balance() {
            for (auto it = this->upstream_server_list->begin(); it != this->upstream_server_list->end(); it++) {
                delete *it;
            }
            this->upstream_server_list->clear();
            this->upstream_server_list->shrink_to_fit();
            delete this->upstream_server_list;
        }

        void add_upstream_server(upstream_server *upstreamServer) {
            this->upstream_server_list->insert(this->upstream_server_list->end(), upstreamServer);
        }

        virtual mongols::upstream_server *choseServer();
    };

}

#endif
