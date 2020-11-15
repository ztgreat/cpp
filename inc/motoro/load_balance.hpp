#ifndef MOTORO_LOAD_BALANCE_HPP
#define MOTORO_LOAD_BALANCE_HPP

#include <string>
#include <motoro/upstream_server.hpp>
#include <vector>

namespace motoro {

    class load_balance {
    public:
        std::vector<motoro::upstream_server *> *upstream_server_list;
    public:
        load_balance() {
            this->upstream_server_list = new std::vector<motoro::upstream_server *>();
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

        virtual motoro::upstream_server *choseServer();
    };

}

#endif
