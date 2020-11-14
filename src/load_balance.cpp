#include <mongols/upstream_server.hpp>
#include "mongols/load_balance.hpp"

namespace mongols {

    mongols::upstream_server *load_balance::choseServer() {
        return (*this->upstream_server_list)[0];
    }
}

