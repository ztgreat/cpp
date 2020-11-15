#include <motoro/upstream_server.hpp>
#include "motoro/load_balance.hpp"

namespace motoro {

    motoro::upstream_server *load_balance::choseServer() {
        return (*this->upstream_server_list)[0];
    }
}

