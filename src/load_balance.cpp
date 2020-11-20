
#include <motoro/upstream_server.hpp>
#include "motoro/load_balance.hpp"

namespace motoro {

    motoro::upstream_server *load_balance::choseServer() {
        if (this->upstream_server_list == nullptr || this->upstream_server_list->empty()) {
            return nullptr;
        }
        if (this->upstream_server_list->size() == 1) {
            return (*this->upstream_server_list)[0];
        }

        // 这里需要通过 取余 策略选取up server
        this->index = (this->index + 1) & SIZE_MAX;
        return (*this->upstream_server_list)[index &
                                             (this->upstream_server_list->size() - 1)];
    }
}
