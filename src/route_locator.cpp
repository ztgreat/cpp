#ifndef CAAA25FF8AD29DAD06218DC8D1D01C7C0F
#define CAAA25FF8AD29DAD06218DC8D1D01C7C0F

#include <string>
#include <motoro/upstream_server.hpp>
#include <vector>
#include <motoro/route_locator.hpp>
#include "motoro/request.hpp"

namespace motoro {

    motoro::upstream_server *motoro::route_locator::choseServer(const motoro::request *request) {

        // tcp
        if (request == nullptr) {
            return this->load_balance->choseServer();
        }

        // http
        // todo need optimization
        std::vector<std::string> param;
        for (auto it = this->route_predicate->begin(); it != this->route_predicate->end(); it++) {
            if ((*it)->match(*request, param)) {
                motoro::upstream_server *up = this->load_balance->choseServer();
                return up;
            }
        }
        return nullptr;

    }

}

#endif
