#ifndef CAAA25FF8AD29DAD06218DC8D1D01C7C0F
#define CAAA25FF8AD29DAD06218DC8D1D01C7C0F

#include <string>
#include <mongols/upstream_server.hpp>
#include <vector>
#include <mongols/route_locator.hpp>
#include "mongols/request.hpp"

namespace mongols {

    mongols::upstream_server *mongols::route_locator::choseServer(const mongols::request *request) {

        // tcp
        if (request == nullptr) {
            return this->load_balance->choseServer();
        }

        // http
        // todo need optimization
        std::vector<std::string> param;
        for (auto it = this->route_predicate->begin(); it != this->route_predicate->end(); it++) {
            if ((*it)->match(*request, param)) {
                mongols::upstream_server *up = this->load_balance->choseServer();
                return up;
            }
        }
        return nullptr;

    }

}

#endif
