#ifndef MONGOLS_ROUTE_LOCATOR_HPP
#define MONGOLS_ROUTE_LOCATOR_HPP

#include <string>
#include <mongols/upstream_server.hpp>
#include <vector>
#include "mongols/request.hpp"
#include "mongols/route_predicate.hpp"
#include "mongols/load_balance.hpp"

namespace mongols {

    class route_locator {
    public:
        std::vector<mongols::route_predicate *> *route_predicate;
        mongols::load_balance *load_balance;
    public:
        route_locator() {
            this->route_predicate = new std::vector<mongols::route_predicate *>();
        };

        ~route_locator() {
            for (auto it = this->route_predicate->begin(); it != this->route_predicate->end(); it++) {
                delete *it;
            }
            this->route_predicate->clear();
            this->route_predicate->shrink_to_fit();
            delete this->route_predicate;
        }

        void addPredicate(mongols::route_predicate *predicate) {
            this->route_predicate->insert(this->route_predicate->end(), predicate);
        }

        void setLoadBalance(mongols::load_balance *loadBalance) {
            this->load_balance = loadBalance;
        }

        virtual upstream_server *choseServer(const mongols::request *);
    };

}

#endif
