#ifndef MOTORO_ROUTE_LOCATOR_HPP
#define MOTORO_ROUTE_LOCATOR_HPP

#include <string>
#include <motoro/upstream_server.hpp>
#include <vector>
#include "motoro/request.hpp"
#include "motoro/route_predicate.hpp"
#include "motoro/load_balance.hpp"

namespace motoro {

    class route_locator {
    public:
        std::vector<motoro::route_predicate *> *route_predicate;
        motoro::load_balance *load_balance;
    public:
        route_locator() {
            this->route_predicate = new std::vector<motoro::route_predicate *>();
        };

        ~route_locator() {
            for (auto it = this->route_predicate->begin(); it != this->route_predicate->end(); it++) {
                delete *it;
            }
            this->route_predicate->clear();
            this->route_predicate->shrink_to_fit();
            delete this->route_predicate;
        }

        void addPredicate(motoro::route_predicate *predicate) {
            this->route_predicate->insert(this->route_predicate->end(), predicate);
        }

        void setLoadBalance(motoro::load_balance *loadBalance) {
            this->load_balance = loadBalance;
        }

        virtual upstream_server *choseServer(const motoro::request *);
    };

}

#endif
