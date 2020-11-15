#ifndef MOTORO_ROUTE_PREDICATE_HPP
#define MOTORO_ROUTE_PREDICATE_HPP

#include <string>
#include "motoro/request.hpp"

namespace motoro {

    class route_predicate {
    public:
        std::string type;
        std::string rule;

        route_predicate() = delete;

        route_predicate(const std::string &type, const std::string &rule) {
            this->type = type;
            this->rule = rule;
        }

        virtual bool match(const motoro::request &request, std::vector<std::string> &param) = 0;
    };

}

#endif
