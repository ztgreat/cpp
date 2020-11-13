#ifndef MONGOLS_ROUTE_PREDICATE_HPP
#define MONGOLS_ROUTE_PREDICATE_HPP

#include <string>
#include "mongols/request.hpp"

namespace mongols {

    class route_predicate {
    public:
        std::string type;
        std::string rule;

        route_predicate() = delete;

        route_predicate(const std::string &type, const std::string &rule) {
            this->type = type;
            this->rule = rule;
        }

        virtual bool match(const mongols::request &request, std::vector<std::string> &param) = 0;
    };

}

#endif
