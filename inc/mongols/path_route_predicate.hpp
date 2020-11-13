#ifndef MONGOLS_PATH_ROUTE_PREDICATE_HPP
#define MONGOLS_PATH_ROUTE_PREDICATE_HPP


#include <string>
#include <upstream_server.hpp>
#include <vector>
#include <memory>
#include "mongols/request.hpp"
#include "mongols/route_locator.hpp"
#include <mongols/util.hpp>

namespace mongols {


    class path_route_predicate : public route_predicate {

    public:

        std::shared_ptr<RE2::Options> re2_options;
        std::shared_ptr<RE2> re2_engine;

        path_route_predicate() = delete;

        path_route_predicate(const std::string &type, const std::string &rule);

        bool match(const mongols::request &request, std::vector<std::string> &param) override;
    };

}
#endif