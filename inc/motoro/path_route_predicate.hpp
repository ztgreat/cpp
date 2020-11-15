#ifndef MOTORO_PATH_ROUTE_PREDICATE_HPP
#define MOTORO_PATH_ROUTE_PREDICATE_HPP


#include <string>
#include <upstream_server.hpp>
#include <vector>
#include <memory>
#include "motoro/request.hpp"
#include "motoro/route_locator.hpp"
#include <motoro/util.hpp>

namespace motoro {


    class path_route_predicate : public route_predicate {

    public:

        std::shared_ptr<RE2::Options> re2_options;
        std::shared_ptr<RE2> re2_engine;

        path_route_predicate() = delete;

        path_route_predicate(const std::string &type, const std::string &rule);

        bool match(const motoro::request &request, std::vector<std::string> &param) override;
    };

}
#endif