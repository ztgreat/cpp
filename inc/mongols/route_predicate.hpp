#ifndef MONGOLS_ROUTE_PREDICATE_HPP
#define MONGOLS_ROUTE_PREDICATE_HPP

#include <string>
#include <upstream_server.hpp>
#include <vector>
#include <memory>
#include "request.hpp"
#include <mongols/util.hpp>

namespace mongols {


    class route_predicate {

    public:
        std::string type;
        std::string rule;

        std::shared_ptr<RE2::Options> re2_options;
        std::shared_ptr<RE2> re2_engine;

        route_predicate() = delete;

        route_predicate(const std::string &type, const std::string &rule) {
            this->type = type;
            this->rule = rule;
            this->re2_options = std::move(std::make_shared<RE2::Options>());
            this->re2_options->set_log_errors(false);
            this->re2_engine = std::move(std::make_shared<RE2>("(" + this->rule + ")", *(this->re2_options)));
        }

        bool test(const mongols::request &request, std::vector<std::string> &param) {
            if (mongols::regex_find(*this->re2_engine, request.uri, param)) {
                return true;
            }
            return false;
        }

    };

}

#endif
