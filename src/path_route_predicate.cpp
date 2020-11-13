#include <string>
#include <vector>
#include <memory>
#include "mongols/request.hpp"
#include "mongols/path_route_predicate.hpp"
#include <mongols/util.hpp>

namespace mongols {


    mongols::path_route_predicate::path_route_predicate(const std::string &type, const std::string &rule)
            : route_predicate(type, rule) {
        this->re2_options = std::move(std::make_shared<RE2::Options>());
        this->re2_options->set_log_errors(false);
        this->re2_engine = std::move(std::make_shared<RE2>("(" + this->rule + ")", *(this->re2_options)));
    }

    bool mongols::path_route_predicate::match(const mongols::request &request, std::vector<std::string> &param) {
        if (mongols::regex_find(*this->re2_engine, request.uri, param)) {
            return true;
        }
        return false;
    }


}
