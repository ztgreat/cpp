#include <string>
#include <vector>
#include <memory>
#include "motoro/request.hpp"
#include "motoro/route_predicate.hpp"
#include <motoro/util.hpp>

namespace motoro {


    motoro::route_predicate::route_predicate(const std::string &type, const std::string &rule) {
        this->rule = rule;
        this->type = type;
        this->re2_options = std::move(std::make_shared<RE2::Options>());
        this->re2_options->set_log_errors(false);
        this->re2_engine = std::move(std::make_shared<RE2>("(" + this->rule + ")", *(this->re2_options)));
    }

    bool motoro::route_predicate::match(const motoro::request &request, std::vector<std::string> &param) {
        return motoro::regex_find(*this->re2_engine, request.uri, param);
    }


}
