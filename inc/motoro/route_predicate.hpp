#ifndef MOTORO_ROUTE_PREDICATE_HPP
#define MOTORO_ROUTE_PREDICATE_HPP

#include <string>
#include "motoro/request.hpp"
#include <motoro/util.hpp>

namespace motoro {

    class route_predicate {
    public:
        std::string type;
        std::string rule;

        // 可以通过组合的方式 把选取 up server 的功能委托给 其它具体实现类
        // 这里暂时 直接将正则 匹配方式写在这里
        std::shared_ptr<RE2::Options> re2_options;
        std::shared_ptr<RE2> re2_engine;

        route_predicate() = delete;

        route_predicate(const std::string &type, const std::string &rule);

        virtual bool match(const motoro::request &request, std::vector<std::string> &param);
    };

}

#endif