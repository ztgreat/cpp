#ifndef EC3865D2_F8D6_44D0_A410_DD0E2BAE448B
#define EC3865D2_F8D6_44D0_A410_DD0E2BAE448B

#include <string>
#include <unordered_map>

namespace motoro {

    class response {
    public:
        response()
                : status(404), content("<p style='text-align:center;margin:100px;'>404 Not Found</p>"), headers(),
                  session(), cache() {
            this->headers.insert(
                    std::move(std::make_pair(std::move("Content-Type"), std::move("text/html;charset=UTF-8"))));
        }

        virtual ~response() = default;

        void set_header(const std::string &key, const std::string &value) {
            if (key == "Content-Type") {
                this->headers.find(key)->second = value;
            } else {
                this->headers.insert(std::move(std::make_pair(key, value)));
            }
        }

        void set_session(const std::string &key, const std::string &value) {
            this->session.insert(std::move(std::make_pair(key, value)));
        }

        void set_cache(const std::string &key, const std::string &value) {
            this->cache.insert(std::move(std::make_pair(key, value)));
        }

        void clean() {
            this->headers.clear();
            this->session.clear();
            this->cache.clear();
        }

        int status;
        std::string content;
        std::unordered_multimap<std::string, std::string> headers;
        std::unordered_map<std::string, std::string> session, cache;
    };
}

#endif /* EC3865D2_F8D6_44D0_A410_DD0E2BAE448B */
