#ifndef D805C907_BBE7_4769_993B_66FA7B2EB25B
#define D805C907_BBE7_4769_993B_66FA7B2EB25B

#include <string>
#include <unordered_map>

namespace motoro {

    class request {
    public:
        request()
                : client(), user_agent(), method(), uri(), param(), headers(), form(), cookies(), session(), cache() {
        }

        virtual ~request() = default;

        void clean() {
            this->client.clear();
            this->user_agent.clear();
            this->method.clear();
            this->uri.clear();
            this->param.clear();

            this->headers.clear();
            this->form.clear();
            this->cookies.clear();
            this->session.clear();
            this->cache.clear();
        }

        std::string client, user_agent, method, uri, param;
        std::unordered_map<std::string, std::string> headers, form, cookies, session, cache;
    };
}

#endif /* D805C907_BBE7_4769_993B_66FA7B2EB25B */
