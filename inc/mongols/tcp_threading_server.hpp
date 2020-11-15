#ifndef D5DFD123_CAF7_4805_B500_8CAC294F07C0
#define D5DFD123_CAF7_4805_B500_8CAC294F07C0

#include "tcp_server.hpp"
#include "thread_pool.hpp"
#include <mutex>

namespace mongols {

    class tcp_threading_server : public tcp_server {
    public:
        tcp_threading_server() = delete;

        tcp_threading_server(const std::string &host, int port, int timeout = 5000, size_t buffer_size = 8192,
                             size_t thread_size = std::thread::hardware_concurrency(), int max_event_size = 64);

        virtual ~tcp_threading_server() = default;

        virtual void set_whitelist(const std::string &);

        virtual void del_whitelist(const std::string &);

    private:
        virtual bool
        add_client(int, const std::string &, int, bool, size_t client_sid,
                   std::shared_ptr<std::string> client_request_id,
                   int);

        virtual void del_client(int);

        virtual bool send_to_all_client(int, const std::string &, const filter_handler_function &);

        virtual bool work(int, const handler_function &);

        virtual bool check_blacklist(const std::string &);

        virtual bool check_whitelist(const std::string &);

        virtual bool read_whitelist_file(const std::string &);

        bool send_to_other_client(int, int, meta_data_t &, const std::string &, const filter_handler_function &);

    private:
        std::mutex main_mtx;
    };
}

#endif /* D5DFD123_CAF7_4805_B500_8CAC294F07C0 */
