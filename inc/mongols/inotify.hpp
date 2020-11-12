#ifndef DCD22375_A901_4F02_B9AA_D96A5924AC43
#define DCD22375_A901_4F02_B9AA_D96A5924AC43

#include <functional>
#include <string>
#include <sys/inotify.h>
#include <unistd.h>

namespace mongols {
    class inotify {
    public:
        inotify() = delete;

        inotify(const std::string &);

        virtual ~inotify();

        bool watch(uint32_t);

        int get_fd() const;

        uint32_t get_mask() const;

        const std::string &get_path() const;

        void set_cb(const std::function<void(struct inotify_event *)> &);

        void run();

    private:
        int fd, wd;
        uint32_t mask;
        std::string path;
        std::function<void(struct inotify_event *)> cb;

    public:
        static size_t buffer_size;
    };
}

#endif /* DCD22375_A901_4F02_B9AA_D96A5924AC43 */
