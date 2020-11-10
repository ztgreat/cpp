#ifndef C81F6ED0_6DA5_4237_AB1A_274674CAE2A8
#define C81F6ED0_6DA5_4237_AB1A_274674CAE2A8

#include "lib/re2/re2.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <pthread.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace mongols {

std::string random_string(const std::string& s);

bool read_file(const std::string& path, std::string& out);

bool is_file(const std::string& s);

bool is_dir(const std::string& s);

std::string real_path(const std::string&);

std::string http_time(time_t* t);

time_t parse_http_time(u_char* value, size_t len);

std::string trim(const std::string& s);
void trim(std::string& s);

void parse_param(const std::string& data, std::unordered_map<std::string, std::string>& result, char c = '&', char cc = '=');

void split(const std::string& s, char delim, std::vector<std::string>& v);
void split(const std::string& s, const std::string& delim, std::vector<std::string>& v);
std::vector<std::string> split(const std::string& s, char delimiter);

class random {
public:
    random()
        : now(time(0))
    {
        srand(this->now);
    }

    template <class T>
    T create(T left, T right)
    {
        return static_cast<T>(this->create() * (right - left) + left);
    }

private:
    time_t now;

    double create()
    {
        return static_cast<double>(rand() / (RAND_MAX + 1.0));
    }
};

struct regular_expression {
    static std::string INTEGER, NUMBER, EMAIL, URL;
};

std::string base64_encode(const std::string&);
std::string base64_decode(const std::string&);

std::string bin2hex(const std::string&);
std::string bin2hex(const char*, size_t);

std::string url_encode(const std::string& str);

std::string url_decode(const std::string& str);

pid_t forker(int, const std::function<void()>&, std::vector<std::pair<pid_t, int>>&);

bool process_bind_cpu(pid_t pid, int cpu);

bool regex_match(const RE2& re2, const std::string& str, std::vector<std::string>& results);
bool regex_match(const std::string& pattern, const std::string& str, std::vector<std::string>& results);
bool regex_find(const RE2& re2, const std::string& str, std::vector<std::string>& results);
bool regex_find(const std::string& pattern, const std::string& str, std::vector<std::string>& results);

class multi_process {
public:
    static std::vector<int> signals;

public:
    multi_process();

    virtual ~multi_process();

    void run(const std::function<void(pthread_mutex_t*, size_t*)>& f, const std::function<bool(int)>& g, size_t = std::thread::hardware_concurrency());

private:
    pthread_mutex_t* mtx;
    pthread_mutexattr_t* mtx_attr;
    size_t* data;
    static int sig;
    static std::vector<std::pair<pid_t, int>> pids;
    static void signal_cb(int sig);
    static void set_signal();
};
}

#endif /* C81F6ED0_6DA5_4237_AB1A_274674CAE2A8 */
