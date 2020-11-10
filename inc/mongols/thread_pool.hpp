#ifndef F7EF3FB2_DFA3_4E87_97D4_6F18EC6293C4
#define F7EF3FB2_DFA3_4E87_97D4_6F18EC6293C4

#include <atomic>
#include <functional>
#include <iostream>
#include <pthread.h>
#include <thread>
#include <vector>

#include "safe_queue.hpp"

namespace mongols {

class join_thread {
private:
    std::vector<std::thread>& th;

public:
    join_thread(std::vector<std::thread>& th)
        : th(th)
    {
    }

    virtual ~join_thread()
    {
        for (auto& i : this->th) {
            if (i.joinable()) {
                i.join();
            }
        }
    }
};

template <typename function_t>
class thread_pool {
private:
    safe_queue<function_t> q;
    std::vector<std::thread> th;
    join_thread joiner;
    std::atomic_bool done;

    void work()
    {
        function_t task;
        while (this->done) {
            this->q.wait_and_pop(task);
            task();
        }
    }

    void shutdown()
    {
        this->done = false;
        for (size_t i = 0; i < this->th.size(); ++i) {
            this->submit([]() {
                return true;
            });
        }
    }

public:
    thread_pool(size_t th_size = std::thread::hardware_concurrency())
        : q()
        , th()
        , joiner(th)
        , done(true)
    {
        try {
            for (size_t i = 0; i < th_size; ++i) {
                this->th.push_back(std::move(std::thread(std::bind(&thread_pool::work, this))));
                cpu_set_t cpuset;
                CPU_ZERO(&cpuset);
                CPU_SET(i, &cpuset);
                pthread_setaffinity_np(this->th.back().native_handle(), sizeof(cpu_set_t), &cpuset);
            }

        } catch (...) {
            this->shutdown();
        }
    }

    virtual ~thread_pool()
    {
        this->shutdown();
    }

    void submit(function_t&& f)
    {
        if (!this->th.empty()) {
            this->q.push(std::move(f));
        }
    }

    size_t size() const
    {
        return this->th.size();
    }

    bool empty() const
    {
        return this->th.empty();
    }
};
}

#endif /* F7EF3FB2_DFA3_4E87_97D4_6F18EC6293C4 */
