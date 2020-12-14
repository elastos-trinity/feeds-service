#include "ThreadPool.hpp"

#include "Log.hpp"
#include "Platform.hpp"

namespace trinity {

/***********************************************/
/***** static variables initialize *************/
/***********************************************/


/***********************************************/
/***** static function implement ***************/
/***********************************************/
std::shared_ptr<ThreadPool> ThreadPool::Create(const std::string& threadName, size_t threadCnt)
{
    struct Impl: ThreadPool {
		explicit Impl(const std::string& threadName, size_t threadCnt)
			: ThreadPool(threadName, threadCnt) {}
		virtual ~Impl() {};
    };
    auto impl = std::make_shared<Impl>(threadName, threadCnt);

    return impl;
}


/***********************************************/
/***** class public function implement  ********/
/***********************************************/
ThreadPool::ThreadPool(const std::string& threadName, size_t threadCnt)
    : mThreadName(threadName)
    , mThreadPool(threadCnt)
    , mMutex()
    , mCondition()
    , mTaskQueue()
    , mQuit(false)
{
    Log::D(Log::Tag::Util, "Create threadpool [%s], count:%d", mThreadName.c_str(), threadCnt);

	std::unique_lock<std::mutex> lock(mMutex);
	for(size_t idx = 0; idx < mThreadPool.size(); idx++) {
		mThreadPool[idx] = std::thread(std::bind(&ThreadPool::processTaskQueue, this, mThreadName));
	}
}

ThreadPool::~ThreadPool()
{
	{
		std::unique_lock<std::mutex> lock(mMutex);
		mQuit = true;
		auto empty = std::queue<Task>();
		std::swap(mTaskQueue, empty); // mTaskQueue.clear();
		mCondition.notify_all();
	}

	// Wait for threads to finish before we exit
	for(size_t idx = 0; idx < mThreadPool.size(); idx++) {
		auto& it = mThreadPool[idx];
		if(it.joinable() && it.get_id() != std::this_thread::get_id()) {
            Log::D(Log::Tag::Util, "ThreadPool [%s] Joining thread %d until completion. tid=%lld:%lld",
            		         mThreadName.c_str(), idx, it.get_id(), std::this_thread::get_id());
			it.join();
            Log::D(Log::Tag::Util, "ThreadPool [%s] Joined thread %d until completion. tid=%lld:%lld",
            		         mThreadName.c_str(), idx, it.get_id(), std::this_thread::get_id());
		} else {
            Log::D(Log::Tag::Util, "ThreadPool [%s] Ignore to Join thread %d until completion. tid=%lld:%lld",
            		         mThreadName.c_str(), idx, it.get_id(), std::this_thread::get_id());
			it.detach();
		}
	}
    mThreadPool.clear();
    Log::D(Log::Tag::Util, "Destroy threadpool [%s]", mThreadName.c_str());
}

int ThreadPool::sleepMS(long milliSecond)
{
	auto interval = 100; // ms
	auto elapsed = 0;
    do {
		auto remains = milliSecond - elapsed;
		auto needsleep = interval < remains  ? interval : remains;

		std::this_thread::sleep_for(std::chrono::milliseconds(needsleep));
		elapsed += needsleep;
		if(mQuit == true) {
			return -1;
		}

	} while (elapsed < milliSecond);

	return 0;
}

void ThreadPool::post(const Task& task)
{
	if(mQuit == true) {
		return;
	}

	std::unique_lock<std::mutex> lock(mMutex);
	mTaskQueue.push(task);

	// Manual unlocking is done before notifying, to avoid waking up
    // the waiting thread only to block again (see notify_one for details)
	lock.unlock();
	mCondition.notify_all();
}

void ThreadPool::post(Task&& task)
{
	if(mQuit == true) {
		return;
	}

	std::unique_lock<std::mutex> lock(mMutex);
	mTaskQueue.push(std::move(task));

	// // Manual unlocking is done before notifying, to avoid waking up
    // // the waiting thread only to block again (see notify_one for details)
	// lock.unlock();
	mCondition.notify_all();
}

/***********************************************/
/***** class protected function implement  *****/
/***********************************************/


/***********************************************/
/***** class private function implement  *******/
/***********************************************/
void ThreadPool::processTaskQueue(std::string threadName)
{
	do {
		std::unique_lock<std::mutex> lock(mMutex);
		//Wait until we have data or a quit signal
		mCondition.wait(lock, [this]{
			return (mTaskQueue.size() || mQuit);
		});

		//after wait, we own the lock
		if(!mQuit && mTaskQueue.size())
		{
			auto task = std::move(mTaskQueue.front());
			mTaskQueue.pop();

			//unlock now that we're done messing with the queue
			auto ptr = shared_from_this(); // hold this ptr to ignore release when task is processing
			lock.unlock();

			task();
			if(ptr.use_count() == 1) { // only hold in this task, exit it.
				break;
			}
		}
	} while (!mQuit);

//	Platform::DetachCurrentThread();
	Log::D(Log::Tag::Util, "ThreadPool [%s] runnable exit.", threadName.c_str());
}

} // namespace trinity
