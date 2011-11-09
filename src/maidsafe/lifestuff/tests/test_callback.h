/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Object with functions for use as functors in tests
* Created:      2010-06-02
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_LIFESTUFF_TESTS_TEST_CALLBACK_H_
#define MAIDSAFE_LIFESTUFF_TESTS_TEST_CALLBACK_H_

#include <string>
#include <vector>

#include "boost/thread/condition.hpp"
#include "boost/thread/mutex.hpp"
#include "maidsafe/lifestuff/return_codes.h"

namespace maidsafe {

namespace lifestuff {

namespace test {

class CallbackObject {
 public:
  CallbackObject()
    : return_int_(kPendingResult),
      get_packet_return_(kPendingResult),
      get_packet_results_(),
      mutex_(),
      cv_() {}

  void IntCallback(int return_code) {
    boost::mutex::scoped_lock lock(mutex_);
    return_int_ = return_code;
    cv_.notify_one();
  }

  int WaitForIntResult() {
    int result;
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (return_int_ == kPendingResult)
        cv_.wait(lock);
      result = return_int_;
      return_int_ = kPendingResult;
    }
    return result;
  }

  void GetPacketCallback(const std::vector<std::string>& results, int rc) {
    boost::mutex::scoped_lock lock(mutex_);
    get_packet_return_ = rc;
    get_packet_results_ = results;
    cv_.notify_one();
  }

  int WaitForGetPacketCallbackResult() {
    int result;
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (get_packet_return_ == kPendingResult)
        cv_.wait(lock);
      result = get_packet_return_;
      get_packet_return_ = kPendingResult;
    }
    return result;
  }

  std::vector<std::string> get_packet_results() { return get_packet_results_; }

  void Reset() {
    boost::mutex::scoped_lock lock(mutex_);
    return_int_ = kPendingResult;
    get_packet_return_ = kPendingResult;
  }

 private:
  int return_int_, get_packet_return_;
  std::vector<std::string> get_packet_results_;
  boost::mutex mutex_;
  boost::condition_variable cv_;
};

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_TESTS_TEST_CALLBACK_H_
