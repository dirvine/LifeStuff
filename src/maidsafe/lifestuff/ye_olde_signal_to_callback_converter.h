/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Creates, stores and accesses user details
* Version:      1.0
* Created:      2009-01-28-22.18.47
* Revision:     none
* Author:       Team
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

#ifndef MAIDSAFE_LIFESTUFF_YE_OLDE_SIGNAL_TO_CALLBACK_CONVERTER_H_
#define MAIDSAFE_LIFESTUFF_YE_OLDE_SIGNAL_TO_CALLBACK_CONVERTER_H_

#include <list>
#include <string>

#include "boost/thread/mutex.hpp"

#include "maidsafe/lifestuff/lifestuff.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 201
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif

namespace maidsafe {

namespace lifestuff {

// TODO(Brian): Try to template this to receive other types of function
//              and declare slots with the same type
class YeOldeSignalToCallbackConverter {
 public:
  explicit YeOldeSignalToCallbackConverter(uint16_t max_size = UINT16_MAX);
  int AddOperation(const std::string &name, const VoidFuncOneInt cb);

  // slots
  void Deleted(const std::string &chunk_name, const int &result);
  void Stored(const std::string &chunk_name, const int &result);
  void Modified(const std::string &chunk_name, const int &result);

 private:
  struct ChunkNameAndCallback {
    ChunkNameAndCallback()
        : chunk_name(),
          callback() {}
    ChunkNameAndCallback(const std::string &name, const VoidFuncOneInt cb)
        : chunk_name(name),
          callback(cb) {}
    std::string chunk_name;
    VoidFuncOneInt callback;
  };

  bool QueueIsFull();
  void ExecuteCallback(const std::string &chunk_name, const int &result);

  std::list<ChunkNameAndCallback> operation_queue_;
  size_t max_size_;
  boost::mutex mutex_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_YE_OLDE_SIGNAL_TO_CALLBACK_CONVERTER_H_
