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

#include "maidsafe/lifestuff/ye_olde_signal_to_callback_converter.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/return_codes.h"

namespace maidsafe {

namespace lifestuff {

YeOldeSignalToCallbackConverter::YeOldeSignalToCallbackConverter(
    uint16_t max_size)
    : operation_queue_(),
      max_size_(max_size),
      mutex_() {}

int YeOldeSignalToCallbackConverter::AddOperation(const std::string &name,
                                                  const VoidFunctionOneInt cb) {
  boost::mutex::scoped_lock loch_of_cliff(mutex_);
  if (QueueIsFull()) {
    DLOG(ERROR) << "Queue is full";
    return -1;
  }

  operation_queue_.push_back(ChunkNameAndCallback(name, cb));

  return kSuccess;
}

void YeOldeSignalToCallbackConverter::Deleted(const std::string &chunk_name,
                                              const int &result) {
  ExecuteCallback(chunk_name, result);
}

void YeOldeSignalToCallbackConverter::Stored(const std::string &chunk_name,
                                             const int &result) {
  ExecuteCallback(chunk_name, result);
}

void YeOldeSignalToCallbackConverter::Modified(const std::string &chunk_name,
                                               const int &result) {
  ExecuteCallback(chunk_name, result);
}

bool YeOldeSignalToCallbackConverter::QueueIsFull() {
  if (static_cast<uint16_t>(operation_queue_.size()) >= max_size_)
    return true;

  return false;
}

void YeOldeSignalToCallbackConverter::ExecuteCallback(
    const std::string &chunk_name,
    const int &result) {
  boost::mutex::scoped_lock loch_of_cliff(mutex_);
  auto it = std::find_if(operation_queue_.begin(),
                         operation_queue_.end(),
                         [&chunk_name] (const ChunkNameAndCallback &cnac) {
                           return cnac.chunk_name == chunk_name;
                         });
  if (it != operation_queue_.end()) {
    (*it).callback(result);
    operation_queue_.erase(it);
  }
}

}  // namespace lifestuff

}  // namespace maidsafe
