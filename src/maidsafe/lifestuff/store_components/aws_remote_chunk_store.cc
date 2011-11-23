/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
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


#include "maidsafe/lifestuff/store_components/aws_remote_chunk_store.h"

#include <algorithm>

#include "boost/tuple/tuple.hpp"

#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/maidsafe.h"

namespace arg = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace lifestuff {

// Default maximum number of operations to be processed in parallel.
const int kMaxActiveOps(4);
// Time to wait in WaitForCompletion before failing.
const bptime::time_duration KCompletionWaitTimeout(bptime::minutes(3));

const std::string AWSRemoteChunkStore::kOpName[] = { "get", "store", "delete" };

AWSRemoteChunkStore::AWSRemoteChunkStore(
    std::shared_ptr<BufferedChunkStore> chunk_store,
    std::shared_ptr<pd::ChunkManager> chunk_manager)
        : ChunkStore(),
          sig_chunk_got_(new pd::ChunkManager::ChunkGot::element_type),
          sig_chunk_stored_(new pd::ChunkManager::ChunkStored::element_type),
          sig_chunk_deleted_(new pd::ChunkManager::ChunkDeleted::element_type),
          chunk_store_(chunk_store),
          chunk_manager_(chunk_manager),
          cm_get_conn_(),
          cm_store_conn_(),
          cm_delete_conn_(),
          mutex_(),
          cond_var_(),
          max_active_ops_(kMaxActiveOps),
          active_ops_count_(0),
          active_get_ops_(),
          active_mod_ops_(),
          pending_mod_ops_(),
          failed_ops_(),
          get_op_count_(0),
          store_op_count_(0),
          delete_op_count_(0),
          modify_op_count_(0),
          get_success_count_(0),
          store_success_count_(0),
          delete_success_count_(0),
          modify_success_count_(0),
          get_total_size_(0),
          store_total_size_(0) {
  boost::mutex::scoped_lock lock(mutex_);

//   chunk_manager_->sig_chunk_got()->connect(
//       ChunkManager::ChunkGot::element_type::slot_type(std::bind(
//           &AWSRemoteChunkStore::OnOpResult, this, kOpGet, arg::_1,
//           arg::_2)).track_foreign(shared_from_this()));
//
//   chunk_manager_->sig_chunk_stored()->connect(
//       ChunkManager::ChunkStored::element_type::slot_type(std::bind(
//           &AWSRemoteChunkStore::OnOpResult, this, kOpStore, arg::_1,
//           arg::_2)).track_foreign(shared_from_this()));
//
//   chunk_manager_->sig_chunk_deleted()->connect(
//       ChunkManager::ChunkDeleted::element_type::slot_type(std::bind(
//           &AWSRemoteChunkStore::OnOpResult, this, kOpDelete, arg::_1,
//           arg::_2)).track_foreign(shared_from_this()));

  cm_get_conn_ = chunk_manager_->sig_chunk_got()->connect(std::bind(
      &AWSRemoteChunkStore::OnOpResult, this, kOpGet, arg::_1, arg::_2));

  cm_store_conn_ = chunk_manager_->sig_chunk_stored()->connect(std::bind(
      &AWSRemoteChunkStore::OnOpResult, this, kOpStore, arg::_1, arg::_2));

  cm_delete_conn_ = chunk_manager_->sig_chunk_deleted()->connect(std::bind(
      &AWSRemoteChunkStore::OnOpResult, this, kOpDelete, arg::_1, arg::_2));
}

AWSRemoteChunkStore::~AWSRemoteChunkStore() {
  cm_get_conn_.disconnect();
  cm_store_conn_.disconnect();
  cm_delete_conn_.disconnect();

  boost::mutex::scoped_lock lock(mutex_);

  DLOG(INFO) << "~AWSRemoteChunkStore() - Retrieved " << get_success_count_
             << " of " << get_op_count_ << " chunks ("
             << BytesToBinarySiUnits(get_total_size_) << ").";
  DLOG(INFO) << "~AWSRemoteChunkStore() - Stored " << store_success_count_
             << " of " << store_op_count_ << " chunks ("
             << BytesToBinarySiUnits(store_total_size_) << ").";
  DLOG(INFO) << "~AWSRemoteChunkStore() - Deleted " << delete_success_count_
             << " of " << delete_op_count_ << " chunks.";
  DLOG(INFO) << "~AWSRemoteChunkStore() - Modified " << modify_success_count_
             << " of " << modify_op_count_ << " chunks.";

  std::string output;
  for (auto it = failed_ops_.begin(); it != failed_ops_.end(); ++it)
    output += "\n\t" + Base32Substr(it->first) + " (" + kOpName[it->second]+")";
  if (!output.empty())
    DLOG(WARNING) << "~AWSRemoteChunkStore() - " << failed_ops_.size()
                  << " failed operations:" << output;

  output.clear();
  for (auto it = pending_mod_ops_.begin(); it != pending_mod_ops_.end(); ++it)
    output += "\n\t" + Base32Substr(it->first) + " (" + kOpName[it->second]+")";
  if (!output.empty())
    DLOG(WARNING) << "~AWSRemoteChunkStore() - " << pending_mod_ops_.size()
                  << " pending operations:" << output;

  output.clear();
  for (auto it = active_mod_ops_.begin(); it != active_mod_ops_.end(); ++it)
    output += "\n\t" + Base32Substr(*it) + " (store, delete or modify)";
  for (auto it = active_get_ops_.begin(); it != active_get_ops_.end(); ++it)
    output += "\n\t" + Base32Substr(*it) + " (get)";
  if (!output.empty())
    DLOG(WARNING) << "~AWSRemoteChunkStore() - " << active_ops_count_
                  << " active operations:" << output;

  active_ops_count_ = 0;
  active_get_ops_.clear();
  active_mod_ops_.clear();
  pending_mod_ops_.clear();
}


std::string AWSRemoteChunkStore::Get(const std::string &name) const {
  DLOG(INFO) << "Get - " << Base32Substr(name);
  DoGet(name);
  std::string result(chunk_store_->Get(name));
  if (result.empty())
    DLOG(ERROR) << "Get - Could not retrieve " << Base32Substr(name);
  return result;
}

bool AWSRemoteChunkStore::Get(const std::string &name,
                              const fs::path &sink_file_name) const {
  DLOG(INFO) << "Get - " << Base32Substr(name);
  DoGet(name);
  bool result(chunk_store_->Get(name, sink_file_name));
  if (!result)
    DLOG(ERROR) << "Get - Could not retrieve " << Base32Substr(name);
  return result;
}

bool AWSRemoteChunkStore::Store(const std::string &name,
                                const std::string &content) {
  DLOG(INFO) << "Store - " << Base32Substr(name);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (active_get_ops_.count(name) > 0)
      cond_var_.wait(lock);
  }
  if (!chunk_store_->Store(name, content)) {
    DLOG(ERROR) << "Store - Could not store " << Base32Substr(name)
                << " locally.";
    return false;
  }
  EnqueueModOp(kOpStore, name);
  return true;
}

bool AWSRemoteChunkStore::Store(const std::string &name,
                                const fs::path &source_file_name,
                                bool delete_source_file) {
  DLOG(INFO) << "Store - " << Base32Substr(name);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (active_get_ops_.count(name) > 0)
      cond_var_.wait(lock);
  }
  if (!chunk_store_->Store(name, source_file_name, delete_source_file)) {
    DLOG(ERROR) << "Store - Could not store " << Base32Substr(name)
                << " locally.";
    return false;
  }
  EnqueueModOp(kOpStore, name);
  return true;
}

bool AWSRemoteChunkStore::Delete(const std::string &name) {
  DLOG(INFO) << "Delete - " << Base32Substr(name);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (active_get_ops_.count(name) > 0)
      cond_var_.wait(lock);
  }
  bool result(chunk_store_->Delete(name));
  if (!result)
    DLOG(WARNING) << "Delete - Could not delete " << Base32Substr(name)
                  << " locally.";
  EnqueueModOp(kOpDelete, name);
  return result;
}

bool AWSRemoteChunkStore::Modify(const std::string &name,
                                 const std::string &content) {
  DLOG(INFO) << "Modify - " << Base32Substr(name);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (active_get_ops_.count(name) > 0)
      cond_var_.wait(lock);
  }
  bool result(chunk_store_->Modify(name, content));
  if (!result)
    DLOG(WARNING) << "Modify - Could not modify " << Base32Substr(name)
                  << " locally.";
  EnqueueModOp(kOpModify, name);
  return result;
}

bool AWSRemoteChunkStore::Modify(const std::string &name,
                                 const fs::path &source_file_name,
                                 bool delete_source_file) {
  DLOG(INFO) << "Modify - " << Base32Substr(name);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (active_get_ops_.count(name) > 0)
      cond_var_.wait(lock);
  }
  bool result(chunk_store_->Modify(name, source_file_name, delete_source_file));
  if (!result)
    DLOG(WARNING) << "Modify - Could not modify " << Base32Substr(name)
                  << " locally.";
  EnqueueModOp(kOpModify, name);
  return result;
}

bool AWSRemoteChunkStore::WaitForCompletion() {
  boost::mutex::scoped_lock lock(mutex_);
  while (!pending_mod_ops_.empty() || active_ops_count_ > 0) {
    DLOG(INFO) << "WaitForCompletion - " << pending_mod_ops_.size()
               << " pending and " << active_ops_count_
               << " active operations...";
    if (!cond_var_.timed_wait(lock, KCompletionWaitTimeout)) {
      DLOG(ERROR) << "WaitForCompletion - Timed out with "
                  << pending_mod_ops_.size() << " pending and "
                  << active_ops_count_ << " active operations.";
      return false;
    }
  }
  DLOG(INFO) << "WaitForCompletion - Done.";
  return true;
}

void AWSRemoteChunkStore::OnOpResult(OperationType op_type,
                                     const std::string &name,
                                     const pd::ReturnCode &result) {
  {
    boost::mutex::scoped_lock lock(mutex_);
    --active_ops_count_;

    if (result == kSuccess) {
      chunk_store_->MarkForDeletion(name);
    } else {
      failed_ops_.push_back(std::make_pair(name, op_type));
      DLOG(ERROR) << "OnOpResult - Op '" << kOpName[op_type] << "' for "
                  << Base32Substr(name) << " failed. (" << result << ")";
      // TODO(Steve) re-enqueue op for retry, but needs counter
    }

    switch (op_type) {
      case kOpGet:
        active_get_ops_.erase(name);
        if (result == kSuccess) {
          ++get_success_count_;
          get_total_size_ += chunk_store_->Size(name);
        }
        break;
      case kOpStore:
        active_mod_ops_.erase(name);
        if (result == kSuccess) {
          ++store_success_count_;
          store_total_size_ += chunk_store_->Size(name);
        }
        break;
      case kOpDelete:
        active_mod_ops_.erase(name);
        if (result == kSuccess)
          ++delete_success_count_;
        break;
      case kOpModify:
        active_mod_ops_.erase(name);
        if (result == kSuccess)
          ++modify_success_count_;
        break;
    }

    cond_var_.notify_all();
  }

  ProcessPendingOps();

  // pass signal on
  switch (op_type) {
    case kOpGet:
      (*sig_chunk_got_)(name, result);
      break;
    case kOpStore:
      (*sig_chunk_stored_)(name, result);
      break;
    case kOpDelete:
      (*sig_chunk_deleted_)(name, result);
      break;
    case kOpModify:
      (*sig_chunk_deleted_)(name, result);
      break;
  }
}

void AWSRemoteChunkStore::DoGet(const std::string &name) const {
  if (chunk_store_->Has(name))
    return;

  boost::mutex::scoped_lock lock(mutex_);
  while (active_mod_ops_.count(name) > 0)
    cond_var_.wait(lock);

  if (active_get_ops_.count(name) == 0) {
    // new Get op required
    active_get_ops_.insert(name);
    ++get_op_count_;

    while (active_ops_count_ >= max_active_ops_)
      cond_var_.wait(lock);

    ++active_ops_count_;
    lock.unlock();
    chunk_manager_->GetChunk(name);
    lock.lock();
  }

  // wait for retrieval
  while (active_get_ops_.count(name) > 0)
    cond_var_.wait(lock);
}

void AWSRemoteChunkStore::EnqueueModOp(OperationType op_type,
                                       const std::string &name) {
  if (op_type != kOpStore && op_type != kOpDelete && op_type != kOpModify) {
    DLOG(ERROR) << "EnqueueModOp - Invalid operation type passed: " << op_type;
    return;
  }

  {
    boost::mutex::scoped_lock lock(mutex_);
    switch (op_type) {
      case kOpStore:
        ++store_op_count_;
        break;
      case kOpDelete:
        // delete cancels out previous store for this chunk
        for (auto rit = pending_mod_ops_.rbegin();
             rit != pending_mod_ops_.rend(); ++rit) {
          if (rit->first == name && rit->second == kOpStore) {
            pending_mod_ops_.erase(--rit.base());
            --store_op_count_;
            DLOG(INFO) << "EnqueueModOp - Ignored delete and removed pending "
                       << "store for " << Base32Substr(name);
            return;
          }
        }
        ++delete_op_count_;
        break;
      case kOpModify:
        ++modify_op_count_;
        break;
      default:
        break;
    }

    pending_mod_ops_.push_back(std::make_pair(name, op_type));
  }

  ProcessPendingOps();
}

void AWSRemoteChunkStore::ProcessPendingOps() {
  boost::mutex::scoped_lock lock(mutex_);
  // TODO(Steve) pass in shared ptr to lock

  while (active_ops_count_ < max_active_ops_) {
    auto it = pending_mod_ops_.begin();  // always (re-)start from beginning!
    while (it != pending_mod_ops_.end() &&
           active_mod_ops_.count(it->first) > 0)
      ++it;
    if (it == pending_mod_ops_.end())
      return;  // no op found that can currently be processed

    std::string name(it->first);
    OperationType op(it->second);
    it = pending_mod_ops_.erase(it);
    ++active_ops_count_;
    active_mod_ops_.insert(name);

    lock.unlock();
    switch (op) {
      case kOpStore:
        chunk_manager_->StoreChunk(name);
        break;
      case kOpDelete:
        chunk_manager_->DeleteChunk(name);
        break;
      case kOpModify:
        std::static_pointer_cast<AWSChunkManager>(chunk_manager_)->
            ModifyChunk(name);
        break;
      default:
        // Get is handled separately
        break;
    }
    lock.lock();
  }
}

}  // namespace lifestuff

}  // namespace maidsafe
