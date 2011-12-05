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


#ifndef MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_AWS_REMOTE_CHUNK_STORE_H_
#define MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_AWS_REMOTE_CHUNK_STORE_H_

#include <functional>
#include <list>
#include <memory>
#include <set>
#include <string>
#include <utility>

#include "boost/asio/io_service.hpp"
#include "boost/multi_index_container.hpp"
#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index/composite_key.hpp"
#include "boost/multi_index/member.hpp"
#include "boost/multi_index/identity.hpp"
#include "boost/multi_index/mem_fun.hpp"
#include "boost/thread.hpp"

#include "maidsafe/common/buffered_chunk_store.h"
#include "maidsafe/lifestuff/store_components/aws_chunk_manager.h"

namespace maidsafe {

namespace lifestuff {

class AWSRemoteChunkStore : public ChunkStore {
                   // public std::enable_shared_from_this<AWSRemoteChunkStore> {
 public:
  enum OperationType {
    kOpGet = 0,
    kOpStore = 1,
    kOpDelete = 2,
    kOpModify = 3
  };
  static const std::string kOpName[];  // see implementation

  typedef std::pair<std::string, OperationType> Operation;

  AWSRemoteChunkStore(std::shared_ptr<BufferedChunkStore> chunk_store,
                      std::shared_ptr<pd::ChunkManager> chunk_manager);

  ~AWSRemoteChunkStore();

  std::string Get(const std::string &name) const;

  bool Get(const std::string &name, const fs::path &sink_file_name) const;

  bool Store(const std::string &name, const std::string &content);

  bool Store(const std::string &name,
             const fs::path &source_file_name,
             bool delete_source_file);

  bool Delete(const std::string &name);

  bool Modify(const std::string &name, const std::string &content);

  bool Modify(const std::string &name,
              const fs::path &source_file_name,
              bool delete_source_file);

  bool MoveTo(const std::string&, ChunkStore*) {
    return false;
  }

  bool Has(const std::string &name) const {
    return chunk_store_->Has(name);
  }

  bool Validate(const std::string &name) const {
    return chunk_store_->Validate(name);
  }

  std::string Version(const std::string &name) const {
    return chunk_store_->Version(name);
  }

  std::uintmax_t Size(const std::string &name) const {
    return chunk_store_->Size(name);
  }

  std::uintmax_t Size() const {
    // TODO(Steve) get from account
    return 0;  // chunk_store_->Size();
  }

  std::uintmax_t Capacity() const {
    // TODO(Steve) get from account
    return 0;  // chunk_store_->Capacity();
  }

  bool Vacant(const std::uintmax_t&) const {
    return true;  // return chunk_store_->Vacant(size);
  }

  std::uintmax_t Count(const std::string &name) const {
    return chunk_store_->Count(name);
  }

  std::uintmax_t Count() const {
    return 0;  // return chunk_store_->Count();
  }

  bool Empty() const {
    return chunk_store_->Empty();
  }

  void Clear() {
    chunk_store_->Clear();
  }

  /// Waits for pending operations, returns false if it times out.
  bool WaitForCompletion();

  /// Sets the maximum number of operations to be processed in parallel.
  void SetMaxActiveOps(int max_active_ops) {
    max_active_ops_ = max_active_ops;
    if (max_active_ops_ < 1)
      max_active_ops_ = 1;
  }

  pd::ChunkManager::ChunkGot sig_chunk_got() const { return sig_chunk_got_; }
  pd::ChunkManager::ChunkStored sig_chunk_stored() const {
    return sig_chunk_stored_;
  }
  pd::ChunkManager::ChunkDeleted sig_chunk_deleted() const {
    return sig_chunk_deleted_;
  }

 private:
  AWSRemoteChunkStore(const AWSRemoteChunkStore&);
  AWSRemoteChunkStore& operator=(const AWSRemoteChunkStore&);

  void OnOpResult(OperationType op_type,
                  const std::string &name,
                  const pd::ReturnCode &result);
  void DoGet(const std::string &name) const;
  void EnqueueModOp(OperationType op_type, const std::string &name);
  void ProcessPendingOps();

  pd::ChunkManager::ChunkGot sig_chunk_got_;
  pd::ChunkManager::ChunkStored sig_chunk_stored_;
  pd::ChunkManager::ChunkDeleted sig_chunk_deleted_;
  std::shared_ptr<BufferedChunkStore> chunk_store_;
  std::shared_ptr<pd::ChunkManager> chunk_manager_;
  bs2::connection cm_get_conn_, cm_store_conn_, cm_delete_conn_;
  mutable boost::mutex mutex_;
  mutable boost::condition_variable cond_var_;
  mutable int max_active_ops_, active_ops_count_;
  mutable std::set<std::string> active_get_ops_, active_mod_ops_;
  mutable std::list<Operation> pending_mod_ops_, failed_ops_;
  mutable std::uintmax_t get_op_count_, store_op_count_, delete_op_count_,
                         modify_op_count_;
  std::uintmax_t get_success_count_, store_success_count_,
                 delete_success_count_, modify_success_count_;
  std::uintmax_t get_total_size_, store_total_size_;
  boost::asio::io_service asio_service_;
  std::shared_ptr<boost::asio::io_service::work> work_;
  boost::thread_group thread_group_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_STORE_COMPONENTS_AWS_REMOTE_CHUNK_STORE_H_
