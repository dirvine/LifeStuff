/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Handler for self-encryption/decryption operations - an
*               interface between the clientcontroller and selfencryption
* Version:      1.0
* Created:      09/09/2008 12:14:35 PM
* Revision:     none
* Compiler:     gcc 4.3
* Author:       David Irvine (di), david.irvine@maidsafe.net
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

#ifndef MAIDSAFE_CLIENT_FILESYSTEM_SEHANDLER_H_
#define MAIDSAFE_CLIENT_FILESYSTEM_SEHANDLER_H_

#include <map>
#include <string>
#include <vector>

#include "boost/filesystem.hpp"
#include "boost/multi_index_container.hpp"
#include "boost/multi_index/composite_key.hpp"
#include "boost/multi_index/member.hpp"
#include "boost/multi_index/ordered_index.hpp"
#include "boost/signals2.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/lifestuff/shared/maidsafe.h"
#include "maidsafe/lifestuff/shared/returncodes.h"
#include "maidsafe/lifestuff/client/filesystem/distributed_filesystem.pb.h"

namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;
namespace mi = boost::multi_index;

/********************************** Signals **********************************/
typedef bs2::signal<void(const std::string&, int)> OnFileNetworkStatus;
typedef bs2::signal<void(const std::string&)> OnFileAdded;
/*****************************************************************************/

namespace maidsafe {
namespace lifestuff {
class SEHandler;
}  // namespace lifestuff
}  // namespace maidsafe

namespace test_seh {
enum ModificationType { kAdd, kGet, kRemove };
void ModifyUpToDateDms(ModificationType modification_type,
                       const boost::uint16_t &test_size,
                       const std::vector<std::string> &keys,
                       const std::vector<std::string> &encrypted_data_maps,
                       std::shared_ptr<maidsafe::lifestuff::SEHandler> seh);
}  // namespace test_seh

namespace maidsafe {

namespace encrypt { 
  class DataMap;
}  // namespace encrypt

class ChunkStore;

namespace lifestuff {

namespace test {
class SEHandlerTest_BEH_MAID_Check_Entry_Test;
class SEHandlerTest_BEH_MAID_EncryptAndDecryptPrivateDb_Test;
class SEHandlerTest_BEH_MAID_UpToDateDatamapsSingleThread_Test;
class SEHandlerTest_BEH_MAID_UpToDateDatamapsMultiThread_Test;
class SEHandlerTest_BEH_MAID_EncryptAndDecryptPrivateDb_Test;
class SEHandlerTest_BEH_MAID_FailureOfChunkEncryptingFile_Test;
class SEHandlerTest_BEH_MAID_FailureSteppedMultipleEqualFiles_Test;
}  // namespace test

class SessionSingleton;
class PacketManager;

const int kMaxStoreRetries = 2;
const int kMaxLoadRetries = 2;
const int kParallelStores = 1;
const int kParallelLoads = 3;

struct PendingChunks {
  PendingChunks()
      : chunkname(), file_path(), msid(), done(kPendingResult), tries(1),
        count(1), dirtype(PRIVATE) {}
  PendingChunks(const std::string &chunk_name, const fs::path &path,
                const std::string &id, int the_count)
      : chunkname(chunk_name), file_path(path), msid(id), done(kPendingResult),
        tries(1), count(the_count), dirtype(PRIVATE) {}
  std::string chunkname;
  fs::path file_path;
  std::string msid;
  ReturnCode done;
  boost::uint8_t tries;
  int count;
  DirType dirtype;
};

// tags
struct by_chunkname {};
struct by_chunkname_count {};
struct by_path_count {};
struct by_path {};

typedef mi::multi_index_container<
  PendingChunks,
  mi::indexed_by<
    mi::ordered_unique<
      mi::tag<by_chunkname_count>,
      mi::composite_key<
        PendingChunks,
        BOOST_MULTI_INDEX_MEMBER(PendingChunks, std::string, chunkname),
        BOOST_MULTI_INDEX_MEMBER(PendingChunks, int, count)
      >
    >,
    mi::ordered_non_unique<
      mi::tag<by_path_count>,
      mi::composite_key<
        PendingChunks,
        BOOST_MULTI_INDEX_MEMBER(PendingChunks, fs::path, file_path),
        BOOST_MULTI_INDEX_MEMBER(PendingChunks, int, count)
      >
    >,
    mi::ordered_non_unique<
      mi::tag<by_chunkname>,
      BOOST_MULTI_INDEX_MEMBER(PendingChunks, std::string, chunkname)
    >,
    mi::ordered_non_unique<
      mi::tag<by_path>,
      BOOST_MULTI_INDEX_MEMBER(PendingChunks, fs::path, file_path)
    >
  >
> PendingChunksSet;

typedef PendingChunksSet::index<by_chunkname>::type PCSbyName;
typedef PendingChunksSet::index<by_path>::type PCSbyPath;
typedef PendingChunksSet::index<by_path_count>::type PCSbyPathCount;

class SEHandler {
 public:
  typedef std::map<std::string, std::string> UpToDateDatamaps;
  SEHandler();
  ~SEHandler();
  void Init(std::shared_ptr<PacketManager> packet_manager,
            std::shared_ptr<ChunkStore> client_chunkstore);
  int EncryptAFile(const fs::path &relative_entry,
                  const DirType &dir_type,
                  const std::string &msid);
  int EncryptString(const std::string &data, std::string *serialised_data_map);
  bool ProcessMetaData(const fs::path &relative_entry,
                       const ItemType &type,
                       const std::string &hash,
                       const boost::uint64_t &file_size,
                       std::string *serialised_meta_data_map);
  int DecryptAFile(const fs::path &relative_entry);
  int DecryptString(const std::string &serialised_data_map,
                    std::string *decrypted_string);
  bool MakeElement(const fs::path &relative_entry,
                   const ItemType &type,
                   const std::string &directory_key);
  //  Gets a unique DHT key for dir's db identifier
  int GenerateUniqueKey(std::string *key);
  //  Retrieves DHT keys for dir and its parent dir if msid == "" or sets
  //  parent_key to MSID public key if msid != ""
  int GetDirKeys(const fs::path &dir_path,
                 const std::string &msid,
                 std::string *key,
                 std::string *parent_key);
  //  Encrypts dir's db and sets serialised_data_map_ to encrypted datamap of db
  int EncryptDb(const fs::path &dir_path,
                const DirType &dir_type,
                const std::string &dir_key,
                const std::string &msid,
                bool encrypt_data_map,
                encrypt::DataMap *data_map);
  //  Decrypts dir's db by extracting datamap from serialised_data_map_
  int DecryptDb(const fs::path &dir_path,
                const DirType &dir_type,
                const std::string &encrypted_data_map,
                const std::string &dir_key,
                const std::string &msid,
                bool data_map_encrypted,
                bool overwrite);
  bs2::connection ConnectToOnFileNetworkStatus(
      const OnFileNetworkStatus::slot_type &slot);
  bs2::connection ConnectToOnFileAdded(const OnFileAdded::slot_type &slot);
  void ClearPendingChunks() {
    boost::mutex::scoped_lock loch_lll(chunkmap_mutex_);
    pending_chunks_.clear();
    path_count_ = 0;
  }
int EncryptDataMap(maidsafe::encrypt::DataMap *data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   std::string *encrypted_data_map);
int DecryptDataMap(const std::string &encrypted_data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   maidsafe::encrypt::DataMap *data_map);

 private:
  SEHandler &operator=(const SEHandler &);
  SEHandler(const SEHandler &);
  friend class test::SEHandlerTest_BEH_MAID_Check_Entry_Test;
  friend class test::SEHandlerTest_BEH_MAID_EncryptAndDecryptPrivateDb_Test;
  friend class test::SEHandlerTest_BEH_MAID_UpToDateDatamapsSingleThread_Test;
  friend class test::SEHandlerTest_BEH_MAID_UpToDateDatamapsMultiThread_Test;
  friend class test::SEHandlerTest_BEH_MAID_FailureOfChunkEncryptingFile_Test;
  friend class
      test::SEHandlerTest_BEH_MAID_FailureSteppedMultipleEqualFiles_Test;
  friend void test_seh::ModifyUpToDateDms(
      test_seh::ModificationType modification_type,
      const boost::uint16_t &test_size,
      const std::vector<std::string> &keys,
      const std::vector<std::string> &encrypted_data_maps,
      std::shared_ptr<SEHandler> seh);
  ItemType CheckEntry(const fs::path &absolute_path,
                      boost::uint64_t *file_size,
                      std::string *file_hash);
  int AddChunksToChunkstore(const encrypt::DataMap &data_map);
  void StoreChunks(const encrypt::DataMap &data_map,
                   const DirType &dir_type,
                   const std::string &msid,
                   const fs::path &path);
  int LoadChunks(const encrypt::DataMap &data_map,
                 std::vector<fs::path> *chunk_paths);
  // Returns previous value of encrypted_data_map if dir_key exists in map, else
  // returns ""
  std::string AddToUpToDateDms(const std::string &dir_key,
                               const std::string &encrypted_data_map);
  std::string GetFromUpToDateDms(const std::string &dir_key);
  int RemoveFromUpToDateDms(const std::string &dir_key);
  void PacketOpCallback(const int &store_manager_result,
                        boost::mutex *mutex,
                        boost::condition_variable *cond_var,
                        int *op_result);
  void ChunkDone(const std::string &chunkname, ReturnCode rc);
  void ChunksToMultiIndex(const encrypt::DataMap &data_map,
                          const std::string &msid,
                          const fs::path &path);
  void StoreChunksToNetwork(const encrypt::DataMap &data_map,
                            const DirType &dir_type,
                            const std::string &msid);
  bool SerializeToString(maidsafe::encrypt::DataMap *data_map,
                         std::string& serialized);
  bool ParseFromString(maidsafe::encrypt::DataMap *data_map,
                       const std::string& serialized);
  bool ResizeObfuscationHash(const std::string &input,
                             const size_t &required_size,
                             std::string *resized_data);

  std::shared_ptr<PacketManager> packet_manager_;
  std::shared_ptr<ChunkStore> client_chunkstore_;
  SessionSingleton *session_singleton_;
  std::map<std::string, std::string> up_to_date_datamaps_;
  PendingChunksSet pending_chunks_;
  boost::mutex up_to_date_datamaps_mutex_, chunkmap_mutex_;
  boost::signals2::connection connection_to_chunk_uploads_;
  OnFileNetworkStatus file_status_;
  int path_count_;
  OnFileAdded file_added_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_FILESYSTEM_SEHANDLER_H_
