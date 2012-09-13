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

#include <sstream>
#include <thread>

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#ifndef LOCAL_TARGETS_ONLY
#  include "maidsafe/pd/client/node.h"
#endif

#include "maidsafe/lifestuff/rcs_helper.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/user_credentials.h"
#include "maidsafe/lifestuff/detail/user_storage.h"

namespace args = std::placeholders;
namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

namespace test {

class UserStorageTest : public testing::Test {
 public:
  UserStorageTest()
    : test_dir_(maidsafe::test::CreateTestPath()),
      mount_dir_(*test_dir_ / RandomAlphaNumericString(8)),
      interval_(1),
      asio_service1_(5),
      asio_service2_(5),
#ifndef LOCAL_TARGETS_ONLY
      node1_(),
      node2_(),
#endif
      remote_chunk_store1_(),
      remote_chunk_store2_(),
      session1_(),
      session2_(),
      user_credentials1_(),
      user_credentials2_(),
      user_storage1_(),
      user_storage2_() {}

 protected:
  void CreateChunkStores() {
#ifdef LOCAL_TARGETS_ONLY
    remote_chunk_store1_ = BuildChunkStore(*test_dir_ / RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service1_.service());
    remote_chunk_store2_ = BuildChunkStore(*test_dir_ / RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service2_.service());
#else
    std::vector<std::pair<std::string, uint16_t>> bootstrap_endpoints;
    remote_chunk_store1_ = BuildChunkStore(*test_dir_,
                                           bootstrap_endpoints,
                                           node1_,
                                           NetworkHealthFunction());
    remote_chunk_store2_ = BuildChunkStore(*test_dir_,
                                           bootstrap_endpoints,
                                           node2_,
                                           NetworkHealthFunction());
#endif
  }

  void SetUp() {
    asio_service1_.Start();
    asio_service2_.Start();
    CreateChunkStores();

    user_credentials1_.reset(new UserCredentials(*remote_chunk_store1_,
                                                 session1_,
                                                 asio_service1_.service()));
    EXPECT_EQ(kSuccess, user_credentials1_->CreateUser(RandomAlphaNumericString(6),
                                                       CreatePin(),
                                                       RandomAlphaNumericString(6)));
    user_credentials2_.reset(new UserCredentials(*remote_chunk_store2_,
                                                 session2_,
                                                 asio_service2_.service()));
    EXPECT_EQ(kSuccess, user_credentials2_->CreateUser(RandomAlphaNumericString(6),
                                                       CreatePin(),
                                                       RandomAlphaNumericString(6)));
    user_storage1_.reset(new UserStorage(remote_chunk_store1_));
    user_storage2_.reset(new UserStorage(remote_chunk_store2_));
  }

  void TearDown() {
    user_credentials1_->Logout();
    user_credentials2_->Logout();
    asio_service1_.Stop();
    asio_service2_.Stop();
    remote_chunk_store1_->WaitForCompletion();
    remote_chunk_store2_->WaitForCompletion();
  }

  void MountDrive(std::shared_ptr<UserStorage> user_storage,
                  Session* session,
                  bool creation) {
    user_storage->MountDrive(mount_dir_, session, creation, false);
//    std::this_thread::sleep_for(std::chrono::seconds(2));
    Sleep(interval_);
  }

  void UnMountDrive(std::shared_ptr<UserStorage> user_storage) {
    user_storage->UnMountDrive();
//    std::this_thread::sleep_for(std::chrono::seconds(2));
    Sleep(interval_);
  }

  maidsafe::test::TestPath test_dir_;
  fs::path mount_dir_;
  bptime::seconds interval_;
  AsioService asio_service1_, asio_service2_;
#ifndef LOCAL_TARGETS_ONLY
  std::shared_ptr<pd::Node> node1_, node2_;
#endif
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store1_, remote_chunk_store2_;
  Session session1_, session2_;
  std::shared_ptr<UserCredentials> user_credentials1_, user_credentials2_;
  std::shared_ptr<UserStorage> user_storage1_, user_storage2_;
};

TEST_F(UserStorageTest, FUNC_GetAndInsertDataMap) {
  MountDrive(user_storage1_, &session1_, true);
  fs::path mount_dir(user_storage1_->mount_dir());

  std::string file_name, file_name_copy;
  EXPECT_EQ(kSuccess, CreateSmallTestFile(mount_dir, 722, &file_name));
  file_name_copy = file_name + "_copy";

  std::string file_content, copy_file_content;
  EXPECT_TRUE(ReadFile(mount_dir / file_name, &file_content));
  std::string serialised_data_map, serialised_data_map_copy;
  EXPECT_EQ(kSuccess, user_storage1_->GetDataMap(mount_dir / file_name, &serialised_data_map));
  EXPECT_EQ(kSuccess,
            user_storage1_->InsertDataMap(mount_dir / file_name_copy, serialised_data_map));
  EXPECT_TRUE(ReadFile(mount_dir / file_name_copy, &copy_file_content));
  EXPECT_EQ(file_content, copy_file_content);
  EXPECT_EQ(kSuccess,
            user_storage1_->GetDataMap(mount_dir / file_name_copy, &serialised_data_map_copy));
  EXPECT_EQ(serialised_data_map, serialised_data_map_copy);

  UnMountDrive(user_storage1_);

  // Try the data map in the other user
  MountDrive(user_storage2_, &session2_, true);
  mount_dir = user_storage2_->mount_dir();

  EXPECT_EQ(kSuccess, user_storage2_->InsertDataMap(mount_dir / file_name, serialised_data_map));
  EXPECT_TRUE(ReadFile(mount_dir / file_name, &copy_file_content));
  EXPECT_EQ(file_content, copy_file_content);

  UnMountDrive(user_storage2_);
}

TEST_F(UserStorageTest, FUNC_SaveDataMapAndConstructFile) {
  MountDrive(user_storage1_, &session1_, true);
  fs::path mount_dir(user_storage1_->mount_dir());

  std::string file_name, file_name_copy, retrived_file_name_copy;
  EXPECT_EQ(kSuccess, CreateSmallTestFile(mount_dir, 722, &file_name));
  file_name_copy = file_name + "_copy";

  std::string file_content, copy_file_content;
  EXPECT_TRUE(ReadFile(mount_dir / file_name, &file_content));
  std::string serialised_data_map, serialised_data_map_copy;
  EXPECT_EQ(kSuccess, user_storage1_->GetDataMap(mount_dir / file_name, &serialised_data_map));
  std::string data_map_hash;
  EXPECT_TRUE(user_storage1_->ParseAndSaveDataMap(file_name_copy,
                                                  serialised_data_map,
                                                  &data_map_hash));
  EXPECT_TRUE(user_storage1_->GetSavedDataMap(data_map_hash,
                                              &serialised_data_map_copy,
                                              &retrived_file_name_copy));
  EXPECT_EQ(serialised_data_map, serialised_data_map_copy);
  EXPECT_EQ(file_name_copy, retrived_file_name_copy);
  EXPECT_EQ(kSuccess,
            user_storage1_->InsertDataMap(mount_dir / file_name_copy, serialised_data_map_copy));
  EXPECT_TRUE(ReadFile(mount_dir / retrived_file_name_copy, &copy_file_content));
  EXPECT_EQ(file_content, copy_file_content) << file_content.size() << " - " << copy_file_content.size();
  UnMountDrive(user_storage1_);
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
