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

#include "maidsafe/lifestuff/detail/routings_handler.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/user_credentials.h"
#include "maidsafe/lifestuff/detail/user_storage.h"

namespace bptime = boost::posix_time;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

namespace test {

class UserStorageTest : public testing::Test {
 public:
  UserStorageTest()
    : test_dir_(maidsafe::test::CreateTestPath()),
      mount_dir_(*test_dir_ / RandomAlphaNumericString(8)),
      interval_(2),
      asio_service1_(5),
      asio_service2_(5),
      remote_chunk_store1_(),
      remote_chunk_store2_(),
      session1_(),
      session2_(),
      routings_handler1_(),
      routings_handler2_(),
      user_credentials1_(),
      user_credentials2_(),
      user_storage1_(),
      user_storage2_() {}

 protected:
  void CreateChunkStores() {
    std::string dir1(RandomAlphaNumericString(8));
    remote_chunk_store1_ = priv::chunk_store::CreateLocalChunkStore(*test_dir_ / dir1 / "buffer",
                                                                    *test_dir_ / "simulation",
                                                                    *test_dir_ / dir1 / "lock",
                                                                    asio_service1_.service());

    std::string dir2(RandomAlphaNumericString(8));
    remote_chunk_store2_ = priv::chunk_store::CreateLocalChunkStore(*test_dir_ / dir2 / "buffer",
                                                                    *test_dir_ / "simulation",
                                                                    *test_dir_ / dir2 / "lock",
                                                                    asio_service2_.service());
  }

  void SetUp() {
    asio_service1_.Start();
    asio_service2_.Start();
    CreateChunkStores();

    NonEmptyString keyword1(RandomAlphaNumericString(6)), password1(RandomAlphaNumericString(6));
    NonEmptyString keyword2(RandomAlphaNumericString(6)), password2(RandomAlphaNumericString(6));
    user_credentials1_ = std::make_shared<UserCredentials>(*remote_chunk_store1_,
                                                           session1_,
                                                           asio_service1_.service(),
                                                           *routings_handler1_,
                                                           true);
    EXPECT_EQ(kSuccess, user_credentials1_->CreateUser(keyword1, CreatePin(), password1));
    user_credentials2_ = std::make_shared<UserCredentials>(*remote_chunk_store2_,
                                                           session2_,
                                                           asio_service2_.service(),
                                                           *routings_handler2_,
                                                           true);
    EXPECT_EQ(kSuccess, user_credentials2_->CreateUser(keyword2, CreatePin(), password2));
    user_storage1_ = std::make_shared<UserStorage>(*remote_chunk_store1_);
    user_storage2_ = std::make_shared<UserStorage>(*remote_chunk_store2_);
  }

  void TearDown() {
    user_credentials1_->Logout();
    user_credentials2_->Logout();
    asio_service1_.Stop();
    asio_service2_.Stop();
    remote_chunk_store1_->WaitForCompletion();
    remote_chunk_store2_->WaitForCompletion();
  }

  void MountDrive(std::shared_ptr<UserStorage>& user_storage, Session* session) {
    user_storage->MountDrive(mount_dir_ / "file_chunk_store",
                             mount_dir_ / "mount_point",
                             session,
                             NonEmptyString("Lifestuff Drive"));
    Sleep(interval_);
    ASSERT_TRUE(user_storage->mount_status());
  }

  void UnMountDrive(std::shared_ptr<UserStorage> user_storage) {
    user_storage->UnMountDrive();
    Sleep(interval_);
  }

  maidsafe::test::TestPath test_dir_;
  fs::path mount_dir_;
  bptime::seconds interval_;
  AsioService asio_service1_, asio_service2_;
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store1_, remote_chunk_store2_;
  Session session1_, session2_;
  std::shared_ptr<RoutingsHandler> routings_handler1_, routings_handler2_;
  std::shared_ptr<UserCredentials> user_credentials1_, user_credentials2_;
  std::shared_ptr<UserStorage> user_storage1_, user_storage2_;
};

TEST_F(UserStorageTest, FUNC_GetAndInsertDataMap) {
  MountDrive(user_storage1_, &session1_);
  fs::path mount_dir(user_storage1_->mount_dir());

  std::string file_name, file_name_copy;
  EXPECT_EQ(kSuccess, CreateSmallTestFile(mount_dir, 722, &file_name));
  file_name_copy = file_name + "_copy";

  std::string file_content, copy_file_content;
  EXPECT_TRUE(ReadFile(mount_dir / file_name, &file_content));
  std::string serialised_data_map, serialised_data_map_copy;
  EXPECT_EQ(kSuccess, user_storage1_->GetDataMap(mount_dir / file_name, &serialised_data_map));
  EXPECT_FALSE(serialised_data_map.empty());
  EXPECT_EQ(kSuccess, user_storage1_->InsertDataMap(mount_dir / file_name_copy,
                                                    NonEmptyString(serialised_data_map)));
  EXPECT_TRUE(ReadFile(mount_dir / file_name_copy, &copy_file_content));
  EXPECT_EQ(file_content, copy_file_content);
  EXPECT_EQ(kSuccess,
            user_storage1_->GetDataMap(mount_dir / file_name_copy, &serialised_data_map_copy));
  EXPECT_EQ(serialised_data_map, serialised_data_map_copy);

  UnMountDrive(user_storage1_);

  // Try the data map in the other user
  MountDrive(user_storage2_, &session2_);
  mount_dir = user_storage2_->mount_dir();

  EXPECT_EQ(kSuccess, user_storage2_->InsertDataMap(mount_dir / file_name,
                                                    NonEmptyString(serialised_data_map)));
  EXPECT_TRUE(ReadFile(mount_dir / file_name, &copy_file_content));
  EXPECT_EQ(file_content, copy_file_content);

  UnMountDrive(user_storage2_);
}

TEST_F(UserStorageTest, FUNC_SaveDataMapAndConstructFile) {
  MountDrive(user_storage1_, &session1_);
  fs::path mount_dir(user_storage1_->mount_dir());

  std::string file_name, file_name_copy, retrived_file_name_copy;
  EXPECT_EQ(kSuccess, CreateSmallTestFile(mount_dir, 722, &file_name));
  file_name_copy = file_name + "_copy";

  std::string file_content, copy_file_content;
  EXPECT_TRUE(ReadFile(mount_dir / file_name, &file_content));
  std::string serialised_data_map, serialised_data_map_copy;
  EXPECT_EQ(kSuccess, user_storage1_->GetDataMap(mount_dir / file_name, &serialised_data_map));
  std::string data_map_hash;
  EXPECT_TRUE(user_storage1_->ParseAndSaveDataMap(NonEmptyString(file_name_copy),
                                                  NonEmptyString(serialised_data_map),
                                                  data_map_hash));
  EXPECT_TRUE(user_storage1_->GetSavedDataMap(NonEmptyString(data_map_hash),
                                              serialised_data_map_copy,
                                              retrived_file_name_copy));
  EXPECT_EQ(serialised_data_map, serialised_data_map_copy);
  EXPECT_EQ(file_name_copy, retrived_file_name_copy);
  EXPECT_EQ(kSuccess, user_storage1_->InsertDataMap(mount_dir / file_name_copy,
                                                    NonEmptyString(serialised_data_map_copy)));
  EXPECT_TRUE(ReadFile(mount_dir / retrived_file_name_copy, &copy_file_content));
  EXPECT_EQ(file_content, copy_file_content);
  UnMountDrive(user_storage1_);
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
