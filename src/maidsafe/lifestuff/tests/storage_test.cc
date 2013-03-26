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

#include "maidsafe/nfs/nfs.h"

#include "maidsafe/lifestuff/detail/routing_handler.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/user_storage.h"
#include "maidsafe/lifestuff/tests/test_utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {
namespace lifestuff {
namespace test {

class UserStorageTest : public testing::Test {
 public:
  typedef std::shared_ptr<RoutingHandler> RoutingHandlerPtr;
  typedef std::shared_ptr<nfs::ClientMaidNfs> ClientNfsPtr;
  typedef std::shared_ptr<UserStorage> UserStoragePtr;

  UserStorageTest()
    : test_dir_(maidsafe::test::CreateTestPath()),
      mount_dir_(*test_dir_ / RandomAlphaNumericString(8)),
      session_(),
      routing_handler_(),
      client_nfs_(),
      user_storage_() {}

 protected:
  void SetUp() {
    session_.passport().CreateFobs();
    session_.passport().ConfirmFobs();
    session_.set_unique_user_id(Identity(RandomAlphaNumericString(64)));
    PublicKeyRequestFunction public_key_request(
      [this](const NodeId& /*node_id*/, const GivePublicKeyFunctor& /*give_key*/) {
        LOG(kInfo) << "Public key requested.";
      });
    passport::Maid maid(session_.passport().Get<passport::Maid>(true));
    routing_handler_.reset(new RoutingHandler(maid, public_key_request));
    client_nfs_.reset(new nfs::ClientMaidNfs(routing_handler_->routing(), maid));
    user_storage_.reset(new UserStorage());
  }

  void TearDown() {}

  void MountDrive() {
    user_storage_->MountDrive(*client_nfs_, session_);
    ASSERT_TRUE(user_storage_->mount_status());
  }

  void UnMountDrive() {
    user_storage_->UnMountDrive(session_);
  }

  fs::path owner_path() {
    return user_storage_->owner_path();
  }

  maidsafe::test::TestPath test_dir_;
  fs::path mount_dir_;
  Session session_;
  RoutingHandlerPtr routing_handler_;
  ClientNfsPtr client_nfs_;
  UserStoragePtr user_storage_;
};


TEST_F(UserStorageTest, BEH_CopyEmptyDirectoryToDrive) {
  EXPECT_NO_THROW(MountDrive());
  fs::path directory(CreateTestDirectory(*test_dir_));
  ASSERT_TRUE(fs::exists(directory));
  EXPECT_NO_THROW(fs::copy_directory(directory, owner_path() / directory.filename()));
  ASSERT_TRUE(fs::exists(owner_path() / directory.filename()));
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, BEH_CopyNonemptyDirectoryToDriveThenDelete) {
  EXPECT_NO_THROW(MountDrive());
  boost::system::error_code error_code;
  int64_t file_size(0);
  fs::path directory(CreateTestDirectory(*test_dir_));
  ASSERT_TRUE(fs::exists(directory, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::path file(CreateTestFile(directory, file_size));
  ASSERT_TRUE(CopyDirectories(directory, owner_path()));
  ASSERT_TRUE(fs::exists(owner_path() / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / directory.filename() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_EQ(2U, fs::remove_all(owner_path() / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(owner_path() / directory.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(owner_path() / directory.filename() / file.filename()));
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, BEH_CopyNonemptyDirectoryToDriveDeleteThenRecopy) {
  EXPECT_NO_THROW(MountDrive());
  int64_t file_size(0);
  fs::path directory(CreateTestDirectory(*test_dir_));
  ASSERT_TRUE(fs::exists(directory));
  fs::path file(CreateTestFile(directory, file_size));
  ASSERT_TRUE(CopyDirectories(directory, owner_path()));
  ASSERT_TRUE(fs::exists(owner_path() / directory.filename()));
  ASSERT_TRUE(fs::exists(owner_path() / directory.filename() / file.filename()));
  boost::system::error_code error_code;
  ASSERT_EQ(2U, fs::remove_all(owner_path() / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(owner_path() / directory.filename()));
  ASSERT_FALSE(fs::exists(owner_path() / directory.filename() / file.filename()));
  ASSERT_TRUE(CopyDirectories(directory, owner_path()));
  ASSERT_TRUE(fs::exists(owner_path() / directory.filename()));
  ASSERT_TRUE(fs::exists(owner_path() / directory.filename() / file.filename()));
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, BEH_CopyNonemptyDirectoryThenRename) {
  EXPECT_NO_THROW(MountDrive());
  boost::system::error_code error_code;
  int64_t file_size(0);
  fs::path directory(CreateTestDirectory(*test_dir_));
  ASSERT_TRUE(fs::exists(directory, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::path file(CreateTestFile(directory, file_size));
  ASSERT_TRUE(CopyDirectories(directory, owner_path()));
  ASSERT_TRUE(fs::exists(owner_path() / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / directory.filename() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::path new_directory_name(owner_path() / maidsafe::RandomAlphaNumericString(5));
  fs::rename(owner_path() / directory.filename(), new_directory_name, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(owner_path() / directory.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(new_directory_name, error_code));
  ASSERT_EQ(error_code.value(), 0);
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, BEH_CopyNonemptyDirectoryRenameThenRecopy) {
  EXPECT_NO_THROW(MountDrive());
  boost::system::error_code error_code;
  int64_t file_size(0);
  fs::path directory(CreateTestDirectory(*test_dir_));
  ASSERT_TRUE(fs::exists(directory, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::path file(CreateTestFile(directory, file_size));
  ASSERT_TRUE(CopyDirectories(directory, owner_path()));
  ASSERT_TRUE(fs::exists(owner_path() / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / directory.filename() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::path new_directory_name(owner_path() / maidsafe::RandomAlphaNumericString(5));
  fs::rename(owner_path() / directory.filename(), new_directory_name, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(owner_path() / directory.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(new_directory_name));
  ASSERT_TRUE(CopyDirectories(directory, owner_path()));
  ASSERT_TRUE(fs::exists(owner_path() / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / directory.filename() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, FUNC_CopyDirectoryContainingFiles) {
  EXPECT_NO_THROW(MountDrive());
  boost::system::error_code error_code;
  fs::path directory(CreateDirectoryContainingFiles(*test_dir_));
  ASSERT_FALSE(directory.empty());
  ASSERT_TRUE(CopyDirectories(directory, owner_path()));
  ASSERT_TRUE(fs::exists(owner_path() / directory.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, FUNC_CopyDirectoryContainingFilesAndDirectories) {
  EXPECT_NO_THROW(MountDrive());
  boost::system::error_code error_code;
  fs::path directories(CreateTestDirectoriesAndFiles(*test_dir_));
  ASSERT_TRUE(fs::exists(directories));
  ASSERT_TRUE(CopyDirectories(directories, owner_path()));
  ASSERT_TRUE(fs::exists(owner_path() / directories.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, FUNC_CopyFileThenCopyCopiedFile) {
  EXPECT_NO_THROW(MountDrive());
  boost::system::error_code error_code;
  int64_t file_size(0);
  fs::path file(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::copy_file(file, owner_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::copy_file(file, owner_path() / file.filename(), fs::copy_option::overwrite_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0) << error_code.message();
  ASSERT_TRUE(fs::exists(owner_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, FUNC_CopyFileDeleteThenRecopy) {
  EXPECT_NO_THROW(MountDrive());
  boost::system::error_code error_code;
  int64_t file_size(0);
  // Create file on disk...
  fs::path file(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  // Copy file to virtual drive...
  fs::copy_file(file, owner_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::remove(owner_path() / file.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(owner_path() / file.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  fs::copy_file(file, owner_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, FUNC_CopyFileRenameThenRecopy) {
  EXPECT_NO_THROW(MountDrive());
  boost::system::error_code error_code;
  int64_t file_size(0);
  fs::path file(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::copy_file(file, owner_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::path new_file_name(owner_path() / (RandomAlphaNumericString(5) + ".txt"));
  fs::rename(owner_path() / file.filename(), new_file_name, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(owner_path() / file.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(new_file_name, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::copy_file(file, owner_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(*test_dir_ / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, BEH_CopyFileThenRead) {
  EXPECT_NO_THROW(MountDrive());
  boost::system::error_code error_code;
  int64_t file_size(0);
  fs::path file(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::copy_file(file, owner_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::path test_file(*test_dir_ / (RandomAlphaNumericString(5) + ".txt"));
  fs::copy_file(owner_path() / file.filename(), test_file, fs::copy_option::overwrite_if_exists);
  ASSERT_TRUE(fs::exists(test_file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_EQ(fs::file_size(test_file), fs::file_size(file));
  ASSERT_TRUE(CompareFileContents(test_file, file));
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, FUNC_CopyFileRenameThenRead) {
  EXPECT_NO_THROW(MountDrive());
  boost::system::error_code error_code;
  int64_t file_size(0);
  fs::path file(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::copy_file(file, owner_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::path new_file_name(owner_path() / (RandomAlphaNumericString(5) + ".txt"));
  fs::rename(owner_path() / file.filename(), new_file_name, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(owner_path() / file.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(new_file_name, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::path test_file(*test_dir_ / new_file_name.filename());
  fs::copy_file(new_file_name, test_file, fs::copy_option::overwrite_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(test_file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(CompareFileContents(test_file, file));
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, FUNC_CopyFileDeleteThenTryToRead) {
  EXPECT_NO_THROW(MountDrive());
  boost::system::error_code error_code;
  int64_t file_size(0);
  fs::path file(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::copy_file(file, owner_path() / file.filename(), fs::copy_option::fail_if_exists);
  ASSERT_TRUE(fs::exists(owner_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::remove(owner_path() / file.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(owner_path() / file.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  fs::path test_file(*test_dir_ / (RandomAlphaNumericString(5) + ".txt"));
  fs::copy_file(owner_path() / file.filename(), test_file, fs::copy_option::overwrite_if_exists,
                error_code);
  ASSERT_NE(error_code.value(), 0);
  ASSERT_FALSE(CompareFileContents(test_file, file));
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, BEH_CreateFileOnDriveThenRead) {
  EXPECT_NO_THROW(MountDrive());
  boost::system::error_code error_code;
  int64_t file_size(0);
  fs::path file(CreateTestFile(owner_path(), file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::path test_file(*test_dir_ / file.filename());
  fs::copy_file(file, test_file, fs::copy_option::overwrite_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, BEH_CopyFileModifyThenRead) {
  EXPECT_NO_THROW(MountDrive());
  boost::system::error_code error_code;
  int64_t file_size(0);
  fs::path file(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::copy_file(file, owner_path() / file.filename(), fs::copy_option::fail_if_exists, error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(ModifyFile(owner_path() / file.filename(), file_size));
  ASSERT_TRUE(fs::exists(owner_path() / file.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::path test_file(*test_dir_ / (RandomAlphaNumericString(5) + ".txt"));
  fs::copy_file(owner_path() / file.filename(), test_file, fs::copy_option::overwrite_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(CompareFileContents(test_file, file));
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, FUNC_CheckFailures) {
  EXPECT_NO_THROW(MountDrive());
  boost::system::error_code error_code;
  int64_t file_size(0);
  fs::path file0(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file0, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::copy_file(file0, owner_path() / file0.filename(), fs::copy_option::fail_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / file0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::copy_file(file0, owner_path() / file0.filename(), fs::copy_option::fail_if_exists,
                error_code);
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / file0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(CreateFileAt(owner_path() / file0.filename()));
  ASSERT_TRUE(fs::exists(file0, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::path file1(CreateTestFile(*test_dir_, file_size));
  ASSERT_TRUE(fs::exists(file1, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::copy_file(file1, owner_path() / file1.filename(), fs::copy_option::fail_if_exists,
                error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / file1.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);

  fs::rename(owner_path() / file1.filename(), owner_path() / file0.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / file0.filename(), error_code));
  ASSERT_FALSE(fs::exists(owner_path() / file1.filename(), error_code));
  ASSERT_EQ(crypto::HashFile<crypto::Tiger>(file1),
            crypto::HashFile<crypto::Tiger>(owner_path() / file0.filename()));
  fs::rename(*test_dir_ / file1.filename(), *test_dir_ / file0.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(*test_dir_ / file0.filename(), error_code));
  ASSERT_FALSE(fs::exists(*test_dir_ / file1.filename(), error_code));
  ASSERT_TRUE(fs::remove(owner_path() / file0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(owner_path() / file0.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_FALSE(fs::remove(owner_path() / file0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(owner_path() / file0.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);

  fs::path directory0(CreateTestDirectory(*test_dir_));
  ASSERT_TRUE(fs::exists(directory0, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::copy_directory(directory0, owner_path() / directory0.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / directory0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::copy_directory(directory0, owner_path() / directory0.filename(), error_code);
  ASSERT_NE(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / directory0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::create_directory(owner_path() / directory0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(directory0, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::path directory1(CreateTestDirectory(*test_dir_));
  ASSERT_TRUE(fs::exists(directory1, error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::copy_directory(directory1, owner_path() / directory1.filename(), error_code);
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_TRUE(fs::exists(owner_path() / directory1.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  fs::rename(owner_path() / directory1.filename(), owner_path() / directory0.filename(),
             error_code);
#ifdef WIN32
  ASSERT_NE(error_code.value(), 0);
#else
  ASSERT_EQ(error_code.value(), 0);
#endif
  ASSERT_TRUE(fs::exists(owner_path() / directory0.filename(), error_code));
  ASSERT_TRUE(fs::remove(owner_path() / directory0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(owner_path() / directory0.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  ASSERT_FALSE(fs::remove(owner_path() / directory0.filename(), error_code));
  ASSERT_EQ(error_code.value(), 0);
  ASSERT_FALSE(fs::exists(owner_path() / directory0.filename(), error_code));
  ASSERT_NE(error_code.value(), 0);
  EXPECT_NO_THROW(UnMountDrive());
}

TEST_F(UserStorageTest, FUNC_FunctionalTest) {
  EXPECT_NO_THROW(MountDrive());
  EXPECT_TRUE(DoRandomEvents(owner_path(), *test_dir_));
  EXPECT_NO_THROW(UnMountDrive());
}




//TEST_F(UserStorageTest, FUNC_GetAndInsertDataMap) {
//  MountDrive(user_storage1_, &session1_);
//  fs::path mount_dir(user_storage1_->mount_dir());
//
//  std::string file_name, file_name_copy;
//  EXPECT_EQ(kSuccess, CreateSmallTestFile(mount_dir, 722, &file_name));
//  file_name_copy = file_name + "_copy";
//
//  std::string file_content, copy_file_content;
//  EXPECT_TRUE(ReadFile(mount_dir / file_name, &file_content));
//  std::string serialised_data_map, serialised_data_map_copy;
//  EXPECT_EQ(kSuccess, user_storage1_->GetDataMap(mount_dir / file_name, &serialised_data_map));
//  EXPECT_FALSE(serialised_data_map.empty());
//  EXPECT_EQ(kSuccess, user_storage1_->InsertDataMap(mount_dir / file_name_copy,
//                                                    NonEmptyString(serialised_data_map)));
//  EXPECT_TRUE(ReadFile(mount_dir / file_name_copy, &copy_file_content));
//  EXPECT_EQ(file_content, copy_file_content);
//  EXPECT_EQ(kSuccess,
//            user_storage1_->GetDataMap(mount_dir / file_name_copy, &serialised_data_map_copy));
//  EXPECT_EQ(serialised_data_map, serialised_data_map_copy);
//
//  UnMountDrive(user_storage1_);
//
//  // Try the data map in the other user
//  MountDrive(user_storage2_, &session2_);
//  mount_dir = user_storage2_->mount_dir();
//
//  EXPECT_EQ(kSuccess, user_storage2_->InsertDataMap(mount_dir / file_name,
//                                                    NonEmptyString(serialised_data_map)));
//  EXPECT_TRUE(ReadFile(mount_dir / file_name, &copy_file_content));
//  EXPECT_EQ(file_content, copy_file_content);
//
//  UnMountDrive(user_storage2_);
//}
//
//TEST_F(UserStorageTest, FUNC_SaveDataMapAndConstructFile) {
//  MountDrive(user_storage1_, &session1_);
//  fs::path mount_dir(user_storage1_->mount_dir());
//
//  std::string file_name, file_name_copy, retrived_file_name_copy;
//  EXPECT_EQ(kSuccess, CreateSmallTestFile(mount_dir, 722, &file_name));
//  file_name_copy = file_name + "_copy";
//
//  std::string file_content, copy_file_content;
//  EXPECT_TRUE(ReadFile(mount_dir / file_name, &file_content));
//  std::string serialised_data_map, serialised_data_map_copy;
//  EXPECT_EQ(kSuccess, user_storage1_->GetDataMap(mount_dir / file_name, &serialised_data_map));
//  std::string data_map_hash;
//  EXPECT_TRUE(user_storage1_->ParseAndSaveDataMap(NonEmptyString(file_name_copy),
//                                                  NonEmptyString(serialised_data_map),
//                                                  data_map_hash));
//  EXPECT_TRUE(user_storage1_->GetSavedDataMap(NonEmptyString(data_map_hash),
//                                              serialised_data_map_copy,
//                                              retrived_file_name_copy));
//  EXPECT_EQ(serialised_data_map, serialised_data_map_copy);
//  EXPECT_EQ(file_name_copy, retrived_file_name_copy);
//  EXPECT_EQ(kSuccess, user_storage1_->InsertDataMap(mount_dir / file_name_copy,
//                                                    NonEmptyString(serialised_data_map_copy)));
//  EXPECT_TRUE(ReadFile(mount_dir / retrived_file_name_copy, &copy_file_content));
//  EXPECT_EQ(file_content, copy_file_content);
//  UnMountDrive(user_storage1_);
//}

}  // namespace test
}  // namespace lifestuff
}  // namespace maidsafe
