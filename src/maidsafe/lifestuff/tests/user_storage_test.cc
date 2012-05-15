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

#include "maidsafe/lifestuff/detail/message_handler.h"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/pd/client/client_container.h"
#endif

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/rcs_helper.h"
#include "maidsafe/lifestuff/detail/authentication.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/public_id.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/user_credentials.h"
#include "maidsafe/lifestuff/detail/user_storage.h"

namespace args = std::placeholders;
namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace test {

class UserStorageTest : public testing::TestWithParam<bool> {
 public:
  UserStorageTest()
    : test_dir_(maidsafe::test::CreateTestPath()),
      mount_dir_(*test_dir_ / RandomAlphaNumericString(8)),
      private_share_(GetParam()),
      interval_(1),
      asio_service1_(),
      asio_service2_(),
#ifndef LOCAL_TARGETS_ONLY
      client_container1_(),
      client_container2_(),
#endif
      remote_chunk_store1_(),
      remote_chunk_store2_(),
      session1_(new Session),
      session2_(new Session),
      user_credentials1_(),
      user_credentials2_(),
      user_storage1_(),
      user_storage2_(),
      public_id1_(),
      public_id2_(),
      message_handler1_(),
      message_handler2_(),
      pub_name1_("User 1"),
      pub_name2_("User 2") {}

  void DoAcceptShareInvitationTest(
      const std::shared_ptr<UserStorage> &user_storage,
      const std::string &/*receiver*/,
      const std::string &sender,
      const std::string &/*share_tag*/,
      const std::string &share_id) {
    std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)));
    fs::path hidden_file(user_storage->mount_dir() /
                         drive::kMsShareRoot /
                         std::string(temp_name + drive::kMsHidden.string()));
    std::string serialised_share_data;
    EXPECT_EQ(kSuccess, user_storage->ReadHiddenFile(hidden_file,
                                                     &serialised_share_data));
    Message message;
    message.ParseFromString(serialised_share_data);

    fs::path relative_path(message.content(1));
    std::string directory_id(message.content(2));
    asymm::Keys share_keyring;
    if (message.content_size() > 4) {
        share_keyring.identity = message.content(3);
        share_keyring.validation_token = message.content(4);
        asymm::DecodePrivateKey(message.content(5),
                                &(share_keyring.private_key));
        asymm::DecodePublicKey(message.content(6),
                               &(share_keyring.public_key));
    }

    EXPECT_EQ(kSuccess, user_storage->DeleteHiddenFile(hidden_file));

    std::string share_name(relative_path.filename().string());
    fs::path share_dir(user_storage->mount_dir() /
                       drive::kMsShareRoot /
                       share_name);
    EXPECT_EQ(kSuccess, user_storage->InsertShare(share_dir,
                                                  share_id,
                                                  sender,
                                                  &share_name,
                                                  directory_id,
                                                  share_keyring));
  }

  void DoUpgradeTest(const std::shared_ptr<UserStorage> &/*user_storage*/,
                     const std::string &receiver,
                     const std::string &sender,
                     const std::string &share_name,
                     int access_level) {
    DLOG(ERROR) << "From: " << sender << ", to: " << receiver << ", name: "
                << share_name << ", access_level: " << access_level;
  }

  void DoLeaveTest(const std::shared_ptr<UserStorage> &user_storage,
                   const std::string &/*receiver*/,
                   const std::string &share_id) {
    fs::path relative_path;
    user_storage->GetShareDetails(share_id, &relative_path,
                                  nullptr, nullptr, nullptr);
    fs::path share_dir(user_storage->mount_dir() /
                       drive::kMsShareRoot /
                       relative_path.filename());
    EXPECT_EQ(kSuccess, user_storage->RemoveShare(share_dir));
  }

 protected:
  void CreateUserCredentials() {
#ifdef LOCAL_TARGETS_ONLY
    remote_chunk_store1_ = BuildChunkStore(*test_dir_ /
                                               RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service1_.service());
    remote_chunk_store2_ = BuildChunkStore(*test_dir_ /
                                               RandomAlphaNumericString(8),
                                           *test_dir_ / "simulation",
                                           asio_service2_.service());
#else
    remote_chunk_store1_ = BuildChunkStore(*test_dir_, &client_container1_);
    remote_chunk_store2_ = BuildChunkStore(*test_dir_, &client_container2_);
#endif
    user_credentials1_.reset(new UserCredentials(remote_chunk_store1_,
                                                 session1_));
    EXPECT_TRUE(user_credentials1_->CreateUser(RandomAlphaNumericString(6),
                                               CreatePin(),
                                               RandomAlphaNumericString(6)));
    user_credentials2_.reset(new UserCredentials(remote_chunk_store2_,
                                                 session2_));
    EXPECT_TRUE(user_credentials2_->CreateUser(RandomAlphaNumericString(6),
                                               CreatePin(),
                                               RandomAlphaNumericString(6)));
  }

  void SetUp() {
    asio_service1_.Start(5);
    asio_service2_.Start(5);
    CreateUserCredentials();

    public_id1_.reset(new PublicId(remote_chunk_store1_,
                                   session1_,
                                   asio_service1_.service()));
    public_id2_.reset(new PublicId(remote_chunk_store2_,
                                   session2_,
                                   asio_service2_.service()));

    message_handler1_.reset(new MessageHandler(remote_chunk_store1_,
                                               session1_,
                                               asio_service1_.service()));
    message_handler2_.reset(new MessageHandler(remote_chunk_store2_,
                                               session2_,
                                               asio_service2_.service()));

    user_storage1_.reset(new UserStorage(remote_chunk_store1_,
                                         message_handler1_));
    user_storage2_.reset(new UserStorage(remote_chunk_store2_,
                                         message_handler2_));

    public_id1_->CreatePublicId(pub_name1_, true);
    public_id2_->CreatePublicId(pub_name2_, true);
    public_id1_->StartCheckingForNewContacts(interval_);
    public_id2_->StartCheckingForNewContacts(interval_);

    public_id1_->SendContactInfo(pub_name1_, pub_name2_);
    Sleep(interval_ * 2);
    public_id2_->ConfirmContact(pub_name2_, pub_name1_);
    Sleep(interval_ * 2);

    public_id1_->StopCheckingForNewContacts();
    public_id2_->StopCheckingForNewContacts();
    message_handler1_->ConnectToPrivateShareDetailsSignal(
        std::bind(&UserStorage::GetShareDetails, user_storage1_.get(),
                  args::_1, args::_2, nullptr, nullptr, nullptr));
    message_handler2_->ConnectToPrivateShareDetailsSignal(
        std::bind(&UserStorage::GetShareDetails, user_storage2_.get(),
                  args::_1, args::_2, nullptr, nullptr, nullptr));
    message_handler1_->ConnectToPrivateShareUpdateSignal(
        std::bind(&UserStorage::UpdateShare, user_storage1_.get(),
                  args::_1, args::_2, args::_3, args::_4));
    message_handler2_->ConnectToPrivateShareUpdateSignal(
        std::bind(&UserStorage::UpdateShare, user_storage2_.get(),
                  args::_1, args::_2, args::_3, args::_4));
  }

  void TearDown() {
    public_id1_->StopCheckingForNewContacts();
    public_id2_->StopCheckingForNewContacts();
    message_handler1_->StopCheckingForNewMessages();
    message_handler2_->StopCheckingForNewMessages();

    session1_->Reset();
    session2_->Reset();
    asio_service1_.Stop();
    asio_service2_.Stop();
    remote_chunk_store1_->WaitForCompletion();
    remote_chunk_store2_->WaitForCompletion();
  }

  maidsafe::test::TestPath test_dir_;
  fs::path mount_dir_;
  bool private_share_;
  bptime::seconds interval_;
  AsioService asio_service1_, asio_service2_;
#ifndef LOCAL_TARGETS_ONLY
  ClientContainerPtr client_container1_, client_container2_;
#endif
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store1_,
                                         remote_chunk_store2_;
  std::shared_ptr<Session> session1_, session2_;
  std::shared_ptr<UserCredentials> user_credentials1_, user_credentials2_;
  std::shared_ptr<UserStorage> user_storage1_, user_storage2_;
  std::shared_ptr<PublicId> public_id1_, public_id2_;
  std::shared_ptr<MessageHandler> message_handler1_, message_handler2_;
  std::string pub_name1_, pub_name2_;
};

INSTANTIATE_TEST_CASE_P(PivateAndOpenShareTests, UserStorageTest,
                        testing::Values(drive::kMsOpenShare,
                                        drive::kMsPrivateShare));

TEST_P(UserStorageTest, FUNC_CreateShare) {
  user_storage1_->MountDrive(mount_dir_, session1_, true);
  Sleep(interval_ * 2);
  boost::system::error_code error_code;
  fs::path share_root_directory_1(user_storage1_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_1, error_code))
              << share_root_directory_1 << ": " << error_code.message();

  StringIntMap users;
  if (private_share_)
    users.insert(std::make_pair(pub_name2_, kShareReadOnly));
  else
    users.insert(std::make_pair(pub_name2_, kShareReadWrite));
  std::string tail;
  fs::path directory0(CreateTestDirectory(user_storage1_->mount_dir(), &tail));
  EXPECT_EQ(kSuccess, user_storage1_->CreateShare(pub_name1_,
                                                  directory0,
                                                  users,
                                                  private_share_));

  user_storage1_->UnMountDrive();

  bs2::connection accept_share_invitation_connection(
    message_handler2_->ConnectToPrivateShareInvitationSignal(
        std::bind(&UserStorageTest::DoAcceptShareInvitationTest,
                  this, user_storage2_,
                  args::_1, args::_2, args::_3, args::_4)));
  bs2::connection save_share_data_connection(
    message_handler2_->ConnectToSavePrivateShareDataSignal(
        std::bind(&UserStorage::SavePrivateShareData,
                  user_storage2_.get(), args::_1, args::_2)));
  user_storage2_->MountDrive(mount_dir_, session2_, true);
  Sleep(interval_ * 2);
  fs::path share_root_directory_2(user_storage2_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_2, error_code))
              << share_root_directory_2 << ": " << error_code.message();

  fs::path directory1(user_storage2_->mount_dir() / drive::kMsShareRoot / tail);
  EXPECT_FALSE(fs::exists(directory1, error_code))
               << directory1 << " : " << error_code.message();

  EXPECT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory1, error_code))
              << directory1 << " : " << error_code.message();

  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
}

TEST_P(UserStorageTest, FUNC_LeaveShare) {
  user_storage1_->MountDrive(mount_dir_, session1_, true);
  Sleep(interval_ * 2);
  boost::system::error_code error_code;
  fs::path share_root_directory_1(user_storage1_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_1, error_code))
              << share_root_directory_1 << ": " << error_code.message();

  StringIntMap users;
  if (private_share_)
    users.insert(std::make_pair(pub_name2_, kShareReadOnly));
  else
    users.insert(std::make_pair(pub_name2_, kShareReadWrite));
  std::string tail;
  fs::path directory0(CreateTestDirectory(user_storage1_->mount_dir(), &tail));
  EXPECT_EQ(kSuccess, user_storage1_->CreateShare(pub_name1_,
                                                  directory0,
                                                  users,
                                                  private_share_));
  user_storage1_->UnMountDrive();

  bs2::connection accept_share_invitation_connection(
    message_handler2_->ConnectToPrivateShareInvitationSignal(
        std::bind(&UserStorageTest::DoAcceptShareInvitationTest,
                  this, user_storage2_,
                  args::_1, args::_2, args::_3, args::_4)));
  bs2::connection save_share_data_connection(
    message_handler2_->ConnectToSavePrivateShareDataSignal(
        std::bind(&UserStorage::SavePrivateShareData,
                  user_storage2_.get(), args::_1, args::_2)));

  user_storage2_->MountDrive(mount_dir_, session2_, true);
  Sleep(interval_ * 2);
  fs::path share_root_directory_2(user_storage2_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_2, error_code))
              << share_root_directory_2 << ": " << error_code.message();

  fs::path directory1(user_storage2_->mount_dir() / drive::kMsShareRoot / tail);
  EXPECT_FALSE(fs::exists(directory1, error_code))
               << directory1 << " : " << error_code.message();
  EXPECT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory1, error_code))
              << directory1 << " : " << error_code.message();

  EXPECT_EQ(kSuccess, user_storage2_->RemoveShare(directory1, pub_name2_));

  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);

  bs2::connection share_user_leaving_connection(
    message_handler1_->ConnectToPrivateShareUserLeavingSignal(
        std::bind(&UserStorage::UserLeavingShare,
                  user_storage1_.get(), args::_2, args::_3)));

  user_storage1_->MountDrive(mount_dir_, session1_, false);
  Sleep(interval_ * 2);
  users.clear();
  EXPECT_EQ(kSuccess, user_storage1_->GetAllShareUsers(directory0, &users));
  EXPECT_EQ(2, users.size());
  EXPECT_EQ(kSuccess,
            message_handler1_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  users.clear();
  EXPECT_EQ(kSuccess, user_storage1_->GetAllShareUsers(directory0, &users));
  EXPECT_EQ(1, users.size());
  message_handler1_->StopCheckingForNewMessages();
  user_storage1_->UnMountDrive();
}

TEST_P(UserStorageTest, FUNC_AddUser) {
  user_storage1_->MountDrive(mount_dir_, session1_, true);
  Sleep(interval_ * 2);
  boost::system::error_code error_code;
  fs::path share_root_directory_1(user_storage1_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_1, error_code))
              << share_root_directory_1 << ": " << error_code.message();

  StringIntMap users;
  std::string tail;
  fs::path directory0(CreateTestDirectory(user_storage1_->mount_dir(), &tail));
  EXPECT_EQ(kSuccess, user_storage1_->CreateShare(pub_name1_,
                                                  directory0,
                                                  users,
                                                  private_share_));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  bs2::connection accept_share_invitation_connection(
    message_handler2_->ConnectToPrivateShareInvitationSignal(
        std::bind(&UserStorageTest::DoAcceptShareInvitationTest,
                  this,
                  user_storage2_,
                  args::_1,
                  args::_2,
                  args::_3,
                  args::_4)));
  bs2::connection save_share_data_connection(
    message_handler2_->ConnectToSavePrivateShareDataSignal(
        std::bind(&UserStorage::SavePrivateShareData,
                  user_storage2_.get(), args::_1, args::_2)));

  user_storage2_->MountDrive(mount_dir_, session2_, true);
  Sleep(interval_ * 2);
  fs::path share_root_directory_2(user_storage2_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_2, error_code))
              << share_root_directory_2 << ": " << error_code.message();

  fs::path directory1(user_storage2_->mount_dir() / drive::kMsShareRoot / tail);

  EXPECT_FALSE(fs::exists(directory1, error_code))
               << directory1 << error_code.message();
  EXPECT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  EXPECT_FALSE(fs::exists(directory1, error_code))
               << directory1 << error_code.message();
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage1_->MountDrive(mount_dir_, session1_, false);
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0
                                                  << error_code.message();
  users.insert(std::make_pair(pub_name2_, kShareReadOnly));
  EXPECT_EQ(kSuccess,
            user_storage1_->AddShareUsers(pub_name1_, directory0,
                                          users, private_share_));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage2_->MountDrive(mount_dir_, session2_, false);
  Sleep(interval_ * 2);
  EXPECT_FALSE(fs::exists(directory1, error_code))
               << directory1 << error_code.message();
  EXPECT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory1, error_code))
              << directory1 << error_code.message();
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
}

TEST_P(UserStorageTest, FUNC_AddReadWriteUser) {
  user_storage1_->MountDrive(mount_dir_, session1_, true);
  Sleep(interval_ * 2);
  boost::system::error_code error_code;
  fs::path share_root_directory_1(user_storage1_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_1, error_code))
              << share_root_directory_1 << ": " << error_code.message();

  StringIntMap users;
  users.insert(std::make_pair(pub_name2_, kShareReadWrite));
  std::string tail;
  fs::path directory0(CreateTestDirectory(user_storage1_->mount_dir(), &tail));
  EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0;
  EXPECT_EQ(kSuccess, user_storage1_->CreateShare(pub_name1_,
                                                  directory0,
                                                  users,
                                                  private_share_));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  bs2::connection accept_share_invitation_connection(
    message_handler2_->ConnectToPrivateShareInvitationSignal(
        std::bind(&UserStorageTest::DoAcceptShareInvitationTest,
                  this, user_storage2_,
                  args::_1, args::_2, args::_3, args::_4)));
  bs2::connection save_share_data_connection(
    message_handler2_->ConnectToSavePrivateShareDataSignal(
        std::bind(&UserStorage::SavePrivateShareData,
                  user_storage2_.get(), args::_1, args::_2)));

  user_storage2_->MountDrive(mount_dir_, session2_, true);
  fs::path directory1(user_storage2_->mount_dir() / drive::kMsShareRoot / tail);
  Sleep(interval_ * 2);
  fs::path share_root_directory_2(user_storage2_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_2, error_code))
              << share_root_directory_2 << ": " << error_code.message();

  EXPECT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
  fs::path sub_directory(CreateTestDirectory(directory1, &tail));
  EXPECT_TRUE(fs::exists(sub_directory, error_code)) << sub_directory;
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage1_->MountDrive(mount_dir_, session1_, false);
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory0 / tail, error_code));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage2_->MountDrive(mount_dir_, session2_, false);
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
  EXPECT_TRUE(fs::exists(sub_directory, error_code)) << sub_directory;
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);
}

TEST_P(UserStorageTest, FUNC_UpgradeUserToReadWrite) {
  user_storage1_->MountDrive(mount_dir_, session1_, true);
  Sleep(interval_ * 2);
  boost::system::error_code error_code;
  fs::path share_root_directory_1(user_storage1_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_1, error_code))
              << share_root_directory_1 << ": " << error_code.message();

  StringIntMap users;
  users.insert(std::make_pair(pub_name2_, kShareReadOnly));
  std::string tail;
  fs::path directory0(CreateTestDirectory(user_storage1_->mount_dir(), &tail));
  EXPECT_EQ(kSuccess, user_storage1_->CreateShare(pub_name1_,
                                                  directory0,
                                                  users,
                                                  private_share_));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  bs2::connection accept_share_invitation_connection(
    message_handler2_->ConnectToPrivateShareInvitationSignal(
        std::bind(&UserStorageTest::DoAcceptShareInvitationTest,
                  this, user_storage2_,
                  args::_1, args::_2, args::_3, args::_4)));
  bs2::connection member_access_level_connection(
    message_handler2_->ConnectToPrivateMemberAccessLevelSignal(
        std::bind(&UserStorageTest::DoUpgradeTest,
                  this, user_storage2_,
                  args::_1, args::_2, args::_4, args::_5)));
  bs2::connection save_share_data_connection(
    message_handler2_->ConnectToSavePrivateShareDataSignal(
        std::bind(&UserStorage::SavePrivateShareData,
                  user_storage2_.get(), args::_1, args::_2)));

  user_storage2_->MountDrive(mount_dir_, session2_, true);
  Sleep(interval_ * 2);
  fs::path share_root_directory_2(user_storage2_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_2, error_code))
              << share_root_directory_2 << ": " << error_code.message();

  fs::path directory1(user_storage2_->mount_dir() / drive::kMsShareRoot / tail);
  EXPECT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);

  EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
  fs::path sub_directory(CreateTestDirectory(directory1, &tail));
  EXPECT_FALSE(fs::exists(sub_directory, error_code)) << sub_directory;
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage1_->MountDrive(mount_dir_, session1_, false);
  Sleep(interval_ * 2);
  EXPECT_EQ(kSuccess,
            user_storage1_->SetShareUsersRights(pub_name1_,
                                                directory0,
                                                pub_name2_,
                                                drive::kShareReadWrite,
                                                private_share_));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage2_->MountDrive(mount_dir_, session2_, false);
  Sleep(interval_ * 2);
  sub_directory = CreateTestDirectory(directory1, &tail);
  EXPECT_FALSE(fs::exists(sub_directory, error_code)) << sub_directory;
  EXPECT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  sub_directory = CreateTestDirectory(directory1, &tail);
  EXPECT_TRUE(fs::exists(sub_directory, error_code)) << sub_directory;
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
}

TEST_P(UserStorageTest, FUNC_StopShareByOwner) {
  user_storage1_->MountDrive(mount_dir_, session1_, true);
  Sleep(interval_ * 2);
  boost::system::error_code error_code;
  fs::path share_root_directory_1(user_storage1_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_1, error_code))
              << share_root_directory_1 << ": " << error_code.message();

  StringIntMap users;
  users.insert(std::make_pair(pub_name2_, kShareReadOnly));
  std::string tail;
  fs::path directory0(CreateTestDirectory(user_storage1_->mount_dir(), &tail));
  EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0
                                                  << error_code.message();
  EXPECT_EQ(kSuccess,
            user_storage1_->CreateShare(pub_name1_,
                                        directory0,
                                        users,
                                        private_share_));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  bs2::connection accept_share_invitation_connection(
    message_handler2_->ConnectToPrivateShareInvitationSignal(
        std::bind(&UserStorageTest::DoAcceptShareInvitationTest,
                  this, user_storage2_,
                  args::_1, args::_2, args::_3, args::_4)));
  bs2::connection leave_share_connection(
    message_handler2_->ConnectToPrivateShareDeletionSignal(
        std::bind(&UserStorageTest::DoLeaveTest,
                  this, user_storage2_, args::_1, args::_2)));
  bs2::connection save_share_data_connection(
    message_handler2_->ConnectToSavePrivateShareDataSignal(
        std::bind(&UserStorage::SavePrivateShareData,
                  user_storage2_.get(), args::_1, args::_2)));

  user_storage2_->MountDrive(mount_dir_, session2_, true);
  Sleep(interval_ * 2);
  fs::path share_root_directory_2(user_storage2_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_2, error_code))
              << share_root_directory_2 << ": " << error_code.message();

  fs::path directory1(user_storage2_->mount_dir() / drive::kMsShareRoot / tail);
  EXPECT_FALSE(fs::exists(directory1, error_code)) << directory1;
  EXPECT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage1_->MountDrive(mount_dir_, session1_, false);
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0;
  EXPECT_EQ(kSuccess, user_storage1_->StopShare(pub_name1_, directory0));
  EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0;
  // EXPECT_FALSE(fs::exists(directory0, error_code)) << directory0;
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage2_->MountDrive(mount_dir_, session2_, false);
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
  EXPECT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  EXPECT_FALSE(fs::exists(directory1, error_code)) << directory1 << " : "
                                                   << error_code.message();
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();

  // Sleep(interval_ * 2);
  // user_storage1_->MountDrive(mount_dir_,
  //                            user_credentials1_->SessionName(),
  //                            session1_,
  //                            false);
  // Sleep(interval_ * 2);
  // EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0;
  // EXPECT_FALSE(fs::exists(directory0, error_code)) << directory0;
  // user_storage1_->UnMountDrive();
  // Sleep(interval_ * 2);
}

TEST_P(UserStorageTest, FUNC_RemoveUserByOwner) {
  user_storage1_->MountDrive(mount_dir_, session1_, true);
  Sleep(interval_ * 2);
  boost::system::error_code error_code;
  fs::path share_root_directory_1(user_storage1_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_1, error_code))
              << share_root_directory_1 << ": " << error_code.message();

  StringIntMap users;
  users.insert(std::make_pair(pub_name2_, kShareReadOnly));
  std::string tail("OTJUP");
  fs::path directory0(user_storage1_->mount_dir() / tail);
  fs::create_directory(directory0, error_code);
  EXPECT_EQ(0, error_code.value());

  EXPECT_EQ(kSuccess, user_storage1_->CreateShare(pub_name1_,
                                                  directory0,
                                                  users,
                                                  private_share_));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  bs2::connection accept_share_invitation_connection(
    message_handler2_->ConnectToPrivateShareInvitationSignal(
        std::bind(&UserStorageTest::DoAcceptShareInvitationTest,
                  this, user_storage2_,
                  args::_1, args::_2, args::_3, args::_4)));
  bs2::connection leave_share_connection(
    message_handler2_->ConnectToPrivateShareDeletionSignal(
        std::bind(&UserStorageTest::DoLeaveTest,
                  this, user_storage2_, args::_1, args::_2)));
  bs2::connection save_share_data_connection(
    message_handler2_->ConnectToSavePrivateShareDataSignal(
        std::bind(&UserStorage::SavePrivateShareData,
                  user_storage2_.get(), args::_1, args::_2)));

  user_storage2_->MountDrive(mount_dir_, session2_, true);
  Sleep(interval_ * 2);
  fs::path share_root_directory_2(user_storage2_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_2, error_code))
              << share_root_directory_2 << ": " << error_code.message();

  fs::path directory1(user_storage2_->mount_dir() / drive::kMsShareRoot / tail);
  EXPECT_FALSE(fs::exists(directory1, error_code)) << directory1;
  EXPECT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage1_->MountDrive(mount_dir_, session1_, false);
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0;
  std::vector<std::string> user_ids;
  user_ids.push_back(pub_name2_);
  EXPECT_EQ(kSuccess, user_storage1_->RemoveShareUsers(pub_name1_,
                                                       directory0,
                                                       user_ids,
                                                       private_share_));
  tail = "I0E1k";
  fs::path sub_directory0(directory0 / tail);
  fs::create_directory(sub_directory0, error_code);
  EXPECT_EQ(0, error_code.value());
  EXPECT_TRUE(fs::exists(sub_directory0, error_code)) << sub_directory0;
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage2_->MountDrive(mount_dir_, session2_, false);
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
  fs::path sub_directory1(directory1 / tail);
  EXPECT_FALSE(fs::exists(sub_directory1, error_code)) << sub_directory1;
  fs::create_directory(sub_directory1, error_code);
  EXPECT_FALSE(fs::exists(sub_directory1, error_code)) << sub_directory1;
  EXPECT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  EXPECT_FALSE(fs::exists(directory1, error_code)) << directory1 << " : "
                                                   << error_code.message();
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage1_->MountDrive(mount_dir_, session1_, false);
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0;
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(sub_directory0, error_code)) << sub_directory0;
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);
}

TEST_P(UserStorageTest, FUNC_MoveShareWhenRemovingUser) {
  AsioService asio_service3;
  asio_service3.Start(5);
#ifndef LOCAL_TARGETS_ONLY
  ClientContainerPtr client_container3;
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store3(
                          BuildChunkStore(*test_dir_, &client_container3));
#else
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store3(
      BuildChunkStore(*test_dir_ / RandomAlphaNumericString(8),
                      *test_dir_ / "simulation",
                      asio_service3.service()));
#endif
  std::shared_ptr<Session> session3(new Session);
  std::shared_ptr<UserCredentials> user_credentials3(
      new UserCredentials(remote_chunk_store3, session3));
  EXPECT_TRUE(user_credentials3->CreateUser(RandomAlphaNumericString(6),
                                            CreatePin(),
                                            RandomAlphaNumericString(6)));
  std::shared_ptr<PublicId> public_id3(
      new PublicId(remote_chunk_store3, session3, asio_service3.service()));
  std::shared_ptr<MessageHandler> message_handler3(
      new MessageHandler(remote_chunk_store3, session3,
                         asio_service3.service()));
  std::shared_ptr<UserStorage> user_storage3(
      new UserStorage(remote_chunk_store3, message_handler3));
  std::string pub_name3("User 3");
  message_handler3->ConnectToPrivateShareDetailsSignal(
      std::bind(&UserStorage::GetShareDetails, user_storage3.get(),
                args::_1, args::_2, nullptr, nullptr, nullptr));


  public_id3->CreatePublicId(pub_name3, true);

  public_id1_->StartCheckingForNewContacts(interval_);
  public_id3->StartCheckingForNewContacts(interval_);

  public_id1_->SendContactInfo(pub_name1_, pub_name3);
  Sleep(interval_ * 2);
  public_id3->ConfirmContact(pub_name3, pub_name1_);
  Sleep(interval_ * 2);

  public_id1_->StopCheckingForNewContacts();
  public_id3->StopCheckingForNewContacts();

  user_storage1_->MountDrive(mount_dir_, session1_, true);
  Sleep(interval_ * 2);
  boost::system::error_code error_code;
  fs::path share_root_directory_1(user_storage1_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_1, error_code))
              << share_root_directory_1 << ": " << error_code.message();

  StringIntMap users;
  users.insert(std::make_pair(pub_name2_, kShareReadOnly));
  users.insert(std::make_pair(pub_name3, kShareReadWrite));
  std::string tail("OTJUP");
  fs::path directory0(user_storage1_->mount_dir() / tail);
  fs::create_directory(directory0, error_code);
  EXPECT_EQ(0, error_code.value());

  EXPECT_EQ(kSuccess, user_storage1_->CreateShare(pub_name1_,
                                                  directory0,
                                                  users,
                                                  private_share_));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  bs2::connection accept_share_invitation_connection_1(
    message_handler2_->ConnectToPrivateShareInvitationSignal(
        std::bind(&UserStorageTest::DoAcceptShareInvitationTest,
                  this, user_storage2_,
                  args::_1, args::_2, args::_3, args::_4)));
  bs2::connection leave_share_connection_1(
    message_handler2_->ConnectToPrivateShareDeletionSignal(
        std::bind(&UserStorageTest::DoLeaveTest,
                  this, user_storage2_, args::_1, args::_2)));
  bs2::connection save_share_data_connection_1(
    message_handler2_->ConnectToSavePrivateShareDataSignal(
        std::bind(&UserStorage::SavePrivateShareData,
                  user_storage2_.get(), args::_1, args::_2)));

  user_storage2_->MountDrive(mount_dir_, session2_, true);
  Sleep(interval_ * 2);
  fs::path share_root_directory_2(user_storage2_->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_2, error_code))
              << share_root_directory_2 << ": " << error_code.message();

  fs::path directory1(user_storage2_->mount_dir() / drive::kMsShareRoot / tail);
  EXPECT_FALSE(fs::exists(directory1, error_code)) << directory1;
  EXPECT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);

  bs2::connection accept_share_invitation_connection_2(
    message_handler3->ConnectToPrivateShareInvitationSignal(
        std::bind(&UserStorageTest::DoAcceptShareInvitationTest,
                  this, user_storage3,
                  args::_1, args::_2, args::_3, args::_4)));
  bs2::connection save_share_data_connection_2(
    message_handler3->ConnectToSavePrivateShareDataSignal(
        std::bind(&UserStorage::SavePrivateShareData,
                  user_storage3.get(), args::_1, args::_2)));
  bs2::connection update_share_data_connection_2(
    message_handler3->ConnectToPrivateShareUpdateSignal(
        std::bind(&UserStorage::UpdateShare, user_storage3.get(),
                  args::_1, args::_2, args::_3, args::_4)));

  user_storage3->MountDrive(mount_dir_, session3, true);
  Sleep(interval_ * 2);
  fs::path share_root_directory_3(user_storage3->mount_dir() /
                                  maidsafe::drive::kMsShareRoot);
  EXPECT_TRUE(fs::create_directories(share_root_directory_3, error_code))
              << share_root_directory_3 << ": " << error_code.message();

  fs::path directory2(user_storage3->mount_dir() / drive::kMsShareRoot / tail);
  EXPECT_FALSE(fs::exists(directory2, error_code)) << directory2;
  EXPECT_EQ(kSuccess,
            message_handler3->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory2, error_code)) << directory2;
  message_handler3->StopCheckingForNewMessages();
  user_storage3->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage1_->MountDrive(mount_dir_, session1_, false);
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0;
  std::vector<std::string> user_ids;
  user_ids.push_back(pub_name2_);
  EXPECT_EQ(kSuccess, user_storage1_->RemoveShareUsers(pub_name1_,
                                                       directory0,
                                                       user_ids,
                                                       private_share_));
  tail = "I0E1k";
  fs::path sub_directory0(directory0 / tail);
  fs::create_directory(sub_directory0, error_code);
  EXPECT_EQ(0, error_code.value());
  EXPECT_TRUE(fs::exists(sub_directory0, error_code)) << sub_directory0;
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage2_->MountDrive(mount_dir_, session2_, false);
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
  fs::path sub_directory1(directory1 / tail);
  EXPECT_FALSE(fs::exists(sub_directory1, error_code)) << sub_directory1;
  fs::create_directory(sub_directory1, error_code);
  EXPECT_FALSE(fs::exists(sub_directory1, error_code)) << sub_directory1;
  EXPECT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  EXPECT_FALSE(fs::exists(directory1, error_code)) << directory1 << " : "
                                                   << error_code.message();
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage3->MountDrive(mount_dir_, session3, false);
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory2, error_code)) << directory2;
  fs::path sub_directory2(directory2 / tail);
  EXPECT_FALSE(fs::exists(sub_directory2, error_code)) << sub_directory2;
//   fs::create_directory(sub_directory2, error_code);
//   EXPECT_FALSE(fs::exists(sub_directory2, error_code)) << sub_directory2;
  EXPECT_EQ(kSuccess,
            message_handler3->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(sub_directory2, error_code)) << sub_directory2 << " : "
                                                      << error_code.message();
  message_handler3->StopCheckingForNewMessages();
  user_storage3->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage1_->MountDrive(mount_dir_, session1_, false);
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0;
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(sub_directory0, error_code)) << sub_directory0;
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  // tear down
  public_id3->StopCheckingForNewContacts();
  message_handler3->StopCheckingForNewMessages();
  session3->Reset();
  asio_service3.Stop();
  remote_chunk_store3->WaitForCompletion();
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
