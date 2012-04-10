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

#include "maidsafe/lifestuff/message_handler.h"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/pd/client/client_container.h"
#endif

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/data_atlas_pb.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/public_id.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/authentication.h"
#include "maidsafe/lifestuff/user_credentials.h"
#include "maidsafe/lifestuff/user_storage.h"

namespace args = std::placeholders;
namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace test {

namespace {

fs::path CreateTestDirectory(fs::path const& parent,
                             std::string *tail) {
  *tail = RandomAlphaNumericString(5);
  fs::path directory(parent / (*tail));
  boost::system::error_code error_code;
  fs::create_directories(directory, error_code);
  return directory;
}

std::shared_ptr<UserCredentials> CreateUserCredentials(
    boost::asio::io_service &service,
    const fs::path &test_dir) {
  std::shared_ptr<Session> session(new Session);
  std::shared_ptr<UserCredentials> client_controller(
      new UserCredentials(service, session));
  client_controller->Init(test_dir);

  std::stringstream pin_stream;
  uint32_t pin(0);
  while (pin == 0)
    pin = RandomUint32();
  pin_stream << pin;
  client_controller->CreateUser(RandomString(6),
                                pin_stream.str(),
                                RandomString(6));
  return client_controller;
}

}  // namespace

class UserStorageTest : public testing::Test {
 public:
  UserStorageTest()
    : test_dir_(maidsafe::test::CreateTestPath()),
      mount_dir_(new fs::path(fs::initial_path() / "LifeStuff")),
      client_controller1_(),
      client_controller2_(),
      user_storage1_(),
      user_storage2_(),
      session1_(),
      session2_(),
      asio_service1_(),
      asio_service2_(),
      interval_(1),
      public_id1_(),
      public_id2_(),
      message_handler1_(),
      message_handler2_(),
      pub_name1_("User 1"),
      pub_name2_("User 2") {}

  void DoShareTest(const std::string &sender,
                   const std::shared_ptr<UserStorage> &user_storage,
                   const InboxItem &message,
                   const fs::path &absolute_path = fs::path()) {
    if (message.content[1] == "insert_share")
      return InsertShareTest(user_storage, message, absolute_path);
    if (message.content[1] == "remove_share")
      return RemoveShareTest(user_storage, message, absolute_path);
    if (message.content[1] == "stop_share")
      return StopShareTest(sender, user_storage, message, absolute_path);
    if (message.content[1] == "update_share")
      return MoveShareTest(user_storage, message, absolute_path);
    if (message.content[1] == "upgrade_share")
      return UpgradeShareTest(user_storage, message, absolute_path);
  }

  void InsertShareTest(const std::shared_ptr<UserStorage> &user_storage,
                       const InboxItem &message,
                       const fs::path &absolute_path) {
    EXPECT_EQ(message.content[1], "insert_share");
    asymm::Keys key_ring;
    if (message.content.size() > 5) {
      key_ring.identity = message.content[4];
      key_ring.validation_token = message.content[5];
      asymm::DecodePrivateKey(message.content[6], &(key_ring.private_key));
      asymm::DecodePublicKey(message.content[7], &(key_ring.public_key));
    }
    // fs::path("/").make_preferred() / message.content(1)
    EXPECT_EQ(kSuccess, user_storage->InsertShare(absolute_path,
                                                  message.content[0],
                                                  message.content[3],
                                                  key_ring));
  }

  void StopShareTest(const std::string &sender,
                     const std::shared_ptr<UserStorage> &user_storage,
                     const InboxItem &message,
                     const fs::path &absolute_path) {
    EXPECT_EQ(message.content[1], "stop_share");
    EXPECT_EQ(kSuccess, user_storage->StopShare(sender, absolute_path));
  }

  void RemoveShareTest(const std::shared_ptr<UserStorage> &user_storage,
                       const InboxItem &message,
                       const fs::path &absolute_path) {
    EXPECT_EQ(message.content[1], "remove_share");
    EXPECT_EQ(kSuccess, user_storage->RemoveShare(absolute_path));
  }

  void UpgradeShareTest(const std::shared_ptr<UserStorage> &user_storage,
                        const InboxItem &message,
                        const fs::path &absolute_path) {
    EXPECT_EQ(message.content[1], "upgrade_share");
    asymm::Keys key_ring;
    key_ring.identity = message.content[2];
    key_ring.validation_token = message.content[3];
    asymm::DecodePrivateKey(message.content[4], &(key_ring.private_key));
    asymm::DecodePublicKey(message.content[5], &(key_ring.public_key));
    EXPECT_EQ(kSuccess, user_storage->UpdateShare(absolute_path,
                                                  message.content[0],
                                                  nullptr,
                                                  nullptr,
                                                  &key_ring));
  }

  void MoveShareTest(const std::shared_ptr<UserStorage> &user_storage,
                     const InboxItem &message,
                     const fs::path &absolute_path) {
    EXPECT_EQ(message.content[1], "update_share");
    asymm::Keys key_ring;
    if (message.content.size() > 5) {
      key_ring.identity = message.content[4];
      key_ring.validation_token = message.content[5];
      asymm::DecodePrivateKey(message.content[6], &(key_ring.private_key));
      asymm::DecodePublicKey(message.content[7], &(key_ring.public_key));
    }
    EXPECT_EQ(kSuccess, user_storage->UpdateShare(absolute_path,
                                                  message.content[0],
                                                  &message.content[2],
                                                  &message.content[3],
                                                  &key_ring));
  }

 protected:
  void SetUp() {
    asio_service1_.Start(5);
    asio_service2_.Start(5);
    client_controller1_ = CreateUserCredentials(asio_service1_.service(),
                                                *test_dir_);
    session1_ = client_controller1_->session_;
    client_controller2_ = CreateUserCredentials(asio_service2_.service(),
                                                *test_dir_);
    session2_ = client_controller2_->session_;

    public_id1_.reset(new PublicId(client_controller1_->remote_chunk_store(),
                                   session1_,
                                   asio_service1_.service()));
    public_id2_.reset(new PublicId(client_controller2_->remote_chunk_store(),
                                   session2_,
                                   asio_service2_.service()));

    message_handler1_.reset(
        new MessageHandler(client_controller1_->remote_chunk_store(),
                           session1_,
                           asio_service1_.service()));
    message_handler2_.reset(
        new MessageHandler(client_controller2_->remote_chunk_store(),
                           session2_,
                           asio_service2_.service()));

    user_storage1_.reset(
        new UserStorage(client_controller1_->remote_chunk_store(),
                        message_handler1_));
    user_storage2_.reset(
        new UserStorage(client_controller2_->remote_chunk_store(),
                        message_handler1_));

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
  }

  void TearDown() {
    session1_->Reset();
    session2_->Reset();
    asio_service1_.Stop();
    asio_service2_.Stop();
  }

  maidsafe::test::TestPath test_dir_, mount_dir_;
  std::shared_ptr<UserCredentials> client_controller1_, client_controller2_;
  std::shared_ptr<UserStorage> user_storage1_, user_storage2_;
  std::shared_ptr<Session> session1_, session2_;
  AsioService asio_service1_, asio_service2_;
  bptime::seconds interval_;
  std::shared_ptr<PublicId> public_id1_, public_id2_;
  std::shared_ptr<MessageHandler> message_handler1_, message_handler2_;
  std::string pub_name1_, pub_name2_;
};

// TEST_F(UserStorageTest, FUNC_CreateShare) {
//   user_storage1_->MountDrive(*mount_dir_, session1_, true);
//   Sleep(interval_ * 2);
//   std::map<std::string, bool> users;
//   users.insert(std::make_pair(pub_name2_, false));
//   std::string tail;
//   fs::path directory0(CreateTestDirectory(user_storage1_->mount_dir() /
//                                               fs::path("/").make_preferred(),
//                                           &tail));
//   EXPECT_EQ(kSuccess,
//             user_storage1_->CreateShare(pub_name1_, directory0, users));
//   user_storage1_->UnMountDrive();
//
//   user_storage2_->MountDrive(*mount_dir_, session2_, true);
//   fs::path directory1(user_storage2_->mount_dir() /
//                       fs::path("/").make_preferred() /
//                       tail);
//   bs2::connection connection(
//     message_handler2_->ConnectToShareSignal(
//         std::bind(&UserStorageTest::DoShareTest,
//                   this,
//                   pub_name1_,
//                   user_storage2_,
//                   args::_1,
//                   directory1)));
//   Sleep(interval_ * 2);
//   boost::system::error_code error_code;
//   EXPECT_FALSE(fs::exists(directory1, error_code))
//                << directory1 << " : " << error_code.message();
//
//   EXPECT_EQ(kSuccess,
//             message_handler2_->StartCheckingForNewMessages(interval_));
//   Sleep(interval_ * 2);
//   EXPECT_TRUE(fs::exists(directory1, error_code))
//               << directory1 << " : " << error_code.message();
//
//   message_handler2_->StopCheckingForNewMessages();
//   user_storage2_->UnMountDrive();
// }
//
// TEST_F(UserStorageTest, FUNC_AddUser) {
//   user_storage1_->MountDrive(*mount_dir_, session1_, true);
//   Sleep(interval_ * 2);
//   std::map<std::string, bool> users;
//   std::string tail;
//   fs::path directory0(CreateTestDirectory(user_storage1_->mount_dir()  /
//                                             fs::path("/").make_preferred(),
//                                           &tail));
//   std::string share_id;
//   EXPECT_EQ(kSuccess, user_storage1_->CreateShare(pub_name1_,
//                                                   directory0,
//                                                   users,
//                                                   &share_id));
//   user_storage1_->UnMountDrive();
//   Sleep(interval_ * 2);
//   user_storage2_->MountDrive(*mount_dir_, session2_, true);
//   Sleep(interval_ * 2);
//   fs::path directory1(user_storage2_->mount_dir() /
//                       fs::path("/").make_preferred() /
//                       tail);
//   bs2::connection connection(
//       message_handler2_->ConnectToShareSignal(
//           std::bind(&UserStorageTest::DoShareTest,
//                     this,
//                     pub_name1_,
//                     user_storage2_,
//                     args::_1,
//                     directory1)));
//
//   boost::system::error_code error_code;
//   EXPECT_FALSE(fs::exists(directory1, error_code))
//                << directory1 << error_code.message();
//   EXPECT_EQ(kSuccess,
//             message_handler2_->StartCheckingForNewMessages(interval_));
//   Sleep(interval_ * 2);
//   EXPECT_FALSE(fs::exists(directory1, error_code))
//                << directory1 << error_code.message();
//   message_handler2_->StopCheckingForNewMessages();
//   user_storage2_->UnMountDrive();
//   Sleep(interval_ * 2);
//
//   user_storage1_->MountDrive(*mount_dir_, session1_, false);
//   Sleep(interval_ * 2);
//   EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0
//                                                   << error_code.message();
//   users.insert(std::make_pair(pub_name2_, false));
//   EXPECT_EQ(kSuccess,
//             user_storage1_->AddShareUsers(pub_name1_, directory0, users));
//   user_storage1_->UnMountDrive();
//   Sleep(interval_ * 2);
//
//   user_storage2_->MountDrive(*mount_dir_, session2_, false);
//   Sleep(interval_ * 2);
//   EXPECT_FALSE(fs::exists(directory1, error_code))
//                << directory1 << error_code.message();
//   EXPECT_EQ(kSuccess,
//             message_handler2_->StartCheckingForNewMessages(interval_));
//   Sleep(interval_ * 2);
//   EXPECT_TRUE(fs::exists(directory1, error_code))
//               << directory1 << error_code.message();
//   message_handler2_->StopCheckingForNewMessages();
//   user_storage2_->UnMountDrive();
// }
//
// TEST_F(UserStorageTest, FUNC_AddAdminUser) {
//   user_storage1_->MountDrive(*mount_dir_, session1_, true);
//   Sleep(interval_ * 2);
//   std::map<std::string, bool> users;
//   users.insert(std::make_pair(pub_name2_, true));
//   std::string tail;
//   fs::path directory0(CreateTestDirectory(user_storage1_->mount_dir() /
//                                               fs::path("/").make_preferred(),
//                                           &tail));
//   boost::system::error_code error_code;
//   EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0;
//   std::string share_id;
//   EXPECT_EQ(kSuccess, user_storage1_->CreateShare(pub_name1_,
//                                                   directory0,
//                                                   users,
//                                                   &share_id));
//   user_storage1_->UnMountDrive();
//   Sleep(interval_ * 2);
//   user_storage2_->MountDrive(*mount_dir_, session2_, true);
//   fs::path directory1(user_storage2_->mount_dir() /
//                       fs::path("/").make_preferred() /
//                       tail);
//   bs2::connection connection(
//       message_handler2_->ConnectToShareSignal(
//           std::bind(&UserStorageTest::DoShareTest,
//                     this,
//                     pub_name1_,
//                     user_storage2_,
//                     args::_1,
//                     directory1)));
//
//   Sleep(interval_ * 2);
//   EXPECT_EQ(kSuccess,
//             message_handler2_->StartCheckingForNewMessages(interval_));
//   Sleep(interval_ * 2);
//   EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
//   fs::path sub_directory(CreateTestDirectory(directory1, &tail));
//   EXPECT_TRUE(fs::exists(sub_directory, error_code)) << sub_directory;
//   message_handler2_->StopCheckingForNewMessages();
//   user_storage2_->UnMountDrive();
//   Sleep(interval_ * 2);
//
//   user_storage1_->MountDrive(*mount_dir_, session1_, false);
//   Sleep(interval_ * 2);
//   EXPECT_TRUE(fs::exists(directory0 / tail, error_code));
//   user_storage1_->UnMountDrive();
//   Sleep(interval_ * 2);
//
//   user_storage2_->MountDrive(*mount_dir_, session2_, false);
//   Sleep(interval_ * 2);
//   EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
//   EXPECT_TRUE(fs::exists(sub_directory, error_code)) << sub_directory;
//   user_storage2_->UnMountDrive();
//   Sleep(interval_ * 2);
// }
//
// TEST_F(UserStorageTest, FUNC_UpgradeUserToAdmin) {
//   user_storage1_->MountDrive(*mount_dir_, session1_, true);
//   Sleep(interval_ * 2);
//   std::map<std::string, bool> users;
//   users.insert(std::make_pair(pub_name2_, false));
//   std::string tail;
//   fs::path directory0(CreateTestDirectory(user_storage1_->mount_dir() /
//                                             fs::path("/").make_preferred(),
//                                           &tail));
//   std::string share_id;
//   EXPECT_EQ(kSuccess, user_storage1_->CreateShare(pub_name1_,
//                                                   directory0,
//                                                   users,
//                                                   &share_id));
//   user_storage1_->UnMountDrive();
//   Sleep(interval_ * 2);
//
//   user_storage2_->MountDrive(*mount_dir_, session2_, true);
//
//   fs::path directory1(user_storage2_->mount_dir() /
//                       fs::path("/").make_preferred() /
//                       tail);
//   bs2::connection connection(
//       message_handler2_->ConnectToShareSignal(
//           std::bind(&UserStorageTest::DoShareTest,
//                     this,
//                     pub_name1_,
//                     user_storage2_,
//                     args::_1,
//                     directory1)));
//
//   Sleep(interval_ * 2);
//   EXPECT_EQ(kSuccess,
//             message_handler2_->StartCheckingForNewMessages(interval_));
//   Sleep(interval_ * 2);
//   boost::system::error_code error_code;
//   EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
//   fs::path sub_directory(CreateTestDirectory(directory1, &tail));
//   EXPECT_FALSE(fs::exists(sub_directory, error_code)) << sub_directory;
//   message_handler2_->StopCheckingForNewMessages();
//   user_storage2_->UnMountDrive();
//   Sleep(interval_ * 2);
//
//   user_storage1_->MountDrive(*mount_dir_, session1_, false);
//   Sleep(interval_ * 2);
//   EXPECT_EQ(kSuccess,
//             user_storage1_->SetShareUsersRights(pub_name1_,
//                                                 directory0,
//                                                 pub_name2_,
//                                                 true));
//   user_storage1_->UnMountDrive();
//   Sleep(interval_ * 2);
//
//   user_storage2_->MountDrive(*mount_dir_, session2_, false);
//   Sleep(interval_ * 2);
//   sub_directory = CreateTestDirectory(directory1, &tail);
//   EXPECT_FALSE(fs::exists(sub_directory, error_code)) << sub_directory;
//   EXPECT_EQ(kSuccess,
//             message_handler2_->StartCheckingForNewMessages(interval_));
//   Sleep(interval_ * 2);
//   sub_directory = CreateTestDirectory(directory1, &tail);
//   EXPECT_TRUE(fs::exists(sub_directory, error_code)) << sub_directory;
//   message_handler2_->StopCheckingForNewMessages();
//   user_storage2_->UnMountDrive();
// }
//
// TEST_F(UserStorageTest, FUNC_StopShareByOwner) {
//   user_storage1_->MountDrive(*mount_dir_, session1_, true);
//   Sleep(interval_ * 2);
//   std::map<std::string, bool> users;
//   users.insert(std::make_pair(pub_name2_, false));
//   std::string tail;
//   fs::path directory0(CreateTestDirectory(user_storage1_->mount_dir() /
//                                               fs::path("/").make_preferred(),
//                                           &tail));
//   boost::system::error_code error_code;
//   EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0
//                                                   << error_code.message();
//   std::string share_id;
//   EXPECT_EQ(kSuccess,
//             user_storage1_->CreateShare(pub_name1_,
//                                         directory0,
//                                         users,
//                                         &share_id));
//   user_storage1_->UnMountDrive();
//   Sleep(interval_ * 2);
//
//   user_storage2_->MountDrive(*mount_dir_, session2_, true);
//   Sleep(interval_ * 2);
//   fs::path directory1(user_storage2_->mount_dir() /
//                       fs::path("/").make_preferred() /
//                       tail);
//   bs2::connection connection(
//     message_handler2_->ConnectToShareSignal(
//         std::bind(&UserStorageTest::DoShareTest,
//                   this,
//                   pub_name1_,
//                   user_storage2_,
//                   args::_1,
//                   directory1)));
//
//   EXPECT_FALSE(fs::exists(directory1, error_code)) << directory1;
//   EXPECT_EQ(kSuccess,
//             message_handler2_->StartCheckingForNewMessages(interval_));
//   Sleep(interval_ * 2);
//   EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
//   message_handler2_->StopCheckingForNewMessages();
//   user_storage2_->UnMountDrive();
//   Sleep(interval_ * 2);
//
//   user_storage1_->MountDrive(*mount_dir_, session1_, false);
//   Sleep(interval_ * 2);
//   EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0;
//   EXPECT_EQ(kSuccess, user_storage1_->StopShare(pub_name1_, directory0));
//   EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0;
//   // EXPECT_FALSE(fs::exists(directory0, error_code)) << directory0;
//   user_storage1_->UnMountDrive();
//   Sleep(interval_ * 2);
//
//   user_storage2_->MountDrive(*mount_dir_, session2_, false);
//   Sleep(interval_ * 2);
//   EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
//   EXPECT_EQ(kSuccess,
//             message_handler2_->StartCheckingForNewMessages(interval_));
//   Sleep(interval_ * 2);
//   EXPECT_FALSE(fs::exists(directory1, error_code)) << directory1 << " : "
//                                                    << error_code.message();
//   message_handler2_->StopCheckingForNewMessages();
//   user_storage2_->UnMountDrive();
//
//   // Sleep(interval_ * 2);
//   // user_storage1_->MountDrive(*mount_dir_,
//   //                            client_controller1_->SessionName(),
//   //                            session1_,
//   //                            false);
//   // Sleep(interval_ * 2);
//   // EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0;
//   // EXPECT_FALSE(fs::exists(directory0, error_code)) << directory0;
//   // user_storage1_->UnMountDrive();
//   // Sleep(interval_ * 2);
// }
//
// TEST_F(UserStorageTest, FUNC_RemoveUserByOwner) {
//   user_storage1_->MountDrive(*mount_dir_, session1_, true);
//   Sleep(interval_ * 2);
//   DLOG(ERROR) << "Guy 1 mounted\n\n\n\n";
//   std::map<std::string, bool> users;
//   users.insert(std::make_pair(pub_name2_, false));
//   std::string tail("OTJUP");
// //  fs::path directory0(CreateTestDirectory(
// //    user_storage1_->mount_dir() / fs::path("/").make_preferred() / "OTJUP",
// //    &tail));
//   fs::path directory0(user_storage1_->mount_dir() /
//                       fs::path("/").make_preferred() /
//                       tail);
//   boost::system::error_code error_code;
//   fs::create_directory(directory0, error_code);
//   EXPECT_EQ(0, error_code.value());
//
//   DLOG(ERROR) << directory0 << "\n\n\n\n";
//   std::string share_id;
//   EXPECT_EQ(kSuccess, user_storage1_->CreateShare(pub_name1_,
//                                                   directory0,
//                                                   users,
//                                                   &share_id));
//   user_storage1_->UnMountDrive();
//   Sleep(interval_ * 2);
//
//   DLOG(ERROR) << "Guy 1 unmounted\n\n\n\n";
//   user_storage2_->MountDrive(*mount_dir_, session2_, true);
//   Sleep(interval_ * 2);
//   DLOG(ERROR) << "Guy 2 mounted\n\n\n\n";
//   fs::path directory1(user_storage2_->mount_dir() /
//                       fs::path("/").make_preferred() /
//                       tail);
//   DLOG(ERROR) << directory1 << "\n\n\n\n";
//   bs2::connection connection(
//       message_handler2_->ConnectToShareSignal(
//             std::bind(&UserStorageTest::DoShareTest,
//                       this,
//                       pub_name1_,
//                       user_storage2_,
//                       args::_1,
//                       directory1)));
//
//   EXPECT_FALSE(fs::exists(directory1, error_code)) << directory1;
//   EXPECT_EQ(kSuccess,
//             message_handler2_->StartCheckingForNewMessages(interval_));
//   Sleep(interval_ * 2);
//   EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
//   message_handler2_->StopCheckingForNewMessages();
//   user_storage2_->UnMountDrive();
//   Sleep(interval_ * 2);
//
//   DLOG(ERROR) << "Guy 2 unmounted\n\n\n\n";
//   user_storage1_->MountDrive(*mount_dir_, session1_, false);
//   Sleep(interval_ * 2);
//   DLOG(ERROR) << "Guy 1 mounted\n\n\n\n";
//   EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0;
//   std::vector<std::string> user_ids;
//   user_ids.push_back(pub_name2_);
//   EXPECT_EQ(kSuccess, user_storage1_->RemoveShareUsers(pub_name1_,
//                                                        directory0,
//                                                        user_ids));
//
// //  fs::path sub_directory0(CreateTestDirectory(directory0, &tail));
//   tail = "I0E1k";
//   fs::path sub_directory0(directory0 / tail);
//   fs::create_directory(sub_directory0, error_code);
//   EXPECT_EQ(0, error_code.value());
//
//   DLOG(ERROR) << sub_directory0 << "\n\n\n\n";
//   EXPECT_TRUE(fs::exists(sub_directory0, error_code)) << sub_directory0;
//   user_storage1_->UnMountDrive();
//   Sleep(interval_ * 2);
//
//   DLOG(ERROR) << "Guy 1 unmounted\n\n\n\n";
//   user_storage2_->MountDrive(*mount_dir_, session2_, false);
//   Sleep(interval_ * 2);
//   DLOG(ERROR) << "Guy 2 mounted\n\n\n\n";
//   EXPECT_TRUE(fs::exists(directory1, error_code)) << directory1;
//   fs::path sub_directory1(directory1 / tail);
//   DLOG(ERROR) << sub_directory1 << "\n\n\n\n";
//   EXPECT_FALSE(fs::exists(sub_directory1, error_code)) << sub_directory1;
//   fs::create_directory(sub_directory1, error_code);
//   EXPECT_FALSE(fs::exists(sub_directory1, error_code)) << sub_directory1;
//   EXPECT_EQ(kSuccess,
//             message_handler2_->StartCheckingForNewMessages(interval_));
//   Sleep(interval_ * 2);
//   EXPECT_FALSE(fs::exists(directory1, error_code)) << directory1 << " : "
//                                                    << error_code.message();
//   message_handler2_->StopCheckingForNewMessages();
//   user_storage2_->UnMountDrive();
//   Sleep(interval_ * 2);
//
//   DLOG(ERROR) << "Guy 2 unmounted\n\n\n\n";
//   user_storage1_->MountDrive(*mount_dir_, session1_, false);
//   Sleep(interval_ * 2);
//   DLOG(ERROR) << "Guy 1 mounted\n\n\n\n";
//   EXPECT_TRUE(fs::exists(directory0, error_code)) << directory0;
//   Sleep(interval_ * 2);
//   DLOG(ERROR) << "Before the failure\n\n\n\n";
//   EXPECT_TRUE(fs::exists(sub_directory0, error_code)) << sub_directory0;
//   user_storage1_->UnMountDrive();
//   Sleep(interval_ * 2);
//   DLOG(ERROR) << "Guy 1 unmounted\n\n\n\n";
// }
//
}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
