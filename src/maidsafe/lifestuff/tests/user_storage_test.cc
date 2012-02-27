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

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/public_id.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/authentication.h"
#include "maidsafe/lifestuff/client_controller.h"
#include "maidsafe/lifestuff/user_storage.h"
#include "maidsafe/lifestuff/ye_olde_signal_to_callback_converter.h"

namespace args = std::placeholders;
namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace test {

fs::path CreateTestDirectory(fs::path const& parent,
                             std::string *tail) {
  *tail = RandomAlphaNumericString(5);
  fs::path directory(parent / (*tail));
  boost::system::error_code error_code;
  fs::create_directories(directory, error_code);
  return directory;
}

class UserStorageTest : public testing::Test {
 public:
  UserStorageTest()
    : test_dir_(maidsafe::test::CreateTestPath()),
      mount_dir_(new fs::path(fs::initial_path() / "LifeStuff")),
      client_controller1_(),
      user_storage1_(),
      session1_(),
      client_controller2_(),
      user_storage2_(),
      session2_(),
      asio_service_(),
      interval_(1),
      converter1_(new YeOldeSignalToCallbackConverter),
      converter2_(new YeOldeSignalToCallbackConverter),
      public_id1_(),
      public_id2_(),
      message_handler1_(),
      message_handler2_(),
      pub_name1_("User 1"),
      pub_name2_("User 2") {}

  void DoShareTest(
      const std::string &sender,
      const std::shared_ptr<maidsafe::lifestuff::UserStorage> &user_storage,
      const pca::Message &message,
      const fs::path &absolute_path = fs::path()) {
    if (message.subject() == "join_share")
      return InsertShareTest(user_storage, message, absolute_path);
    if (message.subject() == "remove_share")
      return RemoveShareTest(user_storage, message, absolute_path);
    if (message.subject() == "leave_share")
      return StopShareTest(sender, user_storage, message, absolute_path);
    if (message.subject() == "upgrade_share")
      return UpgradeShareTest(user_storage, message, absolute_path);
    if (message.subject() == "move_share")
      return MoveShareTest(user_storage, message, absolute_path);
  }

  void InsertShareTest(
        const std::shared_ptr<maidsafe::lifestuff::UserStorage> &user_storage,
        const pca::Message &message,
        const fs::path &absolute_path) {

    ASSERT_EQ(message.subject(), "join_share");
    asymm::Keys key_ring;
    if (message.content_size() > 4) {
      key_ring.identity = message.content(3);
      key_ring.validation_token = message.content(4);
      asymm::DecodePrivateKey(message.content(5), &(key_ring.private_key));
      asymm::DecodePublicKey(message.content(6), &(key_ring.public_key));
    }
    // fs::path("/").make_preferred() / message.content(1)
    ASSERT_EQ(kSuccess, user_storage->InsertShare(absolute_path,
                                                  message.content(0),
                                                  message.content(2),
                                                  key_ring));
  }

  void StopShareTest(
      const std::string &sender,
      const std::shared_ptr<maidsafe::lifestuff::UserStorage> &user_storage,
      const pca::Message &message,
      const fs::path &absolute_path) {
    ASSERT_EQ(message.subject(), "leave_share");
    ASSERT_EQ(kSuccess, user_storage->StopShare(sender, absolute_path));
  }

  void RemoveShareTest(
        const std::shared_ptr<maidsafe::lifestuff::UserStorage> &user_storage,
        const pca::Message &message,
        const fs::path &absolute_path) {
    ASSERT_EQ(message.subject(), "remove_share");
    ASSERT_EQ(kSuccess, user_storage->LeaveShare(absolute_path));
  }

  void UpgradeShareTest(
        const std::shared_ptr<maidsafe::lifestuff::UserStorage> &user_storage,
        const pca::Message &message,
        const fs::path &absolute_path) {
    ASSERT_EQ(message.subject(), "upgrade_share");
    asymm::Keys key_ring;
    key_ring.identity = message.content(1);
    key_ring.validation_token = message.content(2);
    asymm::DecodePrivateKey(message.content(3), &(key_ring.private_key));
    asymm::DecodePublicKey(message.content(4), &(key_ring.public_key));
    ASSERT_EQ(kSuccess, user_storage->ModifyShareDetails(absolute_path,
                                                         message.content(0),
                                                         nullptr,
                                                         nullptr,
                                                         &key_ring));
  }

  void MoveShareTest(
        const std::shared_ptr<maidsafe::lifestuff::UserStorage> &user_storage,
        const pca::Message &message,
        const fs::path &absolute_path) {
    ASSERT_EQ(message.subject(), "move_share");
    asymm::Keys key_ring;
    if (message.content_size() > 4) {
      key_ring.identity = message.content(3);
      key_ring.validation_token = message.content(4);
      asymm::DecodePrivateKey(message.content(5), &(key_ring.private_key));
      asymm::DecodePublicKey(message.content(6), &(key_ring.public_key));
    }
    ASSERT_EQ(kSuccess, user_storage->ModifyShareDetails(absolute_path,
                                                         message.content(0),
                                                         &message.content(1),
                                                         &message.content(2),
                                                         &key_ring));
  }

 protected:
  void SetUp() {
    asio_service_.Start(5);
    client_controller1_ = CreateClientController(pub_name1_);
    session1_ = client_controller1_->session_;
    client_controller2_ = CreateClientController(pub_name2_);
    session2_ = client_controller2_->session_;

    /*client_controller1_->remote_chunk_store()->sig_chunk_stored()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Stored, converter1_.get(),
                  args::_1, args::_2));
    client_controller1_->remote_chunk_store()->sig_chunk_deleted()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Deleted, converter1_.get(),
                  args::_1, args::_2));
    client_controller1_->remote_chunk_store()->sig_chunk_modified()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Modified, converter1_.get(),
                  args::_1, args::_2));

    client_controller2_->remote_chunk_store()->sig_chunk_stored()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Stored, converter2_.get(),
                  args::_1, args::_2));
    client_controller2_->remote_chunk_store()->sig_chunk_deleted()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Deleted, converter2_.get(),
                  args::_1, args::_2));
    client_controller2_->remote_chunk_store()->sig_chunk_modified()->connect(
        std::bind(&YeOldeSignalToCallbackConverter::Modified, converter2_.get(),
                  args::_1, args::_2));*/

    public_id1_.reset(new PublicId(client_controller1_->remote_chunk_store(),
                                   client_controller1_->converter(), // converter1_,
                                   session1_,
                                   asio_service_.service()));
    public_id2_.reset(new PublicId(client_controller2_->remote_chunk_store(),
                                   client_controller2_->converter(), // converter2_,
                                   session2_,
                                   asio_service_.service()));

    message_handler1_.reset(
        new MessageHandler(client_controller1_->remote_chunk_store(),
                           client_controller1_->converter(), // converter1_,
                           session1_,
                           asio_service_.service()));
    message_handler2_.reset(
        new MessageHandler(client_controller2_->remote_chunk_store(),
                           client_controller2_->converter(), // converter2_,
                           session2_,
                           asio_service_.service()));

    user_storage1_.reset(
        new UserStorage(client_controller1_->remote_chunk_store(),
                        client_controller1_->converter(), // converter1_,
                        message_handler1_));
    user_storage2_.reset(
        new UserStorage(client_controller2_->remote_chunk_store(),
                        client_controller2_->converter(), // converter2_,
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
    session1_->ResetSession();
    session2_->ResetSession();
    asio_service_.Stop();
  }

  std::shared_ptr<ClientController> CreateClientController(
      std::string username) {
    std::shared_ptr<Session> session(new Session);
    std::shared_ptr<ClientController> client_controller(
        new ClientController(asio_service_.service(), session));
    client_controller->auth_.reset(new Authentication(session));
    client_controller->Init(true, *test_dir_);
    client_controller->initialised_ = true;
    std::stringstream pin_stream;
    pin_stream << RandomUint32();
    client_controller->CreateUser(username, pin_stream.str(), RandomString(6));
    return client_controller;
  }

  void InitAndCloseCallback(int /*i*/) {}

  std::shared_ptr<fs::path> test_dir_;
  std::shared_ptr<fs::path> mount_dir_;
  std::shared_ptr<ClientController> client_controller1_;
  std::shared_ptr<maidsafe::lifestuff::UserStorage> user_storage1_;
  std::shared_ptr<maidsafe::lifestuff::Session> session1_;
  std::shared_ptr<ClientController> client_controller2_;
  std::shared_ptr<maidsafe::lifestuff::UserStorage> user_storage2_;
  std::shared_ptr<maidsafe::lifestuff::Session> session2_;
  AsioService asio_service_;
  bptime::seconds interval_;
  std::shared_ptr<YeOldeSignalToCallbackConverter> converter1_, converter2_;
  std::shared_ptr<PublicId> public_id1_;
  std::shared_ptr<PublicId> public_id2_;
  std::shared_ptr<MessageHandler> message_handler1_;
  std::shared_ptr<MessageHandler> message_handler2_;
  std::string pub_name1_, pub_name2_;
};

TEST_F(UserStorageTest, FUNC_CreateShare) {
  user_storage1_->MountDrive(*mount_dir_,
                             client_controller1_->SessionName(),
                             session1_,
                             true);
  Sleep(interval_ * 2);
  std::map<std::string, bool> users;
  users.insert(std::make_pair(pub_name2_, false));
  std::string tail;
  fs::path directory0(CreateTestDirectory(user_storage1_->g_mount_dir() /
                                              fs::path("/").make_preferred(),
                                          &tail));
  ASSERT_EQ(kSuccess, user_storage1_->CreateShare(pub_name1_,
                                                  directory0,
                                                  users));
  user_storage1_->UnMountDrive();

  user_storage2_->MountDrive(*mount_dir_,
                             client_controller2_->SessionName(),
                             session2_,
                             true);
  fs::path directory1(user_storage2_->g_mount_dir() /
                      fs::path("/").make_preferred() /
                      tail);
  bs2::connection connection(
    message_handler2_->ConnectToSignal(
        pca::Message::kSharedDirectory,
        std::bind(&UserStorageTest::DoShareTest,
                  this,
                  pub_name1_,
                  user_storage2_,
                  args::_1,
                  directory1)));
  Sleep(interval_ * 2);
  boost::system::error_code error_code;
  ASSERT_FALSE(fs::exists(directory1, error_code))
               << directory1 << " : " << error_code.message();

  ASSERT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  ASSERT_TRUE(fs::exists(directory1, error_code))
              << directory1 << " : " << error_code.message();

  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
}

TEST_F(UserStorageTest, FUNC_AddUser) {
  user_storage1_->MountDrive(*mount_dir_,
                             client_controller1_->SessionName(),
                             session1_,
                             true);
  Sleep(interval_ * 2);
  std::map<std::string, bool> users;
  std::string tail;
  fs::path directory0(CreateTestDirectory(user_storage1_->g_mount_dir()  /
                                            fs::path("/").make_preferred(),
                                          &tail));
  std::string share_id;
  ASSERT_EQ(kSuccess, user_storage1_->CreateShare(pub_name1_,
                                                  directory0,
                                                  users,
                                                  &share_id));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);
  user_storage2_->MountDrive(*mount_dir_,
                             client_controller2_->SessionName(),
                             session2_,
                             true);
  Sleep(interval_ * 2);
  fs::path directory1(user_storage2_->g_mount_dir() /
                      fs::path("/").make_preferred() /
                      tail);
  bs2::connection connection(
      message_handler2_->ConnectToSignal(
          pca::Message::kSharedDirectory,
          std::bind(&UserStorageTest::DoShareTest,
                    this,
                    pub_name1_,
                    user_storage2_,
                    args::_1,
                    directory1)));

  boost::system::error_code error_code;
  ASSERT_FALSE(fs::exists(directory1, error_code))
               << directory1 << error_code.message();
  ASSERT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  ASSERT_FALSE(fs::exists(directory1, error_code))
               << directory1 << error_code.message();
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage1_->MountDrive(*mount_dir_,
                             client_controller1_->SessionName(),
                             session1_,
                             false);
  Sleep(interval_ * 2);
  ASSERT_TRUE(fs::exists(directory0, error_code)) << directory0
                                                  << error_code.message();
  users.insert(std::make_pair(pub_name2_, false));
  ASSERT_EQ(kSuccess,
            user_storage1_->AddShareUsers(pub_name1_, directory0, users));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage2_->MountDrive(*mount_dir_,
                             client_controller2_->SessionName(),
                             session2_,
                             false);
  Sleep(interval_ * 2);
  ASSERT_FALSE(fs::exists(directory1, error_code))
               << directory1 << error_code.message();
  ASSERT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  ASSERT_TRUE(fs::exists(directory1, error_code))
              << directory1 << error_code.message();
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
}

TEST_F(UserStorageTest, FUNC_AddAdminUser) {
  user_storage1_->MountDrive(*mount_dir_,
                             client_controller1_->SessionName(),
                             session1_,
                             true);
  Sleep(interval_ * 2);
  std::map<std::string, bool> users;
  users.insert(std::make_pair(pub_name2_, true));
  std::string tail;
  fs::path directory0(CreateTestDirectory(user_storage1_->g_mount_dir() /
                                              fs::path("/").make_preferred(),
                                          &tail));
  boost::system::error_code error_code;
  ASSERT_TRUE(fs::exists(directory0, error_code)) << directory0;
  std::string share_id;
  ASSERT_EQ(kSuccess, user_storage1_->CreateShare(pub_name1_,
                                                  directory0,
                                                  users,
                                                  &share_id));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);
  user_storage2_->MountDrive(*mount_dir_,
                             client_controller2_->SessionName(),
                             session2_,
                             true);
  fs::path directory1(user_storage2_->g_mount_dir() /
                      fs::path("/").make_preferred() /
                      tail);
  bs2::connection connection(
      message_handler2_->ConnectToSignal(
          pca::Message::kSharedDirectory,
          std::bind(&UserStorageTest::DoShareTest,
                    this,
                    pub_name1_,
                    user_storage2_,
                    args::_1,
                    directory1)));

  Sleep(interval_ * 2);
  ASSERT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  ASSERT_TRUE(fs::exists(directory1, error_code)) << directory1;
  fs::path sub_directory(CreateTestDirectory(directory1, &tail));
  ASSERT_TRUE(fs::exists(sub_directory, error_code)) << sub_directory;
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);
  
  user_storage1_->MountDrive(*mount_dir_,
                             client_controller1_->SessionName(),
                             session1_,
                             false);
  Sleep(interval_ * 2);
  ASSERT_TRUE(fs::exists(directory0 / tail, error_code));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);
  
  user_storage2_->MountDrive(*mount_dir_,
                             client_controller2_->SessionName(),
                             session2_,
                             false);
  Sleep(interval_ * 2);
  ASSERT_TRUE(fs::exists(directory1, error_code)) << directory1;
  ASSERT_TRUE(fs::exists(sub_directory, error_code)) << sub_directory;
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);
}

TEST_F(UserStorageTest, FUNC_UpgradeUserToAdmin) {
  user_storage1_->MountDrive(*mount_dir_,
                             client_controller1_->SessionName(),
                             session1_,
                             true);
  Sleep(interval_ * 2);
  std::map<std::string, bool> users;
  users.insert(std::make_pair(pub_name2_, false));
  std::string tail;
  fs::path directory0(CreateTestDirectory(user_storage1_->g_mount_dir() /
                                            fs::path("/").make_preferred(),
                                          &tail));
  std::string share_id;
  ASSERT_EQ(kSuccess, user_storage1_->CreateShare(pub_name1_,
                                                  directory0,
                                                  users,
                                                  &share_id));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage2_->MountDrive(*mount_dir_,
                             client_controller2_->SessionName(),
                             session2_, true);

  fs::path directory1(user_storage2_->g_mount_dir() /
                      fs::path("/").make_preferred() /
                      tail);
  bs2::connection connection(
      message_handler2_->ConnectToSignal(
          pca::Message::kSharedDirectory,
          std::bind(&UserStorageTest::DoShareTest,
                    this,
                    pub_name1_,
                    user_storage2_,
                    args::_1,
                    directory1)));

  Sleep(interval_ * 2);
  ASSERT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  boost::system::error_code error_code;
  ASSERT_TRUE(fs::exists(directory1, error_code)) << directory1;
  fs::path sub_directory(CreateTestDirectory(directory1, &tail));
  ASSERT_FALSE(fs::exists(sub_directory, error_code)) << sub_directory;
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage1_->MountDrive(*mount_dir_,
                             client_controller1_->SessionName(),
                             session1_,
                             false);
  Sleep(interval_ * 2);
  ASSERT_EQ(kSuccess,
            user_storage1_->SetShareUsersRights(pub_name1_,
                                                directory0,
                                                pub_name2_,
                                                true));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage2_->MountDrive(*mount_dir_,
                             client_controller2_->SessionName(),
                             session2_,
                             false);
  Sleep(interval_ * 2);
  sub_directory = CreateTestDirectory(directory1, &tail);
  ASSERT_FALSE(fs::exists(sub_directory, error_code)) << sub_directory;
  ASSERT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  sub_directory = CreateTestDirectory(directory1, &tail);
  ASSERT_TRUE(fs::exists(sub_directory, error_code)) << sub_directory;
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
}

TEST_F(UserStorageTest, FUNC_StopShareByOwner) {
  user_storage1_->MountDrive(*mount_dir_,
                             client_controller1_->SessionName(),
                             session1_,
                             true);
  Sleep(interval_ * 2);
  std::map<std::string, bool> users;
  users.insert(std::make_pair(pub_name2_, false));
  std::string tail;
  fs::path directory0(CreateTestDirectory(user_storage1_->g_mount_dir() /
                                              fs::path("/").make_preferred(),
                                          &tail));
  boost::system::error_code error_code;
  ASSERT_TRUE(fs::exists(directory0, error_code)) << directory0
                                                  << error_code.message();
  std::string share_id;
  ASSERT_EQ(kSuccess,
            user_storage1_->CreateShare(pub_name1_,
                                        directory0,
                                        users,
                                        &share_id));
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage2_->MountDrive(*mount_dir_,
                             client_controller2_->SessionName(),
                             session2_, true);
  Sleep(interval_ * 2);
  fs::path directory1(user_storage2_->g_mount_dir() /
                      fs::path("/").make_preferred() /
                      tail);
  bs2::connection connection(
    message_handler2_->ConnectToSignal(
        pca::Message::kSharedDirectory,
        std::bind(&UserStorageTest::DoShareTest,
                  this,
                  pub_name1_,
                  user_storage2_,
                  args::_1,
                  directory1)));

  ASSERT_FALSE(fs::exists(directory1, error_code)) << directory1;
  ASSERT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  ASSERT_TRUE(fs::exists(directory1, error_code)) << directory1;
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage1_->MountDrive(*mount_dir_,
                             client_controller1_->SessionName(),
                             session1_,
                             false);
  Sleep(interval_ * 2);
  ASSERT_TRUE(fs::exists(directory0, error_code)) << directory0;
  ASSERT_EQ(kSuccess, user_storage1_->StopShare(pub_name1_, directory0));
  ASSERT_TRUE(fs::exists(directory0, error_code)) << directory0;
  // ASSERT_FALSE(fs::exists(directory0, error_code)) << directory0;
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage2_->MountDrive(*mount_dir_,
                             client_controller2_->SessionName(),
                             session2_,
                             false);
  Sleep(interval_ * 2);
  ASSERT_TRUE(fs::exists(directory1, error_code)) << directory1;
  ASSERT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  ASSERT_FALSE(fs::exists(directory1, error_code)) << directory1 << " : "
                                                   << error_code.message();
  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
  Sleep(interval_ * 2);

  user_storage1_->MountDrive(*mount_dir_,
                             client_controller1_->SessionName(),
                             session1_,
                             false);
  Sleep(interval_ * 2);
  ASSERT_TRUE(fs::exists(directory0, error_code)) << directory0;
  //ASSERT_FALSE(fs::exists(directory0, error_code)) << directory0;
  user_storage1_->UnMountDrive();
  Sleep(interval_ * 2);
}

//TEST_F(UserStorageTest, FUNC_RemoveUserByOwner) {
//  user_storage1_->MountDrive(*mount_dir_,
//                             client_controller1_->SessionName(),
//                             session1_, true);
//  Sleep(interval_ * 2);
//  std::map<std::string, bool> users;
//  users.insert(std::make_pair(pub_name2_, false));
//  std::string tail;
//  fs::path dir0(CreateTestDirectory(user_storage1_->g_mount_dir() /
//                                    fs::path("/").make_preferred(), &tail));
//  std::string share_id;
//  ASSERT_EQ(kSuccess, user_storage1_->CreateShare(dir0, users, &share_id));
//  user_storage1_->UnMountDrive();
//  Sleep(interval_ * 2);
//
//  bs2::connection connection(
//    message_handler2_->ConnectToSignal(pca::Message::kSharedDirectory,
//      std::bind(&UserStorageTest::DoShareTest, this, user_storage2_, args::_1)));
//
//  user_storage2_->MountDrive(*mount_dir_,
//                             client_controller2_->SessionName(),
//                             session2_, true);
//  Sleep(interval_ * 2);
//  fs::path dir(user_storage2_->g_mount_dir() / fs::path("/").make_preferred() /
//               tail);
//  boost::system::error_code error_code;
//  ASSERT_FALSE(fs::exists(dir, error_code)) << dir;
//  ASSERT_EQ(kSuccess,
//            message_handler2_->StartCheckingForNewMessages(interval_));
//  Sleep(interval_ * 2);
//  ASSERT_TRUE(fs::exists(dir, error_code)) << dir;
//  message_handler2_->StopCheckingForNewMessages();
//  user_storage2_->UnMountDrive();
//  Sleep(interval_ * 2);
//
//  user_storage1_->MountDrive(*mount_dir_,
//                             client_controller1_->SessionName(),
//                             session1_, false);
//  Sleep(interval_ * 2);
//  ASSERT_TRUE(fs::exists(dir0, error_code)) << dir0;
//  std::vector<std::string> user_ids;
//  user_ids.push_back(pub_name2_);
//  ASSERT_EQ(kSuccess, user_storage1_->RemoveShareUsers(share_id, user_ids));
//  fs::path sub_dir0(CreateTestDirectory(dir0, &tail));
//  ASSERT_TRUE(fs::exists(sub_dir0, error_code)) << sub_dir0;
//  user_storage1_->UnMountDrive();
//  Sleep(interval_ * 2);
//
//  /*bs2::connection connection2(
//    message_handler2_->ConnectToSignal(pca::Message::kSharedDirectory,
//      std::bind(&UserStorageTest::StopShareTest, this, user_storage2_, args::_1)));*/
//
//  user_storage2_->MountDrive(*mount_dir_,
//                             client_controller2_->SessionName(),
//                             session2_, false);
//  Sleep(interval_ * 2);
//  ASSERT_TRUE(fs::exists(dir, error_code)) << dir;
//  fs::path sub_dir(dir / tail);
//  ASSERT_FALSE(fs::exists(sub_dir, error_code)) << sub_dir;
//  ASSERT_EQ(kSuccess,
//            message_handler2_->StartCheckingForNewMessages(interval_));
//  Sleep(interval_ * 2);
//  ASSERT_FALSE(fs::exists(dir, error_code)) << dir << " : "
//                                           << error_code.message();
//  message_handler2_->StopCheckingForNewMessages();
//  user_storage2_->UnMountDrive();
//  Sleep(interval_ * 2);
//
//  user_storage1_->MountDrive(*mount_dir_,
//                             client_controller1_->SessionName(),
//                             session1_, false);
//  Sleep(interval_ * 2);
//  ASSERT_TRUE(fs::exists(dir0, error_code)) << dir0;
//  ASSERT_TRUE(fs::exists(sub_dir0, error_code)) << sub_dir0;
//  user_storage1_->UnMountDrive();
//  Sleep(interval_ * 2);
//}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
