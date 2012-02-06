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
#include "maidsafe/lifestuff/tests/test_callback.h"
#if defined AMAZON_WEB_SERVICE_STORE
#  include "maidsafe/lifestuff/store_components/aws_store_manager.h"
#else
#  include "maidsafe/lifestuff/store_components/local_store_manager.h"
#endif

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
  EXPECT_TRUE(fs::create_directories(directory, error_code))
              << directory  << ": " << error_code.message();
  EXPECT_EQ(0, error_code.value()) << directory << ": "
                                   << error_code.message();
  EXPECT_TRUE(fs::exists(directory, error_code)) << directory << ": "
                                                 << error_code.message();
  return directory;
}

class UserStorageTest : public testing::Test {
 public:
  UserStorageTest()
    : test_dir_(maidsafe::test::CreateTestPath()),
      g_mount_dir_(new fs::path(fs::initial_path() / "LifeStuff")),
      client_controller1_(CreateClientController("User 1")),
      user_storage1_(CreateUserStorage(client_controller1_)),
      session1_(client_controller1_->session_),
      client_controller2_(CreateClientController("User 2")),
      user_storage2_(CreateUserStorage(client_controller2_)),
      session2_(client_controller2_->session_),
      asio_service_(),
      work_(new ba::io_service::work(asio_service_)),
      threads_(),
      interval_(1),
      public_id1_(new PublicId(client_controller1_->packet_manager_,
                               session1_, asio_service_)),
      public_id2_(new PublicId(client_controller2_->packet_manager_,
                               session2_, asio_service_)),
      message_handler1_(new MessageHandler(
                                  client_controller1_->packet_manager_,
                                  session1_,
                                  asio_service_)),
      message_handler2_(new MessageHandler(
                                  client_controller2_->packet_manager_,
                                  session2_,
                                  asio_service_)) {
  for (int i(0); i != 5; ++i)
    threads_.create_thread(std::bind(
        static_cast<std::size_t(boost::asio::io_service::*)()>
            (&boost::asio::io_service::run), &asio_service_));

  message_handler1_->ConnectToSignal(pca::Message::kSharedDirectory,
                                     std::bind(&UserStorage::NewMessageSlot,
                                               user_storage1_, args::_1));
  public_id1_->CreatePublicId("User 1", true);
  user_storage1_->SetMessageHandler(message_handler1_);

  message_handler2_->ConnectToSignal(pca::Message::kSharedDirectory,
                                     std::bind(&UserStorage::NewMessageSlot,
                                               user_storage2_, args::_1));
  public_id2_->CreatePublicId("User 2", true);
  user_storage2_->SetMessageHandler(message_handler2_);

  public_id1_->StartCheckingForNewContacts(interval_);
  public_id2_->StartCheckingForNewContacts(interval_);

  public_id1_->SendContactInfo("User 1", "User 2");
  Sleep(interval_ * 2);
  public_id2_->ConfirmContact("User 2", "User 1");
  Sleep(interval_ * 2);

  public_id1_->StopCheckingForNewContacts();
  public_id2_->StopCheckingForNewContacts();
}

 protected:
  void SetUp() {}

  void TearDown() {
    work_.reset();
    asio_service_.stop();
    threads_.join_all();
  }

  std::shared_ptr<ClientController> CreateClientController(
      std::string username) {
    std::shared_ptr<Session> ss(new Session);
    std::shared_ptr<ClientController> cc(new ClientController(ss));
#if defined AMAZON_WEB_SERVICE_STORE
    std::shared_ptr<PacketManager>
        packet_manager(new AWSStoreManager(ss, *test_dir_));
#else
    std::shared_ptr<PacketManager>
        packet_manager(new LocalStoreManager(ss, test_dir_->string()));
#endif
    ss->ResetSession();
    packet_manager->Init(std::bind(&UserStorageTest::InitAndCloseCallback,
                                   this, args::_1));
    cc->auth_.reset(new Authentication(ss));
    cc->auth_->Init(packet_manager);
    cc->packet_manager_ = packet_manager;
    cc->initialised_ = true;
    std::stringstream pin_stream;
    pin_stream << RandomUint32();
    cc->CreateUser(username, pin_stream.str(), RandomString(6));
    return cc;
  }

  std::shared_ptr<UserStorage> CreateUserStorage(
      std::shared_ptr<ClientController> cc) {
    std::shared_ptr<maidsafe::lifestuff::UserStorage> us (
        new UserStorage(cc->packet_manager()));
    return us;
  }

  void InitAndCloseCallback(int /*i*/) {}

  std::shared_ptr<fs::path> test_dir_;
  std::shared_ptr<fs::path> g_mount_dir_;
  std::shared_ptr<ClientController> client_controller1_;
  std::shared_ptr<maidsafe::lifestuff::UserStorage> user_storage1_;
  std::shared_ptr<maidsafe::lifestuff::Session> session1_;
  std::shared_ptr<ClientController> client_controller2_;
  std::shared_ptr<maidsafe::lifestuff::UserStorage> user_storage2_;
  std::shared_ptr<maidsafe::lifestuff::Session> session2_;
  ba::io_service asio_service_;
  std::shared_ptr<ba::io_service::work> work_;
  boost::thread_group threads_;
  bptime::seconds interval_;
  std::shared_ptr<PublicId> public_id1_;
  std::shared_ptr<PublicId> public_id2_;
  std::shared_ptr<MessageHandler> message_handler1_;
  std::shared_ptr<MessageHandler> message_handler2_;
};

TEST_F(UserStorageTest, FUNC_FirstTest) {
  user_storage1_->MountDrive(*g_mount_dir_,
                             client_controller1_->SessionName(),
                             session1_, true);
  Sleep(interval_ * 2);
  std::map<std::string, bool> users;
  users.insert(std::make_pair("User 2", false));
  std::string tail;
  fs::path dir0(CreateTestDirectory(user_storage1_->g_mount_dir(), &tail));
  ASSERT_EQ(kSuccess, user_storage1_->CreateShare(dir0, users));
  user_storage1_->UnMountDrive();

  user_storage2_->MountDrive(*g_mount_dir_,
                             client_controller2_->SessionName(),
                             session2_, true);
  Sleep(interval_ * 2);
  fs::path dir(user_storage2_->g_mount_dir() / (tail));
  boost::system::error_code error_code;
  EXPECT_FALSE(fs::exists(dir, error_code)) << dir;

  ASSERT_EQ(kSuccess,
            message_handler2_->StartCheckingForNewMessages(interval_));
  Sleep(interval_ * 2);
  EXPECT_TRUE(fs::exists(dir, error_code)) << dir << " : "
                                           << error_code.message();

  message_handler2_->StopCheckingForNewMessages();
  user_storage2_->UnMountDrive();
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe