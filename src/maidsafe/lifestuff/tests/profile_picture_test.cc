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

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/pd/client/client_container.h"
#endif

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/message_handler.h"
#include "maidsafe/lifestuff/public_id.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/user_credentials.h"
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

namespace {

bptime::seconds g_interval(1);
typedef std::function<void(const std::string&, const std::string&)>
        NewContactSlotType;
typedef std::function<void(const std::string&)> ConfirmContactSlotType;

fs::path CreateTestDirectory(fs::path const& parent,
                             std::string *tail) {
  *tail = RandomAlphaNumericString(5);
  fs::path directory(parent / (*tail));
  boost::system::error_code error_code;

  fs::create_directories(directory, error_code);
  if (error_code)
    return fs::path();

  return directory;
}

struct TestElements {
  TestElements()
      : user_credentials(),
        user_storage(),
        session(new Session),
        asio_service(),
        converter(new YeOldeSignalToCallbackConverter),
        public_id(),
        message_handler() {}
  std::shared_ptr<UserCredentials> user_credentials;
  std::shared_ptr<UserStorage> user_storage;
  std::shared_ptr<Session> session;
  AsioService asio_service;
  std::shared_ptr<YeOldeSignalToCallbackConverter> converter;
  std::shared_ptr<PublicId> public_id;
  std::shared_ptr<MessageHandler> message_handler;
};

void InitTestElements(const fs::path &test_dir,
                      TestElements *test_elements) {
  // Initialisation
  test_elements->asio_service.Start(5);
  test_elements->user_credentials.reset(
      new UserCredentials(test_elements->asio_service.service(),
                          test_elements->session));
  test_elements->user_credentials->Init(test_dir);

  test_elements->public_id.reset(
      new PublicId(test_elements->user_credentials->remote_chunk_store(),
                    test_elements->user_credentials->converter(),
                    test_elements->session,
                    test_elements->asio_service.service()));

  test_elements->message_handler.reset(
      new MessageHandler(test_elements->user_credentials->remote_chunk_store(),
                         test_elements->user_credentials->converter(),
                         test_elements->session,
                         test_elements->asio_service.service()));

  test_elements->user_storage.reset(
      new UserStorage(test_elements->user_credentials->remote_chunk_store(),
                      test_elements->user_credentials->converter(),
                      test_elements->message_handler));
}

void CreateUserTestElements(const fs::path &test_dir,
                            const std::string &username,
                            const std::string &pin,
                            const std::string &password,
                            const std::string &public_username,
                            TestElements *test_elements) {
  InitTestElements(test_dir, test_elements);
  // User creation
  test_elements->user_credentials->CreateUser(username, pin, password);
  test_elements->public_id->CreatePublicId(public_username, true);
  test_elements->public_id->StartCheckingForNewContacts(g_interval);
  test_elements->message_handler->StartCheckingForNewMessages(g_interval);
  test_elements->user_storage->MountDrive(test_dir,
                                          test_elements->session,
                                          true);
}

void LoginTestElements(
    const fs::path &test_dir,
    const std::string &username,
    const std::string &pin,
    const std::string &password,
    TestElements *test_elements,
    const NewContactSlotType &new_contact_slot = NewContactSlotType(),
    const ConfirmContactSlotType &confirm_contact_slot =
        ConfirmContactSlotType()) {
  InitTestElements(test_dir, test_elements);
  test_elements->user_credentials->CheckUserExists(username, pin);
  test_elements->user_credentials->ValidateUser(password);

  if (new_contact_slot) {
    test_elements->public_id->new_contact_signal()->connect(new_contact_slot);
  }
  if (confirm_contact_slot) {
    test_elements->public_id->contact_confirmed_signal()->connect(
        confirm_contact_slot);
  }

  test_elements->public_id->StartCheckingForNewContacts(g_interval);
  test_elements->message_handler->StartCheckingForNewMessages(g_interval);
  test_elements->user_storage->MountDrive(test_dir,
                                          test_elements->session,
                                          false);
}

void ConnectTwoPublicIdsAndStopChecking(const std::string &public_username1,
                                        const std::string &public_username2,
                                        std::shared_ptr<PublicId> public_id1,
                                        std::shared_ptr<PublicId> public_id2) {
  public_id1->SendContactInfo(public_username1, public_username2);
  Sleep(g_interval * 2);
  public_id2->ConfirmContact(public_username2, public_username1);
  Sleep(g_interval * 2);

  public_id1->StopCheckingForNewContacts();
  public_id2->StopCheckingForNewContacts();
}

void TestElementsTearDown(TestElements *test_elements) {
  test_elements->user_storage->UnMountDrive();
  test_elements->public_id->StopCheckingForNewContacts();
  test_elements->message_handler->StopCheckingForNewMessages();
  test_elements->user_credentials->Logout();
  test_elements->session->Reset();
}

void ShareMessageSlot(const pca::Message &incoming_message,
                      pca::Message *received_message,
                      volatile bool *done) {
  *received_message = incoming_message;
  *done = true;
}

int InsertShareTest(const std::shared_ptr<UserStorage> &user_storage,
                    const pca::Message &message,
                    const fs::path &absolute_path) {
  asymm::Keys key_ring;
  if (message.content_size() > 4) {
    key_ring.identity = message.content(3);
    key_ring.validation_token = message.content(4);
    asymm::DecodePrivateKey(message.content(5), &(key_ring.private_key));
    asymm::DecodePublicKey(message.content(6), &(key_ring.public_key));
  }
  return user_storage->InsertShare(absolute_path,
                                   message.content(0),
                                   message.content(2),
                                   key_ring);
}

void NewContactSlot(const std::string&,
                    const std::string&,
                    volatile bool *done) {
  *done = true;
}

void ConfirmContactSlot(const std::string&, volatile bool *done) {
  *done = true;
}

std::string CreatePin() {
  std::stringstream pin_stream;
  uint32_t int_pin(0);
  while (int_pin == 0)
    int_pin = RandomUint32();

  pin_stream << int_pin;
  return pin_stream.str();
}

}  // namespace

class ProfilePictureTest : public testing::Test {
 public:
  ProfilePictureTest()
    : test_dir_(maidsafe::test::CreateTestPath()),
      mount_dir_(fs::initial_path() / "LifeStuff"),
      asio_service_(),
      interval_(1),
      user_credentials_(),
      user_storage_(),
      session_(new Session),
      converter_(new YeOldeSignalToCallbackConverter),
      public_id_(),
      message_handler_(),
      public_username_(RandomAlphaNumericString(5)),
      username_(RandomString(6)),
      pin_(),
      password_(RandomString(6)) {}

 protected:
  void SetUp() {
    asio_service_.Start(5);
    user_credentials_.reset(new UserCredentials(asio_service_.service(),
                                                session_));
    user_credentials_->Init(*test_dir_);

    std::stringstream pin_stream;
    pin_stream << RandomUint32();
    pin_ = pin_stream.str();

    public_id_.reset(new PublicId(user_credentials_->remote_chunk_store(),
                                  user_credentials_->converter(),
                                  session_,
                                  asio_service_.service()));

    message_handler_.reset(
        new MessageHandler(user_credentials_->remote_chunk_store(),
                           user_credentials_->converter(),
                           session_,
                           asio_service_.service()));

    user_storage_.reset(
        new UserStorage(user_credentials_->remote_chunk_store(),
                        user_credentials_->converter(),
                        message_handler_));

    user_credentials_->CreateUser(username_, pin_, password_);
    public_id_->CreatePublicId(public_username_, true);
    public_id_->StartCheckingForNewContacts(interval_);
    message_handler_->StartCheckingForNewMessages(interval_);
    user_storage_->MountDrive(mount_dir_, session_, true);
  }

  void TearDown() {
    Quit();
    asio_service_.Stop();
  }

  void Quit() {
    user_storage_->UnMountDrive();
    public_id_->StopCheckingForNewContacts();
    message_handler_->StopCheckingForNewMessages();
    user_credentials_->Logout();
    session_->Reset();
  }

  void LogIn() {
    EXPECT_EQ(-201004, user_credentials_->CheckUserExists(username_, pin_));
    EXPECT_TRUE(user_credentials_->ValidateUser(password_));
    public_id_->StartCheckingForNewContacts(interval_);
    message_handler_->StartCheckingForNewMessages(interval_);
    user_storage_->MountDrive(mount_dir_, session_, false);
  }

  maidsafe::test::TestPath test_dir_;
  fs::path mount_dir_;
  AsioService asio_service_;
  bptime::seconds interval_;
  std::shared_ptr<UserCredentials> user_credentials_;
  std::shared_ptr<UserStorage> user_storage_;
  std::shared_ptr<Session> session_;
  std::shared_ptr<YeOldeSignalToCallbackConverter> converter_;
  std::shared_ptr<PublicId> public_id_;
  std::shared_ptr<MessageHandler> message_handler_;
  std::string public_username_, username_, pin_, password_;
};

TEST_F(ProfilePictureTest, FUNC_CreateDirectoryLogoutLoginCheckDirectory) {
  // Create directory
  std::string tail;
  boost::system::error_code error_code;
  fs::path test(CreateTestDirectory(user_storage_->mount_dir(), &tail));
  EXPECT_TRUE(fs::exists(test, error_code));
  EXPECT_EQ(0, error_code.value());

  // Logout
  Quit();

  // Login
  LogIn();

  // Check directory exists
  EXPECT_TRUE(fs::exists(test, error_code));
  EXPECT_EQ(0, error_code.value());
}

TEST_F(ProfilePictureTest, FUNC_ChangeProfilePictureDataMap) {
  // Create file
  std::string file_name(RandomAlphaNumericString(8)),
              file_content(RandomString(5 * 1024));
  fs::path file_path(user_storage_->mount_dir() / file_name);
  std::ofstream ofstream(file_path.c_str(), std::ios::binary);
  ofstream << file_content;
  ofstream.close();

  boost::system::error_code error_code;
  EXPECT_TRUE(fs::exists(file_path, error_code));
  EXPECT_EQ(0, error_code.value());

  std::string new_data_map;
  user_storage_->GetDataMap(file_path, &new_data_map);
  EXPECT_FALSE(new_data_map.empty());
  session_->set_profile_picture_data_map(new_data_map);

  // Logout
  Quit();

  // Login
  LogIn();

  // Check directory exists
  EXPECT_TRUE(fs::exists(file_path, error_code));
  EXPECT_EQ(0, error_code.value());
  EXPECT_EQ(new_data_map, session_->profile_picture_data_map());
  new_data_map.clear();
  user_storage_->GetDataMap(file_path, &new_data_map);
  EXPECT_EQ(new_data_map, session_->profile_picture_data_map());
}

TEST(FullTest, FUNC_NotifyProfilePicture) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
              public_username1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(8)),
              file_content1(RandomString(5 * 1024)),
              file_name2(RandomAlphaNumericString(8)),
              file_content2(RandomString(5 * 1024)),
              data_map1,
              data_map2;
  boost::system::error_code error_code;
  fs::path file_path1, file_path2;

  {
    TestElements test_elements1;
    CreateUserTestElements(*test_dir,
                           username1,
                           pin1,
                           password1,
                           public_username1,
                           &test_elements1);
    file_path1 = test_elements1.user_storage->mount_dir() / file_name1;
    std::ofstream ofstream(file_path1.c_str(), std::ios::binary);
    ofstream << file_content1;
    ofstream.close();

    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    test_elements1.user_storage->GetDataMap(file_path1, &data_map1);
    EXPECT_FALSE(data_map1.empty());
    test_elements1.session->set_profile_picture_data_map(data_map1);

    TestElementsTearDown(&test_elements1);
  }

  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_username2(RandomAlphaNumericString(5));
  {
    TestElements test_elements2;
    CreateUserTestElements(*test_dir,
                           username2,
                           pin2,
                           password2,
                           public_username2,
                           &test_elements2);

    file_path2 = test_elements2.user_storage->mount_dir() / file_name2;
    std::ofstream ofstream(file_path2.c_str(), std::ios::binary);
    ofstream << file_content2;
    ofstream.close();

    EXPECT_TRUE(fs::exists(file_path2, error_code));
    EXPECT_EQ(0, error_code.value());
    test_elements2.user_storage->GetDataMap(file_path2, &data_map2);
    EXPECT_FALSE(data_map2.empty());
    test_elements2.session->set_profile_picture_data_map(data_map2);

    EXPECT_EQ(kSuccess,
              test_elements2.public_id->SendContactInfo(public_username2,
                                                        public_username1));

    TestElementsTearDown(&test_elements2);
  }

  volatile bool done(false);
  {
    TestElements test_elements1;
    LoginTestElements(*test_dir, username1, pin1, password1, &test_elements1,
                      std::bind(&NewContactSlot, args::_1, args::_2, &done));

    while (!done)
      Sleep(bptime::milliseconds(100));

    Contact contact2;
    EXPECT_EQ(kSuccess,
              test_elements1.session->contact_handler_map()
                  [public_username1]->ContactInfo(public_username2, &contact2));
    EXPECT_EQ(data_map2, contact2.profile_picture_data_map);

    EXPECT_EQ(kSuccess,
              test_elements1.public_id->ConfirmContact(public_username1,
                                                       public_username2));
    TestElementsTearDown(&test_elements1);
  }

  {
    done = false;
    TestElements test_elements2;
    LoginTestElements(*test_dir, username2, pin2, password2, &test_elements2,
                      NewContactSlotType(),
                      std::bind(&ConfirmContactSlot, args::_1, &done));

    while (!done)
      Sleep(bptime::milliseconds(100));

    Contact contact1;
    EXPECT_EQ(kSuccess,
              test_elements2.session->contact_handler_map()
                  [public_username2]->ContactInfo(public_username1, &contact1));
    EXPECT_EQ(data_map1, contact1.profile_picture_data_map);

    TestElementsTearDown(&test_elements2);
  }
}

TEST(FullTest, FUNC_DestructionOfObjects) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username(RandomString(6)),
              pin(CreatePin()),
              password(RandomString(6)),
              public_username(RandomAlphaNumericString(5));
  std::string tail;
  boost::system::error_code error_code;
  fs::path directory;

  {
    TestElements test_elements;
    CreateUserTestElements(*test_dir, username, pin, password, public_username,
                           &test_elements);

    directory = CreateTestDirectory(test_elements.user_storage->mount_dir(),
                                    &tail);

    EXPECT_TRUE(fs::exists(directory, error_code));
    EXPECT_EQ(0, error_code.value());

    TestElementsTearDown(&test_elements);
  }
  {
    TestElements test_elements;
    LoginTestElements(*test_dir, username, pin, password, &test_elements);

    EXPECT_TRUE(fs::exists(directory, error_code));
    EXPECT_EQ(0, error_code.value());

    TestElementsTearDown(&test_elements);
  }
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
