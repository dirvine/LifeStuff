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
#include "maidsafe/lifestuff/data_atlas_pb.h"
#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/message_handler.h"
#include "maidsafe/lifestuff/public_id.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/user_credentials.h"
#include "maidsafe/lifestuff/user_storage.h"

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

typedef std::function<void(const std::string&,
                           const std::string&,
                           ContactPresence)> PresenceSlotType;

struct TestElements {
  TestElements()
      : user_credentials(),
        user_storage(),
        session(new Session),
        asio_service(),
        public_id(),
        message_handler() {}
  std::shared_ptr<UserCredentials> user_credentials;
  std::shared_ptr<UserStorage> user_storage;
  std::shared_ptr<Session> session;
  AsioService asio_service;
  std::shared_ptr<PublicId> public_id;
  std::shared_ptr<MessageHandler> message_handler;
};

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
                   test_elements->session,
                   test_elements->asio_service.service()));

  test_elements->message_handler.reset(
      new MessageHandler(test_elements->user_credentials->remote_chunk_store(),
                         test_elements->session,
                         test_elements->asio_service.service()));

  test_elements->user_storage.reset(
      new UserStorage(test_elements->user_credentials->remote_chunk_store(),
                      test_elements->message_handler));
}

void CreateUserTestElements(const fs::path &test_dir,
                            const std::string &username,
                            const std::string &pin,
                            const std::string &password,
                            const std::string &public_username,
                            TestElements *test_elements,
                            bool mount = true) {
  InitTestElements(test_dir, test_elements);
  // User creation
  test_elements->user_credentials->CreateUser(username, pin, password);
  test_elements->public_id->CreatePublicId(public_username, true);
  test_elements->public_id->StartCheckingForNewContacts(g_interval);
  test_elements->message_handler->StartCheckingForNewMessages(g_interval);

  if (mount) {
    test_elements->user_storage->MountDrive(test_dir,
                                            test_elements->session,
                                            true);
  }
}

void LoginTestElements(
    const fs::path &test_dir,
    const std::string &username,
    const std::string &pin,
    const std::string &password,
    TestElements *test_elements,
    const NewContactFunction &new_contact_slot = NewContactFunction(),
    const ContactConfirmationFunction &confirm_contact_slot =
        ContactConfirmationFunction(),
    const ContactProfilePictureFunction &profile_picture_slot =
        ContactProfilePictureFunction(),
    bool mount = true) {
  InitTestElements(test_dir, test_elements);
  test_elements->user_credentials->CheckUserExists(username, pin);
  test_elements->user_credentials->ValidateUser(password);

  if (new_contact_slot) {
    test_elements->public_id->ConnectToNewContactSignal(new_contact_slot);
  }
  if (confirm_contact_slot) {
    test_elements->public_id->ConnectToContactConfirmedSignal(
        confirm_contact_slot);
  }
  if (profile_picture_slot) {
    test_elements->message_handler->ConnectToContactProfilePictureSignal(
        profile_picture_slot);
  }

  test_elements->public_id->StartCheckingForNewContacts(g_interval);
  test_elements->message_handler->StartUp(g_interval);

  if (mount) {
    test_elements->user_storage->MountDrive(test_dir,
                                            test_elements->session,
                                            false);
  }
}

void TestElementsTearDown(TestElements *test_elements,
                          bool unmount = true) {
  if (unmount) {
    test_elements->user_storage->UnMountDrive();
  }

  test_elements->public_id->StopCheckingForNewContacts();
  test_elements->message_handler->ShutDown();
  test_elements->user_credentials->Logout();
  test_elements->session->Reset();
}

void TwoStringsAndBoolSlot(const std::string&,
                           const std::string&,
                           volatile bool *done) {
  *done = true;
}

void ConfirmContactSlot(const std::string&,
                        const std::string&,
                        volatile bool *done) {
  *done = true;
}

void PresenceSlot(const std::string&,
                  const std::string&,
                  ContactPresence,
                  volatile bool *done) {
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

InboxItem CreatePresenceMessage(const std::string &sender,
                                const std::string &receiver,
                                bool logged_in) {
  InboxItem message(kContactPresence);
  message.sender_public_id = sender;
  message.receiver_public_id = receiver;
  message.timestamp = boost::lexical_cast<std::string>(GetDurationSinceEpoch());
  if (logged_in)
    message.content.push_back(kLiteralOnline);
  else
    message.content.push_back(kLiteralOffline);
  return message;
}

int ConnectPublicIds(const std::string &public_username1,
                     std::shared_ptr<PublicId> public_id1,
                     std::shared_ptr<MessageHandler> handler1,
                     const std::string &public_username2,
                     std::shared_ptr<PublicId> public_id2,
                     std::shared_ptr<MessageHandler> handler2) {
  volatile bool done1(false), done2(false);
  public_id2->ConnectToNewContactSignal(
      std::bind(&TwoStringsAndBoolSlot, args::_1, args::_2, &done2));
  public_id1->SendContactInfo(public_username1, public_username2);

  while (!done2)
    Sleep(bptime::milliseconds(100));

  public_id1->ConnectToContactConfirmedSignal(std::bind(&ConfirmContactSlot,
                                                            args::_1,
                                                            args::_2,
                                                            &done1));
  public_id2->ConfirmContact(public_username2, public_username1);

  while (!done1)
    Sleep(bptime::milliseconds(100));

  done1 = false;
  done2 = false;
  handler1->ConnectToContactPresenceSignal(std::bind(&PresenceSlot, args::_1,
                                                     args::_2, args::_3,
                                                     &done1));
  handler2->ConnectToContactPresenceSignal(std::bind(&PresenceSlot, args::_1,
                                                     args::_2, args::_3,
                                                     &done2));

  int result(handler1->Send(public_username1,
                            public_username2,
                            CreatePresenceMessage(public_username1,
                                                  public_username2,
                                                  true)));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed updating presence 1";
    return result;
  }

  result = handler2->Send(public_username2,
                          public_username1,
                          CreatePresenceMessage(public_username2,
                                                public_username1,
                                                true));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed updating presence 2";
    return result;
  }

  while (!done1 || !done2)
    Sleep(bptime::milliseconds(100));

  return kSuccess;
}

}  // namespace

class FixtureFullTest : public testing::Test {
 public:
  FixtureFullTest()
    : test_dir_(maidsafe::test::CreateTestPath()),
      mount_dir_(fs::initial_path() / "LifeStuff"),
      asio_service_(),
      interval_(1),
      user_credentials_(),
      user_storage_(),
      session_(new Session),
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
                                  session_,
                                  asio_service_.service()));

    message_handler_.reset(
        new MessageHandler(user_credentials_->remote_chunk_store(),
                           session_,
                           asio_service_.service()));

    user_storage_.reset(
        new UserStorage(user_credentials_->remote_chunk_store(),
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
  std::shared_ptr<PublicId> public_id_;
  std::shared_ptr<MessageHandler> message_handler_;
  std::string public_username_, username_, pin_, password_;
};

TEST_F(FixtureFullTest, FUNC_CreateDirectoryLogoutLoginCheckDirectory) {
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

TEST_F(FixtureFullTest, FUNC_ChangeProfilePictureDataMap) {
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
  session_->set_profile_picture_data_map(public_username_, new_data_map);

  // Logout
  Quit();

  // Login
  LogIn();

  // Check directory exists
  EXPECT_TRUE(fs::exists(file_path, error_code));
  EXPECT_EQ(0, error_code.value());
  EXPECT_EQ(new_data_map, session_->profile_picture_data_map(public_username_));
  new_data_map.clear();
  user_storage_->GetDataMap(file_path, &new_data_map);
  EXPECT_EQ(new_data_map, session_->profile_picture_data_map(public_username_));
}

TEST_F(FixtureFullTest, FUNC_ReconstructFileFromDataMap) {
  // Create file
//   std::string file_name("cabello.jpg"),
  std::string file_name(RandomAlphaNumericString(8)),
              file_content(RandomString(5 * 1024));
  fs::path file_path(user_storage_->mount_dir() / file_name);
  std::ofstream ofstream(file_path.c_str(), std::ios::binary);
  ofstream << file_content;
  ofstream.close();
//   std::string s;
//   std::cin >> s;

  std::string large_file_name(RandomAlphaNumericString(8)),
              large_file_content(RandomString(20 * 1024 * 1024) +
                                 std::string("a"));
  fs::path large_file_path(user_storage_->mount_dir() / large_file_name);
  std::ofstream large_ofstream(large_file_path.c_str(), std::ios::binary);
  large_ofstream << large_file_content;
  large_ofstream.close();

  boost::system::error_code error_code;
  EXPECT_TRUE(fs::exists(file_path, error_code));
  EXPECT_EQ(0, error_code.value());
  EXPECT_TRUE(fs::exists(large_file_path, error_code));
  EXPECT_EQ(0, error_code.value());

  std::string new_data_map, large_data_map;
  user_storage_->GetDataMap(file_path, &new_data_map);
  EXPECT_FALSE(new_data_map.empty());
  session_->set_profile_picture_data_map(public_username_, new_data_map);
  user_storage_->GetDataMap(file_path, &large_data_map);
  EXPECT_FALSE(large_data_map.empty());

  // Logout
  Quit();

  // Login
  LogIn();

  // Check directory exists
  EXPECT_TRUE(fs::exists(file_path, error_code));
  EXPECT_EQ(0, error_code.value());
  EXPECT_EQ(new_data_map, session_->profile_picture_data_map(public_username_));
  new_data_map.clear();
  user_storage_->GetDataMap(file_path, &new_data_map);
  EXPECT_EQ(new_data_map, session_->profile_picture_data_map(public_username_));
  large_data_map.clear();
  user_storage_->GetDataMap(large_file_path, &large_data_map);

  std::string reconstructed_content(user_storage_->ConstructFile(new_data_map));
  EXPECT_EQ(file_content, reconstructed_content);
  std::string large_reconstructed_content(
      user_storage_->ConstructFile(large_data_map));
  EXPECT_TRUE(large_reconstructed_content.empty());

  //////////////////
//   fs::path reconstructed_path(
//       user_storage_->mount_dir() /
//       std::string(RandomAlphaNumericString(8) + ".jpg"));
//   std::ofstream reconstructed_ofs(reconstructed_path.c_str(),
//                                   std::ios::binary);
//   reconstructed_ofs << reconstructed_content;
//   reconstructed_ofs.close();
//
//   s.clear();
//   std::cin >> s;
}

TEST(IndependentFullTest, FUNC_OnlinePresenceTest) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
              public_username1(RandomAlphaNumericString(5)),
              username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_username2(RandomAlphaNumericString(5));

  TestElements test_elements1;
  CreateUserTestElements(*test_dir,
                          username1,
                          pin1,
                          password1,
                          public_username1,
                          &test_elements1,
                          false);

  TestElements test_elements2;
  CreateUserTestElements(*test_dir,
                          username2,
                          pin2,
                          password2,
                          public_username2,
                          &test_elements2,
                          false);

  EXPECT_EQ(kSuccess, ConnectPublicIds(public_username1,
                                       test_elements1.public_id,
                                       test_elements1.message_handler,
                                       public_username2,
                                       test_elements2.public_id,
                                       test_elements2.message_handler));

  // They should both see each other as online after PingContact message
  Contact contact1, contact2;
  EXPECT_EQ(kSuccess,
            test_elements1.session->contact_handler_map()
                [public_username1]->ContactInfo(public_username2,
                                                &contact2));
  EXPECT_EQ(kOnline, contact2.presence);
  EXPECT_EQ(kSuccess,
            test_elements2.session->contact_handler_map()
                [public_username2]->ContactInfo(public_username1,
                                                &contact1));
  EXPECT_EQ(kOnline, contact1.presence);

  // Log out 1, message should be sent and 2 should have 1 as offline
  volatile bool done(false);
  test_elements2.message_handler->ConnectToContactPresenceSignal(
      std::bind(&PresenceSlot, args::_1, args::_2, args::_3, &done));
  TestElementsTearDown(&test_elements1, false);

  while (!done)
    Sleep(bptime::milliseconds(100));

  EXPECT_EQ(kSuccess,
            test_elements2.session->contact_handler_map()
                [public_username2]->ContactInfo(public_username1,
                                                &contact1));
  EXPECT_EQ(kOffline, contact1.presence);

  // Log in 1, message should be sent and 2 should update 1 as online
  done = false;
  LoginTestElements(*test_dir, username1, pin1, password1, &test_elements1,
                    NewContactFunction(), ContactConfirmationFunction(),
                    ContactProfilePictureFunction(), false);

  while (!done)
    Sleep(bptime::milliseconds(100));

  EXPECT_EQ(kSuccess,
            test_elements2.session->contact_handler_map()
                [public_username2]->ContactInfo(public_username1,
                                                &contact1));
  EXPECT_EQ(kOnline, contact1.presence);
  EXPECT_EQ(kSuccess,
            test_elements1.session->contact_handler_map()
                [public_username1]->ContactInfo(public_username2,
                                                &contact2));
  EXPECT_EQ(kOnline, contact2.presence);

  TestElementsTearDown(&test_elements2, false);
}

TEST(IndependentFullTest, FUNC_NotifyProfilePicture) {
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
    test_elements1.session->set_profile_picture_data_map(public_username1,
                                                         data_map1);

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
    test_elements2.session->set_profile_picture_data_map(public_username2,
                                                         data_map2);

    EXPECT_EQ(kSuccess,
              test_elements2.public_id->SendContactInfo(public_username2,
                                                        public_username1));

    TestElementsTearDown(&test_elements2);
  }

  volatile bool done(false);
  {
    TestElements test_elements1;
    LoginTestElements(*test_dir, username1, pin1, password1, &test_elements1,
                      std::bind(&TwoStringsAndBoolSlot, args::_1, args::_2,
                                &done));

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
                      NewContactFunction(), std::bind(&ConfirmContactSlot,
                                                      args::_1,
                                                      args::_2,
                                                      &done));

    while (!done)
      Sleep(bptime::milliseconds(100));

    Contact contact1;
    EXPECT_EQ(kSuccess,
              test_elements2.session->contact_handler_map()
                  [public_username2]->ContactInfo(public_username1, &contact1));
    EXPECT_EQ(data_map1, contact1.profile_picture_data_map);

    TestElementsTearDown(&test_elements2);
  }

  {
    TestElements test_elements1;
    LoginTestElements(*test_dir, username1, pin1, password1, &test_elements1);

    file_content1 = RandomString(5 * 1024);
    file_name1 = RandomAlphaNumericString(8) + std::string(".jpg");
    file_path1 = test_elements1.user_storage->mount_dir() / file_name1;
    std::ofstream ofstream(file_path1.c_str(), std::ios::binary);
    ofstream << file_content1;
    ofstream.close();

    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    test_elements1.user_storage->GetDataMap(file_path1, &data_map1);
    EXPECT_FALSE(data_map2.empty());
    test_elements1.session->set_profile_picture_data_map(public_username1,
                                                         data_map1);

    InboxItem message(kContactProfilePicture);
    message.sender_public_id = public_username1;
    message.receiver_public_id = public_username2;
    message.content.push_back(data_map1);
    message.timestamp =
        boost::lexical_cast<std::string>(GetDurationSinceEpoch());
    EXPECT_EQ(kSuccess, test_elements1.message_handler->Send(public_username1,
                                                             public_username2,
                                                             message));

    TestElementsTearDown(&test_elements1);
  }

  {
    done = false;
    TestElements test_elements2;
    LoginTestElements(*test_dir, username2, pin2, password2, &test_elements2,
                      NewContactFunction(), ContactConfirmationFunction(),
                      std::bind(&TwoStringsAndBoolSlot, args::_1, args::_2,
                                &done));

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

TEST(IndependentFullTest, FUNC_DestructionOfObjects) {
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
