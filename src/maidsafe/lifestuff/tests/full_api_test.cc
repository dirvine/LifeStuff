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
#include "maidsafe/lifestuff/lifestuff_api.h"
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

void FileRecieved(const std::string&,
                  const std::string&,
                  const std::string&,
                  const std::string &signal_file_id,
                  std::string *slot_file_id,
                  volatile bool *done) {
  *slot_file_id = signal_file_id;
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

TEST(IndependentFullTest, FUNC_SendFile) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
              public_username1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(8)),
              file_content1(RandomString(5 * 1024)),
              file_name2(RandomAlphaNumericString(8));
  boost::system::error_code error_code;
  fs::path file_path1, file_path2;
  volatile bool done;

  {
    LifeStuff test_elements1;
    EXPECT_EQ(kSuccess, test_elements1.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements1.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              ShareInvitationFunction(),
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done)));
    EXPECT_EQ(kSuccess, test_elements1.CreateUser(username1, pin1, password1));
    EXPECT_EQ(kSuccess, test_elements1.CreatePublicId(public_username1));

    file_path1 = test_elements1.mount_path() / file_name1;
    std::ofstream ofstream(file_path1.c_str(), std::ios::binary);
    ofstream << file_content1;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
    EXPECT_EQ(kSuccess, test_elements1.Finalise());
  }
  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_username2(RandomAlphaNumericString(5));
  DLOG(ERROR) << "\n\n\n\n";
  {
    LifeStuff test_elements2;
    EXPECT_EQ(kSuccess, test_elements2.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements2.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              ShareInvitationFunction(),
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done)));
    EXPECT_EQ(kSuccess, test_elements2.CreateUser(username2, pin2, password2));
    EXPECT_EQ(kSuccess, test_elements2.CreatePublicId(public_username2));
    EXPECT_EQ(kSuccess, test_elements2.AddContact(public_username2,
                                                  public_username1));
    EXPECT_EQ(kSuccess, test_elements2.LogOut());
    EXPECT_EQ(kSuccess, test_elements2.Finalise());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    LifeStuff test_elements1;
    EXPECT_EQ(kSuccess, test_elements1.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements1.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              ShareInvitationFunction(),
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              ContactPresenceFunction()));
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    while (!done)
      Sleep(bptime::milliseconds(100));
    EXPECT_EQ(kSuccess, test_elements1.ConfirmContact(public_username1,
                                                      public_username2));

    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements1.SendFile(public_username1,
                                                public_username2,
                                                file_path1));

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
    EXPECT_EQ(kSuccess, test_elements1.Finalise());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    done = false;
    volatile bool file_received(false);
    std::string file_id;
    LifeStuff test_elements2;
    EXPECT_EQ(kSuccess, test_elements2.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements2.ConnectToSignals(ChatFunction(),
                                              std::bind(&FileRecieved, args::_1,
                                                        args::_2, args::_3,
                                                        args::_4, &file_id,
                                                        &file_received),
                                              ShareInvitationFunction(),
                                              NewContactFunction(),
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactProfilePictureFunction(),
                                              ContactPresenceFunction()));
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!done && !file_received)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(file_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptSentFile(test_elements2.mount_path() /
                                                file_name2,
                                            file_id));

    EXPECT_TRUE(fs::exists(test_elements2.mount_path() / file_name2,
                           error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
    EXPECT_EQ(kSuccess, test_elements2.Finalise());
  }
}

TEST(IndependentFullTest, FUNC_PresenceOnLogIn) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
              public_username1(RandomAlphaNumericString(5));
  volatile bool done;

  {
    LifeStuff test_elements1;
    EXPECT_EQ(kSuccess, test_elements1.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements1.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              ShareInvitationFunction(),
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done)));
    EXPECT_EQ(kSuccess, test_elements1.CreateUser(username1, pin1, password1));
    EXPECT_EQ(kSuccess, test_elements1.CreatePublicId(public_username1));
    EXPECT_EQ(kSuccess, test_elements1.LogOut());
    EXPECT_EQ(kSuccess, test_elements1.Finalise());
  }
  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_username2(RandomAlphaNumericString(5));
  DLOG(ERROR) << "\n\n\n\n";
  {
    LifeStuff test_elements2;
    EXPECT_EQ(kSuccess, test_elements2.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements2.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              ShareInvitationFunction(),
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done)));
    EXPECT_EQ(kSuccess, test_elements2.CreateUser(username2, pin2, password2));
    EXPECT_EQ(kSuccess, test_elements2.CreatePublicId(public_username2));
    EXPECT_EQ(kSuccess, test_elements2.AddContact(public_username2,
                                                  public_username1));
    EXPECT_EQ(kSuccess, test_elements2.LogOut());
    EXPECT_EQ(kSuccess, test_elements2.Finalise());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    done = false;
    LifeStuff test_elements1;
    EXPECT_EQ(kSuccess, test_elements1.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements1.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              ShareInvitationFunction(),
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              ContactPresenceFunction()));
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    while (!done)
      Sleep(bptime::milliseconds(100));
    EXPECT_EQ(kSuccess, test_elements1.ConfirmContact(public_username1,
                                                      public_username2));
    EXPECT_EQ(kSuccess, test_elements1.LogOut());
    EXPECT_EQ(kSuccess, test_elements1.Finalise());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    done = false;
    LifeStuff test_elements2;
    EXPECT_EQ(kSuccess, test_elements2.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements2.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              ShareInvitationFunction(),
                                              NewContactFunction(),
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactProfilePictureFunction(),
                                              ContactPresenceFunction()));
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!done)
      Sleep(bptime::milliseconds(100));
    EXPECT_EQ(kSuccess, test_elements2.LogOut());
    EXPECT_EQ(kSuccess, test_elements2.Finalise());
  }
  {
    done = false;
    LifeStuff test_elements1;
    EXPECT_EQ(kSuccess, test_elements1.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements1.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              ShareInvitationFunction(),
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done)));
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    EXPECT_FALSE(done);
    EXPECT_EQ(kSuccess, test_elements1.LogOut());
    EXPECT_EQ(kSuccess, test_elements1.Finalise());
  }
}

TEST(IndependentFullTest, FUNC_ProfilePicture) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
//               public_username1(RandomAlphaNumericString(5)),
              public_username1("public_username1"),
              file_content1,
              file_content2(RandomString(900 * 1024));
  boost::system::error_code error_code;
  volatile bool done;

  DLOG(ERROR) << "\n\nCreating " << public_username1;
  {
    LifeStuff test_elements1;
    EXPECT_EQ(kSuccess, test_elements1.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements1.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              ShareInvitationFunction(),
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done)));
    EXPECT_EQ(kSuccess, test_elements1.CreateUser(username1, pin1, password1));
    EXPECT_EQ(kSuccess, test_elements1.CreatePublicId(public_username1));
    EXPECT_EQ(kSuccess, test_elements1.LogOut());
    EXPECT_EQ(kSuccess, test_elements1.Finalise());
  }
  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
//               public_username2(RandomAlphaNumericString(5));
              public_username2("public_username2");
  DLOG(ERROR) << "\n\n\n\nCreating " << public_username2;
  {
    LifeStuff test_elements2;
    EXPECT_EQ(kSuccess, test_elements2.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements2.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              ShareInvitationFunction(),
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done)));
    EXPECT_EQ(kSuccess, test_elements2.CreateUser(username2, pin2, password2));
    EXPECT_EQ(kSuccess, test_elements2.CreatePublicId(public_username2));
    EXPECT_EQ(kSuccess, test_elements2.AddContact(public_username2,
                                                  public_username1));
    EXPECT_EQ(kSuccess, test_elements2.LogOut());
    EXPECT_EQ(kSuccess, test_elements2.Finalise());
  }
  DLOG(ERROR) << "\n\n\n\nLoggin in " << public_username1;
  {
    done = false;
    LifeStuff test_elements1;
    EXPECT_EQ(kSuccess, test_elements1.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements1.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              ShareInvitationFunction(),
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              ContactPresenceFunction()));
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    while (!done)
      Sleep(bptime::milliseconds(100));
    EXPECT_EQ(kSuccess, test_elements1.ConfirmContact(public_username1,
                                                      public_username2));
    EXPECT_EQ(kSuccess, test_elements1.LogOut());
    EXPECT_EQ(kSuccess, test_elements1.Finalise());
  }
  DLOG(ERROR) << "\n\n\n\nLogging in " << public_username2;
  {
    done = false;
    LifeStuff test_elements2;
    EXPECT_EQ(kSuccess, test_elements2.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements2.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              ShareInvitationFunction(),
                                              NewContactFunction(),
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactProfilePictureFunction(),
                                              ContactPresenceFunction()));
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!done)
      Sleep(bptime::milliseconds(100));

    // Setting of profile image
    EXPECT_EQ(kSuccess, test_elements2.ChangeProfilePicture(public_username2,
                                                            file_content2));
    Sleep(bptime::seconds(1));

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
    EXPECT_EQ(kSuccess, test_elements2.Finalise());
  }
  DLOG(ERROR) << "\n\n\n\nLogging in " << public_username1;
  {
    done = false;
    LifeStuff test_elements1;
    EXPECT_EQ(kSuccess, test_elements1.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements1.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              ShareInvitationFunction(),
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactPresenceFunction()));
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    while (!done)
      Sleep(bptime::milliseconds(100));

    file_content1 = test_elements1.GetContactProfilePicture(public_username1,
                                                            public_username2);
    EXPECT_TRUE(file_content2 == file_content1);

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
    EXPECT_EQ(kSuccess, test_elements1.Finalise());
  }
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
