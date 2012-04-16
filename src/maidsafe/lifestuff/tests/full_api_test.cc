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

void DeleteContactSlot(const std::string&,
                       const std::string&,
                       const std::string &signal_message,
                       std::string *slot_message,
                       volatile bool *done) {
  *slot_message = signal_message;
  *done = true;
}

void PresenceSlot(const std::string&,
                  const std::string&,
                  ContactPresence,
                  volatile bool *done) {
  *done = true;
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

}  // namespace

class FixtureFullTest : public testing::Test {
 public:
  FixtureFullTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        mount_dir_(fs::initial_path() / "LifeStuff"),
        asio_service_(),
        interval_(1),
#ifndef LOCAL_TARGETS_ONLY
        client_container_(),
#endif
        remote_chunk_store_(),
        user_credentials_(),
        user_storage_(),
        session_(new Session),
        public_id_(),
        message_handler_(),
        public_username_(RandomAlphaNumericString(5)),
        username_(RandomString(6)),
        pin_(CreatePin()),
        password_(RandomString(6)) {}

 protected:
  void SetUp() {
    asio_service_.Start(5);
#ifdef LOCAL_TARGETS_ONLY
    remote_chunk_store_ = BuildChunkStore(*test_dir_ /
                                               RandomAlphaNumericString(8),
                                          *test_dir_ / "simulation",
                                          asio_service_.service());
#else
    remote_chunk_store_ = BuildChunkStore(*test_dir_, client_container_);
#endif
    EXPECT_TRUE(remote_chunk_store_.get() != nullptr);
    user_credentials_.reset(new UserCredentials(remote_chunk_store_, session_));

    public_id_.reset(new PublicId(remote_chunk_store_,
                                  session_,
                                  asio_service_.service()));

    message_handler_.reset(new MessageHandler(remote_chunk_store_,
                                              session_,
                                              asio_service_.service()));

    user_storage_.reset(new UserStorage(remote_chunk_store_, message_handler_));

    EXPECT_TRUE(user_credentials_->CreateUser(username_, pin_, password_));
    EXPECT_EQ(kSuccess, public_id_->CreatePublicId(public_username_, true));
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
#ifndef LOCAL_TARGETS_ONLY
  ClientContainerPtr client_container_;
#endif
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store_;
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
  std::string file_name(RandomAlphaNumericString(8)),
              file_content(RandomString(5 * 1024));
  fs::path file_path(user_storage_->mount_dir() / file_name);
  std::ofstream ofstream(file_path.c_str(), std::ios::binary);
  ofstream << file_content;
  ofstream.close();

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
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
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
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
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
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              ContactPresenceFunction(),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
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
                                              NewContactFunction(),
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactProfilePictureFunction(),
                                              ContactPresenceFunction(),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
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
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
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
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
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
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              ContactPresenceFunction(),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
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
                                              NewContactFunction(),
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactProfilePictureFunction(),
                                              ContactPresenceFunction(),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
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
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
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
              public_username1(RandomAlphaNumericString(5)),
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
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
    EXPECT_EQ(kSuccess, test_elements1.CreateUser(username1, pin1, password1));
    EXPECT_EQ(kSuccess, test_elements1.CreatePublicId(public_username1));
    EXPECT_EQ(kSuccess, test_elements1.LogOut());
    EXPECT_EQ(kSuccess, test_elements1.Finalise());
  }
  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_username2(RandomAlphaNumericString(5));
  DLOG(ERROR) << "\n\n\n\nCreating " << public_username2;
  {
    LifeStuff test_elements2;
    EXPECT_EQ(kSuccess, test_elements2.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements2.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
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
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              ContactPresenceFunction(),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
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
                                              NewContactFunction(),
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactProfilePictureFunction(),
                                              ContactPresenceFunction(),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
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
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactPresenceFunction(),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
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

TEST(IndependentFullTest, FUNC_RemoveContact) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
              public_username1(RandomAlphaNumericString(5)),
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
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
    EXPECT_EQ(kSuccess, test_elements1.CreateUser(username1, pin1, password1));
    EXPECT_EQ(kSuccess, test_elements1.CreatePublicId(public_username1));
    EXPECT_EQ(kSuccess, test_elements1.LogOut());
    EXPECT_EQ(kSuccess, test_elements1.Finalise());
  }
  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_username2(RandomAlphaNumericString(5));
  DLOG(ERROR) << "\n\n\n\nCreating " << public_username2;
  {
    LifeStuff test_elements2;
    EXPECT_EQ(kSuccess, test_elements2.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements2.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              std::bind(&PresenceSlot, args::_1,
                                                        args::_2, args::_3,
                                                        &done),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
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
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              ContactPresenceFunction(),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
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
                                              NewContactFunction(),
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactProfilePictureFunction(),
                                              ContactPresenceFunction(),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!done)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
    EXPECT_EQ(kSuccess, test_elements2.Finalise());
  }
  DLOG(ERROR) << "\n\n\n\nLogging in " << public_username1;
  std::string removal_message("It's not me, it's you.");
  {
    done = false;
    LifeStuff test_elements1;
    EXPECT_EQ(kSuccess, test_elements1.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements1.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              std::bind(&TwoStringsAndBoolSlot,
                                                        args::_1, args::_2,
                                                        &done),
                                              ContactPresenceFunction(),
                                              ContactDeletionFunction(),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    EXPECT_EQ(kSuccess, test_elements1.RemoveContact(public_username1,
                                                     public_username2,
                                                     removal_message));
    EXPECT_TRUE(test_elements1.GetContacts(public_username1).empty());

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
    EXPECT_EQ(kSuccess, test_elements1.Finalise());
  }
  DLOG(ERROR) << "\n\n\n\nLogging in " << public_username2;
  {
    done = false;
    std::string message2;
    LifeStuff test_elements2;
    EXPECT_EQ(kSuccess, test_elements2.Initialise(*test_dir));
    EXPECT_EQ(kSuccess,
              test_elements2.ConnectToSignals(ChatFunction(),
                                              FileTransferFunction(),
                                              NewContactFunction(),
                                              ContactConfirmationFunction(),
                                              ContactProfilePictureFunction(),
                                              ContactPresenceFunction(),
                                              std::bind(&DeleteContactSlot,
                                                        args::_1, args::_2,
                                                        args::_3, &message2,
                                                        &done),
                                              ShareInvitationFunction(),
                                              ShareDeletionFunction(),
                                              MemberAccessLevelFunction()));
    DLOG(ERROR) << "beofre Login";
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    DLOG(ERROR) << "After Login";
    while (!done)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(removal_message, message2);
    bool contact_deleted(false);
    while (!contact_deleted)
      contact_deleted = test_elements2.GetContacts(public_username2).empty();
    EXPECT_TRUE(contact_deleted);

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
    EXPECT_EQ(kSuccess, test_elements2.Finalise());
  }
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
