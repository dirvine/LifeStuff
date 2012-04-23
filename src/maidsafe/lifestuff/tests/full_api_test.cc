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

struct TestingVariables {
  TestingVariables()
      : chat_message(),
        chat_message_received(false),
        file_name(),
        file_id(),
        file_transfer_received(false),
        newly_contacted(false),
        confirmed(false),
        picture_updated(false),
        presence_announced(false),
        removal_message(),
        removed(false),
        new_private_share_id(),
        privately_invited(false),
        deleted_private_share_name(),
        private_share_deleted(false),
        access_private_share_name(),
        private_member_access(0),
        private_member_access_changed(false) {}
  std::string chat_message;
  bool chat_message_received;
  std::string file_name, file_id;
  bool file_transfer_received,
       newly_contacted,
       confirmed,
       picture_updated,
       presence_announced;
  std::string removal_message;
  bool removed;
  std::string new_private_share_id;
  bool privately_invited;
  std::string deleted_private_share_name;
  bool private_share_deleted;
  std::string access_private_share_name;
  int private_member_access;
  bool private_member_access_changed;
};

void ChatSlot(const std::string&,
              const std::string&,
              const std::string &signal_message,
              std::string *slot_message,
              volatile bool *done) {
  if (slot_message)
    *slot_message = signal_message;
  *done = true;
}

void FileTransferSlot(const std::string&,
                      const std::string&,
                      const std::string &signal_file_name,
                      const std::string &signal_file_id,
                      std::string *slot_file_name,
                      std::string *slot_file_id,
                      volatile bool *done) {
  if (slot_file_name)
    *slot_file_name = signal_file_name;
  if (slot_file_id)
    *slot_file_id = signal_file_id;
  *done = true;
}

void NewContactSlot(const std::string&,
                    const std::string&,
                    volatile bool *done) {
  *done = true;
}


void ContactConfirmationSlot(const std::string&,
                             const std::string&,
                             volatile bool *done) {
  *done = true;
}

void ContactProfilePictureSlot(const std::string&,
                               const std::string&,
                               volatile bool *done) {
  *done = true;
}

void ContactPresenceSlot(const std::string&,
                         const std::string&,
                         ContactPresence,
                         volatile bool *done) {
  *done = true;
}

void ContactDeletionSlot(const std::string&,
                         const std::string&,
                         const std::string &signal_message,
                         std::string *slot_message,
                         volatile bool *done) {
  if (slot_message)
    *slot_message = signal_message;
  *done = true;
}

void ShareInvitationSlot(const std::string&,
                         const std::string&,
                         const std::string&,
                         const std::string &signal_share_id,
                         std::string *slot_share_id,
                         volatile bool *done) {
  if (slot_share_id)
    *slot_share_id = signal_share_id;
  *done = true;
}

void ShareDeletionSlot(const std::string&,
                       const std::string &signal_share_name,
                       std::string *slot_share_name,
                       volatile bool *done) {
  if (slot_share_name)
    *slot_share_name = signal_share_name;
  *done = true;
}

void MemberAccessLevelSlot(const std::string&,
                           const std::string&,
                           const std::string &signal_share_name,
                           int signal_member_access,
                           std::string *slot_share_name,
                           int *slot_member_access,
                           volatile bool *done) {
  if (slot_share_name)
    *slot_share_name = signal_share_name;
  if (slot_member_access)
    *slot_member_access = signal_member_access;
  *done = true;
}

int CreateAndConnectTwoPublicIds(LifeStuff &test_elements1,  // NOLINT (Dan)
                                 LifeStuff &test_elements2,  // NOLINT (Dan)
                                 TestingVariables &testing_variables1,  // NOLINT (Dan)
                                 TestingVariables &testing_variables2,  // NOLINT (Dan)
                                 const fs::path &test_dir,
                                 const std::string &username1,
                                 const std::string &pin1,
                                 const std::string &password1,
                                 const std::string &public_id1,
                                 const std::string &username2,
                                 const std::string &pin2,
                                 const std::string &password2,
                                 const std::string &public_id2) {
  int result(0);
  // Initialise and connect
  result += test_elements1.Initialise(test_dir);
  result += test_elements2.Initialise(test_dir);
  result += test_elements1.ConnectToSignals(
                std::bind(&ChatSlot, args::_1, args::_2, args::_3,
                          &testing_variables1.chat_message,
                          &testing_variables1.chat_message_received),
                std::bind(&FileTransferSlot,
                          args::_1, args::_2, args::_3, args::_4,
                          &testing_variables1.file_name,
                          &testing_variables1.file_id,
                          &testing_variables1.file_transfer_received),
                std::bind(&NewContactSlot, args::_1, args::_2,
                          &testing_variables1.newly_contacted),
                std::bind(&ContactConfirmationSlot, args::_1, args::_2,
                          &testing_variables1.confirmed),
                std::bind(&ContactProfilePictureSlot, args::_1, args::_2,
                          &testing_variables1.picture_updated),
                std::bind(&ContactPresenceSlot, args::_1, args::_2, args::_3,
                          &testing_variables1.presence_announced),
                std::bind(&ContactDeletionSlot, args::_1, args::_2, args::_3,
                          &testing_variables1.removal_message,
                          &testing_variables1.removed),
                std::bind(&ShareInvitationSlot,
                          args::_1, args::_2, args::_3, args::_4,
                          &testing_variables1.new_private_share_id,
                          &testing_variables1.privately_invited),
                std::bind(&ShareDeletionSlot, args::_1, args::_2,
                          &testing_variables1.deleted_private_share_name,
                          &testing_variables1.private_share_deleted),
                std::bind(&MemberAccessLevelSlot,
                          args::_1, args::_2, args::_3, args::_4,
                          &testing_variables1.access_private_share_name,
                          &testing_variables1.private_member_access,
                          &testing_variables1.private_member_access_changed));
  result += test_elements2.ConnectToSignals(
                std::bind(&ChatSlot, args::_1, args::_2, args::_3,
                          &testing_variables2.chat_message,
                          &testing_variables2.chat_message_received),
                std::bind(&FileTransferSlot,
                          args::_1, args::_2, args::_3, args::_4,
                          &testing_variables2.file_name,
                          &testing_variables2.file_id,
                          &testing_variables2.file_transfer_received),
                std::bind(&NewContactSlot, args::_1, args::_2,
                          &testing_variables2.newly_contacted),
                std::bind(&ContactConfirmationSlot, args::_1, args::_2,
                          &testing_variables2.confirmed),
                std::bind(&ContactProfilePictureSlot, args::_1, args::_2,
                          &testing_variables2.picture_updated),
                std::bind(&ContactPresenceSlot, args::_1, args::_2, args::_3,
                          &testing_variables2.presence_announced),
                std::bind(&ContactDeletionSlot, args::_1, args::_2, args::_3,
                          &testing_variables2.removal_message,
                          &testing_variables2.removed),
                std::bind(&ShareInvitationSlot,
                          args::_1, args::_2, args::_3, args::_4,
                          &testing_variables2.new_private_share_id,
                          &testing_variables2.privately_invited),
                std::bind(&ShareDeletionSlot, args::_1, args::_2,
                          &testing_variables2.deleted_private_share_name,
                          &testing_variables2.private_share_deleted),
                std::bind(&MemberAccessLevelSlot,
                          args::_1, args::_2, args::_3, args::_4,
                          &testing_variables2.access_private_share_name,
                          &testing_variables2.private_member_access,
                          &testing_variables2.private_member_access_changed));
  if (result != kSuccess)
    return result;

  {
    result += test_elements1.CreateUser(username1, pin1, password1);
    result += test_elements1.CreatePublicId(public_id1);
    result += test_elements1.LogOut();
    if (result != kSuccess)
      return result;
  }
  {
    result += test_elements2.CreateUser(username2, pin2, password2);
    result += test_elements2.CreatePublicId(public_id2);
    result += test_elements2.AddContact(public_id2, public_id1);
    result += test_elements2.LogOut();
    if (result != kSuccess)
      return result;
  }
  {
    result += test_elements1.LogIn(username1, pin1, password1);

    while (!testing_variables1.newly_contacted)
      Sleep(bptime::milliseconds(100));

    result += test_elements1.ConfirmContact(public_id1, public_id2);
    result += test_elements1.LogOut();
    if (result != kSuccess)
      return result;
  }
  {
    result += test_elements2.LogIn(username2, pin2, password2);
    while (!testing_variables2.confirmed)
      Sleep(bptime::milliseconds(100));
    result += test_elements2.LogOut();
    if (result != kSuccess)
      return result;
  }

  return result;
}

}  // namespace

TEST(IndependentFullTest, FUNC_CreateDirectoryLogoutLoginCheckDirectory) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username(RandomString(6)),
              pin(CreatePin()),
              password(RandomString(6));
  boost::system::error_code error_code;
  volatile bool done;

  LifeStuff test_elements1;
  EXPECT_EQ(kSuccess, test_elements1.Initialise(*test_dir));
  EXPECT_EQ(kSuccess,
            test_elements1.ConnectToSignals(ChatFunction(),
                                            FileTransferFunction(),
                                            NewContactFunction(),
                                            ContactConfirmationFunction(),
                                            ContactProfilePictureFunction(),
                                            std::bind(&ContactPresenceSlot,
                                                      args::_1, args::_2,
                                                      args::_3, &done),
                                            ContactDeletionFunction(),
                                            ShareInvitationFunction(),
                                            ShareDeletionFunction(),
                                            MemberAccessLevelFunction()));
  EXPECT_EQ(kSuccess, test_elements1.CreateUser(username, pin, password));
  // Create directory
  std::string tail;
  fs::path test(CreateTestDirectory(test_elements1.mount_path(), &tail));
  EXPECT_TRUE(fs::exists(test, error_code));
  EXPECT_EQ(0, error_code.value());

  // Log out - Log in
  EXPECT_EQ(kSuccess, test_elements1.LogOut());
  EXPECT_EQ(kSuccess, test_elements1.LogIn(username, pin, password));

  // Check directory exists
  EXPECT_TRUE(fs::exists(test, error_code));
  EXPECT_EQ(0, error_code.value());
  EXPECT_EQ(kSuccess, test_elements1.LogOut());
  EXPECT_EQ(kSuccess, test_elements1.Finalise());
}

TEST(IndependentFullTest, FUNC_ChangeCredentials) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username(RandomString(6)),
              pin(CreatePin()),
              password(RandomString(6));
  volatile bool done;

  LifeStuff test_elements1;
  EXPECT_EQ(kSuccess, test_elements1.Initialise(*test_dir));
  EXPECT_EQ(kSuccess,
            test_elements1.ConnectToSignals(ChatFunction(),
                                            FileTransferFunction(),
                                            NewContactFunction(),
                                            ContactConfirmationFunction(),
                                            ContactProfilePictureFunction(),
                                            std::bind(&ContactPresenceSlot,
                                                      args::_1, args::_2,
                                                      args::_3, &done),
                                            ContactDeletionFunction(),
                                            ShareInvitationFunction(),
                                            ShareDeletionFunction(),
                                            MemberAccessLevelFunction()));
  EXPECT_EQ(kSuccess, test_elements1.CreateUser(username, pin, password));
  EXPECT_EQ(kSuccess, test_elements1.CheckPassword(password));
  EXPECT_EQ(kSuccess, test_elements1.LogOut());

  EXPECT_EQ(kSuccess, test_elements1.LogIn(username, pin, password));
  EXPECT_EQ(kSuccess, test_elements1.CheckPassword(password));

  // Change credentials
  EXPECT_EQ(kSuccess, test_elements1.ChangeKeyword(username,
                                                   username + username,
                                                   password));
  EXPECT_EQ(kSuccess, test_elements1.ChangePin(pin, pin + "0", password));
  EXPECT_EQ(kSuccess, test_elements1.ChangePassword(password,
                                                    password + password));

  EXPECT_EQ(kSuccess, test_elements1.LogOut());

  EXPECT_EQ(kSuccess, test_elements1.LogIn(username + username,
                                           pin + "0",
                                           password + password));
  EXPECT_EQ(kSuccess, test_elements1.ChangeKeyword(username + username,
                                                   username,
                                                   password + password));
  EXPECT_EQ(kSuccess, test_elements1.LogOut());

  EXPECT_EQ(kSuccess, test_elements1.LogIn(username,
                                           pin + "0",
                                           password + password));
  EXPECT_EQ(kSuccess, test_elements1.ChangePin(pin + "0",
                                               pin,
                                               password + password));
  EXPECT_EQ(kSuccess, test_elements1.LogOut());

  EXPECT_EQ(kSuccess, test_elements1.LogIn(username, pin, password + password));
  EXPECT_EQ(kSuccess, test_elements1.ChangePassword(password + password,
                                                    password));
  EXPECT_EQ(kSuccess, test_elements1.LogOut());

  EXPECT_EQ(kSuccess, test_elements1.LogIn(username, pin, password));
  EXPECT_EQ(kSuccess, test_elements1.CheckPassword(password));
  EXPECT_EQ(kSuccess, test_elements1.LogOut());
  EXPECT_EQ(kSuccess, test_elements1.Finalise());
}

TEST(IndependentFullTest, FUNC_SendFile) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  EXPECT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));

  boost::system::error_code error_code;
  fs::path file_path1, file_path2;
  std::string file_name1(RandomAlphaNumericString(8)),
              file_content1(RandomString(5 * 1024)),
              file_name2(RandomAlphaNumericString(8));
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    file_path1 = test_elements1.mount_path() / file_name1;
    std::ofstream ofstream(file_path1.c_str(), std::ios::binary);
    ofstream << file_content1;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess,
              test_elements1.SendFile(public_id1, public_id2, file_path1));

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.file_transfer_received)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables2.file_id.empty());
    EXPECT_EQ(file_name1, testing_variables2.file_name);
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptSentFile(test_elements2.mount_path() /
                                                file_name2,
                                            testing_variables2.file_id));

    EXPECT_TRUE(fs::exists(test_elements2.mount_path() / file_name2,
                           error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST(IndependentFullTest, FUNC_ProfilePicture) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  EXPECT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));

  std::string file_content1, file_content2(RandomString(5 * 1024));
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    // Setting of profile image
    EXPECT_EQ(kSuccess, test_elements2.ChangeProfilePicture(public_id2,
                                                            file_content2));
    Sleep(bptime::seconds(1));

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    while (!testing_variables1.picture_updated)
      Sleep(bptime::milliseconds(100));

    file_content1 = test_elements1.GetContactProfilePicture(public_id1,
                                                            public_id2);
    EXPECT_TRUE(file_content2 == file_content1);

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST(IndependentFullTest, FUNC_RemoveContact) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  EXPECT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));

  DLOG(ERROR) << "\n\n\n\n";
  std::string removal_message("It's not me, it's you.");
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    EXPECT_EQ(kSuccess, test_elements1.RemoveContact(public_id1,
                                                     public_id2,
                                                     removal_message));
    EXPECT_TRUE(test_elements1.GetContacts(public_id1).empty());

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.removed)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(removal_message, testing_variables2.removal_message);
    bool contact_deleted(false);
    while (!contact_deleted)
      contact_deleted = test_elements2.GetContacts(public_id2).empty();
    EXPECT_TRUE(contact_deleted);

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

class PrivateSharesApiTest : public ::testing::TestWithParam<int> {
 public:
  PrivateSharesApiTest() : rights_(GetParam()) {}

 protected:
  int rights_;
};

INSTANTIATE_TEST_CASE_P(ReadOnlyReadWrite,
                        PrivateSharesApiTest,
                        testing::Values(0, 1));

TEST_P(PrivateSharesApiTest, FUNC_CreateEmptyPrivateShare) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  EXPECT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));

  DLOG(ERROR) << "\n\n\n\n";
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id2, rights_));
    results.insert(std::make_pair(public_id2, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements1.CreateEmptyPrivateShare(public_id1,
                                                               contacts,
                                                               &share_name1,
                                                               &results));

    fs::path share_path(test_elements1.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id2]);

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables2.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptPrivateShareInvitation(
                  &share_name1,
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id));

    fs::path share_path(test_elements2.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));

    fs::path a_file_path(share_path / file_name1);
    if (rights_ == 0) {
      EXPECT_FALSE(WriteFile(a_file_path, file_content2));
      EXPECT_FALSE(fs::exists(a_file_path, error_code));
      EXPECT_NE(0, error_code.value());
    } else {
      EXPECT_TRUE(WriteFile(a_file_path, file_content2));
      EXPECT_TRUE(fs::exists(a_file_path, error_code));
      EXPECT_EQ(0, error_code.value());
    }

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    fs::path share_path(test_elements1.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    fs::path a_file_path(share_path / file_name1);
    if (rights_ == 0) {
      EXPECT_TRUE(WriteFile(a_file_path, file_content1));
      EXPECT_TRUE(fs::exists(a_file_path, error_code));
      EXPECT_EQ(0, error_code.value());
    } else {
      std::string file_stuff;
      EXPECT_TRUE(ReadFile(a_file_path, &file_stuff));
      EXPECT_EQ(file_content2, file_stuff);
      EXPECT_TRUE(WriteFile(a_file_path, file_content1));
    }

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));

    fs::path share_path(test_elements2.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    fs::path a_file_path(share_path / file_name1);
    EXPECT_TRUE(fs::exists(a_file_path, error_code)) << a_file_path;
    EXPECT_NE(0, error_code.value());

    std::string a_file_content;
    EXPECT_TRUE(ReadFile(a_file_path, &a_file_content));
    EXPECT_EQ(file_content1, a_file_content);

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST_P(PrivateSharesApiTest, FUNC_FromExistingDirectoryPrivateShare) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  EXPECT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));

  DLOG(ERROR) << "\n\n\n\n";
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_name2(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    // Create directory with contents to share
    fs::path share_path(test_elements1.mount_path() /
                        fs::path("/").make_preferred() /
                        kMyStuff /
                        share_name1);
    fs::create_directories(share_path, error_code);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value()) << share_path;
    EXPECT_TRUE(WriteFile(share_path / file_name1, file_content1))
                << (share_path / file_name1);


    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id2, rights_));
    results.insert(std::make_pair(public_id2, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements1.CreatePrivateShareFromExistingDirectory(
                  public_id1,
                  share_path,
                  contacts,
                  &share_name1,
                  &results));

    EXPECT_FALSE(fs::exists(share_path, error_code)) << share_path;
    share_path = test_elements1.mount_path() /
                 fs::path("/").make_preferred() /
                 kSharedStuff /
                 share_name1;
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id2]);

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables2.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptPrivateShareInvitation(
                  &share_name1,
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id));

    fs::path share_path(test_elements2.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));
    EXPECT_EQ(0, error_code.value());

    // Read the existing file
    std::string file_in_share_content;
    EXPECT_TRUE(ReadFile(share_path / file_name1, &file_in_share_content));
    EXPECT_EQ(file_content1, file_in_share_content);

    fs::path a_file_path(share_path / file_name2);
    if (rights_ == 0) {
      EXPECT_FALSE(WriteFile(a_file_path, file_content2));
      EXPECT_FALSE(fs::exists(a_file_path, error_code));
      EXPECT_NE(0, error_code.value());
    } else {
      EXPECT_TRUE(WriteFile(a_file_path, file_content2));
      EXPECT_TRUE(fs::exists(a_file_path, error_code));
      EXPECT_EQ(0, error_code.value());
    }

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    fs::path share_path(test_elements1.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    fs::path a_file_path(share_path / file_name2);
    std::string file_stuff;
    if (rights_ == 0) {
      EXPECT_FALSE(ReadFile(a_file_path, &file_stuff));
      EXPECT_TRUE(file_stuff.empty());
    } else {
      EXPECT_TRUE(ReadFile(a_file_path, &file_stuff));
      EXPECT_EQ(file_content2, file_stuff);
    }
    EXPECT_TRUE(WriteFile(a_file_path, file_content1));

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));

    fs::path share_path(test_elements2.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    fs::path a_file_path(share_path / file_name2);
    std::string a_file_content;

    EXPECT_TRUE(ReadFile(a_file_path, &a_file_content));
    EXPECT_EQ(file_content1, a_file_content);

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST_P(PrivateSharesApiTest, FUNC_RejectInvitationPrivateShare) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  EXPECT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));

  DLOG(ERROR) << "\n\n\n\n";
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_name2(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    // Create directory with contents to share
    fs::path share_path(test_elements1.mount_path() /
                        fs::path("/").make_preferred() /
                        kMyStuff /
                        share_name1);
    fs::create_directories(share_path, error_code);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value()) << share_path;
    EXPECT_TRUE(WriteFile(share_path / file_name1, file_content1))
                << (share_path / file_name1);


    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id2, rights_));
    results.insert(std::make_pair(public_id2, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements1.CreatePrivateShareFromExistingDirectory(
                  public_id1,
                  share_path,
                  contacts,
                  &share_name1,
                  &results));

    EXPECT_FALSE(fs::exists(share_path, error_code)) << share_path;
    share_path = test_elements1.mount_path() /
                 fs::path("/").make_preferred() /
                 kSharedStuff /
                 share_name1;
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id2]);

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables2.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements2.RejectPrivateShareInvitation(
                  public_id2,
                  testing_variables2.new_private_share_id));

    fs::path share_path(test_elements2.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    EXPECT_FALSE(fs::exists(share_path, error_code));
    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST_P(PrivateSharesApiTest, FUNC_DeletePrivateShare) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  EXPECT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));

  DLOG(ERROR) << "\n\n\n\n";
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id2, rights_));  // Read only rights
    results.insert(std::make_pair(public_id2, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements1.CreateEmptyPrivateShare(public_id1,
                                                               contacts,
                                                               &share_name1,
                                                               &results));

    fs::path share_path(test_elements1.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id2]);

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables2.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptPrivateShareInvitation(
                  &share_name1,
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id));

    fs::path share_path(test_elements2.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));
    EXPECT_EQ(0, error_code.value());

    // Check only owner can delete
    EXPECT_NE(kSuccess, test_elements2.DeletePrivateShare(public_id2,
                                                          share_name1));
    EXPECT_TRUE(fs::is_directory(share_path, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    EXPECT_EQ(kSuccess, test_elements1.DeletePrivateShare(public_id1,
                                                          share_name1));
    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.private_share_deleted)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(share_name1, testing_variables2.deleted_private_share_name);
    fs::path share_path(test_elements1.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    EXPECT_FALSE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST_P(PrivateSharesApiTest, FUNC_LeavePrivateShare) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  EXPECT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));

  DLOG(ERROR) << "\n\n\n\n";
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id2, rights_));  // Read only rights
    results.insert(std::make_pair(public_id2, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements1.CreateEmptyPrivateShare(public_id1,
                                                               contacts,
                                                               &share_name1,
                                                               &results));

    fs::path share_path(test_elements1.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id2]);

    // Check owner can't leave
    EXPECT_NE(kSuccess, test_elements1.LeavePrivateShare(public_id1,
                                                         share_name1));
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables2.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptPrivateShareInvitation(
                  &share_name1,
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id));

    fs::path share_path(test_elements2.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements2.LeavePrivateShare(public_id2,
                                                         share_name1));

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    // TODO(Team): Wait till message from member arrives
    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));

    EXPECT_EQ(share_name1, testing_variables2.deleted_private_share_name);
    fs::path share_path(test_elements1.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    EXPECT_FALSE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}


TEST(IndependentFullTest, FUNC_MembershipDowngradePrivateShare) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  EXPECT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));

  DLOG(ERROR) << "\n\n\n\n";
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id2, 1));  // Admin rights
    results.insert(std::make_pair(public_id2, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements1.CreateEmptyPrivateShare(public_id1,
                                                               contacts,
                                                               &share_name1,
                                                               &results));

    fs::path share_path(test_elements1.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id2]);

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables2.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptPrivateShareInvitation(
                  &share_name1,
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id));

    fs::path share_path(test_elements2.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));

    fs::path a_file_path(share_path / file_name1);
    EXPECT_TRUE(WriteFile(a_file_path, file_content2));
    EXPECT_TRUE(fs::exists(a_file_path, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    StringIntMap amendments, results;
    amendments.insert(std::make_pair(public_id2, 0));
    EXPECT_EQ(kSuccess, test_elements1.EditPrivateShareMembers(public_id1,
                                                               amendments,
                                                               share_name1,
                                                               &results));
    EXPECT_EQ(kSuccess, results[public_id2]);
    results[public_id2] = -1;
    EXPECT_EQ(kSuccess, test_elements1.GetPrivateShareMemebers(public_id1,
                                                               share_name1,
                                                               &results));
    EXPECT_EQ(0, results[public_id2]);  // ro now

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));

    while (!testing_variables2.private_member_access_changed)
      Sleep(bptime::milliseconds(100));
    StringIntMap shares;
    EXPECT_EQ(kSuccess,
              test_elements2.GetPrivateShareList(public_id2, &shares));

    EXPECT_EQ(1U, shares.size());
    EXPECT_FALSE(shares.find(share_name1) == shares.end());
    EXPECT_EQ(0, shares[share_name1]);  // ro

    fs::path share_path(test_elements2.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    fs::path a_file_path(share_path / file_name1);
    EXPECT_FALSE(WriteFile(a_file_path, file_content1));

    std::string local_content;
    EXPECT_TRUE(ReadFile(a_file_path, &local_content));
    EXPECT_EQ(file_content2, local_content);

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST(IndependentFullTest, FUNC_MembershipUpgradePrivateShare) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomString(6)),
              pin1(CreatePin()),
              password1(RandomString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomString(6)),
              pin2(CreatePin()),
              password2(RandomString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  EXPECT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));

  DLOG(ERROR) << "\n\n\n\n";
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id2, 0));  // Read only rights
    results.insert(std::make_pair(public_id2, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements1.CreateEmptyPrivateShare(public_id1,
                                                               contacts,
                                                               &share_name1,
                                                               &results));

    fs::path share_path(test_elements1.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id2]);

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables2.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptPrivateShareInvitation(
                  &share_name1,
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id));

    fs::path share_path(test_elements2.mount_path() /
                        fs::path("/").make_preferred() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));

    fs::path a_file_path(share_path / file_name1);
    EXPECT_FALSE(WriteFile(a_file_path, file_content2));
    EXPECT_FALSE(fs::exists(a_file_path, error_code));
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    StringIntMap amendments, results;
    amendments.insert(std::make_pair(public_id2, 1));  // rw
    EXPECT_EQ(kSuccess, test_elements1.EditPrivateShareMembers(public_id1,
                                                               amendments,
                                                               share_name1,
                                                               &results));
    EXPECT_EQ(kSuccess, results[public_id2]);
    results[public_id2] = -1;
    EXPECT_EQ(kSuccess, test_elements1.GetPrivateShareMemebers(public_id1,
                                                               share_name1,
                                                               &results));
    EXPECT_EQ(1U, results[public_id2]);  // rq now

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));

    while (!testing_variables2.private_member_access_changed)
      Sleep(bptime::milliseconds(100));
    StringIntMap shares;
    EXPECT_EQ(kSuccess,
              test_elements2.GetPrivateShareList(public_id2, &shares));

    EXPECT_EQ(1U, shares.size());
    EXPECT_FALSE(shares.find(share_name1) == shares.end());
    EXPECT_EQ(1U, shares[share_name1]);

    fs::path share_path(test_elements2.mount_path() /
                    fs::path("/").make_preferred() /
                    kSharedStuff /
                    share_name1);
    fs::path a_file_path(share_path / file_name1);
    EXPECT_TRUE(WriteFile(a_file_path, file_content2));
    EXPECT_TRUE(fs::exists(a_file_path, error_code));
    EXPECT_EQ(0, error_code.value());

    std::string local_content;
    EXPECT_TRUE(ReadFile(a_file_path, &local_content));
    EXPECT_EQ(file_content2, local_content);

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
