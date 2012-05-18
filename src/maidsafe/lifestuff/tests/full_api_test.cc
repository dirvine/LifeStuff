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

#include <functional>
#include <sstream>

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/pd/client/client_container.h"
#endif

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/lifestuff_api.h"
#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/message_handler.h"
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
        new_private_share_name(),
        new_private_share_id(),
        new_private_access_level(-1),
        privately_invited(false),
        new_open_share_id(),
        openly_invited(false),
        deleted_private_share_name(),
        private_share_deleted(false),
        access_private_share_name(),
        private_member_access(0),
        private_member_access_changed(false),
        old_share_name(),
        new_share_name(),
        share_renamed(false) {}
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
  std::string new_private_share_name, new_private_share_id;
  int new_private_access_level;
  bool privately_invited;
  std::string new_open_share_id;
  bool openly_invited;
  std::string deleted_private_share_name;
  bool private_share_deleted;
  std::string access_private_share_name;
  int private_member_access;
  bool private_member_access_changed;
  std::string old_share_name;
  std::string new_share_name;
  bool share_renamed;
};

void ChatSlot(const std::string&,
              const std::string&,
              const std::string &signal_message,
              const std::string&,
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
                      const std::string&,
                      std::string *slot_file_name,
                      std::string *slot_file_id,
                      volatile bool *done) {
  if (slot_file_name)
    *slot_file_name = signal_file_name;
  if (slot_file_id)
    *slot_file_id = signal_file_id;
  *done = true;
}

void MultipleFileTransferSlot(const std::string&,
                              const std::string&,
                              const std::string &signal_file_name,
                              const std::string &signal_file_id,
                              const std::string&,
                              std::vector<std::string> *ids,
                              std::vector<std::string> *names,
                              size_t *total_files,
                              volatile bool *done) {
  ids->push_back(signal_file_id);
  names->push_back(signal_file_name);
  if (ids->size() == *total_files)
    *done = true;
}

void NewContactSlot(const std::string&,
                    const std::string&,
                    const std::string&,
                    volatile bool *done) {
  *done = true;
}


void ContactConfirmationSlot(const std::string&,
                             const std::string&,
                             const std::string&,
                             volatile bool *done) {
  *done = true;
}

void ContactProfilePictureSlot(const std::string&,
                               const std::string&,
                               const std::string&,
                               volatile bool *done) {
  *done = true;
}

void ContactPresenceSlot(const std::string&,
                         const std::string&,
                         const std::string&,
                         ContactPresence,
                         volatile bool *done) {
  *done = true;
}

void ContactDeletionSlot(const std::string&,
                         const std::string&,
                         const std::string &signal_message,
                         const std::string&,
                         std::string *slot_message,
                         volatile bool *done) {
  if (slot_message)
    *slot_message = signal_message;
  *done = true;
}

void PrivateShareInvitationSlot(const std::string&,
                                const std::string&,
                                const std::string &signal_share_name,
                                const std::string &signal_share_id,
                                int access_level,
                                const std::string&,
                                std::string *slot_share_name,
                                std::string *slot_share_id,
                                int *slot_access_level,
                                volatile bool *done) {
  if (slot_share_name)
    *slot_share_name = signal_share_name;
  if (slot_share_id)
    *slot_share_id = signal_share_id;
  if (slot_access_level)
    *slot_access_level = access_level;
  *done = true;
}

void PrivateShareDeletionSlot(const std::string&,
                              const std::string &signal_share_name,
                              const std::string&,
                              const std::string&,
                              const std::string&,
                              std::string *slot_share_name,
                              volatile bool *done) {
  if (slot_share_name)
    *slot_share_name = signal_share_name;
  *done = true;
}

void PrivateMemberAccessLevelSlot(const std::string&,
                                  const std::string&,
                                  const std::string&,
                                  const std::string &signal_share_name,
                                  int signal_member_access,
                                  const std::string&,
                                  std::string *slot_share_name,
                                  int *slot_member_access,
                                  volatile bool *done) {
  if (slot_share_name)
    *slot_share_name = signal_share_name;
  if (slot_member_access)
    *slot_member_access = signal_member_access;
  *done = true;
}

void OpenShareInvitationSlot(const std::string&,
                             const std::string&,
                             const std::string& signal_share_id,
                             const std::string&,
                             const std::string&,
                             std::string *slot_share_id,
                             volatile bool *done) {
  if (slot_share_id)
    *slot_share_id = signal_share_id;
  *done = true;
}

void ShareRenameSlot(const std::string& old_share_name,
                     const std::string& new_share_name,
                     std::string *slot_old_share_name,
                     std::string *slot_new_share_name,
                     volatile bool *done) {
  if (slot_old_share_name)
    *slot_old_share_name = old_share_name;
  if (slot_new_share_name)
    *slot_new_share_name = new_share_name;
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
                                 const std::string &public_id2,
                                 bool several_files = false,
                                 std::vector<std::string> *ids = nullptr,
                                 std::vector<std::string> *names = nullptr,
                                 size_t *total_files = nullptr) {
  FileTransferFunction ftf(
      std::bind(&FileTransferSlot,
                args::_1, args::_2, args::_3, args::_4, args::_5,
                &testing_variables2.file_name,
                &testing_variables2.file_id,
                &testing_variables2.file_transfer_received));
  if (several_files) {
    ftf = std::bind(&MultipleFileTransferSlot,
                    args::_1, args::_2, args::_3, args::_4, args::_5,
                    ids, names, total_files,
                    &testing_variables2.file_transfer_received);
  }
  int result(0);
  // Initialise and connect
  result += test_elements1.Initialise(test_dir);
  result += test_elements2.Initialise(test_dir);
  result += test_elements1.ConnectToSignals(
                std::bind(&ChatSlot, args::_1, args::_2, args::_3, args::_4,
                          &testing_variables1.chat_message,
                          &testing_variables1.chat_message_received),
                std::bind(&FileTransferSlot,
                          args::_1, args::_2, args::_3, args::_4, args::_5,
                          &testing_variables1.file_name,
                          &testing_variables1.file_id,
                          &testing_variables1.file_transfer_received),
                std::bind(&NewContactSlot, args::_1, args::_2, args::_3,
                          &testing_variables1.newly_contacted),
                std::bind(&ContactConfirmationSlot,
                          args::_1, args::_2, args::_3,
                          &testing_variables1.confirmed),
                std::bind(&ContactProfilePictureSlot,
                          args::_1, args::_2, args::_3,
                          &testing_variables1.picture_updated),
                std::bind(&ContactPresenceSlot,
                          args::_1, args::_2, args::_3, args::_4,
                          &testing_variables1.presence_announced),
                std::bind(&ContactDeletionSlot,
                          args::_1, args::_2, args::_3, args::_4,
                          &testing_variables1.removal_message,
                          &testing_variables1.removed),
                std::bind(&PrivateShareInvitationSlot,
                          args::_1, args::_2, args::_3,
                          args::_4, args::_5, args::_6,
                          &testing_variables1.new_private_share_name,
                          &testing_variables1.new_private_share_id,
                          &testing_variables1.new_private_access_level,
                          &testing_variables1.privately_invited),
                std::bind(&PrivateShareDeletionSlot,
                          args::_1, args::_2, args::_3, args::_4, args::_5,
                          &testing_variables1.deleted_private_share_name,
                          &testing_variables1.private_share_deleted),
                std::bind(&PrivateMemberAccessLevelSlot,
                          args::_1, args::_2, args::_3,
                          args::_4, args::_5, args::_6,
                          &testing_variables1.access_private_share_name,
                          &testing_variables1.private_member_access,
                          &testing_variables1.private_member_access_changed),
                std::bind(&OpenShareInvitationSlot,
                          args::_1, args::_2, args::_3, args::_4, args::_5,
                          &testing_variables1.new_open_share_id,
                          &testing_variables1.openly_invited),
                std::bind(&ShareRenameSlot,
                          args::_1, args::_2,
                          &testing_variables1.old_share_name,
                          &testing_variables1.new_share_name,
                          &testing_variables1.share_renamed));
  result += test_elements2.ConnectToSignals(
                std::bind(&ChatSlot, args::_1, args::_2, args::_3, args::_4,
                          &testing_variables2.chat_message,
                          &testing_variables2.chat_message_received),
                ftf,
                std::bind(&NewContactSlot, args::_1, args::_2, args::_3,
                          &testing_variables2.newly_contacted),
                std::bind(&ContactConfirmationSlot,
                          args::_1, args::_2, args::_3,
                          &testing_variables2.confirmed),
                std::bind(&ContactProfilePictureSlot,
                          args::_1, args::_2, args::_3,
                          &testing_variables2.picture_updated),
                std::bind(&ContactPresenceSlot,
                          args::_1, args::_2, args::_3, args::_4,
                          &testing_variables2.presence_announced),
                std::bind(&ContactDeletionSlot,
                          args::_1, args::_2, args::_3, args::_4,
                          &testing_variables2.removal_message,
                          &testing_variables2.removed),
                std::bind(&PrivateShareInvitationSlot,
                          args::_1, args::_2, args::_3,
                          args::_4, args::_5, args::_6,
                          &testing_variables2.new_private_share_name,
                          &testing_variables2.new_private_share_id,
                          &testing_variables2.new_private_access_level,
                          &testing_variables2.privately_invited),
                std::bind(&PrivateShareDeletionSlot,
                          args::_1, args::_2, args::_3, args::_4, args::_5,
                          &testing_variables2.deleted_private_share_name,
                          &testing_variables2.private_share_deleted),
                std::bind(&PrivateMemberAccessLevelSlot,
                          args::_1, args::_2, args::_3,
                          args::_4, args::_5, args::_6,
                          &testing_variables2.access_private_share_name,
                          &testing_variables2.private_member_access,
                          &testing_variables2.private_member_access_changed),
                std::bind(&OpenShareInvitationSlot,
                          args::_1, args::_2, args::_3, args::_4, args::_5,
                          &testing_variables2.new_open_share_id,
                          &testing_variables2.openly_invited),
                std::bind(&ShareRenameSlot,
                          args::_1, args::_2,
                          &testing_variables2.old_share_name,
                          &testing_variables2.new_share_name,
                          &testing_variables2.share_renamed));
  if (result != kSuccess)
    return result;

  {
    result += test_elements1.CreateUser(username1, pin1, password1);
    result += test_elements1.CreatePublicId(public_id1);
    result += test_elements1.LogOut();
    if (result != kSuccess) {
      DLOG(ERROR) << "Failure log out 1";
      return result;
    }
  }
  {
    result += test_elements2.CreateUser(username2, pin2, password2);
    result += test_elements2.CreatePublicId(public_id2);
    result += test_elements2.AddContact(public_id2, public_id1);
    result += test_elements2.LogOut();
    if (result != kSuccess) {
      DLOG(ERROR) << "Failure creating 2";
      return result;
    }
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
    DLOG(ERROR) << "result: " <<result;
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
  std::string username(RandomAlphaNumericString(6)),
              pin(CreatePin()),
              password(RandomAlphaNumericString(6));
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
                                                      args::_3, args::_4,
                                                      &done),
                                            ContactDeletionFunction(),
                                            PrivateShareInvitationFunction(),
                                            PrivateShareDeletionFunction(),
                                            PrivateMemberAccessLevelFunction(),
                                            OpenShareInvitationFunction(),
                                            ShareRenamedFunction()));
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

TEST(IndependentFullTest, FUNC_LargeFileForMemoryCheck) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username(RandomAlphaNumericString(6)),
              pin(CreatePin()),
              password(RandomAlphaNumericString(6));
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
                                                      args::_3, args::_4,
                                                      &done),
                                            ContactDeletionFunction(),
                                            PrivateShareInvitationFunction(),
                                            PrivateShareDeletionFunction(),
                                            PrivateMemberAccessLevelFunction(),
                                            OpenShareInvitationFunction(),
                                            ShareRenamedFunction()));
  EXPECT_EQ(kSuccess, test_elements1.CreateUser(username, pin, password));
  // Create directory
  std::string tail;
  EXPECT_EQ(kSuccess, CreateTestFile(test_elements1.mount_path(), 500, &tail));
  EXPECT_TRUE(fs::exists(test_elements1.mount_path() / tail, error_code));
  EXPECT_EQ(0, error_code.value());

  // Log out - Log in
  EXPECT_EQ(kSuccess, test_elements1.LogOut());
  EXPECT_EQ(kSuccess, test_elements1.LogIn(username, pin, password));

  // Check directory exists
  EXPECT_TRUE(fs::exists(test_elements1.mount_path() / tail, error_code));
  EXPECT_EQ(0, error_code.value());
  EXPECT_EQ(kSuccess, test_elements1.LogOut());
  EXPECT_EQ(kSuccess, test_elements1.Finalise());
}

TEST(IndependentFullTest, FUNC_ChangeCredentials) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username(RandomAlphaNumericString(6)),
              pin(CreatePin()), new_pin(CreatePin()),
              password(RandomAlphaNumericString(6));
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
                                                      args::_3, args::_4,
                                                      &done),
                                            ContactDeletionFunction(),
                                            PrivateShareInvitationFunction(),
                                            PrivateShareDeletionFunction(),
                                            PrivateMemberAccessLevelFunction(),
                                            OpenShareInvitationFunction(),
                                            ShareRenamedFunction()));
  EXPECT_EQ(kSuccess, test_elements1.CreateUser(username, pin, password));
  EXPECT_EQ(kSuccess, test_elements1.CheckPassword(password));
  EXPECT_EQ(kSuccess, test_elements1.LogOut());

  EXPECT_EQ(kSuccess, test_elements1.LogIn(username, pin, password));
  EXPECT_EQ(kSuccess, test_elements1.CheckPassword(password));

  // Change credentials
  EXPECT_EQ(kSuccess, test_elements1.ChangeKeyword(username,
                                                   username + username,
                                                   password));
  EXPECT_EQ(kSuccess, test_elements1.ChangePin(pin, new_pin, password));
  EXPECT_EQ(kSuccess, test_elements1.ChangePassword(password,
                                                    password + password));

  EXPECT_EQ(kSuccess, test_elements1.LogOut());

  EXPECT_EQ(kSuccess, test_elements1.LogIn(username + username,
                                           new_pin,
                                           password + password));
  EXPECT_EQ(kSuccess, test_elements1.ChangeKeyword(username + username,
                                                   username,
                                                   password + password));
  EXPECT_EQ(kSuccess, test_elements1.LogOut());

  EXPECT_EQ(kSuccess, test_elements1.LogIn(username,
                                           new_pin,
                                           password + password));
  EXPECT_EQ(kSuccess, test_elements1.ChangePin(new_pin,
                                               pin,
                                               password + password));
  EXPECT_EQ(kSuccess, test_elements1.LogOut());

  EXPECT_EQ(kSuccess, test_elements1.LogIn(username, pin, password + password));
  EXPECT_EQ(kSuccess, test_elements1.ChangePassword(password + password,
                                                    password));
  EXPECT_EQ(kSuccess, test_elements1.LogOut());

  EXPECT_EQ(kSuccess, test_elements1.LogIn(username, pin, password));
  EXPECT_EQ(kSuccess, test_elements1.CheckPassword(password));
  EXPECT_EQ(kSuccess, test_elements1.ChangeKeyword(username,
                                                   username,
                                                   password));
  EXPECT_EQ(kSuccess, test_elements1.ChangePin(pin, pin, password));
  EXPECT_EQ(kSuccess, test_elements1.ChangePassword(password, password));
  EXPECT_EQ(kSuccess, test_elements1.LogOut());

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
}

TEST(IndependentFullTest, FUNC_SendFileSaveToGivenPath) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(10)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(10)),
              public_id1(RandomAlphaNumericString(10));
  std::string username2(RandomAlphaNumericString(10)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(10)),
              public_id2(RandomAlphaNumericString(10));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));

  boost::system::error_code error_code;
  fs::path file_path1;
  std::string file_name1(RandomAlphaNumericString(8)),
              file_content1(RandomString(5 * 1024)),
              file_name2(RandomAlphaNumericString(8));

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

    Sleep(bptime::seconds(2));
    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.file_transfer_received)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables2.file_id.empty());
    EXPECT_EQ(file_name1, testing_variables2.file_name);
    EXPECT_NE(kSuccess,
              test_elements2.AcceptSentFile(testing_variables2.file_id));
    EXPECT_NE(kSuccess,
              test_elements2.AcceptSentFile(testing_variables2.file_id,
                                            test_elements2.mount_path() /
                                                file_name2,
                                            &file_name2));
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptSentFile(testing_variables2.file_id,
                                            test_elements2.mount_path() /
                                                file_name2));

    EXPECT_TRUE(fs::exists(test_elements2.mount_path() / file_name2,
                           error_code));
    EXPECT_EQ(0, error_code.value());

    Sleep(bptime::seconds(2));
    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST(IndependentFullTest, FUNC_SendFileSaveToDefaultLocation) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));

  boost::system::error_code error_code;
  fs::path file_path1;
  std::string file_name1(RandomAlphaNumericString(8)),
              file_content1(RandomString(5 * 1024));
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
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.file_transfer_received)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables2.file_id.empty());
    EXPECT_EQ(file_name1, testing_variables2.file_name);
    std::string saved_file_name;
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptSentFile(testing_variables2.file_id,
                                            fs::path(),
                                            &saved_file_name));
    EXPECT_EQ(file_name1, saved_file_name);
    fs::path path2(test_elements2.mount_path() /
                   kMyStuff /
                   kDownloadStuff /
                   saved_file_name);
    EXPECT_TRUE(fs::exists(path2, error_code));
    EXPECT_EQ(0, error_code.value());
    std::string file_content2;
    EXPECT_TRUE(ReadFile(path2, &file_content2));
    EXPECT_EQ(file_content1, file_content2);

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
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
  {
    testing_variables2.file_transfer_received = false;
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.file_transfer_received)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables2.file_id.empty());
    EXPECT_EQ(file_name1, testing_variables2.file_name);
    std::string saved_file_name;
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptSentFile(testing_variables2.file_id,
                                            fs::path(),
                                            &saved_file_name));
    EXPECT_EQ(file_name1 + " (1)", saved_file_name);
    fs::path path2a(test_elements2.mount_path() /
                    kMyStuff /
                    kDownloadStuff /
                    file_name1),
             path2b(test_elements2.mount_path() /
                    kMyStuff /
                    kDownloadStuff /
                    saved_file_name);

    EXPECT_TRUE(fs::exists(path2a, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(path2b, error_code));
    EXPECT_EQ(0, error_code.value());
    std::string file_content2;
    EXPECT_TRUE(ReadFile(path2b, &file_content2));
    EXPECT_TRUE(file_content1 == file_content2);

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST(IndependentFullTest, FUNC_SendFileAcceptToDeletedDefaultLocation) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));

  boost::system::error_code error_code;
  fs::path file_path1;
  std::string file_name1(RandomAlphaNumericString(8)),
              file_content1(RandomString(5 * 1024));

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
  {
    testing_variables2.file_transfer_received = false;
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.file_transfer_received)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables2.file_id.empty());
    EXPECT_EQ(file_name1, testing_variables2.file_name);

    // Delete accepted files dir
    fs::remove_all(test_elements2.mount_path() / kMyStuff, error_code);
    EXPECT_EQ(0, error_code.value());
    EXPECT_FALSE(fs::exists(test_elements2.mount_path() / kMyStuff,
                            error_code));
    EXPECT_NE(0, error_code.value());

    std::string saved_file_name;
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptSentFile(testing_variables2.file_id,
                                            fs::path(),
                                            &saved_file_name));
    EXPECT_EQ(file_name1, saved_file_name);
    fs::path path2(test_elements2.mount_path() /
                   kMyStuff /
                   kDownloadStuff /
                   saved_file_name);
    EXPECT_TRUE(fs::exists(path2, error_code));
    EXPECT_EQ(0, error_code.value());
    std::string file_content2;
    EXPECT_TRUE(ReadFile(path2, &file_content2));
    EXPECT_EQ(file_content1, file_content2);

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST(IndependentFullTest, FUNC_SendFileWithRejection) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  int file_count(0), file_max(10);
  size_t files_expected(file_max);
  std::vector<fs::path> file_paths;
  std::vector<std::string> file_names, file_contents, received_ids,
                           received_names;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2,
                                                   true,
                                                   &received_ids,
                                                   &received_names,
                                                   &files_expected));

  boost::system::error_code error_code;

  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    for (; file_count < file_max; ++file_count) {
      file_paths.push_back(fs::path(test_elements1.mount_path() /
                                    RandomAlphaNumericString(8)));
      std::ofstream ofstream(file_paths[file_count].c_str(), std::ios::binary);
      file_contents.push_back(RandomString(5 * 1024));
      ofstream << file_contents[file_count];
      ofstream.close();
      EXPECT_TRUE(fs::exists(file_paths[file_count], error_code));
      EXPECT_EQ(0, error_code.value());
      EXPECT_EQ(kSuccess, test_elements1.SendFile(public_id1,
                                                  public_id2,
                                                  file_paths[file_count]));
    }

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.file_transfer_received)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(files_expected, received_ids.size());
    EXPECT_EQ(files_expected, received_names.size());
    fs::path path2(test_elements2.mount_path() /
                   kMyStuff /
                   kDownloadStuff);
    for (size_t st(0); st < received_ids.size(); ++st) {
      EXPECT_EQ(file_paths[st].filename().string(), received_names[st]);
      EXPECT_EQ(kSuccess, test_elements2.RejectSentFile(received_ids[st]));
      EXPECT_FALSE(fs::exists(path2 / received_names[st], error_code));
      EXPECT_NE(0, error_code.value());
      std::string hidden(received_ids[st] + kHiddenFileExtension), content;
      EXPECT_NE(kSuccess, test_elements2.ReadHiddenFile(
                              test_elements2.mount_path() / hidden,
                              &content));
    }

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST(IndependentFullTest, FUNC_ProfilePicture) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
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
    EXPECT_NE(kSuccess, test_elements1.ChangeProfilePicture(public_id1, ""));

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    // Setting of profile image
    EXPECT_EQ(kSuccess,
              test_elements2.ChangeProfilePicture(public_id2,
                                                  kBlankProfilePicture));

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    testing_variables1.picture_updated = false;
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    while (!testing_variables1.picture_updated)
      Sleep(bptime::milliseconds(100));

    file_content1 = test_elements1.GetContactProfilePicture(public_id1,
                                                            public_id2);
    EXPECT_TRUE(kBlankProfilePicture == file_content1);

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST(IndependentFullTest, FUNC_RemoveContact) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
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

TEST(IndependentFullTest, FUNC_CreateEmptyOpenShare) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));
  DLOG(ERROR) << "\n\n\n\n";
  std::string share_name(RandomAlphaNumericString(5)),
              file_name(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(50));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    StringIntMap  results;
    std::vector<std::string> contacts;
    contacts.push_back(public_id2);
    results.insert(std::make_pair(public_id2, kGeneralError));
    EXPECT_EQ(kSuccess, test_elements1.CreateEmptyOpenShare(public_id1,
                                                            contacts,
                                                            &share_name,
                                                            &results));
    fs::path share_path(test_elements1.mount_path() /
                        kSharedStuff /
                        share_name);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id2]);
    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.openly_invited)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables2.new_open_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptOpenShareInvitation(
                  public_id2,
                  public_id1,
                  testing_variables2.new_open_share_id,
                  &share_name));

    fs::path share(test_elements2.mount_path() / kSharedStuff / share_name);
    EXPECT_TRUE(fs::is_directory(share, error_code));
    fs::path file_path(share / file_name);
    EXPECT_TRUE(WriteFile(file_path, file_content1));
    EXPECT_TRUE(fs::exists(file_path, error_code));
    EXPECT_EQ(0, error_code.value());

    std::string file_content;
    EXPECT_TRUE(ReadFile(file_path, &file_content));
    EXPECT_EQ(file_content1, file_content);

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    fs::path share(test_elements1.mount_path() / kSharedStuff / share_name);
    fs::path file_path(share / file_name);
    std::string file_content;
    EXPECT_TRUE(ReadFile(file_path, &file_content));
    EXPECT_EQ(file_content1, file_content);
    EXPECT_TRUE(WriteFile(file_path, file_content2));
    EXPECT_TRUE(ReadFile(file_path, &file_content));
    EXPECT_EQ(file_content2, file_content);

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    fs::path share(test_elements1.mount_path() / kSharedStuff / share_name);
    fs::path file_path(share / file_name);
    std::string file_content;
    EXPECT_TRUE(ReadFile(file_path, &file_content));
    EXPECT_EQ(file_content2, file_content);

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));

    fs::path share(test_elements2.mount_path() / kSharedStuff / share_name);
    fs::path file_path(share / file_name);
    EXPECT_TRUE(fs::exists(file_path, error_code)) << file_path;
    EXPECT_EQ(0, error_code.value());
    uintmax_t size(fs::file_size(file_path, error_code));
    EXPECT_EQ(file_content2.size(), size) << file_path;

    std::string file_content;
    EXPECT_TRUE(ReadFile(file_path, &file_content));
    EXPECT_EQ(file_content2, file_content);
    EXPECT_NE(file_content1, file_content);

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST(IndependentFullTest, FUNC_CreateOpenShare) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));
  DLOG(ERROR) << "\n\n\n\n";
  std::string directory_name(RandomAlphaNumericString(5)),
              share_name(RandomAlphaNumericString(5)),
              file1_name(RandomAlphaNumericString(5)),
              file2_name(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    fs::path directory(test_elements1.mount_path() / kMyStuff / directory_name);
    EXPECT_TRUE(fs::create_directory(directory, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file1_path(directory / file1_name);
    EXPECT_TRUE(WriteFile(file1_path, file_content1));
    EXPECT_TRUE(fs::exists(file1_path, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path share_directory(directory / share_name);
    EXPECT_TRUE(fs::create_directory(share_directory, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file2_path(share_directory / file2_name);
    EXPECT_TRUE(WriteFile(file2_path, file_content2));
    EXPECT_TRUE(fs::exists(file2_path, error_code));
    EXPECT_EQ(0, error_code.value());

    StringIntMap  results;
    std::vector<std::string> contacts;
    contacts.push_back(public_id2);
    results.insert(std::make_pair(public_id2, kGeneralError));
    EXPECT_EQ(kSuccess, test_elements1.CreateOpenShareFromExistingDirectory(
                                          public_id1,
                                          share_directory,
                                          contacts,
                                          &share_name,
                                          &results));
    fs::path share(test_elements1.mount_path() / kSharedStuff / share_name);
    EXPECT_EQ(kSuccess, results[public_id2]);
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share / file2_name, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_FALSE(fs::exists(directory / share_name, error_code));
    EXPECT_NE(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.openly_invited)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables2.new_open_share_id.empty());
    EXPECT_EQ(kSuccess, test_elements2.RejectOpenShareInvitation(
                            public_id2,
                            testing_variables2.new_open_share_id));
    fs::path share(test_elements2.mount_path() / kSharedStuff / share_name),
             file_path(share / file2_name);
    EXPECT_FALSE(fs::exists(share, error_code));
    EXPECT_NE(0, error_code.value());
    EXPECT_FALSE(fs::exists(file_path, error_code));
    EXPECT_NE(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    fs::path share(test_elements1.mount_path() / kSharedStuff / share_name);
    fs::path file_path(share / file2_name);
    std::string file_stuff;
    EXPECT_TRUE(ReadFile(file_path, &file_stuff));
    EXPECT_EQ(file_content2, file_stuff);
    EXPECT_TRUE(WriteFile(file_path, file_content1));

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST(IndependentFullTest, FUNC_InviteOpenShareMembers) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));
  DLOG(ERROR) << "\n\n\n\n";
  std::string directory_name(RandomAlphaNumericString(5)),
              share1_name(RandomAlphaNumericString(5)),
              share2_name(RandomAlphaNumericString(5)),
              file1_name(RandomAlphaNumericString(5)),
              file2_name(RandomAlphaNumericString(5)),
              file3_name(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20)),
              file_content3(RandomString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    fs::path directory(test_elements1.mount_path() / kMyStuff / directory_name);
    EXPECT_TRUE(fs::create_directory(directory, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file1_path(directory / file1_name);
    EXPECT_TRUE(WriteFile(file1_path, file_content1));
    EXPECT_TRUE(fs::exists(file1_path, error_code));
    EXPECT_EQ(0, error_code.value());

    fs::path share_directory1(directory / share1_name);
    EXPECT_TRUE(fs::create_directory(share_directory1, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file2_path(share_directory1 / file2_name);
    EXPECT_TRUE(WriteFile(file2_path, file_content2));
    EXPECT_TRUE(fs::exists(file2_path, error_code));
    EXPECT_EQ(0, error_code.value());

    fs::path share_directory2(directory / share2_name);
    EXPECT_TRUE(fs::create_directory(share_directory2, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file3_path(share_directory2 / file3_name);
    EXPECT_TRUE(WriteFile(file3_path, file_content3));
    EXPECT_TRUE(fs::exists(file3_path, error_code));
    EXPECT_EQ(0, error_code.value());

    StringIntMap  results;
    std::vector<std::string> contacts;
    contacts.push_back(public_id2);
    results.insert(std::make_pair(public_id2, kGeneralError));
    EXPECT_EQ(kSuccess, test_elements1.CreateOpenShareFromExistingDirectory(
                                          public_id1,
                                          share_directory1,
                                          contacts,
                                          &share1_name,
                                          &results));
    fs::path share(test_elements1.mount_path() / kSharedStuff / share1_name);
    EXPECT_EQ(kSuccess, results[public_id2]);
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share / file2_name, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_FALSE(fs::exists(directory / share1_name, error_code));
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.openly_invited)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables2.new_open_share_id.empty());
    EXPECT_EQ(kSuccess, test_elements2.RejectOpenShareInvitation(
                            public_id2,
                            testing_variables2.new_open_share_id));
    fs::path share(test_elements2.mount_path() / kSharedStuff / share1_name),
             file_path(share / file2_name);
    EXPECT_FALSE(fs::exists(share, error_code));
    EXPECT_NE(0, error_code.value());
    EXPECT_FALSE(fs::exists(file_path, error_code));
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    fs::path share1(test_elements1.mount_path() / kSharedStuff / share1_name);
    fs::path file_path(share1 / file2_name);
    std::string file_stuff;
    EXPECT_TRUE(ReadFile(file_path, &file_stuff));
    EXPECT_EQ(file_content2, file_stuff);
    EXPECT_TRUE(WriteFile(file_path, file_content1));

    fs::path directory(test_elements1.mount_path() / kMyStuff / directory_name);
    StringIntMap  results;
    std::vector<std::string> contacts;
    fs::path share_directory2(directory / share2_name);
    EXPECT_EQ(kSuccess, test_elements1.CreateOpenShareFromExistingDirectory(
                                          public_id1,
                                          share_directory2,
                                          contacts,
                                          &share2_name,
                                          &results));
    fs::path share2(test_elements1.mount_path() / kSharedStuff / share2_name);
    EXPECT_EQ(kSuccess, results[public_id2]);
    EXPECT_TRUE(fs::exists(share2, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share2 / file3_name, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_FALSE(fs::exists(directory / share2_name, error_code));
    EXPECT_NE(0, error_code.value());

    std::vector<std::string> shares;
    EXPECT_EQ(kSuccess, test_elements1.GetOpenShareList(public_id1,
                                                        &shares));
    EXPECT_EQ(2, shares.size());

    std::vector<std::string> members;
    EXPECT_EQ(kSuccess, test_elements1.GetOpenShareMembers(public_id1,
                                                           share2_name,
                                                           &members));
    EXPECT_EQ(1, members.size());

    contacts.push_back(public_id2);
    results.insert(std::make_pair(public_id2, kGeneralError));
    EXPECT_EQ(kSuccess, test_elements1.InviteMembersToOpenShare(public_id1,
                                                                contacts,
                                                                share2_name,
                                                                &results));
    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.openly_invited)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables2.new_open_share_id.empty());
    EXPECT_EQ(kSuccess, test_elements2.AcceptOpenShareInvitation(
                                          public_id2,
                                          public_id1,
                                          testing_variables2.new_open_share_id,
                                          &share2_name));
    fs::path share(test_elements2.mount_path() / kSharedStuff / share2_name),
             file_path(share / file3_name);
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(file_path, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(WriteFile(file_path, file_content2));

    std::vector<std::string> shares;
    EXPECT_EQ(kSuccess, test_elements2.GetOpenShareList(public_id2,
                                                        &shares));
    EXPECT_EQ(1, shares.size());

    std::vector<std::string> members;
    EXPECT_EQ(kSuccess, test_elements2.GetOpenShareMembers(public_id2,
                                                           share2_name,
                                                           &members));
    EXPECT_EQ(2, members.size());

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST(IndependentFullTest, FUNC_LeaveOpenShare) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));
  DLOG(ERROR) << "\n\n\n\n";
  std::string directory_name(RandomAlphaNumericString(5)),
              share_name(RandomAlphaNumericString(5)),
              file1_name(RandomAlphaNumericString(5)),
              file2_name(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    fs::path directory(test_elements1.mount_path() / kMyStuff / directory_name);
    EXPECT_TRUE(fs::create_directory(directory, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file1_path(directory / file1_name);
    EXPECT_TRUE(WriteFile(file1_path, file_content1));
    EXPECT_TRUE(fs::exists(file1_path, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path share_directory(directory / share_name);
    EXPECT_TRUE(fs::create_directory(share_directory, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file2_path(share_directory / file2_name);
    EXPECT_TRUE(WriteFile(file2_path, file_content2));
    EXPECT_TRUE(fs::exists(file2_path, error_code));
    EXPECT_EQ(0, error_code.value());

    StringIntMap  results;
    std::vector<std::string> contacts;
    contacts.push_back(public_id2);
    results.insert(std::make_pair(public_id2, kGeneralError));
    EXPECT_EQ(kSuccess, test_elements1.CreateOpenShareFromExistingDirectory(
                                          public_id1,
                                          share_directory,
                                          contacts,
                                          &share_name,
                                          &results));
    fs::path share(test_elements1.mount_path() / kSharedStuff / share_name);
    EXPECT_EQ(kSuccess, results[public_id2]);
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share / file2_name, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_FALSE(fs::exists(directory / share_name, error_code));
    EXPECT_NE(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.openly_invited)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables2.new_open_share_id.empty());
    EXPECT_EQ(kSuccess, test_elements2.AcceptOpenShareInvitation(
                                          public_id2,
                                          public_id1,
                                          testing_variables2.new_open_share_id,
                                          &share_name));
    fs::path share(test_elements2.mount_path() / kSharedStuff / share_name),
             file_path(share / file2_name);
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(file_path, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    fs::path share(test_elements1.mount_path() / kSharedStuff / share_name);
    fs::path file_path(share / file2_name);
    std::string file_stuff;
    EXPECT_TRUE(ReadFile(file_path, &file_stuff));
    EXPECT_EQ(file_content2, file_stuff);
    EXPECT_TRUE(WriteFile(file_path, file_content1));

    EXPECT_EQ(kSuccess, test_elements1.LeaveOpenShare(public_id1,
                                                      share_name));
    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    fs::path share(test_elements2.mount_path() / kSharedStuff / share_name),
             file_path(share / file2_name);
    std::string file_stuff;
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(file_path, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(ReadFile(file_path, &file_stuff));
    EXPECT_EQ(file_content1, file_stuff);

    std::vector<std::string> shares;
    EXPECT_EQ(kSuccess, test_elements2.GetOpenShareList(public_id2,
                                                        &shares));
    EXPECT_EQ(1, shares.size());

    std::vector<std::string> members;
    EXPECT_EQ(kSuccess, test_elements2.GetOpenShareMembers(public_id2,
                                                           share_name,
                                                           &members));
    EXPECT_EQ(1, members.size());
    EXPECT_EQ(public_id2, members[0]);

    EXPECT_EQ(kSuccess, test_elements2.LeaveOpenShare(public_id2,
                                                      share_name));
    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST(IndependentFullTest, FUNC_SameOpenShareName) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));
  DLOG(ERROR) << "\n\n\n\n";
  std::string directory0_name(RandomAlphaNumericString(5)),
              directory1_name(RandomAlphaNumericString(5)),
              directory2_name(RandomAlphaNumericString(5)),
              directory3_name(RandomAlphaNumericString(5)),
              directory4_name(RandomAlphaNumericString(5)),
              file1_name(RandomAlphaNumericString(5)),
              file2_name(RandomAlphaNumericString(5)),
              file3_name(RandomAlphaNumericString(5)),
              file4_name(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20)),
              file_content3(RandomString(20)),
              file_content4(RandomString(20)),
              share_name(RandomAlphaNumericString(5)),
              stored_share_name(share_name);
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    fs::path directory0(test_elements1.mount_path() /
                        kMyStuff /
                        directory0_name);
    EXPECT_TRUE(fs::create_directory(directory0, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path directory1(directory0 / directory1_name);
    EXPECT_TRUE(fs::create_directory(directory1, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path directory2(directory0 / directory2_name);
    EXPECT_TRUE(fs::create_directory(directory2, error_code));
    EXPECT_EQ(0, error_code.value());

    fs::path share_directory1(directory1 / share_name);
    EXPECT_TRUE(fs::create_directory(share_directory1, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path share_directory2(directory2 / share_name);
    EXPECT_TRUE(fs::create_directory(share_directory2, error_code));
    EXPECT_EQ(0, error_code.value());

    fs::path file1_path(share_directory1 / file1_name);
    EXPECT_TRUE(WriteFile(file1_path, file_content1));
    EXPECT_TRUE(fs::exists(file1_path, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file2_path(share_directory2 / file2_name);
    EXPECT_TRUE(WriteFile(file2_path, file_content2));
    EXPECT_TRUE(fs::exists(file2_path, error_code));
    EXPECT_EQ(0, error_code.value());

    fs::path directory3(share_directory1 / directory3_name);
    EXPECT_TRUE(fs::create_directory(directory3, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path directory4(share_directory2 / directory4_name);
    EXPECT_TRUE(fs::create_directory(directory4, error_code));
    EXPECT_EQ(0, error_code.value());

    fs::path file3_path(directory3 / file3_name);
    EXPECT_TRUE(WriteFile(file3_path, file_content3));
    EXPECT_TRUE(fs::exists(file3_path, error_code));
    EXPECT_EQ(0, error_code.value());
    fs::path file4_path(directory4 / file4_name);
    EXPECT_TRUE(WriteFile(file4_path, file_content4));
    EXPECT_TRUE(fs::exists(file4_path, error_code));
    EXPECT_EQ(0, error_code.value());

    StringIntMap  results;
    std::vector<std::string> contacts;
    EXPECT_EQ(kSuccess, test_elements1.CreateOpenShareFromExistingDirectory(
                                          public_id1,
                                          share_directory1,
                                          contacts,
                                          &share_name,
                                          &results));
    fs::path share1(test_elements1.mount_path() / kSharedStuff / share_name);
    EXPECT_TRUE(fs::exists(share1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share1 / file1_name, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(stored_share_name, share_name);

    EXPECT_FALSE(fs::exists(directory1 / share_name, error_code));
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements1.CreateOpenShareFromExistingDirectory(
                                          public_id1,
                                          share_directory2,
                                          contacts,
                                          &share_name,
                                          &results));
    fs::path share2(test_elements1.mount_path() / kSharedStuff / share_name);
    EXPECT_TRUE(fs::exists(share2, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share2 / file2_name, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_NE(stored_share_name, share_name);
    EXPECT_EQ(stored_share_name + " (1)", share_name);

    EXPECT_FALSE(fs::exists(directory2 / share_name, error_code));
    EXPECT_NE(0, error_code.value());

    std::vector<std::string> shares;
    EXPECT_EQ(kSuccess, test_elements1.GetOpenShareList(public_id1,
                                                        &shares));
    EXPECT_EQ(2, shares.size());

    std::vector<std::string> members;
    EXPECT_EQ(kSuccess, test_elements1.GetOpenShareMembers(public_id1,
                                                           share_name,
                                                           &members));
    EXPECT_EQ(1, members.size());
    EXPECT_EQ(public_id1, members[0]);

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
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
                        testing::Values(kShareReadOnly,
                                        kShareReadWrite));

TEST_P(PrivateSharesApiTest, FUNC_CreateEmptyPrivateShare) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
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
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
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
    EXPECT_EQ(share_name1, testing_variables2.new_private_share_name);
    EXPECT_EQ(rights_, testing_variables2.new_private_access_level);
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptPrivateShareInvitation(
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id,
                  &share_name1));

    fs::path share_path(test_elements2.mount_path() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));

    fs::path a_file_path(share_path / file_name1);
    if (rights_ == kShareReadOnly) {
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
                        kSharedStuff /
                        share_name1);
    fs::path a_file_path(share_path / file_name1);
    if (rights_ == kShareReadOnly) {
      EXPECT_TRUE(WriteFile(a_file_path, file_content1));
      EXPECT_TRUE(fs::exists(a_file_path, error_code));
      EXPECT_EQ(0, error_code.value());
    } else {
      std::string file_stuff;
      EXPECT_TRUE(ReadFile(a_file_path, &file_stuff));
      EXPECT_EQ(file_content2, file_stuff);
      EXPECT_TRUE(WriteFile(a_file_path, file_content1));
      EXPECT_TRUE(fs::exists(a_file_path, error_code));
    }

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));

    fs::path share_path(test_elements2.mount_path() /
                        kSharedStuff /
                        share_name1);
    fs::path a_file_path(share_path / file_name1);
    EXPECT_TRUE(fs::exists(a_file_path, error_code)) << a_file_path;
    EXPECT_EQ(0, error_code.value());

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
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
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
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    // Create directory with contents to share
    fs::path share_path(test_elements1.mount_path() /
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
    EXPECT_EQ(share_name1, testing_variables2.new_private_share_name);
    EXPECT_EQ(rights_, testing_variables2.new_private_access_level);
    EXPECT_EQ(kSuccess,
              test_elements2.AcceptPrivateShareInvitation(
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id,
                  &share_name1));

    fs::path share_path(test_elements2.mount_path() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));
    EXPECT_EQ(0, error_code.value());

    // Read the existing file
    std::string file_in_share_content;
    EXPECT_TRUE(ReadFile(share_path / file_name1, &file_in_share_content));
    EXPECT_EQ(file_content1, file_in_share_content);

    fs::path a_file_path(share_path / file_name2);
    if (rights_ == kShareReadOnly) {
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
                        kSharedStuff /
                        share_name1);
    fs::path a_file_path(share_path / file_name2);
    std::string file_stuff;
    if (rights_ == kShareReadOnly) {
      EXPECT_FALSE(ReadFile(a_file_path, &file_stuff));
      EXPECT_TRUE(file_stuff.empty());
    } else {
      EXPECT_TRUE(ReadFile(a_file_path, &file_stuff));
      EXPECT_EQ(file_content2, file_stuff);
    }
    EXPECT_TRUE(WriteFile(a_file_path, file_content1));
    EXPECT_TRUE(fs::exists(a_file_path, error_code));

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));

    fs::path share_path(test_elements2.mount_path() /
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
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
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
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    // Create directory with contents to share
    fs::path share_path(test_elements1.mount_path() /
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
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
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
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
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
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id,
                  &share_name1));

    fs::path share_path(test_elements2.mount_path() /
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

    // Still using share_id to identify the share, instead of share_name
//     EXPECT_EQ(share_name1, testing_variables2.deleted_private_share_name);
    fs::path share_path(test_elements2.mount_path() /
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
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
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
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
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
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id2]);

    // Check owner can't leave
    EXPECT_EQ(kOwnerTryingToLeave,
              test_elements1.LeavePrivateShare(public_id1, share_name1));
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
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id,
                  &share_name1));

    fs::path share_path(test_elements2.mount_path() /
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

    // Still using share_id to identify the share, instead of share_name
    // And when leaving, Deletion Signal won't get fired
//     EXPECT_EQ(share_name1, testing_variables2.deleted_private_share_name);
    fs::path share_path(test_elements1.mount_path() /
                        kSharedStuff /
                        share_name1);
    EXPECT_FALSE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST(IndependentFullTest, FUNC_RenamePrivateShare) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
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
              share_name2(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id2, kShareReadWrite));
    results.insert(std::make_pair(public_id2, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements1.CreateEmptyPrivateShare(public_id1,
                                                               contacts,
                                                               &share_name1,
                                                               &results));
    EXPECT_EQ(kSuccess, results[public_id2]);

    EXPECT_EQ(kSuccess, test_elements1.GetPrivateShareMembers(public_id1,
                                                              share_name1,
                                                              &results));
    EXPECT_EQ(1U, results.size());
    EXPECT_TRUE(results.end() == results.find(public_id1));
    EXPECT_FALSE(results.end() == results.find(public_id2));

    fs::path share_path(test_elements1.mount_path() /
                        kSharedStuff /
                        share_name1);
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
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id,
                  &share_name1));

    fs::path share_path(test_elements2.mount_path() /
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
    fs::path old_share_path(test_elements1.mount_path() /
                            kSharedStuff /
                            share_name1);
    fs::path new_share_path(test_elements1.mount_path() /
                            kSharedStuff /
                            share_name2);
    fs::rename(old_share_path, new_share_path, error_code);
    EXPECT_EQ(0, error_code.value());
    while (!testing_variables1.share_renamed)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::is_directory(old_share_path, error_code));
    fs::path a_file_path(new_share_path / file_name1);
    std::string local_content;
    EXPECT_TRUE(ReadFile(a_file_path, &local_content));
    EXPECT_EQ(file_content2, local_content);

    EXPECT_EQ(share_name1, testing_variables1.old_share_name);
    EXPECT_EQ(share_name2, testing_variables1.new_share_name);

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    fs::path share_path(test_elements2.mount_path() /
                        kSharedStuff /
                        share_name1);
    fs::path new_share_path(test_elements2.mount_path() /
                            kSharedStuff /
                            share_name2);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));
    EXPECT_FALSE(fs::is_directory(new_share_path, error_code));

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  std::string sub_directory_name(RandomAlphaNumericString(8));
  std::string new_sub_directory_name(RandomAlphaNumericString(8));
  std::string new_file_name(RandomAlphaNumericString(8));
  {
    testing_variables1.share_renamed = false;
    testing_variables1.old_share_name.clear();
    testing_variables1.new_share_name.clear();

    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    fs::path share_path(test_elements1.mount_path() /
                        kSharedStuff /
                        share_name2);

    fs::path sub_directory(share_path / sub_directory_name);
    EXPECT_TRUE(fs::create_directory(sub_directory, error_code));
    EXPECT_TRUE(fs::exists(sub_directory, error_code));
    fs::path sub_directory_new(share_path / new_sub_directory_name);
    fs::rename(sub_directory, sub_directory_new, error_code);

    fs::path a_file_path(share_path / file_name1);
    fs::path new_a_file_path(share_path / new_file_name);
    fs::rename(a_file_path, new_a_file_path, error_code);

    Sleep(bptime::seconds(1));
    EXPECT_FALSE(testing_variables1.share_renamed);
    EXPECT_TRUE(testing_variables1.old_share_name.empty());
    EXPECT_TRUE(testing_variables1.new_share_name.empty());

    EXPECT_TRUE(fs::exists(sub_directory_new, error_code));
    EXPECT_FALSE(fs::exists(sub_directory, error_code));
    EXPECT_TRUE(fs::exists(new_a_file_path, error_code));
    EXPECT_FALSE(fs::exists(a_file_path, error_code));

    std::string local_content;
    EXPECT_TRUE(ReadFile(new_a_file_path, &local_content));
    EXPECT_EQ(file_content2, local_content);

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    fs::path share_path(test_elements2.mount_path() /
                        kSharedStuff /
                        share_name1);
    fs::path sub_directory(share_path / sub_directory_name);
    fs::path sub_directory_new(share_path / new_sub_directory_name);
    fs::path a_file_path(share_path / file_name1);
    fs::path a_file_path_new(share_path / new_file_name);

    EXPECT_TRUE(fs::exists(sub_directory_new, error_code));
    EXPECT_FALSE(fs::exists(sub_directory, error_code));
    EXPECT_TRUE(fs::exists(a_file_path_new, error_code));
    EXPECT_FALSE(fs::exists(a_file_path, error_code));

    std::string local_content;
    EXPECT_TRUE(ReadFile(a_file_path_new, &local_content));
    EXPECT_EQ(file_content2, local_content);

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
}

TEST(IndependentFullTest, FUNC_MembershipDowngradePrivateShare) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
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
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id2, kShareReadWrite));
    results.insert(std::make_pair(public_id2, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements1.CreateEmptyPrivateShare(public_id1,
                                                               contacts,
                                                               &share_name1,
                                                               &results));
    EXPECT_EQ(kSuccess, results[public_id2]);

    EXPECT_EQ(kSuccess, test_elements1.GetPrivateShareMembers(public_id1,
                                                              share_name1,
                                                              &results));
    EXPECT_EQ(1U, results.size());
    EXPECT_TRUE(results.end() == results.find(public_id1));
    EXPECT_FALSE(results.end() == results.find(public_id2));

    fs::path share_path(test_elements1.mount_path() /
                        kSharedStuff /
                        share_name1);
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
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id,
                  &share_name1));

    fs::path share_path(test_elements2.mount_path() /
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
    amendments.insert(std::make_pair(public_id2, kShareReadOnly));
    EXPECT_EQ(kSuccess, test_elements1.EditPrivateShareMembers(public_id1,
                                                               amendments,
                                                               share_name1,
                                                               &results));
    EXPECT_EQ(kSuccess, results[public_id2]);
    results[public_id2] = -1;
    EXPECT_EQ(kSuccess, test_elements1.GetPrivateShareMembers(public_id1,
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
    EXPECT_EQ(kShareReadOnly, shares[share_name1]);

    fs::path share_path(test_elements2.mount_path() /
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
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
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
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id2, kShareReadOnly));
    results.insert(std::make_pair(public_id2, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements1.CreateEmptyPrivateShare(public_id1,
                                                               contacts,
                                                               &share_name1,
                                                               &results));

    fs::path share_path(test_elements1.mount_path() /
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
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id,
                  &share_name1));

    fs::path share_path(test_elements2.mount_path() /
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
    amendments.insert(std::make_pair(public_id2, kShareReadWrite));
    EXPECT_EQ(kSuccess, test_elements1.EditPrivateShareMembers(public_id1,
                                                               amendments,
                                                               share_name1,
                                                               &results));
    EXPECT_EQ(kSuccess, results[public_id2]);
    results[public_id2] = -1;
    EXPECT_EQ(kSuccess, test_elements1.GetPrivateShareMembers(public_id1,
                                                              share_name1,
                                                              &results));
    EXPECT_EQ(kShareReadWrite, results[public_id2]);

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
    EXPECT_EQ(kShareReadWrite, shares[share_name1]);

    fs::path share_path(test_elements2.mount_path() /
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

TEST(IndependentFullTest, FUNC_PrivateShareOwnerRemoveNonOwnerContact) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
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
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id2, kShareReadOnly));
    results.insert(std::make_pair(public_id2, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements1.CreateEmptyPrivateShare(public_id1,
                                                               contacts,
                                                               &share_name1,
                                                               &results));

    fs::path share_path(test_elements1.mount_path() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id2]);
    StringIntMap shares_members;
    test_elements1.GetPrivateShareMembers(public_id1,
                                          share_name1,
                                          &shares_members);
    EXPECT_EQ(1U, shares_members.size());

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
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id,
                  &share_name1));

    fs::path share_path(test_elements2.mount_path() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    EXPECT_EQ(kSuccess, test_elements1.RemoveContact(public_id1,
                                                     public_id2,
                                                     removal_message));
    EXPECT_TRUE(test_elements1.GetContacts(public_id1).empty());
    fs::path share_path(test_elements1.mount_path() /
                        kSharedStuff /
                        share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    StringIntMap shares_members;
    test_elements1.GetPrivateShareMembers(public_id1,
                                          share_name1,
                                          &shares_members);
    EXPECT_EQ(0, shares_members.size());

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

    while (!testing_variables2.private_share_deleted)
      Sleep(bptime::milliseconds(100));
    fs::path share_path(test_elements2.mount_path() /
                        kSharedStuff /
                        share_name1);
    Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(fs::is_directory(share_path, error_code));

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST(IndependentFullTest, FUNC_PrivateShareNonOwnerRemoveOwnerContact) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2;
  TestingVariables testing_variables1, testing_variables2;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
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
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
  fs::path directory1, directory2;
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id2, kShareReadOnly));
    results.insert(std::make_pair(public_id2, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements1.CreateEmptyPrivateShare(public_id1,
                                                               contacts,
                                                               &share_name1,
                                                               &results));
    directory1 = test_elements1.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id2]);
    StringIntMap shares_members;
    test_elements1.GetPrivateShareMembers(public_id1,
                                          share_name1,
                                          &shares_members);
    EXPECT_EQ(1U, shares_members.size());

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
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id,
                  &share_name1));
    directory2 = test_elements2.mount_path()/ kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    EXPECT_EQ(kSuccess, test_elements2.RemoveContact(public_id2,
                                                     public_id1,
                                                     removal_message));
    EXPECT_TRUE(test_elements2.GetContacts(public_id2).empty());
    // OS will cache the directory info for about 1 seconds
    while (fs::exists(directory2, error_code))
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(fs::is_directory(directory2, error_code)) << directory2;

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    while (!testing_variables1.removed)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(removal_message, testing_variables1.removal_message);
    bool contact_deleted(false);
    while (!contact_deleted)
      contact_deleted = test_elements1.GetContacts(public_id1).empty();
    EXPECT_TRUE(contact_deleted);

    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    StringIntMap shares_members;
    test_elements1.GetPrivateShareMembers(public_id1,
                                          share_name1,
                                          &shares_members);
    EXPECT_EQ(0, shares_members.size());

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

TEST(IndependentFullTest, FUNC_PrivateShareNonOwnerRemoveNonOwnerContact) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string username1(RandomAlphaNumericString(6)),
              pin1(CreatePin()),
              password1(RandomAlphaNumericString(6)),
              public_id1(RandomAlphaNumericString(5));
  std::string username2(RandomAlphaNumericString(6)),
              pin2(CreatePin()),
              password2(RandomAlphaNumericString(6)),
              public_id2(RandomAlphaNumericString(5));
  LifeStuff test_elements1, test_elements2, test_elements3;
  TestingVariables testing_variables1, testing_variables2, testing_variables3;
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements1,
                                                   test_elements2,
                                                   testing_variables1,
                                                   testing_variables2,
                                                   *test_dir,
                                                   username1, pin1, password1,
                                                   public_id1,
                                                   username2, pin2, password2,
                                                   public_id2));

  std::string username3(RandomAlphaNumericString(6)),
              pin3(CreatePin()),
              password3(RandomAlphaNumericString(6)),
              public_id3(RandomAlphaNumericString(5));
  test_elements3.Initialise(*test_dir);
  test_elements3.ConnectToSignals(
                std::bind(&ChatSlot, args::_1, args::_2, args::_3, args::_4,
                          &testing_variables3.chat_message,
                          &testing_variables3.chat_message_received),
                std::bind(&FileTransferSlot,
                          args::_1, args::_2, args::_3, args::_4, args::_5,
                          &testing_variables3.file_name,
                          &testing_variables3.file_id,
                          &testing_variables3.file_transfer_received),
                std::bind(&NewContactSlot, args::_1, args::_2, args::_3,
                          &testing_variables3.newly_contacted),
                std::bind(&ContactConfirmationSlot,
                          args::_1, args::_2, args::_3,
                          &testing_variables3.confirmed),
                std::bind(&ContactProfilePictureSlot,
                          args::_1, args::_2, args::_3,
                          &testing_variables3.picture_updated),
                std::bind(&ContactPresenceSlot,
                          args::_1, args::_2, args::_3, args::_4,
                          &testing_variables3.presence_announced),
                std::bind(&ContactDeletionSlot,
                          args::_1, args::_2, args::_3, args::_4,
                          &testing_variables3.removal_message,
                          &testing_variables3.removed),
                std::bind(&PrivateShareInvitationSlot,
                          args::_1, args::_2, args::_3,
                          args::_4, args::_5, args::_6,
                          &testing_variables3.new_private_share_name,
                          &testing_variables3.new_private_share_id,
                          &testing_variables3.new_private_access_level,
                          &testing_variables3.privately_invited),
                std::bind(&PrivateShareDeletionSlot,
                          args::_1, args::_2, args::_3, args::_4, args::_5,
                          &testing_variables3.deleted_private_share_name,
                          &testing_variables3.private_share_deleted),
                std::bind(&PrivateMemberAccessLevelSlot,
                          args::_1, args::_2, args::_3,
                          args::_4, args::_5, args::_6,
                          &testing_variables3.access_private_share_name,
                          &testing_variables3.private_member_access,
                          &testing_variables3.private_member_access_changed),
                std::bind(&OpenShareInvitationSlot,
                          args::_1, args::_2, args::_3, args::_4, args::_5,
                          &testing_variables3.new_open_share_id,
                          &testing_variables3.openly_invited),
                std::bind(&ShareRenameSlot,
                          args::_1, args::_2,
                          &testing_variables3.old_share_name,
                          &testing_variables3.new_share_name,
                          &testing_variables3.share_renamed));
  test_elements3.CreateUser(username3, pin3, password3);
  test_elements3.CreatePublicId(public_id3);
  test_elements3.AddContact(public_id3, public_id1);
  test_elements3.AddContact(public_id3, public_id2);
  test_elements3.LogOut();

  testing_variables1.newly_contacted = false;
  test_elements1.LogIn(username1, pin1, password1);
  while (!testing_variables1.newly_contacted)
    Sleep(bptime::milliseconds(100));
  test_elements1.ConfirmContact(public_id1, public_id3);
  test_elements1.LogOut();

  testing_variables2.newly_contacted = false;
  test_elements2.LogIn(username2, pin2, password2);
  while (!testing_variables2.newly_contacted)
    Sleep(bptime::milliseconds(100));
  test_elements2.ConfirmContact(public_id2, public_id3);
  test_elements2.LogOut();

  test_elements3.LogIn(username3, pin3, password3);
    while (!testing_variables3.confirmed)
      Sleep(bptime::milliseconds(100));
  test_elements3.LogOut();

  DLOG(ERROR) << "\n\n\n\n";
  std::string removal_message("It's not me, it's you.");
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
  fs::path directory1, directory2, directory3;
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id2, kShareReadOnly));
    contacts.insert(std::make_pair(public_id3, kShareReadOnly));
    results.insert(std::make_pair(public_id2, kGeneralError));
    results.insert(std::make_pair(public_id3, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements1.CreateEmptyPrivateShare(public_id1,
                                                               contacts,
                                                               &share_name1,
                                                               &results));
    directory1 = test_elements1.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id2]);
    StringIntMap shares_members;
    test_elements1.GetPrivateShareMembers(public_id1,
                                          share_name1,
                                          &shares_members);
    EXPECT_EQ(2U, shares_members.size());

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
                  public_id2,
                  public_id1,
                  testing_variables2.new_private_share_id,
                  &share_name1));
    directory2 = test_elements2.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements3.LogIn(username3, pin3, password3));
    while (!testing_variables3.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables3.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements3.AcceptPrivateShareInvitation(
                  public_id3,
                  public_id1,
                  testing_variables3.new_private_share_id,
                  &share_name1));
    directory3 = test_elements3.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory3, error_code)) << directory3;

    EXPECT_EQ(kSuccess, test_elements3.RemoveContact(public_id3,
                                                     public_id2,
                                                     removal_message));
    EXPECT_EQ(1U, test_elements3.GetContacts(public_id3).size());

    EXPECT_TRUE(fs::is_directory(directory3, error_code)) << directory3;

    EXPECT_EQ(kSuccess, test_elements3.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements2.LogIn(username2, pin2, password2));
    while (!testing_variables2.removed)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(removal_message, testing_variables2.removal_message);
    bool contact_deleted(false);
    while (!contact_deleted)
       if (test_elements2.GetContacts(public_id2).size() > 1)
         contact_deleted = true;
    EXPECT_TRUE(contact_deleted);

    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;
    EXPECT_EQ(0, error_code.value());


    EXPECT_EQ(kSuccess, test_elements2.LogOut());
  }
  DLOG(ERROR) << "\n\n\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements1.LogIn(username1, pin1, password1));
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory2;
    EXPECT_EQ(0, error_code.value());
    StringIntMap shares_members;
    test_elements1.GetPrivateShareMembers(public_id1,
                                          share_name1,
                                          &shares_members);
    EXPECT_EQ(2U, shares_members.size());
    EXPECT_EQ(2U, test_elements1.GetContacts(public_id1).size());

    EXPECT_EQ(kSuccess, test_elements1.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements1.Finalise());
  EXPECT_EQ(kSuccess, test_elements2.Finalise());
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
