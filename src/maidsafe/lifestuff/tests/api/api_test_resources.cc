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

#include <string>
#include <vector>

#include "maidsafe/lifestuff/tests/api/api_test_resources.h"

namespace maidsafe {

namespace lifestuff {

namespace test {

namespace testresources {

void ChatSlot(const std::string&,
              const std::string&,
              const std::string& signal_message,
              const std::string&,
              std::string* slot_message,
              volatile bool* done) {
  if (slot_message)
    *slot_message = signal_message;
  *done = true;
}

void FileTransferSlot(const std::string&,
                      const std::string&,
                      const std::string& signal_file_name,
                      const std::string& signal_file_id,
                      const std::string&,
                      std::string* slot_file_name,
                      std::string* slot_file_id,
                      volatile bool* done) {
  if (slot_file_name)
    *slot_file_name = signal_file_name;
  if (slot_file_id)
    *slot_file_id = signal_file_id;
  *done = true;
}

void MultipleFileTransferSlot(const std::string&,
                              const std::string&,
                              const std::string& signal_file_name,
                              const std::string& signal_file_id,
                              const std::string&,
                              std::vector<std::string>* ids,
                              std::vector<std::string>* names,
                              size_t* total_files,
                              volatile bool* done) {
  ids->push_back(signal_file_id);
  names->push_back(signal_file_name);
  if (ids->size() == *total_files)
    *done = true;
}

void NewContactSlot(const std::string&,
                    const std::string&,
                    const std::string& message,
                    const std::string&,
                    volatile bool* done,
                    std::string* contact_request_message) {
  *done = true;
  *contact_request_message = message;
}

void ContactConfirmationSlot(const std::string&,
                             const std::string&,
                             const std::string&,
                             volatile bool* done) {
  *done = true;
}

void ContactProfilePictureSlot(const std::string&,
                               const std::string&,
                               const std::string&,
                               volatile bool* done) {
  *done = true;
}

void ContactPresenceSlot(const std::string&,
                         const std::string&,
                         const std::string&,
                         ContactPresence,
                         volatile bool* done) {
  *done = true;
}

void ContactDeletionSlot(const std::string&,
                         const std::string&,
                         const std::string& signal_message,
                         const std::string&,
                         std::string* slot_message,
                         volatile bool* done) {
  if (slot_message)
    *slot_message = signal_message;
  *done = true;
}

void PrivateShareInvitationSlot(const std::string&,
                                const std::string&,
                                const std::string& signal_share_name,
                                const std::string& signal_share_id,
                                int access_level,
                                const std::string&,
                                std::string* slot_share_name,
                                std::string* slot_share_id,
                                int* slot_access_level,
                                volatile bool* done) {
  if (slot_share_name)
    *slot_share_name = signal_share_name;
  if (slot_share_id)
    *slot_share_id = signal_share_id;
  if (slot_access_level)
    *slot_access_level = access_level;
  *done = true;
}

void PrivateShareDeletionSlot(const std::string&,
                              const std::string& signal_share_name,
                              const std::string&,
                              const std::string&,
                              const std::string&,
                              std::string* slot_share_name,
                              volatile bool* done) {
  if (slot_share_name)
    *slot_share_name = signal_share_name;
  *done = true;
}

void PrivateMemberAccessChangeSlot(const std::string&,
                                   const std::string&,
                                   const std::string&,
                                   const std::string&,
                                   int signal_member_access,
                                   const std::string& /*slot_share_name*/,
                                   int* slot_member_access,
                                   volatile bool* done) {
  if (slot_member_access)
    *slot_member_access = signal_member_access;
  *done = true;
}

void OpenShareInvitationSlot(const std::string&,
                             const std::string&,
                             const std::string&,
                             const std::string& signal_share_id,
                             const std::string&,
                             std::string* slot_share_id,
                             volatile bool* done) {
  if (slot_share_id)
    *slot_share_id = signal_share_id;
  *done = true;
}

void ShareRenameSlot(const std::string& old_share_name,
                     const std::string& new_share_name,
                     std::string* slot_old_share_name,
                     std::string* slot_new_share_name,
                     volatile bool* done) {
  if (slot_old_share_name)
    *slot_old_share_name = old_share_name;
  if (slot_new_share_name)
    *slot_new_share_name = new_share_name;
  *done = true;
}

void ShareChangedSlot(const std::string& share_name,
                      const fs::path& target_path,
                      const uint32_t& num_of_entries,
                      const fs::path& old_path,
                      const fs::path& new_path,
                      const int& op_type,
                      boost::mutex* mutex,
                      ShareChangeLogBook* share_changes) {
  if (mutex && share_changes) {
    boost::mutex::scoped_lock lock(*mutex);
    share_changes->push_back(ShareChangeLog(share_name,
                                            target_path,
                                            num_of_entries,
                                            old_path,
                                            new_path,
                                            op_type));
  } else if (share_changes) {
    share_changes->push_back(ShareChangeLog(share_name,
                                            target_path,
                                            num_of_entries,
                                            old_path,
                                            new_path,
                                            op_type));
  }
}

int CreateAndConnectTwoPublicIds(LifeStuff& test_elements1,
                                 LifeStuff& test_elements2,
                                 testresources::TestingVariables& testing_variables1,
                                 testresources::TestingVariables& testing_variables2,
                                 const fs::path& test_dir,
                                 const std::string& keyword1,
                                 const std::string& pin1,
                                 const std::string& password1,
                                 const std::string& public_id1,
                                 const std::string& keyword2,
                                 const std::string& pin2,
                                 const std::string& password2,
                                 const std::string& public_id2,
                                 bool several_files,
                                 std::vector<std::string>* ids,
                                 std::vector<std::string>* names,
                                 size_t* total_files,
                                 boost::mutex* mutex) {
  FileTransferFunction ftf =
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& signal_file_name,
           const std::string& signal_file_id,
           const std::string& timestamp) {
        FileTransferSlot(own_public_id, contact_public_id, signal_file_name, signal_file_id,
                         timestamp,
                         &testing_variables2.file_name,
                         &testing_variables2.file_id,
                         &testing_variables2.file_transfer_received);
      };
  if (several_files) {
  ftf = [&] (const std::string& own_public_id,
             const std::string& contact_public_id,
             const std::string& signal_file_name,
             const std::string& signal_file_id,
             const std::string& timestamp) {
          MultipleFileTransferSlot(own_public_id, contact_public_id, signal_file_name,
                                   signal_file_id,
                                   timestamp,
                                   ids, names, total_files,
                                   &testing_variables2.file_transfer_received);
        };
  }
  int result(0);
  // Initialise and connect
  result += test_elements1.Initialise(test_dir);
  result += test_elements2.Initialise(test_dir);
  result += test_elements1.ConnectToSignals(
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_message,
                     const std::string& timestamp) {
                  ChatSlot(own_public_id, contact_public_id, signal_message, timestamp,
                           &testing_variables1.chat_message,
                           &testing_variables1.chat_message_received);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_file_name,
                     const std::string& signal_file_id,
                     const std::string& timestamp) {
                  FileTransferSlot(own_public_id, contact_public_id, signal_file_name,
                                   signal_file_id,
                                   timestamp,
                                   &testing_variables1.file_name,
                                   &testing_variables1.file_id,
                                   &testing_variables1.file_transfer_received);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& message,
                     const std::string& timestamp) {
                  NewContactSlot(own_public_id, contact_public_id, message, timestamp,
                                 &testing_variables1.newly_contacted,
                                 &testing_variables1.contact_request_message);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& timestamp) {
                  ContactConfirmationSlot(own_public_id, contact_public_id, timestamp,
                                          &testing_variables1.confirmed);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& timestamp) {
                  ContactProfilePictureSlot(own_public_id, contact_public_id, timestamp,
                                            &testing_variables1.picture_updated);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& timestamp,
                    ContactPresence contact_presence) {
                  ContactPresenceSlot(own_public_id, contact_public_id, timestamp,
                                      contact_presence,
                                      &testing_variables1.presence_announced);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_message,
                     const std::string& timestamp) {
                  ContactDeletionSlot(own_public_id, contact_public_id, signal_message,
                                      timestamp,
                                      &testing_variables1.removal_message,
                                      &testing_variables1.removed);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_share_name,
                     const std::string& signal_share_id,
                     int access_level,
                     const std::string& timestamp) {
                  PrivateShareInvitationSlot(own_public_id, contact_public_id,
                                             signal_share_name,
                                             signal_share_id,
                                             access_level,
                                             timestamp,
                                             &testing_variables1.new_private_share_name,
                                             &testing_variables1.new_private_share_id,
                                             &testing_variables1.new_private_access_level,
                                             &testing_variables1.privately_invited);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_share_name,
                     const std::string& signal_share_id,
                     const std::string& timestamp) {
                  PrivateShareDeletionSlot(own_public_id, contact_public_id,
                                           signal_share_name,
                                           signal_share_id,
                                           timestamp,
                                           &testing_variables1.deleted_private_share_name,
                                           &testing_variables1.private_share_deleted);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_share_name,
                     const std::string& signal_share_id,
                     int signal_member_access,
                     const std::string /*&time_stamp*/) {
                  PrivateMemberAccessChangeSlot(
                      own_public_id, contact_public_id, signal_share_name, signal_share_id,
                      signal_member_access,
                      testing_variables1.access_private_share_name,
                      &testing_variables1.private_member_access,
                      &testing_variables1.private_member_access_changed);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_share_name,
                     const std::string& signal_share_id,
                     const std::string& timestamp) {
                  OpenShareInvitationSlot(own_public_id, contact_public_id,
                                          signal_share_name,
                                          signal_share_id,
                                          timestamp,
                                          &testing_variables1.new_open_share_id,
                                          &testing_variables1.openly_invited);
                },
                [&] (const std::string& old_share_name,
                     const std::string& new_share_name) {
                  ShareRenameSlot(old_share_name, new_share_name,
                                  &testing_variables1.old_share_name,
                                  &testing_variables1.new_share_name,
                                  &testing_variables1.share_renamed);
                },
                [&] (const std::string& share_name,
                     const fs::path& target_path,
                     const uint32_t& num_of_entries,
                     const fs::path& old_path,
                     const fs::path& new_path,
                     const int& op_type) {
                  ShareChangedSlot(share_name, target_path, num_of_entries, old_path,
                                   new_path,
                                   op_type,
                                   mutex,
                                   &testing_variables1.share_changes);
                });
  result += test_elements2.ConnectToSignals(
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_message,
                     const std::string& timestamp) {
                  ChatSlot(own_public_id, contact_public_id, signal_message, timestamp,
                           &testing_variables2.chat_message,
                           &testing_variables2.chat_message_received);
                },
                ftf,
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& message,
                     const std::string& timestamp) {
                  NewContactSlot(own_public_id, contact_public_id, message, timestamp,
                                 &testing_variables2.newly_contacted,
                                 &testing_variables2.contact_request_message);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& timestamp) {
                  ContactConfirmationSlot(own_public_id, contact_public_id, timestamp,
                                          &testing_variables2.confirmed);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& timestamp) {
                  ContactProfilePictureSlot(own_public_id, contact_public_id, timestamp,
                                            &testing_variables2.picture_updated);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& timestamp,
                    ContactPresence contact_presence) {
                  ContactPresenceSlot(own_public_id, contact_public_id, timestamp,
                                      contact_presence,
                                      &testing_variables2.presence_announced);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_message,
                     const std::string& timestamp) {
                  ContactDeletionSlot(own_public_id, contact_public_id, signal_message,
                                      timestamp,
                                      &testing_variables2.removal_message,
                                      &testing_variables2.removed);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_share_name,
                     const std::string& signal_share_id,
                     int access_level,
                     const std::string& timestamp) {
                  PrivateShareInvitationSlot(own_public_id, contact_public_id,
                                             signal_share_name,
                                             signal_share_id,
                                             access_level,
                                             timestamp,
                                             &testing_variables2.new_private_share_name,
                                             &testing_variables2.new_private_share_id,
                                             &testing_variables2.new_private_access_level,
                                             &testing_variables2.privately_invited);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_share_name,
                     const std::string& signal_share_id,
                     const std::string& timestamp) {
                  PrivateShareDeletionSlot(own_public_id, contact_public_id,
                                           signal_share_name,
                                           signal_share_id,
                                           timestamp,
                                           &testing_variables2.deleted_private_share_name,
                                           &testing_variables2.private_share_deleted);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_share_name,
                     const std::string& signal_share_id,
                     int signal_member_access,
                     const std::string /*&timestamp*/) {
                  PrivateMemberAccessChangeSlot(
                      own_public_id, contact_public_id, signal_share_name, signal_share_id,
                      signal_member_access,
                      testing_variables2.access_private_share_name,
                      &testing_variables2.private_member_access,
                      &testing_variables2.private_member_access_changed);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_share_name,
                     const std::string& signal_share_id,
                     const std::string& timestamp) {
                  OpenShareInvitationSlot(own_public_id, contact_public_id,
                                          signal_share_name,
                                          signal_share_id,
                                          timestamp,
                                          &testing_variables2.new_open_share_id,
                                          &testing_variables2.openly_invited);
                },
                [&] (const std::string& old_share_name,
                     const std::string& new_share_name) {
                  ShareRenameSlot(old_share_name, new_share_name,
                                  &testing_variables2.old_share_name,
                                  &testing_variables2.new_share_name,
                                  &testing_variables2.share_renamed);
                },
                [&] (const std::string& share_name,
                     const fs::path& target_path,
                     const uint32_t& num_of_entries,
                     const fs::path& old_path,
                     const fs::path& new_path,
                     const int& op_type) {
                  ShareChangedSlot(share_name, target_path, num_of_entries, old_path,
                                   new_path,
                                   op_type,
                                   mutex,
                                   &testing_variables2.share_changes);
                });
  if (result != kSuccess)
    return result;

  {
    result += test_elements1.CreateUser(keyword1, pin1, password1);
    result += test_elements1.CreatePublicId(public_id1);
    result += test_elements1.LogOut();
    if (result != kSuccess) {
      LOG(kError) << "Failure log out 1";
      return result;
    }
  }
  {
    result += test_elements2.CreateUser(keyword2, pin2, password2);
    result += test_elements2.CreatePublicId(public_id2);
    result += test_elements2.AddContact(public_id2, public_id1);
    result += test_elements2.LogOut();
    if (result != kSuccess) {
      LOG(kError) << "Failure creating 2";
      return result;
    }
  }
  {
    result += test_elements1.LogIn(keyword1, pin1, password1);

    while (!testing_variables1.newly_contacted)
      Sleep(bptime::milliseconds(100));

    result += test_elements1.ConfirmContact(public_id1, public_id2);
    result += test_elements1.LogOut();
    if (result != kSuccess)
      return result;
  }
  {
    result += test_elements2.LogIn(keyword2, pin2, password2);
//     LOG(kError) << "result: " << result;
    while (!testing_variables2.confirmed)
      Sleep(bptime::milliseconds(100));
    result += test_elements2.LogOut();
    if (result != kSuccess)
      return result;
  }

  return result;
}

}  // namespace testresources

namespace sleepthreads {

void RandomSleep(const std::pair<int, int> sleeps) {
  // Sleeps for random number of milliseconds m with m satisfying sleeps.first <= m < sleeps.second
  if (sleeps.second > 0 && sleeps.first >= 0) {
    if (sleeps.first < sleeps.second)
      Sleep(bptime::milliseconds(RandomUint32() % (sleeps.second - sleeps.first) + sleeps.first));
    else
      Sleep(bptime::milliseconds(sleeps.first));
  }
}

void RunChangePin(LifeStuff& test_elements,
                  int& result,
                  const std::string& new_pin,
                  const std::string& password,
                  const std::pair<int, int> sleeps) {
  RandomSleep(sleeps);
  result = test_elements.ChangePin(new_pin, password);
}

void RunChangeKeyword(LifeStuff& test_elements,
                      int& result,
                      const std::string& new_keyword,
                      const std::string& password,
                      const std::pair<int, int> sleeps) {
  RandomSleep(sleeps);
  result = test_elements.ChangeKeyword(new_keyword, password);
}

void RunChangePassword(LifeStuff& test_elements,
                       int& result,
                       const std::string& new_password,
                       const std::string& password,
                       const std::pair<int, int> sleeps) {
  RandomSleep(sleeps);
  result = test_elements.ChangePassword(new_password, password);
}

void RunCreatePublicId(LifeStuff& test_elements,
                       int& result,
                       const std::string& new_id,
                       const std::pair<int, int> sleeps) {
  RandomSleep(sleeps);
  result = test_elements.CreatePublicId(new_id);
}

void RunCreateUser(LifeStuff& test_elements,
                   int& result,
                   const std::string& keyword,
                   const std::string& pin,
                   const std::string& password,
                   const std::pair<int, int> sleeps) {
  RandomSleep(sleeps);
  result = test_elements.CreateUser(keyword, pin, password);
}

void RunChangeProfilePicture(LifeStuff& test_elements_,
                             int& result,
                             const std::string public_id,
                             const std::string file_content) {
  result = test_elements_.ChangeProfilePicture(public_id, file_content);
}

void RunLogIn(LifeStuff& test_elements,
              int& result,
              const std::string& keyword,
              const std::string& pin,
              const std::string& password,
              const std::pair<int, int> sleeps) {
  RandomSleep(sleeps);
  result = test_elements.LogIn(keyword, pin, password);
}

}  // namespace sleepthreads

void OneUserApiTest::SetUp() {
  EXPECT_EQ(kSuccess, test_elements_.Initialise(*test_dir_));
  EXPECT_EQ(kSuccess,
            test_elements_.ConnectToSignals(ChatFunction(),
                                            FileTransferFunction(),
                                            NewContactFunction(),
                                            ContactConfirmationFunction(),
                                            ContactProfilePictureFunction(),
                                            [&] (const std::string& own_public_id,
                                                 const std::string& contact_public_id,
                                                 const std::string& timestamp,
                                                 ContactPresence cp) {
                                              testresources::ContactPresenceSlot(own_public_id,
                                                                                 contact_public_id,
                                                                                 timestamp,
                                                                                 cp,
                                                                                 &done_);
                                            },
                                            ContactDeletionFunction(),
                                            PrivateShareInvitationFunction(),
                                            PrivateShareDeletionFunction(),
                                            PrivateMemberAccessChangeFunction(),
                                            OpenShareInvitationFunction(),
                                            ShareRenamedFunction(),
                                            ShareChangedFunction()));
  EXPECT_EQ(kSuccess, test_elements_.CreateUser(keyword_, pin_, password_));
}

void OneUserApiTest::TearDown() {
  EXPECT_EQ(kSuccess, test_elements_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_.Finalise());
}

void TwoInstancesApiTest::SetUp() {
  EXPECT_EQ(kSuccess, test_elements_.Initialise(*test_dir_));
  EXPECT_EQ(kSuccess, test_elements_2_.Initialise(*test_dir_));
  EXPECT_EQ(kSuccess,
            test_elements_.ConnectToSignals(ChatFunction(),
                                            FileTransferFunction(),
                                            NewContactFunction(),
                                            ContactConfirmationFunction(),
                                            ContactProfilePictureFunction(),
                                            [&] (const std::string& own_public_id,
                                                 const std::string& contact_public_id,
                                                 const std::string& timestamp,
                                                 ContactPresence cp) {
                                              testresources::ContactPresenceSlot(own_public_id,
                                                                                 contact_public_id,
                                                                                 timestamp,
                                                                                 cp,
                                                                                 &done_);
                                            },
                                            ContactDeletionFunction(),
                                            PrivateShareInvitationFunction(),
                                            PrivateShareDeletionFunction(),
                                            PrivateMemberAccessChangeFunction(),
                                            OpenShareInvitationFunction(),
                                            ShareRenamedFunction(),
                                            ShareChangedFunction()));
  EXPECT_EQ(kSuccess,
            test_elements_2_.ConnectToSignals(ChatFunction(),
                                            FileTransferFunction(),
                                            NewContactFunction(),
                                            ContactConfirmationFunction(),
                                            ContactProfilePictureFunction(),
                                            [&] (const std::string& own_public_id,
                                                 const std::string& contact_public_id,
                                                 const std::string& timestamp,
                                                 ContactPresence cp) {
                                              testresources::ContactPresenceSlot(own_public_id,
                                                                                 contact_public_id,
                                                                                 timestamp,
                                                                                 cp,
                                                                                 &done_);
                                            },
                                            ContactDeletionFunction(),
                                            PrivateShareInvitationFunction(),
                                            PrivateShareDeletionFunction(),
                                            PrivateMemberAccessChangeFunction(),
                                            OpenShareInvitationFunction(),
                                            ShareRenamedFunction(),
                                            ShareChangedFunction()));
}

void TwoInstancesApiTest::TearDown() {
  EXPECT_EQ(kSuccess, test_elements_.Finalise());
  EXPECT_EQ(kSuccess, test_elements_2_.Finalise());
}

void TwoUsersApiTest::SetUp() {
  ASSERT_EQ(kSuccess,
            CreateAndConnectTwoPublicIds(test_elements_1_, test_elements_2_,
                                         testing_variables_1_, testing_variables_2_,
                                         *test_dir_,
                                         keyword_1_, pin_1_, password_1_, public_id_1_,
                                         keyword_2_, pin_2_, password_2_, public_id_2_));
}

void TwoUsersApiTest::TearDown() {
  if (test_elements_1_.state() == kConnected)
    EXPECT_EQ(kSuccess, test_elements_1_.Finalise());
  if (test_elements_2_.state() == kConnected)
    EXPECT_EQ(kSuccess, test_elements_2_.Finalise());
}

void PrivateSharesApiTest::SetUp() {
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements_1_,
                                                   test_elements_2_,
                                                   testing_variables_1_,
                                                   testing_variables_2_,
                                                   *test_dir_,
                                                   keyword_1_, pin_1_, password_1_,
                                                   public_id_1_,
                                                   keyword_2_, pin_2_, password_2_,
                                                   public_id_2_));
}

void PrivateSharesApiTest::TearDown() {
  if (test_elements_1_.state() == kConnected)
    EXPECT_EQ(kSuccess, test_elements_1_.Finalise());
  if (test_elements_2_.state() == kConnected)
    EXPECT_EQ(kSuccess, test_elements_2_.Finalise());
}

void TwoUsersMutexApiTest::SetUp() {
  ASSERT_EQ(kSuccess, CreateAndConnectTwoPublicIds(test_elements_1_,
                                                   test_elements_2_,
                                                   testing_variables_1_,
                                                   testing_variables_2_,
                                                   *test_dir_,
                                                   keyword_1_, pin_1_, password_1_,
                                                   public_id_1_,
                                                   keyword_2_, pin_2_, password_2_,
                                                   public_id_2_, false,
                                                   nullptr, nullptr, nullptr,
                                                   &mutex_));
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
