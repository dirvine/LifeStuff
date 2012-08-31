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
                                   const std::string& share_name,
                                   const std::string&,
                                   int signal_member_access,
                                   const std::string& /*slot_share_name*/,
                                   int* slot_member_access,
                                   volatile bool *done) {
  ASSERT_NE("", share_name);
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

void LifestuffCardSlot(const std::string&,
                       const std::string&,
                       const std::string&,
                       volatile bool* done) {
  *done = true;
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
  int result(0);
  result = CreateAccountWithPublicId(test_elements1,
                                     testing_variables1,
                                     test_dir,
                                     keyword1,
                                     pin1,
                                     password1,
                                     public_id1,
                                     false,
                                     ids,
                                     names,
                                     total_files,
                                     mutex);
  if (result != kSuccess)
    return result;
  result = CreateAccountWithPublicId(test_elements2,
                                     testing_variables2,
                                     test_dir,
                                     keyword2,
                                     pin2,
                                     password2,
                                     public_id2,
                                     several_files,
                                     ids,
                                     names,
                                     total_files,
                                     mutex);
  if (result != kSuccess)
    return result;
  result = ConnectTwoPublicIds(test_elements1,
                               test_elements2,
                               testing_variables1,
                               testing_variables2,
                               keyword1,
                               pin1,
                               password1,
                               public_id1,
                               keyword2,
                               pin2,
                               password2,
                               public_id2);
  return result;
}

int InitialiseAndConnect(LifeStuff& test_elements,
                   testresources::TestingVariables& testing_variables,
                   const fs::path& test_dir,
                   bool several_files,
                   std::vector<std::string>* ids,
                   std::vector<std::string>* names,
                   size_t* total_files,
                   boost::mutex* mutex) {
  FileTransferFunction ftf;
  if (several_files) {
    ftf = [=, &testing_variables] (const std::string& own_public_id,
                                   const std::string& contact_public_id,
                                   const std::string& signal_file_name,
                                   const std::string& signal_file_id,
                                   const std::string& timestamp) {
      MultipleFileTransferSlot(own_public_id,
                               contact_public_id,
                               signal_file_name,
                               signal_file_id,
                               timestamp,
                               ids,
                               names,
                               total_files,
                               &testing_variables.file_transfer_received);
    };
  } else {
    ftf = [=, &testing_variables] (const std::string& own_public_id,
                                   const std::string& contact_public_id,
                                   const std::string& signal_file_name,
                                   const std::string& signal_file_id,
                                   const std::string& timestamp) {
            FileTransferSlot(own_public_id,
                             contact_public_id,
                             signal_file_name,
                             signal_file_id,
                             timestamp,
                             &testing_variables.file_name,
                             &testing_variables.file_id,
                             &testing_variables.file_transfer_received);
          };
  }

  int result(0);
  // Initialise and connect
  result += test_elements.Initialise(test_dir);
  result += test_elements.ConnectToSignals(
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_message,
                     const std::string& timestamp) {
                  ChatSlot(own_public_id,
                           contact_public_id,
                           signal_message,
                           timestamp,
                           &testing_variables.chat_message,
                           &testing_variables.chat_message_received);
                },
                ftf,
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& message,
                     const std::string& timestamp) {
                  NewContactSlot(own_public_id,
                                 contact_public_id,
                                 message,
                                 timestamp,
                                 &testing_variables.newly_contacted,
                                 &testing_variables.contact_request_message);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& timestamp) {
                  ContactConfirmationSlot(own_public_id,
                                          contact_public_id,
                                          timestamp,
                                          &testing_variables.confirmed);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& timestamp) {
                  ContactProfilePictureSlot(own_public_id,
                                            contact_public_id,
                                            timestamp,
                                            &testing_variables.picture_updated);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& timestamp,
                    ContactPresence contact_presence) {
                  ContactPresenceSlot(own_public_id,
                                      contact_public_id,
                                      timestamp,
                                      contact_presence,
                                      &testing_variables.presence_announced);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_message,
                     const std::string& timestamp) {
                  ContactDeletionSlot(own_public_id,
                                      contact_public_id,
                                      signal_message,
                                      timestamp,
                                      &testing_variables.removal_message,
                                      &testing_variables.removed);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_share_name,
                     const std::string& signal_share_id,
                     int access_level,
                     const std::string& timestamp) {
                  PrivateShareInvitationSlot(own_public_id,
                                             contact_public_id,
                                             signal_share_name,
                                             signal_share_id,
                                             access_level,
                                             timestamp,
                                             &testing_variables.new_private_share_name,
                                             &testing_variables.new_private_share_id,
                                             &testing_variables.new_private_access_level,
                                             &testing_variables.privately_invited);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_share_name,
                     const std::string& signal_share_id,
                     const std::string& timestamp) {
                  PrivateShareDeletionSlot(own_public_id,
                                           contact_public_id,
                                           signal_share_name,
                                           signal_share_id,
                                           timestamp,
                                           &testing_variables.deleted_private_share_name,
                                           &testing_variables.private_share_deleted);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_share_name,
                     const std::string& signal_share_id,
                     int signal_member_access,
                     const std::string /*&timestamp*/) {
                  PrivateMemberAccessChangeSlot(
                      own_public_id,
                      contact_public_id,
                      signal_share_name,
                      signal_share_id,
                      signal_member_access,
                      testing_variables.access_private_share_name,
                      &testing_variables.private_member_access,
                      &testing_variables.private_member_access_changed);
                },
                [&] (const std::string& own_public_id,
                     const std::string& contact_public_id,
                     const std::string& signal_share_name,
                     const std::string& signal_share_id,
                     const std::string& timestamp) {
                  OpenShareInvitationSlot(own_public_id,
                                          contact_public_id,
                                          signal_share_name,
                                          signal_share_id,
                                          timestamp,
                                          &testing_variables.new_open_share_id,
                                          &testing_variables.openly_invited);
                },
                [&] (const std::string& old_share_name,
                     const std::string& new_share_name) {
                  ShareRenameSlot(old_share_name,
                                  new_share_name,
                                  &testing_variables.old_share_name,
                                  &testing_variables.new_share_name,
                                  &testing_variables.share_renamed);
                },
                [=, &testing_variables] (const std::string& share_name,
                                         const fs::path& target_path,
                                         const uint32_t& num_of_entries,
                                         const fs::path& old_path,
                                         const fs::path& new_path,
                                         const int& op_type) {
                  ShareChangedSlot(share_name,
                                   target_path,
                                   num_of_entries,
                                   old_path,
                                   new_path,
                                   op_type,
                                   mutex,
                                   &testing_variables.share_changes);
                },
                [&] (const std::string& own_id,
                     const std::string& contact_id,
                     const std::string& timestamp) {
                  LifestuffCardSlot(own_id,
                                    contact_id,
                                    timestamp,
                                    &testing_variables.social_info_map_changed);
                });
  return result;
}

int CreateAccountWithPublicId(LifeStuff& test_elements,
                              testresources::TestingVariables& testing_variables,
                              const fs::path& test_dir,
                              const std::string& keyword,
                              const std::string& pin,
                              const std::string& password,
                              const std::string& public_id,
                              bool several_files,
                              std::vector<std::string>* ids,
                              std::vector<std::string>* names,
                              size_t* total_files,
                              boost::mutex* mutex) {
  int result(0);
  result = InitialiseAndConnect(test_elements,
                                testing_variables,
                                test_dir,
                                several_files,
                                ids,
                                names,
                                total_files,
                                mutex);
  if (result != kSuccess) {
    LOG(kError) << "Failure initialising and connecting";
    return result;
  }
  result += test_elements.CreateUser(keyword, pin, password);
  result += test_elements.CreatePublicId(public_id);
  result += test_elements.LogOut();
  if (result != kSuccess) {
    LOG(kError) << "Failure creating account";
  }
  return result;
}

int ConnectTwoPublicIds(LifeStuff& test_elements1,
                        LifeStuff& test_elements2,
                        testresources::TestingVariables& testing_variables1,
                        testresources::TestingVariables& testing_variables2,
                        const std::string& keyword1,
                        const std::string& pin1,
                        const std::string& password1,
                        const std::string& public_id1,
                        const std::string& keyword2,
                        const std::string& pin2,
                        const std::string& password2,
                        const std::string& public_id2) {
  // First user adds second user
  int result(0);
  testing_variables1.confirmed = false;
  testing_variables2.newly_contacted = false;
  {
    result += test_elements1.LogIn(keyword1, pin1, password1);
    result += test_elements1.AddContact(public_id1, public_id2);
    result += test_elements1.LogOut();
    if (result != kSuccess) {
      LOG(kError) << "Failure adding contact";
      return result;
    }
  }
  {
    result += test_elements2.LogIn(keyword2, pin2, password2);

    while (!testing_variables2.newly_contacted)
      Sleep(bptime::milliseconds(100));

    result += test_elements2.ConfirmContact(public_id2, public_id1);
    result += test_elements2.LogOut();
    if (result != kSuccess) {
      LOG(kError) << "Failure confirming contact";
      return result;
    }
  }
  {
    result += test_elements1.LogIn(keyword1, pin1, password1);
    while (!testing_variables1.confirmed)
      Sleep(bptime::milliseconds(100));
    result += test_elements1.LogOut();
    if (result != kSuccess)
      return result;
  }

  return result;
}

void CreatePrivateShareAddingOneContact(LifeStuff& test_elements_a,
                                 LifeStuff& test_elements_b,
                                 testresources::TestingVariables& testing_variables_b,
                                 const std::string& keyword_a,
                                 const std::string& pin_a,
                                 const std::string& password_a,
                                 const std::string& public_id_a,
                                 const std::string& keyword_b,
                                 const std::string& pin_b,
                                 const std::string& password_b,
                                 const std::string& public_id_b,
                                 std::string share_name,
                                 const int& rights) {
  LOG(kInfo) << "\n\nCreating private share " << share_name <<
                " owned by " << public_id_a <<
                " and inviting " << public_id_b << "\n";

  if (rights != kShareReadWrite && rights != kShareReadOnly) {
    LOG(kInfo) << "CreatePrivateShareAddingOneContact given incorrect rights value: " << rights;
    return;
  }

  testing_variables_b.privately_invited = false;
  testing_variables_b.new_private_share_id.clear();
  boost::system::error_code error_code;

  // a creates share, inviting b
  EXPECT_EQ(kSuccess, test_elements_a.LogIn(keyword_a, pin_a, password_a));

  StringIntMap contacts, results;
  contacts.insert(std::make_pair(public_id_b, rights));
  results.insert(std::make_pair(public_id_b, kGeneralError));

  EXPECT_EQ(kSuccess,
            test_elements_a.CreateEmptyPrivateShare(public_id_a, contacts,
                                                    &share_name, &results));
  fs::path directory1(test_elements_a.mount_path() / kSharedStuff / share_name);
  EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
  EXPECT_EQ(0, error_code.value());
  EXPECT_EQ(kSuccess, results[public_id_b]);
  StringIntMap shares_members;
  test_elements_a.GetPrivateShareMembers(public_id_a, share_name, &shares_members);
  EXPECT_EQ(1U, shares_members.size());
  PrivateShareRoles expected_state(kShareReadOnlyUnConfirmed);
  if (rights == kShareReadWrite)
    expected_state = kShareReadWriteUnConfirmed;
  EXPECT_EQ(expected_state, shares_members.find(public_id_b)->second);

  EXPECT_EQ(kSuccess, test_elements_a.LogOut());

  // b accepts invitation into share
  EXPECT_EQ(kSuccess, test_elements_b.LogIn(keyword_b, pin_b, password_b));
  while (!testing_variables_b.privately_invited)
    Sleep(bptime::milliseconds(100));
  EXPECT_FALSE(testing_variables_b.new_private_share_id.empty());
  EXPECT_EQ(
      kSuccess,
      test_elements_b.AcceptPrivateShareInvitation(public_id_b,
                                                   public_id_a,
                                                   testing_variables_b.new_private_share_id,
                                                   &share_name));
  fs::path directory2(test_elements_b.mount_path() / kSharedStuff / share_name);
  EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;
  EXPECT_EQ(kSuccess, test_elements_b.LogOut());
}

void AddOneContactToExistingPrivateShare(LifeStuff& test_elements_a,
                                  LifeStuff& test_elements_b,
                                  testresources::TestingVariables& testing_variables_b,
                                  const std::string& keyword_a,
                                  const std::string& pin_a,
                                  const std::string& password_a,
                                  const std::string& public_id_a,
                                  const std::string& keyword_b,
                                  const std::string& pin_b,
                                  const std::string& password_b,
                                  const std::string& public_id_b,
                                  std::string share_name,
                                  const int& rights) {
  LOG(kInfo) << "\n\nInviting " << public_id_b <<
                " into share " << share_name <<
                " owned by " << public_id_a << "\n";

  if (rights != kShareReadWrite && rights != kShareReadOnly) {
    LOG(kInfo) << "AddOneContactToExistingPrivateShare given incorrect rights value: " << rights;
    return;
  }

  testing_variables_b.privately_invited = false;
  testing_variables_b.new_private_share_id.clear();
  boost::system::error_code error_code;

  // a invites b into share
  EXPECT_EQ(kSuccess, test_elements_a.LogIn(keyword_a, pin_a, password_a));

  StringIntMap results;
  EXPECT_EQ(kSuccess, test_elements_a.GetPrivateShareMembers(public_id_a,
                                                             share_name,
                                                             &results));
  EXPECT_EQ(1U, results.size());
  EXPECT_TRUE(results.end() == results.find(public_id_a));
  EXPECT_TRUE(results.end() == results.find(public_id_b));

  StringIntMap amendments;
  results.clear();
  amendments.insert(std::make_pair(public_id_b, rights));
  EXPECT_EQ(kSuccess, test_elements_a.EditPrivateShareMembers(public_id_a,
                                                              amendments,
                                                              share_name,
                                                              &results));
  EXPECT_EQ(kSuccess, results[public_id_b]);
  results[public_id_b] = -1;
  EXPECT_EQ(kSuccess, test_elements_a.GetPrivateShareMembers(public_id_a,
                                                             share_name,
                                                             &results));
  PrivateShareRoles expected_state(kShareReadOnlyUnConfirmed);
  if (rights == kShareReadWrite)
    expected_state = kShareReadWriteUnConfirmed;
  EXPECT_EQ(expected_state, results[public_id_b]);

  EXPECT_EQ(kSuccess, test_elements_a.LogOut());

  // b accepts invitation into share
  EXPECT_EQ(kSuccess, test_elements_b.LogIn(keyword_b, pin_b, password_b));
  while (!testing_variables_b.privately_invited)
    Sleep(bptime::milliseconds(100));
  EXPECT_FALSE(testing_variables_b.new_private_share_id.empty());
  EXPECT_EQ(
      kSuccess,
      test_elements_b.AcceptPrivateShareInvitation(public_id_b,
                                                   public_id_a,
                                                   testing_variables_b.new_private_share_id,
                                                   &share_name));
  fs::path directory2(test_elements_b.mount_path() / kSharedStuff / share_name);
  EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;
  EXPECT_EQ(kSuccess, test_elements_b.LogOut());
}

void CreateOpenShareAddingOneContact(LifeStuff &test_elements_a,
                                     LifeStuff &test_elements_b,
                                     TestingVariables &testing_variables_b,
                                     const std::string &keyword_a,
                                     const std::string &pin_a,
                                     const std::string &password_a,
                                     const std::string &public_id_a,
                                     const std::string &keyword_b,
                                     const std::string &pin_b,
                                     const std::string &password_b,
                                     const std::string &public_id_b,
                                     std::string share_name) {
  LOG(kInfo) << "\n\nCreating open share " << share_name <<
                " owned by " << public_id_a <<
                " and inviting " << public_id_b << "\n";

  testing_variables_b.openly_invited = false;
  testing_variables_b.new_open_share_id.clear();

  boost::system::error_code error_code;

  // a creates share, inviting b
  EXPECT_EQ(kSuccess, test_elements_a.LogIn(keyword_a, pin_a, password_a));

  StringIntMap results;
  std::vector<std::string> contacts;
  contacts.push_back(public_id_b);
  results.insert(std::make_pair(public_id_b, kGeneralError));
  EXPECT_EQ(kSuccess,
            test_elements_a.CreateEmptyOpenShare(public_id_a, contacts, &share_name, &results));
  fs::path share_path(test_elements_a.mount_path() / kSharedStuff / share_name);
  EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
  EXPECT_EQ(0, error_code.value());
  EXPECT_EQ(kSuccess, results[public_id_b]);
  EXPECT_EQ(kSuccess, test_elements_a.LogOut());

  // b accepts invitation into share
  EXPECT_EQ(kSuccess, test_elements_b.LogIn(keyword_b, pin_b, password_b));
  while (!testing_variables_b.openly_invited)
    Sleep(bptime::milliseconds(100));
  EXPECT_FALSE(testing_variables_b.new_open_share_id.empty());
  EXPECT_EQ(kSuccess,
            test_elements_b.AcceptOpenShareInvitation(public_id_b,
                                                      public_id_a,
                                                      testing_variables_b.new_open_share_id,
                                                      &share_name));
  fs::path share(test_elements_b.mount_path() / kSharedStuff / share_name);
  EXPECT_TRUE(fs::is_directory(share, error_code)) << share;
  EXPECT_EQ(kSuccess, test_elements_b.LogOut());
}

void TwoUsersDefriendEachOther(LifeStuff& test_elements_a,
                               LifeStuff& test_elements_b,
                               testresources::TestingVariables& testing_variables_b,
                               const std::string& keyword_a,
                               const std::string& pin_a,
                               const std::string& password_a,
                               const std::string& public_id_a,
                               const std::string& keyword_b,
                               const std::string& pin_b,
                               const std::string& password_b,
                               const std::string& public_id_b) {
  int i(0);
  testing_variables_b.removed = false;

  EXPECT_EQ(kSuccess, test_elements_b.LogIn(keyword_b, pin_b, password_b)) << "Public ID: "
                                                                           << public_id_b;
  size_t num_contacts_b(test_elements_b.GetContacts(public_id_b).size());
  EXPECT_EQ(kSuccess, test_elements_b.LogOut());

  EXPECT_EQ(kSuccess, test_elements_a.LogIn(keyword_a, pin_a, password_a));

  size_t num_contacts_a(test_elements_a.GetContacts(public_id_a).size());
  EXPECT_EQ(kSuccess, test_elements_a.RemoveContact(public_id_a, public_id_b, ""));
  EXPECT_EQ(test_elements_a.GetContacts(public_id_a).size(), num_contacts_a - 1);
  std::vector<std::string>* share_names(new std::vector<std::string>);
  EXPECT_EQ(kSuccess,
            test_elements_a.GetPrivateSharesIncludingMember(public_id_a, public_id_b, share_names));
  EXPECT_EQ(0, share_names->size());
  share_names->clear();
  EXPECT_EQ(kSuccess, test_elements_a.LogOut());

  EXPECT_EQ(kSuccess, test_elements_b.LogIn(keyword_b, pin_b, password_b));
  while (!testing_variables_b.removed && i < 150) {
    ++i;
    Sleep(bptime::milliseconds(100));
  }
  EXPECT_TRUE(testing_variables_b.removed);
  if (i >= 150) {
    LOG(kInfo) << "Removing contact taken too long! (" << public_id_a <<
                  " removing " << public_id_b << ")";
    EXPECT_TRUE(false);
  }
  EXPECT_EQ(test_elements_b.GetContacts(public_id_b).size(), num_contacts_b - 1);
  EXPECT_EQ(kSuccess,
            test_elements_b.GetPrivateSharesIncludingMember(public_id_b, public_id_a, share_names));
  EXPECT_EQ(0, share_names->size());
  EXPECT_EQ(kSuccess, test_elements_b.LogOut());
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
                                            ShareChangedFunction(),
                                            LifestuffCardUpdateFunction()));
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
                                            ShareChangedFunction(),
                                            LifestuffCardUpdateFunction()));
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
                                            ShareChangedFunction(),
                                            LifestuffCardUpdateFunction()));
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
