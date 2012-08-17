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
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/lifestuff_api.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/message_handler.h"
#include "maidsafe/lifestuff/detail/public_id.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/user_credentials.h"
#include "maidsafe/lifestuff/detail/user_storage.h"
#include "maidsafe/lifestuff/tests/api/api_test_resources.h"

namespace args = std::placeholders;
namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace lifestuff {

namespace test {

TEST_F(OneUserApiTest, FUNC_CreateDirectoryLogoutLoginCheckDirectory) {
  // Create directory
  std::string tail;
  fs::path test(CreateTestDirectory(test_elements_.mount_path(), &tail));
  EXPECT_TRUE(fs::exists(test, error_code_));
  EXPECT_EQ(0, error_code_.value());

  // Log out - Log in
  EXPECT_EQ(kSuccess, test_elements_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));

  // Check directory exists
  EXPECT_TRUE(fs::exists(test, error_code_));
  EXPECT_EQ(0, error_code_.value());
}

TEST_F(OneUserApiTest, FUNC_LargeFileForMemoryCheck) {
  // Create directory
  std::string tail;
  EXPECT_EQ(kSuccess, CreateTestFile(test_elements_.mount_path(), 500, &tail));
  EXPECT_TRUE(fs::exists(test_elements_.mount_path() / tail, error_code_));
  EXPECT_EQ(0, error_code_.value());

  // Log out - Log in
  EXPECT_EQ(kSuccess, test_elements_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));

  // Check directory exists
  EXPECT_TRUE(fs::exists(test_elements_.mount_path() / tail, error_code_));
  EXPECT_EQ(0, error_code_.value());
}

TEST_F(TwoUsersApiTest, FUNC_CreateEmptyOpenShare) {
  std::string share_name(RandomAlphaNumericString(5)),
              file_name(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(50));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap  results;
    std::vector<std::string> contacts;
    contacts.push_back(public_id_2_);
    results.insert(std::make_pair(public_id_2_, kGeneralError));
    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyOpenShare(public_id_1_, contacts, &share_name, &results));
    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.openly_invited)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables_2_.new_open_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptOpenShareInvitation(public_id_2_,
                                                         public_id_1_,
                                                         testing_variables_2_.new_open_share_id,
                                                         &share_name));
    fs::path share(test_elements_2_.mount_path() / kSharedStuff / share_name);
    EXPECT_TRUE(fs::is_directory(share, error_code));
    fs::path file_path(share / file_name);
    EXPECT_TRUE(WriteFile(file_path, file_content1));
    EXPECT_TRUE(fs::exists(file_path, error_code));
    EXPECT_EQ(0, error_code.value());

    std::string file_content;
    EXPECT_TRUE(ReadFile(file_path, &file_content));
    EXPECT_EQ(file_content1, file_content);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    fs::path share(test_elements_1_.mount_path() / kSharedStuff / share_name);
    fs::path file_path(share / file_name);
    std::string file_content;
    EXPECT_TRUE(ReadFile(file_path, &file_content));
    EXPECT_EQ(file_content1, file_content);
    EXPECT_TRUE(WriteFile(file_path, file_content2));
    EXPECT_TRUE(ReadFile(file_path, &file_content));
    EXPECT_EQ(file_content2, file_content);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    fs::path share(test_elements_1_.mount_path() / kSharedStuff / share_name);
    fs::path file_path(share / file_name);
    std::string file_content;
    EXPECT_TRUE(ReadFile(file_path, &file_content));
    EXPECT_EQ(file_content2, file_content);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));

    fs::path share(test_elements_2_.mount_path() / kSharedStuff / share_name);
    fs::path file_path(share / file_name);
    EXPECT_TRUE(fs::exists(file_path, error_code)) << file_path;
    EXPECT_EQ(0, error_code.value());
    uintmax_t size(fs::file_size(file_path, error_code));
    EXPECT_EQ(file_content2.size(), size) << file_path;

    std::string file_content;
    EXPECT_TRUE(ReadFile(file_path, &file_content));
    EXPECT_EQ(file_content2, file_content);
    EXPECT_NE(file_content1, file_content);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_CreateOpenShare) {
  std::string directory_name(RandomAlphaNumericString(5)),
              share_name(RandomAlphaNumericString(5)),
              file1_name(RandomAlphaNumericString(5)),
              file2_name(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    fs::path directory(test_elements_1_.mount_path() /
                       kMyStuff / directory_name);
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
    contacts.push_back(public_id_2_);
    results.insert(std::make_pair(public_id_2_, kGeneralError));
    EXPECT_EQ(kSuccess, test_elements_1_.CreateOpenShareFromExistingDirectory(public_id_1_,
                                                                            share_directory,
                                                                            contacts,
                                                                            &share_name,
                                                                            &results));
    fs::path share(test_elements_1_.mount_path() / kSharedStuff / share_name);
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share / file2_name, error_code));
    EXPECT_EQ(0, error_code.value());

    int count(0), limit(30);
    while ((fs::exists(directory / share_name, error_code) && !error_code) &&
           count++ < limit) {
      Sleep(bptime::milliseconds(100));
    }
    EXPECT_FALSE(fs::exists(directory / share_name, error_code));
    EXPECT_NE(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.openly_invited)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables_2_.new_open_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.RejectOpenShareInvitation(public_id_2_,
                                                         testing_variables_2_.new_open_share_id));
    fs::path share(test_elements_2_.mount_path() / kSharedStuff / share_name),
             file_path(share / file2_name);
    EXPECT_FALSE(fs::exists(share, error_code));
    EXPECT_NE(0, error_code.value());
    EXPECT_FALSE(fs::exists(file_path, error_code));
    EXPECT_NE(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    fs::path share(test_elements_1_.mount_path() / kSharedStuff / share_name);
    fs::path file_path(share / file2_name);
    std::string file_stuff;
    EXPECT_TRUE(ReadFile(file_path, &file_stuff));
    EXPECT_EQ(file_content2, file_stuff);
    EXPECT_TRUE(WriteFile(file_path, file_content1));

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_InviteOpenShareMembers) {
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
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    fs::path directory(test_elements_1_.mount_path() / kMyStuff / directory_name);
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
    contacts.push_back(public_id_2_);
    results.insert(std::make_pair(public_id_2_, kGeneralError));
    EXPECT_EQ(kSuccess, test_elements_1_.CreateOpenShareFromExistingDirectory(public_id_1_,
                                                                              share_directory1,
                                                                              contacts,
                                                                              &share1_name,
                                                                              &results));
    fs::path share(test_elements_1_.mount_path() / kSharedStuff / share1_name);
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share / file2_name, error_code));
    EXPECT_EQ(0, error_code.value());

    int count(0), limit(30);
    while ((fs::exists(directory / share1_name, error_code) && !error_code) && count++ < limit)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::exists(directory / share1_name, error_code));
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.openly_invited)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables_2_.new_open_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.RejectOpenShareInvitation(public_id_2_,
                                                         testing_variables_2_.new_open_share_id));
    fs::path share(test_elements_2_.mount_path() / kSharedStuff / share1_name),
             file_path(share / file2_name);
    EXPECT_FALSE(fs::exists(share, error_code));
    EXPECT_NE(0, error_code.value());
    EXPECT_FALSE(fs::exists(file_path, error_code));
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    fs::path share1(test_elements_1_.mount_path() / kSharedStuff / share1_name);
    fs::path file_path(share1 / file2_name);
    std::string file_stuff;
    EXPECT_TRUE(ReadFile(file_path, &file_stuff));
    EXPECT_EQ(file_content2, file_stuff);
    EXPECT_TRUE(WriteFile(file_path, file_content1));

    fs::path directory(test_elements_1_.mount_path() / kMyStuff / directory_name);
    StringIntMap results;
    std::vector<std::string> contacts;
    fs::path share_directory2(directory / share2_name);
    EXPECT_EQ(kSuccess, test_elements_1_.CreateOpenShareFromExistingDirectory(public_id_1_,
                                                                              share_directory2,
                                                                              contacts,
                                                                              &share2_name,
                                                                              &results));
    fs::path share2(test_elements_1_.mount_path() / kSharedStuff / share2_name);
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    EXPECT_TRUE(fs::exists(share2, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share2 / file3_name, error_code));
    EXPECT_EQ(0, error_code.value());

    int count(0), limit(30);
    while (fs::exists(directory / share2_name, error_code) && !error_code && count++ < limit)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::exists(directory / share2_name, error_code));
    EXPECT_NE(0, error_code.value());

    std::vector<std::string> shares;
    EXPECT_EQ(kSuccess, test_elements_1_.GetOpenShareList(public_id_1_, &shares));
    EXPECT_EQ(2, shares.size());

    StringIntMap members;
    EXPECT_EQ(kSuccess, test_elements_1_.GetOpenShareMembers(public_id_1_, share2_name, &members));
    EXPECT_EQ(0, members.size());

    contacts.push_back(public_id_2_);
    results.insert(std::make_pair(public_id_2_, kGeneralError));
    EXPECT_EQ(kSuccess,
              test_elements_1_.InviteMembersToOpenShare(public_id_1_, contacts, share2_name,
                                                        &results));
    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.openly_invited)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables_2_.new_open_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptOpenShareInvitation(public_id_2_,
                                                       public_id_1_,
                                                       testing_variables_2_.new_open_share_id,
                                                       &share2_name));
    fs::path share(test_elements_2_.mount_path() / kSharedStuff / share2_name),
             file_path(share / file3_name);
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(file_path, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(WriteFile(file_path, file_content2));

    std::vector<std::string> shares;
    EXPECT_EQ(kSuccess, test_elements_2_.GetOpenShareList(public_id_2_, &shares));
    EXPECT_EQ(1, shares.size());

    StringIntMap members;
    EXPECT_EQ(kSuccess, test_elements_2_.GetOpenShareMembers(public_id_2_, share2_name, &members));
    EXPECT_EQ(1, members.size());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_LeaveOpenShare) {
  std::string directory_name(RandomAlphaNumericString(5)),
              share_name(RandomAlphaNumericString(5)),
              file1_name(RandomAlphaNumericString(5)),
              file2_name(RandomAlphaNumericString(5)),
              file_content1(RandomString(20)),
              file_content2(RandomString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    fs::path directory(test_elements_1_.mount_path() / kMyStuff / directory_name);
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
    contacts.push_back(public_id_2_);
    results.insert(std::make_pair(public_id_2_, kGeneralError));
    EXPECT_EQ(kSuccess, test_elements_1_.CreateOpenShareFromExistingDirectory(public_id_1_,
                                                                              share_directory,
                                                                              contacts,
                                                                              &share_name,
                                                                              &results));
    fs::path share(test_elements_1_.mount_path() / kSharedStuff / share_name);
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share / file2_name, error_code));
    EXPECT_EQ(0, error_code.value());

    int count(0), limit(30);
    while ((fs::exists(directory / share_name, error_code) && !error_code) && count++ < limit)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::exists(directory / share_name, error_code));
    EXPECT_NE(0, error_code.value());
    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.openly_invited)
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(testing_variables_2_.new_open_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptOpenShareInvitation(public_id_2_,
                                                         public_id_1_,
                                                         testing_variables_2_.new_open_share_id,
                                                         &share_name));
    fs::path share(test_elements_2_.mount_path() / kSharedStuff / share_name),
             file_path(share / file2_name);
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(file_path, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    fs::path share(test_elements_1_.mount_path() / kSharedStuff / share_name);
    fs::path file_path(share / file2_name);
    std::string file_stuff;
    EXPECT_TRUE(ReadFile(file_path, &file_stuff));
    EXPECT_EQ(file_content2, file_stuff);
    EXPECT_TRUE(WriteFile(file_path, file_content1));

    EXPECT_EQ(kSuccess, test_elements_1_.LeaveOpenShare(public_id_1_, share_name));
    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    fs::path share(test_elements_2_.mount_path() / kSharedStuff / share_name),
             file_path(share / file2_name);
    std::string file_stuff;
    EXPECT_TRUE(fs::exists(share, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(file_path, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(ReadFile(file_path, &file_stuff));
    EXPECT_EQ(file_content1, file_stuff);

    std::vector<std::string> shares;
    EXPECT_EQ(kSuccess, test_elements_2_.GetOpenShareList(public_id_2_, &shares));
    EXPECT_EQ(1, shares.size());

    StringIntMap members;
    EXPECT_EQ(kSuccess, test_elements_2_.GetOpenShareMembers(public_id_2_, share_name, &members));
    EXPECT_EQ(0, members.size());

    EXPECT_EQ(kSuccess, test_elements_2_.LeaveOpenShare(public_id_2_, share_name));
    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_SameOpenShareName) {
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
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    fs::path directory0(test_elements_1_.mount_path() / kMyStuff / directory0_name);
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
    EXPECT_EQ(kSuccess, test_elements_1_.CreateOpenShareFromExistingDirectory(public_id_1_,
                                                                              share_directory1,
                                                                              contacts,
                                                                              &share_name,
                                                                              &results));
    fs::path share1(test_elements_1_.mount_path() / kSharedStuff / share_name);
    EXPECT_TRUE(fs::exists(share1, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share1 / file1_name, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(stored_share_name, share_name);

    int count(0), limit(30);
    while ((fs::exists(directory1 / share_name, error_code) && !error_code) && count++ < limit)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::exists(directory1 / share_name, error_code));
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_1_.CreateOpenShareFromExistingDirectory(public_id_1_,
                                                                              share_directory2,
                                                                              contacts,
                                                                              &share_name,
                                                                              &results));
    fs::path share2(test_elements_1_.mount_path() / kSharedStuff / share_name);
    EXPECT_TRUE(fs::exists(share2, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_TRUE(fs::exists(share2 / file2_name, error_code));
    EXPECT_EQ(0, error_code.value());
    EXPECT_NE(stored_share_name, share_name);
    EXPECT_EQ(stored_share_name + " (1)", share_name);

    EXPECT_FALSE(fs::exists(directory2 / share_name, error_code));
    EXPECT_NE(0, error_code.value());

    std::vector<std::string> shares;
    EXPECT_EQ(kSuccess, test_elements_1_.GetOpenShareList(public_id_1_, &shares));
    EXPECT_EQ(2, shares.size());

    StringIntMap members;
    EXPECT_EQ(kSuccess, test_elements_1_.GetOpenShareMembers(public_id_1_, share_name, &members));
    EXPECT_EQ(0, members.size());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
}

INSTANTIATE_TEST_CASE_P(ReadOnlyReadWrite,
                        PrivateSharesApiTest,
                        testing::Values(kShareReadOnly, kShareReadWrite));

TEST_P(PrivateSharesApiTest, FUNC_CreateEmptyPrivateShare) {
  std::string file_name1(RandomAlphaNumericString(5)),
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, rights_));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name_1_, &results));

    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(share_name_1_, testing_variables_2_.new_private_share_name);
    EXPECT_EQ(rights_, testing_variables_2_.new_private_access_level);
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name_1_));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
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

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name_1_);
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

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    fs::path a_file_path(share_path / file_name1);
    EXPECT_TRUE(fs::exists(a_file_path, error_code)) << a_file_path;
    EXPECT_EQ(0, error_code.value());

    std::string a_file_content;
    EXPECT_TRUE(ReadFile(a_file_path, &a_file_content));
    EXPECT_EQ(file_content1, a_file_content);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_P(PrivateSharesApiTest, FUNC_FromExistingDirectoryPrivateShare) {
  std::string file_name1(RandomAlphaNumericString(5)),
              file_name2(RandomAlphaNumericString(5)),
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create directory with contents to share
    fs::path share_path(test_elements_1_.mount_path() / kMyStuff / share_name_1_);
    fs::create_directories(share_path, error_code);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value()) << share_path;
    EXPECT_TRUE(WriteFile(share_path / file_name1, file_content1)) << (share_path / file_name1);


    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, rights_));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreatePrivateShareFromExistingDirectory(public_id_1_,
                                                                                 share_path,
                                                                                 contacts,
                                                                                 &share_name_1_,
                                                                                 &results));

    int count(0), limit(30);
    while ((fs::exists(share_path, error_code) && !error_code) && count++ < limit)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::exists(share_path, error_code)) << share_path;
    share_path = test_elements_1_.mount_path() / kSharedStuff / share_name_1_;
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(share_name_1_, testing_variables_2_.new_private_share_name);
    EXPECT_EQ(rights_, testing_variables_2_.new_private_access_level);
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name_1_));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
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

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name_1_);
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

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    fs::path a_file_path(share_path / file_name2);
    std::string a_file_content;

    EXPECT_TRUE(ReadFile(a_file_path, &a_file_content));
    EXPECT_EQ(file_content1, a_file_content);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_P(PrivateSharesApiTest, FUNC_RejectInvitationPrivateShare) {
  std::string file_name1(RandomAlphaNumericString(5)),
              file_content1(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create directory with contents to share
    fs::path share_path(test_elements_1_.mount_path() / kMyStuff / share_name_1_);
    fs::create_directories(share_path, error_code);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value()) << share_path;
    EXPECT_TRUE(WriteFile(share_path / file_name1, file_content1)) << (share_path / file_name1);


    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, rights_));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreatePrivateShareFromExistingDirectory(public_id_1_,
                                                                                 share_path,
                                                                                 contacts,
                                                                                 &share_name_1_,
                                                                                 &results));

    int count(0), limit(30);
    while ((fs::exists(share_path, error_code) && !error_code) && count++ < limit)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::exists(share_path, error_code)) << share_path;
    share_path = test_elements_1_.mount_path() / kSharedStuff / share_name_1_;
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.RejectPrivateShareInvitation(
              public_id_2_, testing_variables_2_.new_private_share_id));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_FALSE(fs::exists(share_path, error_code));
    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_P(PrivateSharesApiTest, FUNC_DeletePrivateShare) {
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, rights_));  // Read only rights
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name_1_, &results));

    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name_1_));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));
    EXPECT_EQ(0, error_code.value());

    // Check only owner can delete
    EXPECT_NE(kSuccess, test_elements_2_.DeletePrivateShare(public_id_2_, share_name_1_, true));
    EXPECT_TRUE(fs::is_directory(share_path, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, test_elements_1_.DeletePrivateShare(public_id_1_, share_name_1_, false));
    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.private_share_deleted)
      Sleep(bptime::milliseconds(100));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_FALSE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_P(PrivateSharesApiTest, FUNC_LeavePrivateShare) {
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, rights_));  // Read only rights
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name_1_, &results));

    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    // Check owner can't leave
    EXPECT_EQ(kOwnerTryingToLeave, test_elements_1_.LeavePrivateShare(public_id_1_, share_name_1_));
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name_1_));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LeavePrivateShare(public_id_2_, share_name_1_));

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    // TODO(Team): Wait till message from member arrives
    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));

    // Still using share_id to identify the share, instead of share_name
    // And when leaving, Deletion Signal won't get fired
//     EXPECT_EQ(share_name_1_, testing_variables2.deleted_private_share_name);
    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_FALSE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_RenamePrivateShare) {
  std::string share_name1(RandomAlphaNumericString(5)),
              share_name2(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name1, &results));
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1,
                                                                &results));
    EXPECT_EQ(1U, results.size());
    EXPECT_TRUE(results.end() == results.find(public_id_1_));
    EXPECT_EQ(kShareReadWriteUnConfirmed, results.find(public_id_2_)->second);

    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name1));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));

    fs::path a_file_path(share_path / file_name1);
    EXPECT_TRUE(WriteFile(a_file_path, file_content2));
    EXPECT_TRUE(fs::exists(a_file_path, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap results;
    EXPECT_EQ(kSuccess, test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                                                share_name1,
                                                                &results));
    EXPECT_EQ(1U, results.size());
    EXPECT_TRUE(results.end() == results.find(public_id_1_));
    EXPECT_FALSE(results.end() == results.find(public_id_2_));
    fs::path old_share_path(test_elements_1_.mount_path() / kSharedStuff / share_name1);
    fs::path new_share_path(test_elements_1_.mount_path() / kSharedStuff / share_name2);
    fs::rename(old_share_path, new_share_path, error_code);
    EXPECT_EQ(0, error_code.value());
    while (!testing_variables_1_.share_renamed)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::is_directory(old_share_path, error_code));
    fs::path a_file_path(new_share_path / file_name1);
    std::string local_content;
    EXPECT_TRUE(ReadFile(a_file_path, &local_content));
    EXPECT_EQ(file_content2, local_content);

    EXPECT_EQ(share_name1, testing_variables_1_.old_share_name);
    EXPECT_EQ(share_name2, testing_variables_1_.new_share_name);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    fs::path new_share_path(test_elements_2_.mount_path() / kSharedStuff / share_name2);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));
    EXPECT_FALSE(fs::is_directory(new_share_path, error_code));

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  std::string sub_directory_name(RandomAlphaNumericString(8));
  std::string new_sub_directory_name(RandomAlphaNumericString(8));
  std::string new_file_name(RandomAlphaNumericString(8));
  {
    testing_variables_1_.share_renamed = false;
    testing_variables_1_.old_share_name.clear();
    testing_variables_1_.new_share_name.clear();

    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name2);
    fs::path sub_directory(share_path / sub_directory_name);
    EXPECT_TRUE(fs::create_directory(sub_directory, error_code));
    EXPECT_TRUE(fs::exists(sub_directory, error_code));

    // This additional sleep is required as the merging of directory_listing has a gap of 1.5s
    // because of the UTC time being used (rounded to seconds)
    Sleep(bptime::seconds(2));

    fs::path sub_directory_new(share_path / new_sub_directory_name);
    fs::rename(sub_directory, sub_directory_new, error_code);

    fs::path a_file_path(share_path / file_name1);
    fs::path new_a_file_path(share_path / new_file_name);
    fs::rename(a_file_path, new_a_file_path, error_code);

    Sleep(bptime::seconds(1));
    EXPECT_FALSE(testing_variables_1_.share_renamed);
    EXPECT_TRUE(testing_variables_1_.old_share_name.empty());
    EXPECT_TRUE(testing_variables_1_.new_share_name.empty());

    EXPECT_TRUE(fs::exists(sub_directory_new, error_code));
    EXPECT_FALSE(fs::exists(sub_directory, error_code));
    EXPECT_TRUE(fs::exists(new_a_file_path, error_code));
    EXPECT_FALSE(fs::exists(a_file_path, error_code));

    std::string local_content;
    EXPECT_TRUE(ReadFile(new_a_file_path, &local_content));
    EXPECT_EQ(file_content2, local_content);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
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

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_P(PrivateSharesApiTest, FUNC_CreateDeletePrivateShare) {
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, rights_));  // Read only rights
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name_1_,
                                                                 &results));
    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name_1_),
             my_path(test_elements_1_.mount_path() / kMyStuff / share_name_1_);
    EXPECT_TRUE(fs::exists(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    EXPECT_EQ(kSuccess, test_elements_1_.DeletePrivateShare(public_id_1_,
                                                            share_name_1_,
                                                            false));

    int count(0), limit(30);
    while ((fs::exists(share_path, error_code) && !error_code) && count++ < limit)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(fs::exists(share_path, error_code)) << share_path;
    EXPECT_NE(0, error_code.value());
    EXPECT_TRUE(fs::exists(my_path, error_code)) << my_path;
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kNoShareTarget,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name_1_));
    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name_1_);
    EXPECT_FALSE(fs::exists(share_path, error_code));
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_MembershipDowngradePrivateShare) {
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_content1(RandomAlphaNumericString(20)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name1, &results));
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1,
                                                                &results));
    EXPECT_EQ(1U, results.size());
    EXPECT_TRUE(results.end() == results.find(public_id_1_));
    EXPECT_EQ(kShareReadWriteUnConfirmed, results.find(public_id_2_)->second);

    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name1));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));

    fs::path a_file_path(share_path / file_name1);
    EXPECT_TRUE(WriteFile(a_file_path, file_content2));
    EXPECT_TRUE(fs::exists(a_file_path, error_code));
    EXPECT_EQ(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap results;
    EXPECT_EQ(kSuccess, test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                                                share_name1,
                                                                &results));
    EXPECT_EQ(1U, results.size());
    EXPECT_TRUE(results.end() == results.find(public_id_1_));
    EXPECT_FALSE(results.end() == results.find(public_id_2_));

    StringIntMap amendments;
    results.clear();
    amendments.insert(std::make_pair(public_id_2_, kShareReadOnly));
    EXPECT_EQ(kSuccess, test_elements_1_.EditPrivateShareMembers(public_id_1_,
                                                                 amendments,
                                                                 share_name1,
                                                                 &results));
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    results[public_id_2_] = -1;
    EXPECT_EQ(kSuccess, test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                                                share_name1,
                                                                &results));
    EXPECT_EQ(0, results[public_id_2_]);  // ro now

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.private_member_access_changed)
      Sleep(bptime::milliseconds(100));
    StringIntMap shares;
    EXPECT_EQ(kSuccess, test_elements_2_.GetPrivateShareList(public_id_2_, &shares));

    EXPECT_EQ(1U, shares.size());
    EXPECT_FALSE(shares.find(share_name1) == shares.end());
    EXPECT_EQ(kShareReadOnly, shares[share_name1]);

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    fs::path a_file_path(share_path / file_name1);
    EXPECT_FALSE(WriteFile(a_file_path, file_content1));

    std::string local_content;
    EXPECT_TRUE(ReadFile(a_file_path, &local_content));
    EXPECT_EQ(file_content2, local_content);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_MembershipUpgradePrivateShare) {
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name1(RandomAlphaNumericString(5)),
              file_content2(RandomAlphaNumericString(20));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadOnly));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name1, &results));

    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name1));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));

    fs::path a_file_path(share_path / file_name1);
    EXPECT_FALSE(WriteFile(a_file_path, file_content2));
    EXPECT_FALSE(fs::exists(a_file_path, error_code));
    EXPECT_NE(0, error_code.value());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap amendments, results;
    amendments.insert(std::make_pair(public_id_2_, kShareReadWrite));
    EXPECT_EQ(kSuccess, test_elements_1_.EditPrivateShareMembers(public_id_1_,
                                                                 amendments,
                                                                 share_name1,
                                                                 &results));
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    results[public_id_2_] = -1;
    EXPECT_EQ(kSuccess, test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1,
                                                                &results));
    EXPECT_EQ(kShareReadWrite, results[public_id_2_]);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));

    while (!testing_variables_2_.private_member_access_changed)
      Sleep(bptime::milliseconds(100));
    StringIntMap shares;
    EXPECT_EQ(kSuccess, test_elements_2_.GetPrivateShareList(public_id_2_, &shares));

    EXPECT_EQ(1U, shares.size());
    EXPECT_FALSE(shares.find(share_name1) == shares.end());
    EXPECT_EQ(kShareReadWrite, shares[share_name1]);

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    fs::path a_file_path(share_path / file_name1);
    EXPECT_TRUE(WriteFile(a_file_path, file_content2));
    EXPECT_TRUE(fs::exists(a_file_path, error_code));
    EXPECT_EQ(0, error_code.value());

    std::string local_content;
    EXPECT_TRUE(ReadFile(a_file_path, &local_content));
    EXPECT_EQ(file_content2, local_content);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_PrivateShareOwnerRemoveNonOwnerContact) {
  std::string removal_message("It's not me, it's you.");
  std::string share_name1(RandomAlphaNumericString(5));
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadOnly));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name1,
                                                                 &results));

    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;

    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(1, shares_members.size());
    EXPECT_EQ(kShareReadOnlyUnConfirmed, shares_members.find(public_id_2_)->second);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name1));

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code));

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap results;
    EXPECT_EQ(kSuccess, test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                                                share_name1,
                                                                &results));
    EXPECT_EQ(1U, results.size());

    EXPECT_EQ(kSuccess, test_elements_1_.RemoveContact(public_id_1_,
                                                       public_id_2_,
                                                       removal_message));
    EXPECT_TRUE(test_elements_1_.GetContacts(public_id_1_).empty());
    fs::path share_path(test_elements_1_.mount_path() / kSharedStuff / share_name1);
    EXPECT_TRUE(fs::is_directory(share_path, error_code)) << share_path;
    EXPECT_EQ(0, error_code.value());
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(0, shares_members.size());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.removed)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(removal_message, testing_variables_2_.removal_message);
    bool contact_deleted(false);
    while (!contact_deleted)
      contact_deleted = test_elements_2_.GetContacts(public_id_2_).empty();
    EXPECT_TRUE(contact_deleted);

    fs::path share_path(test_elements_2_.mount_path() / kSharedStuff / share_name1);
    Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(fs::is_directory(share_path, error_code));

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_PrivateShareNonOwnerRemoveOwnerContact) {
  std::string removal_message("It's not me, it's you.");
  std::string share_name1(RandomAlphaNumericString(5));
  fs::path directory1, directory2;
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadOnly));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name1, &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;

    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(1, shares_members.size());
    EXPECT_EQ(kShareReadOnlyUnConfirmed, shares_members.find(public_id_2_)->second);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name1));
    directory2 = test_elements_2_.mount_path()/ kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    EXPECT_EQ(kSuccess, test_elements_2_.RemoveContact(public_id_2_, public_id_1_,
                                                       removal_message));
    EXPECT_TRUE(test_elements_2_.GetContacts(public_id_2_).empty());
    // OS will cache the directory info for about 1 seconds
    while (fs::exists(directory2, error_code))
      Sleep(bptime::milliseconds(100));
    EXPECT_FALSE(fs::is_directory(directory2, error_code)) << directory2;

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    while (!testing_variables_1_.removed)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(removal_message, testing_variables_1_.removal_message);
    bool contact_deleted(false);
    while (!contact_deleted)
      contact_deleted = test_elements_1_.GetContacts(public_id_1_).empty();
    EXPECT_TRUE(contact_deleted);

    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(0, shares_members.size());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
}

TEST_F(TwoUsersApiTest, FUNC_PrivateShareNonOwnerRemoveNonOwnerContact) {
  LifeStuff test_elements3;
  testresources::TestingVariables testing_variables3;
  std::string keyword3(RandomAlphaNumericString(6)),
              pin3(CreatePin()),
              password3(RandomAlphaNumericString(6)),
              public_id3(RandomAlphaNumericString(5));
  ASSERT_EQ(kSuccess, CreatePublicId(test_elements3,
                                     testing_variables3,
                                     *test_dir_,
                                     keyword3,
                                     pin3,
                                     password3,
                                     public_id3));
  ASSERT_EQ(kSuccess, ConnectTwoPublicIds(test_elements3,
                                          test_elements_1_,
                                          testing_variables3,
                                          testing_variables_1_,
                                          keyword3,
                                          pin3,
                                          password3,
                                          public_id3,
                                          keyword_1_,
                                          pin_1_,
                                          password_1_,
                                          public_id_1_));
  ASSERT_EQ(kSuccess, ConnectTwoPublicIds(test_elements3,
                                          test_elements_2_,
                                          testing_variables3,
                                          testing_variables_2_,
                                          keyword3,
                                          pin3,
                                          password3,
                                          public_id3,
                                          keyword_2_,
                                          pin_2_,
                                          password_2_,
                                          public_id_2_));

  std::string removal_message("It's not me, it's you.");
  std::string share_name1(RandomAlphaNumericString(5));
  fs::path directory1, directory2, directory3;
  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadOnly));
    contacts.insert(std::make_pair(public_id3, kShareReadOnly));
    results.insert(std::make_pair(public_id_2_, kGeneralError));
    results.insert(std::make_pair(public_id3, kGeneralError));

    EXPECT_EQ(kSuccess,
              test_elements_1_.CreateEmptyPrivateShare(public_id_1_, contacts,
                                                       &share_name1, &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(2U, shares_members.size());
    EXPECT_EQ(kShareReadOnlyUnConfirmed, shares_members.find(public_id_2_)->second);
    EXPECT_EQ(kShareReadOnlyUnConfirmed, shares_members.find(public_id3)->second);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(
        kSuccess,
        test_elements_2_.AcceptPrivateShareInvitation(public_id_2_,
                                                      public_id_1_,
                                                      testing_variables_2_.new_private_share_id,
                                                      &share_name1));
    directory2 = test_elements_2_.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements3.LogIn(keyword3, pin3, password3));
    while (!testing_variables3.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables3.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements3.AcceptPrivateShareInvitation(public_id3,
                                                          public_id_1_,
                                                          testing_variables3.new_private_share_id,
                                                          &share_name1));
    directory3 = test_elements3.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory3, error_code)) << directory3;

    EXPECT_EQ(kSuccess, test_elements3.RemoveContact(public_id3, public_id_2_, removal_message));
    EXPECT_EQ(1U, test_elements3.GetContacts(public_id3).size());

    EXPECT_TRUE(fs::is_directory(directory3, error_code)) << directory3;

    EXPECT_EQ(kSuccess, test_elements3.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.removed)
      Sleep(bptime::milliseconds(100));

    EXPECT_EQ(removal_message, testing_variables_2_.removal_message);
    bool contact_deleted(false);
    while (!contact_deleted) {
      Sleep(bptime::milliseconds(1000));
      ContactMap map(test_elements_2_.GetContacts(public_id_2_));
      contact_deleted = map.find(public_id3) == map.end();
    }
    EXPECT_TRUE(contact_deleted);

    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;
    EXPECT_EQ(0, error_code.value());


    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory2;
    EXPECT_EQ(0, error_code.value());
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(2U, shares_members.size());
    EXPECT_EQ(2U, test_elements_1_.GetContacts(public_id_1_).size());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }

  EXPECT_EQ(kSuccess, test_elements_1_.Finalise());
  EXPECT_EQ(kSuccess, test_elements_2_.Finalise());
  EXPECT_EQ(kSuccess, test_elements3.Finalise());
}

TEST_P(PrivateSharesApiTest, DISABLED_FUNC_PrivateSharesMutualRemovalWithUninvolvedOnlooker) {
  LifeStuff test_elements_3;
  testresources::TestingVariables testing_variables_3;
  std::string keyword_3(RandomAlphaNumericString(6)),
              pin_3(CreatePin()),
              password_3(RandomAlphaNumericString(6)),
              public_id_3("User 3" + RandomAlphaNumericString(5));
  ASSERT_EQ(kSuccess, CreatePublicId(test_elements_3,
                                     testing_variables_3,
                                     *test_dir_,
                                     keyword_3,
                                     pin_3,
                                     password_3,
                                     public_id_3));
  // 1 added 2 in setup
  // 1 adds 3
  ASSERT_EQ(kSuccess, ConnectTwoPublicIds(test_elements_1_,
                                          test_elements_3,
                                          testing_variables_1_,
                                          testing_variables_3,
                                          keyword_1_,
                                          pin_1_,
                                          password_1_,
                                          public_id_1_,
                                          keyword_3,
                                          pin_3,
                                          password_3,
                                          public_id_3));

  std::string share_name_1(RandomAlphaNumericString(7));
  std::string share_name_2(RandomAlphaNumericString(7));

  // 1 creates share_name_1, inviting 2
  CreateShareAddingOneContact(test_elements_1_,
                              test_elements_2_,
                              testing_variables_2_,
                              keyword_1_,
                              pin_1_,
                              password_1_,
                              public_id_1_,
                              keyword_2_,
                              pin_2_,
                              password_2_,
                              public_id_2_,
                              share_name_1,
                              rights_);

  // 1 creates share_name_1, inviting 2
  CreateShareAddingOneContact(test_elements_2_,
                              test_elements_1_,
                              testing_variables_1_,
                              keyword_2_,
                              pin_2_,
                              password_2_,
                              public_id_2_,
                              keyword_1_,
                              pin_1_,
                              password_1_,
                              public_id_1_,
                              share_name_2,
                              rights_);
  // 2 removes 1
  LOG(kInfo) << "\n\n2 removing 1\n";
  TwoUsersDefriendEachOther(test_elements_2_,
                            test_elements_1_,
                            testing_variables_1_,
                            keyword_2_,
                            pin_2_,
                            password_2_,
                            public_id_2_,
                            keyword_1_,
                            pin_1_,
                            password_1_,
                            public_id_1_);

  // 3 removes 1
  LOG(kInfo) << "\n\n3 removing 1\n";
  TwoUsersDefriendEachOther(test_elements_3,
                            test_elements_1_,
                            testing_variables_1_,
                            keyword_3,
                            pin_3,
                            password_3,
                            public_id_3,
                            keyword_1_,
                            pin_1_,
                            password_1_,
                            public_id_1_);
}

TEST_P(PrivateSharesApiTest, DISABLED_FUNC_PrivateShareBefriendDefriendCombinations) {
  LifeStuff test_elements_3, test_elements_4;
  testresources::TestingVariables testing_variables_3, testing_variables_4;
  std::string keyword_3(RandomAlphaNumericString(6)),
              pin_3(CreatePin()),
              password_3(RandomAlphaNumericString(6)),
              public_id_3("User 3" + RandomAlphaNumericString(5)),
              keyword_4(RandomAlphaNumericString(6)),
              pin_4(CreatePin()),
              password_4(RandomAlphaNumericString(6)),
              public_id_4("User 4" + RandomAlphaNumericString(5));
  ASSERT_EQ(kSuccess, CreatePublicId(test_elements_3,
                                     testing_variables_3,
                                     *test_dir_,
                                     keyword_3,
                                     pin_3,
                                     password_3,
                                     public_id_3));
//  ASSERT_EQ(kSuccess, CreatePublicId(test_elements_4,
//                                     testing_variables_4,
//                                     *test_dir_,
//                                     keyword_4,
//                                     pin_4,
//                                     password_4,
//                                     public_id_4));
  // 1 added 2 in setup
  // 1 adds 3
  ASSERT_EQ(kSuccess, ConnectTwoPublicIds(test_elements_1_,
                                          test_elements_3,
                                          testing_variables_1_,
                                          testing_variables_3,
                                          keyword_1_,
                                          pin_1_,
                                          password_1_,
                                          public_id_1_,
                                          keyword_3,
                                          pin_3,
                                          password_3,
                                          public_id_3));
//  // 2 adds 4
//  ASSERT_EQ(kSuccess, ConnectTwoPublicIds(test_elements_2_,
//                                          test_elements_4,
//                                          testing_variables_2_,
//                                          testing_variables_4,
//                                          keyword_2_,
//                                          pin_2_,
//                                          password_2_,
//                                          public_id_2_,
//                                          keyword_4,
//                                          pin_4,
//                                          password_4,
//                                          public_id_4));
//  // 3 adds 4
//  ASSERT_EQ(kSuccess, ConnectTwoPublicIds(test_elements_3,
//                                          test_elements_4,
//                                          testing_variables_3,
//                                          testing_variables_4,
//                                          keyword_3,
//                                          pin_3,
//                                          password_3,
//                                          public_id_3,
//                                          keyword_4,
//                                          pin_4,
//                                          password_4,
//                                          public_id_4));

  // Create shares
  std::string share_name_1(RandomAlphaNumericString(7)),
              share_name_2(RandomAlphaNumericString(7)),
              share_name_3(RandomAlphaNumericString(7)),
              share_name_4(RandomAlphaNumericString(7));



  // 1 creates share_name_1, inviting 2
  CreateShareAddingOneContact(test_elements_1_,
                              test_elements_2_,
                              testing_variables_2_,
                              keyword_1_,
                              pin_1_,
                              password_1_,
                              public_id_1_,
                              keyword_2_,
                              pin_2_,
                              password_2_,
                              public_id_2_,
                              share_name_1,
                              rights_);
  // 2 creates share_name_2, inviting 1
  CreateShareAddingOneContact(test_elements_2_,
                              test_elements_1_,
                              testing_variables_1_,
                              keyword_2_,
                              pin_2_,
                              password_2_,
                              public_id_2_,
                              keyword_1_,
                              pin_1_,
                              password_1_,
                              public_id_1_,
                              share_name_2,
                              rights_);
//  // 3 creates share_name_3, inviting 4
//  CreateShareAddingOneContact(test_elements_3,
//                    test_elements_4,
//                    testing_variables_4,
//                    keyword_3,
//                    pin_3,
//                    password_3,
//                    public_id_3,
//                    keyword_4,
//                    pin_4,
//                    password_4,
//                    public_id_4,
//                    share_name_3);
//  // 4 creates share_name_4, inviting 3
//  CreateShareAddingOneContact(test_elements_4,
//                    test_elements_3,
//                    testing_variables_3,
//                    keyword_4,
//                    pin_4,
//                    password_4,
//                    public_id_4,
//                    keyword_3,
//                    pin_3,
//                    password_3,
//                    public_id_3,
//                    share_name_4);



//  // 1 invites 3 into share_name_1
//  AddOneContactToExistingShare(test_elements_1_,
//                    test_elements_3,
//                    testing_variables_3,
//                    keyword_1_,
//                    pin_1_,
//                    password_1_,
//                    public_id_1_,
//                    keyword_3,
//                    pin_3,
//                    password_3,
//                    public_id_3,
//                    share_name_1);
//  // 2 invites 4 into share_name_2
//  AddOneContactToExistingShare(test_elements_2_,
//                    test_elements_4,
//                    testing_variables_4,
//                    keyword_2_,
//                    pin_2_,
//                    password_2_,
//                    public_id_2_,
//                    keyword_4,
//                    pin_4,
//                    password_4,
//                    public_id_4,
//                    share_name_2);
//  // 3 invites 1 into share_name_3
//  AddOneContactToExistingShare(test_elements_3,
//                    test_elements_1_,
//                    testing_variables_1_,
//                    keyword_3,
//                    pin_3,
//                    password_3,
//                    public_id_3,
//                    keyword_1_,
//                    pin_1_,
//                    password_1_,
//                    public_id_1_,
//                    share_name_3);
//  // 4 invites 2 into share_name_4
//  AddOneContactToExistingShare(test_elements_4,
//                    test_elements_2_,
//                    testing_variables_2_,
//                    keyword_4,
//                    pin_4,
//                    password_4,
//                    public_id_4,
//                    keyword_2_,
//                    pin_2_,
//                    password_2_,
//                    public_id_2_,
//                    share_name_4);

  // 2 removes 1
  TwoUsersDefriendEachOther(test_elements_2_,
                  test_elements_1_,
                  testing_variables_1_,
                  keyword_2_,
                  pin_2_,
                  password_2_,
                  public_id_2_,
                  keyword_1_,
                  pin_1_,
                  password_1_,
                  public_id_1_);

//  // 3 removes 4
//  TwoUsersDefriendEachOther(test_elements_3,
//                  test_elements_4,
//                  testing_variables_4,
//                  keyword_3,
//                  pin_3,
//                  password_3,
//                  public_id_3,
//                  keyword_4,
//                  pin_4,
//                  password_4,
//                  public_id_4,
//                  2);

  // TODO(Alison) - check shares

  // 3 removes 1
  TwoUsersDefriendEachOther(test_elements_3,
                  test_elements_1_,
                  testing_variables_1_,
                  keyword_3,
                  pin_3,
                  password_3,
                  public_id_3,
                  keyword_1_,
                  pin_1_,
                  password_1_,
                  public_id_1_);

//  // 2 removes 4
//  TwoUsersDefriendEachOther(test_elements_2_,
//                  test_elements_4,
//                  testing_variables_4,
//                  keyword_2_,
//                  pin_2_,
//                  password_2_,
//                  public_id_2_,
//                  keyword_4,
//                  pin_4,
//                  password_4,
//                  public_id_4,
//                  4);

  // TODO(Alison) - check shares
}

TEST_F(TwoUsersMutexApiTest, FUNC_AddModifyRemoveOneFile) {
  std::string share_name1(RandomAlphaNumericString(5)),
              file_name(RandomAlphaNumericString(5)),
              file_content(RandomAlphaNumericString(20));
  fs::path directory1, directory2, file_path;

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name1,
                                                                 &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(1U, shares_members.size());
    EXPECT_EQ(kShareReadWriteUnConfirmed, shares_members.find(public_id_2_)->second);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name1));
    directory2 = test_elements_2_.mount_path()/ kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    file_path =  directory2 / file_name;
    std::ofstream ofstream(file_path.c_str(), std::ios::binary);
    ofstream << file_content;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path, error_code));
    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_2_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name1, &shares_members);
    EXPECT_EQ(1U, shares_members.size());

    uint8_t attempts(0);
    uint8_t expected_num_of_logs(1);
    while ((testing_variables_1_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_1_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_1_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name1, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / file_name,
              share_change_entry.target_path.string());
    EXPECT_TRUE(share_change_entry.old_path.empty());
    EXPECT_TRUE(share_change_entry.new_path.empty());
    EXPECT_EQ(drive::kAdded, share_change_entry.op_type);

    file_path = directory1 / file_name;
    testing_variables_1_.share_changes.clear();

    std::ofstream ofstream(file_path.c_str(),
                           std::ios_base::out | std::ios_base::binary);
    std::string new_file_content(RandomAlphaNumericString(100));
    ofstream << new_file_content;
    ofstream.close();
    Sleep(bptime::milliseconds(500));

    EXPECT_TRUE(fs::remove(file_path, error_code));
    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_1_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    uint8_t attempts(0);
    // Modify and Remove will be logged seperate as in real usage,
    // Remove shall not happen immediately afer Modify
    uint8_t expected_num_of_logs(2);
    while ((testing_variables_2_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_2_.share_changes.size());
    uint8_t num_of_removal_entries(0), num_of_modify_entries(0);
    for (auto it = testing_variables_2_.share_changes.begin();
         it != testing_variables_2_.share_changes.end(); ++it) {
      EXPECT_EQ(1, (*it).num_of_entries);
      EXPECT_EQ(share_name1, (*it).share_name);
      EXPECT_EQ(fs::path("/").make_preferred() / file_name,
                (*it).target_path.string());
      EXPECT_TRUE((*it).old_path.empty());
      EXPECT_TRUE((*it).new_path.empty());
      if ((*it).op_type == drive::kRemoved)
        ++num_of_removal_entries;
      if ((*it).op_type == drive::kModified)
        ++num_of_modify_entries;
    }
    EXPECT_EQ(1, num_of_removal_entries);
    EXPECT_EQ(1, num_of_modify_entries);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersMutexApiTest, FUNC_AddRemoveMultipleNodes) {
  std::string share_name(RandomAlphaNumericString(5));
  fs::path directory1, directory2;
  std::string sub_directory_name(RandomAlphaNumericString(5));
  std::string further_sub_directory_name(RandomAlphaNumericString(5));
  int num_of_nodes(5 + RandomInt32() % 6);
  int num_of_further_nodes(5 + RandomInt32() % 6);
  std::vector<std::string> names_of_nodes;

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name,
                                                                 &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                            share_name,
                                            &shares_members);
    EXPECT_EQ(1U, shares_members.size());
    EXPECT_EQ(kShareReadWriteUnConfirmed, shares_members.find(public_id_2_)->second);

    fs::path sub_directory(directory1 / sub_directory_name);
    fs::path further_sub_director(sub_directory / further_sub_directory_name);
    EXPECT_TRUE(fs::create_directory(sub_directory, error_code));
    EXPECT_TRUE(fs::create_directory(further_sub_director, error_code));

    for (int i = 0; i < num_of_further_nodes; ++i) {
      int file_or_dir(RandomInt32() % 2);
      if (file_or_dir == 0) {
        std::string file_name(RandomAlphaNumericString(4));
        fs::path file_path(further_sub_director / file_name);
        std::string file_content(RandomAlphaNumericString(100));
        std::ofstream ofstream(file_path.c_str(), std::ios::binary);
        ofstream << file_content;
        ofstream.close();
        EXPECT_TRUE(fs::exists(file_path, error_code)) << file_path;
        names_of_nodes.push_back(file_name);
      } else {
        std::string dir_name(RandomAlphaNumericString(6));
        fs::path directory(further_sub_director / dir_name);
        EXPECT_TRUE(fs::create_directory(directory, error_code)) << directory;
        names_of_nodes.push_back(dir_name);
      }
    }

    EXPECT_EQ(0, error_code.value());
    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_1_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name));
    directory2 = test_elements_2_.mount_path()/ kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    fs::path sub_director(directory2 / sub_directory_name);
    for (int i = 0; i < num_of_nodes; ++i) {
      int file_or_dir(RandomInt32() % 2);
      if (file_or_dir == 0) {
        std::string file_name(RandomAlphaNumericString(4));
        fs::path file_path(sub_director / file_name);
        std::string file_content(RandomAlphaNumericString(100));
        std::ofstream ofstream(file_path.c_str(), std::ios::binary);
        ofstream << file_content;
        ofstream.close();
        EXPECT_TRUE(fs::exists(file_path, error_code)) << file_path;
      } else {
        std::string dir_name(RandomAlphaNumericString(6));
        fs::path directory(sub_director / dir_name);
        EXPECT_TRUE(fs::create_directory(directory, error_code)) << directory;
      }
    }

    fs::path further_sub_director(sub_director / further_sub_directory_name);
    for (auto it = names_of_nodes.begin(); it != names_of_nodes.end(); ++it) {
      fs::path node_path(further_sub_director / (*it));
      fs::remove(node_path, error_code);
    }

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_EQ(1, testing_variables_2_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_2_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / sub_directory_name,
              share_change_entry.target_path.string());
    EXPECT_TRUE(share_change_entry.old_path.empty());
    EXPECT_TRUE(share_change_entry.new_path.empty());
    EXPECT_EQ(drive::kAdded, share_change_entry.op_type);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name, &shares_members);
    EXPECT_EQ(1U, shares_members.size());

    uint8_t attempts(0);
    uint8_t expected_num_of_logs(2);
    while ((testing_variables_1_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_1_.share_changes.size());
    uint8_t num_of_added_entries(0), num_of_removal_entries(0);
    for (auto it = testing_variables_1_.share_changes.begin();
         it != testing_variables_1_.share_changes.end(); ++it) {
      EXPECT_EQ(share_name, (*it).share_name);
      EXPECT_TRUE((*it).old_path.empty());
      EXPECT_TRUE((*it).new_path.empty());
      if ((*it).op_type == drive::kRemoved) {
        EXPECT_EQ(fs::path("/").make_preferred() /
                      sub_directory_name / further_sub_directory_name,
                  (*it).target_path);
        EXPECT_EQ(num_of_further_nodes, (*it).num_of_entries);
        ++num_of_removal_entries;
      }
      if ((*it).op_type == drive::kAdded) {
        EXPECT_EQ(fs::path("/").make_preferred() / sub_directory_name,
                  (*it).target_path);
        EXPECT_EQ(num_of_nodes, (*it).num_of_entries);
        ++num_of_added_entries;
      }
    }
    EXPECT_EQ(1, num_of_removal_entries);
    EXPECT_EQ(1, num_of_added_entries);

    testing_variables_1_.share_changes.clear();
    fs::path directory(directory1 / sub_directory_name);
    EXPECT_GT(fs::remove_all(directory, error_code), 0);
    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_1_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    testing_variables_2_.share_changes.clear();
    uint8_t attempts(0);
    uint8_t expected_num_of_logs(2);
    while ((testing_variables_2_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_2_.share_changes.size());
    // The original add log will still be picked up, as the trace_back_time
    // has been reset
    uint8_t num_of_added_entries(0), num_of_removal_entries(0);
    for (auto it = testing_variables_2_.share_changes.begin();
         it != testing_variables_2_.share_changes.end(); ++it) {
      EXPECT_EQ(1, (*it).num_of_entries);
      EXPECT_EQ(share_name, (*it).share_name);
      EXPECT_EQ(fs::path("/").make_preferred() / sub_directory_name,
                (*it).target_path.string());
      EXPECT_TRUE((*it).old_path.empty());
      EXPECT_TRUE((*it).new_path.empty());
      if ((*it).op_type == drive::kRemoved)
        ++num_of_removal_entries;
      if ((*it).op_type == drive::kAdded)
        ++num_of_added_entries;
    }
    EXPECT_EQ(1, num_of_removal_entries);
    EXPECT_EQ(1, num_of_added_entries);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersMutexApiTest, FUNC_RenameOneNode) {
  std::string share_name(RandomAlphaNumericString(5)),
              file_name(RandomAlphaNumericString(5)),
              new_file_name(RandomAlphaNumericString(5)),
              file_content(RandomAlphaNumericString(20));
  fs::path directory1, directory2, file_path, new_file_path;

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name,
                                                                 &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                            share_name,
                                            &shares_members);
    EXPECT_EQ(1U, shares_members.size());
    EXPECT_EQ(kShareReadWriteUnConfirmed, shares_members.find(public_id_2_)->second);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name));
    directory2 = test_elements_2_.mount_path()/ kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    file_path =  directory2 / file_name;
    std::ofstream ofstream(file_path.c_str(), std::ios::binary);
    ofstream << file_content;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path, error_code));
    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_2_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name, &shares_members);
    EXPECT_EQ(1U, shares_members.size());

    uint8_t attempts(0);
    uint8_t expected_num_of_logs(1);
    while ((testing_variables_1_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_1_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_1_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / file_name,
              share_change_entry.target_path.string());
    EXPECT_TRUE(share_change_entry.old_path.empty());
    EXPECT_TRUE(share_change_entry.new_path.empty());
    EXPECT_EQ(drive::kAdded, share_change_entry.op_type);

    file_path = directory1 / file_name;
    new_file_path = directory1 / new_file_name;
    testing_variables_1_.share_changes.clear();

    fs::rename(file_path, new_file_path, error_code);
    EXPECT_EQ(0, error_code.value());
    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_1_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    uint8_t attempts(0);
    uint8_t expected_num_of_logs(1);
    while ((testing_variables_2_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_2_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_2_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / file_name,
              share_change_entry.target_path);
    EXPECT_EQ(fs::path("/").make_preferred() / file_name,
              share_change_entry.old_path);
    EXPECT_EQ(fs::path("/").make_preferred() / new_file_name,
              share_change_entry.new_path);
    EXPECT_EQ(drive::kRenamed, share_change_entry.op_type);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

TEST_F(TwoUsersMutexApiTest, FUNC_MoveNodeToShareAndMoveOut) {
  std::string share_name(RandomAlphaNumericString(5));
  fs::path directory1, directory2;
  std::string sub_directory_name(RandomAlphaNumericString(5));

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name,
                                                                 &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                            share_name,
                                            &shares_members);
    EXPECT_EQ(1U, shares_members.size());
    EXPECT_EQ(kShareReadWriteUnConfirmed, shares_members.find(public_id_2_)->second);

    fs::path directory(test_elements_1_.mount_path() / sub_directory_name);
    EXPECT_TRUE(fs::create_directory(directory, error_code));

    fs::path sub_directory(directory1 / sub_directory_name);
    fs::rename(directory, sub_directory, error_code);
    EXPECT_EQ(0, error_code.value());

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_1_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  LOG(kError) << "\n\n1\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name));
    directory2 = test_elements_2_.mount_path() / kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    fs::path directory(test_elements_2_.mount_path() / sub_directory_name);
    fs::path sub_directory(directory2 / sub_directory_name);
    fs::rename(sub_directory, directory, error_code);
    EXPECT_EQ(0, error_code.value());

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_EQ(1, testing_variables_2_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_2_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / sub_directory_name,
              share_change_entry.target_path);
    EXPECT_TRUE(share_change_entry.old_path.empty());
    EXPECT_TRUE(share_change_entry.new_path.empty());
    EXPECT_EQ(drive::kAdded, share_change_entry.op_type);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  LOG(kError) << "\n\n2\n\n";
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name, &shares_members);
    EXPECT_EQ(1U, shares_members.size());

    uint8_t attempts(0);
    uint8_t expected_num_of_logs(1);
    while ((testing_variables_1_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_1_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_1_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / sub_directory_name,
              share_change_entry.target_path);
    EXPECT_TRUE(share_change_entry.old_path.empty());
    EXPECT_TRUE(share_change_entry.new_path.empty());
    EXPECT_EQ(drive::kRemoved, share_change_entry.op_type);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  LOG(kError) << "\n\n3\n\n";
}

TEST_F(TwoUsersMutexApiTest, FUNC_MoveNodeInnerShare) {
  std::string share_name(RandomAlphaNumericString(5));
  fs::path directory1, directory2, file_path, new_file_path;
  std::string file_name(RandomAlphaNumericString(6)),
              file_content(RandomAlphaNumericString(20)),
              sub_directory_name(RandomAlphaNumericString(5));

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name,
                                                                 &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                            share_name,
                                            &shares_members);
    EXPECT_EQ(1U, shares_members.size());
    EXPECT_EQ(kShareReadWriteUnConfirmed, shares_members.find(public_id_2_)->second);

    fs::path sub_directory(directory1 / sub_directory_name);
    EXPECT_TRUE(fs::create_directory(sub_directory, error_code));
    file_path =  directory1 / file_name;
    std::ofstream ofstream(file_path.c_str(), std::ios::binary);
    ofstream << file_content;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path, error_code));

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_1_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name));
    directory2 = test_elements_2_.mount_path() / kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    file_path = directory2 / file_name;
    new_file_path = directory2 / sub_directory_name / file_name;
    fs::rename(file_path, new_file_path, error_code);
    EXPECT_EQ(0, error_code.value());

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_EQ(1, testing_variables_2_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_2_.share_changes.begin());
    EXPECT_EQ(2, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    // When log the notification, the share_root will be removed
    // (other users may have their own share_root for the same share)
    // i.e. the target, old and new path are relative path to share_root
    EXPECT_TRUE(share_change_entry.target_path.empty());
    EXPECT_TRUE(share_change_entry.old_path.empty());
    EXPECT_TRUE(share_change_entry.new_path.empty());
    EXPECT_EQ(drive::kAdded, share_change_entry.op_type);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name, &shares_members);
    EXPECT_EQ(1U, shares_members.size());

    uint8_t attempts(0);
    uint8_t expected_num_of_logs(1);
    while ((testing_variables_1_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_1_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_1_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / file_name,
              share_change_entry.target_path);
    EXPECT_EQ("", share_change_entry.old_path.string());
    EXPECT_EQ(fs::path("/").make_preferred() / sub_directory_name,
              share_change_entry.new_path);
    EXPECT_EQ(drive::kMoved, share_change_entry.op_type);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
}

TEST_F(TwoUsersMutexApiTest, FUNC_MoveNodeInterShares) {
  std::string share_name1(RandomAlphaNumericString(5));
  std::string share_name2(RandomAlphaNumericString(5));
  fs::path directory1, directory2, file_path, new_file_path;
  std::string file_name(RandomAlphaNumericString(6)),
              file_content(RandomAlphaNumericString(20));

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private shares
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name1,
                                                                 &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name1));
    directory1 = test_elements_2_.mount_path() / kSharedStuff / share_name1;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;

    // Create empty private shares
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_1_, kShareReadWrite));
    results.insert(std::make_pair(public_id_1_, kGeneralError));
    EXPECT_EQ(kSuccess, test_elements_2_.CreateEmptyPrivateShare(public_id_2_,
                                                                 contacts,
                                                                 &share_name2,
                                                                 &results));
    directory2 = test_elements_2_.mount_path() / kSharedStuff / share_name2;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    file_path =  directory1 / file_name;
    std::ofstream ofstream(file_path.c_str(), std::ios::binary);
    ofstream << file_content;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path, error_code));

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_2_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    while (!testing_variables_1_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_1_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_1_.AcceptPrivateShareInvitation(
                  public_id_1_,
                  public_id_2_,
                  testing_variables_1_.new_private_share_id,
                  &share_name2));

    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name1;
    directory2 = test_elements_1_.mount_path() / kSharedStuff / share_name2;

    file_path =  directory1 / file_name;
    new_file_path = directory2 / file_name;
    fs::rename(file_path, new_file_path, error_code);
    EXPECT_EQ(0, error_code.value());

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_EQ(1, testing_variables_1_.share_changes.size());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    uint8_t attempts(0);
    uint8_t expected_num_of_logs(2);
    while ((testing_variables_2_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    uint8_t num_of_added_entries(0), num_of_removal_entries(0);
    for (auto it = testing_variables_2_.share_changes.begin();
         it != testing_variables_2_.share_changes.end(); ++it) {
      EXPECT_EQ(1, (*it).num_of_entries);
      EXPECT_EQ(fs::path("/").make_preferred() / file_name,
                (*it).target_path);
      EXPECT_TRUE((*it).old_path.empty());
      EXPECT_TRUE((*it).new_path.empty());
      if ((*it).op_type == drive::kRemoved) {
        EXPECT_EQ(share_name1, (*it).share_name);
        ++num_of_removal_entries;
      }
      if ((*it).op_type == drive::kAdded) {
        EXPECT_EQ(share_name2, (*it).share_name);
        ++num_of_added_entries;
      }
    }
    EXPECT_EQ(1, num_of_removal_entries);
    EXPECT_EQ(1, num_of_added_entries);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}

#ifndef WIN32
// Renaming items to hidden .Trash files under the same folder is used
// by Linux OS when delete files via file browser (enabling recycle bin)
// Windows OS doesn't have the same behaviour for mounted drives
TEST_F(TwoUsersMutexApiTest, FUNC_MoveNodeToTrashThenMoveBack) {
  std::string share_name(RandomAlphaNumericString(5)),
              file_name(RandomAlphaNumericString(5)),
              new_file_name(".Trash" + RandomAlphaNumericString(5)),
              file_content(RandomAlphaNumericString(20));
  fs::path directory1, directory2, file_path, new_file_path;

  boost::system::error_code error_code;
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    // Create empty private share
    StringIntMap contacts, results;
    contacts.insert(std::make_pair(public_id_2_, kShareReadWrite));
    results.insert(std::make_pair(public_id_2_, kGeneralError));

    EXPECT_EQ(kSuccess, test_elements_1_.CreateEmptyPrivateShare(public_id_1_,
                                                                 contacts,
                                                                 &share_name,
                                                                 &results));
    directory1 = test_elements_1_.mount_path() / kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory1, error_code)) << directory1;
    EXPECT_EQ(0, error_code.value());
    EXPECT_EQ(kSuccess, results[public_id_2_]);
    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_,
                                            share_name,
                                            &shares_members);
    EXPECT_EQ(1U, shares_members.size());
    EXPECT_EQ(kShareReadWriteUnConfirmed, shares_members.find(public_id_2_)->second);

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    while (!testing_variables_2_.privately_invited)
      Sleep(bptime::milliseconds(100));

    EXPECT_FALSE(testing_variables_2_.new_private_share_id.empty());
    EXPECT_EQ(kSuccess,
              test_elements_2_.AcceptPrivateShareInvitation(
                  public_id_2_,
                  public_id_1_,
                  testing_variables_2_.new_private_share_id,
                  &share_name));
    directory2 = test_elements_2_.mount_path()/ kSharedStuff / share_name;
    EXPECT_TRUE(fs::is_directory(directory2, error_code)) << directory2;

    file_path =  directory2 / file_name;
    std::ofstream ofstream(file_path.c_str(), std::ios::binary);
    ofstream << file_content;
    ofstream.close();
    EXPECT_TRUE(fs::exists(file_path, error_code));

    new_file_path = directory2 / new_file_name;
    fs::rename(file_path, new_file_path, error_code);
    EXPECT_EQ(0, error_code.value());

    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_2_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));

    StringIntMap shares_members;
    test_elements_1_.GetPrivateShareMembers(public_id_1_, share_name, &shares_members);
    EXPECT_EQ(1U, shares_members.size());

    uint8_t attempts(0);
    uint8_t expected_num_of_logs(2);
    while ((testing_variables_1_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    uint8_t num_of_added_entries(0), num_of_removal_entries(0);
    for (auto it = testing_variables_1_.share_changes.begin();
         it != testing_variables_1_.share_changes.end(); ++it) {
      EXPECT_EQ(1, (*it).num_of_entries);
      EXPECT_EQ(share_name, (*it).share_name);
      EXPECT_EQ(fs::path("/").make_preferred() / file_name,
                (*it).target_path.string());
      EXPECT_TRUE((*it).old_path.empty());
      EXPECT_TRUE((*it).new_path.empty());
      if ((*it).op_type == drive::kRemoved)
        ++num_of_removal_entries;
      if ((*it).op_type == drive::kAdded)
        ++num_of_added_entries;
    }
    EXPECT_EQ(1, num_of_removal_entries);
    EXPECT_EQ(1, num_of_added_entries);

    file_path = directory1 / file_name;
    new_file_path = directory1 / new_file_name;
    testing_variables_1_.share_changes.clear();

    fs::rename(new_file_path, file_path, error_code);
    EXPECT_EQ(0, error_code.value());
    // allowing enough time for the change to be logged
    Sleep(bptime::milliseconds(5000));
    EXPECT_TRUE(testing_variables_1_.share_changes.empty());

    EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  }
  {
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
    uint8_t attempts(0);
    uint8_t expected_num_of_logs(1);
    while ((testing_variables_2_.share_changes.size() < expected_num_of_logs) &&
           (attempts < 10)) {
      Sleep(bptime::milliseconds(1000));
      ++attempts;
    }
    EXPECT_LT(attempts, 10);
    // Additional time allowing any unexpected notifications to be logged
    Sleep(bptime::milliseconds(2000));

    EXPECT_EQ(expected_num_of_logs, testing_variables_2_.share_changes.size());
    testresources::ShareChangeLog share_change_entry(
                      *testing_variables_2_.share_changes.begin());
    EXPECT_EQ(1, share_change_entry.num_of_entries);
    EXPECT_EQ(share_name, share_change_entry.share_name);
    EXPECT_EQ(fs::path("/").make_preferred() / new_file_name,
              share_change_entry.target_path.string());
    EXPECT_EQ(fs::path("/").make_preferred() / new_file_name,
              share_change_entry.old_path.string());
    EXPECT_EQ(fs::path("/").make_preferred() / file_name,
              share_change_entry.new_path.string());
    EXPECT_EQ(drive::kRenamed, share_change_entry.op_type);

    EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  }
}
#endif

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
