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

TEST_F(OneUserApiTest, FUNC_ChangeCredentials) {
  std::string new_pin(CreatePin());
  EXPECT_EQ(kSuccess, test_elements_.CheckPassword(password_));
  EXPECT_EQ(kSuccess, test_elements_.LogOut());

  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
  EXPECT_EQ(kSuccess, test_elements_.CheckPassword(password_));

  // Change credentials
  EXPECT_EQ(kSuccess, test_elements_.ChangeKeyword(keyword_ + keyword_, password_));
  EXPECT_EQ(kSuccess, test_elements_.ChangePin(new_pin, password_));
  EXPECT_EQ(kSuccess, test_elements_.ChangePassword(password_ + password_, password_));

  EXPECT_EQ(kSuccess, test_elements_.LogOut());

  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_ + keyword_, new_pin, password_ + password_));
  EXPECT_EQ(kSuccess, test_elements_.ChangeKeyword(keyword_, password_ + password_));
  EXPECT_EQ(kSuccess, test_elements_.LogOut());

  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, new_pin, password_ + password_));
  EXPECT_EQ(kSuccess, test_elements_.ChangePin(pin_, password_ + password_));
  EXPECT_EQ(kSuccess, test_elements_.LogOut());

  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_ + password_));
  EXPECT_EQ(kSuccess, test_elements_.ChangePassword(password_, password_ + password_));
  EXPECT_EQ(kSuccess, test_elements_.LogOut());

  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
  EXPECT_EQ(kSuccess, test_elements_.CheckPassword(password_));
  EXPECT_EQ(kSuccess, test_elements_.ChangeKeyword(keyword_, password_));
  EXPECT_EQ(kSuccess, test_elements_.ChangePin(pin_, password_));
  EXPECT_EQ(kSuccess, test_elements_.ChangePassword(password_, password_));
}

TEST_F(OneUserApiTest, FUNC_ChangePinAndPasswordSimultaneously) {
  std::string new_pin(CreatePin());
  std::string new_password(RandomAlphaNumericString(5));
  int result_pin(0), result_password(0);

  std::vector<std::pair<int, int>> sleep_values;
  sleep_values.push_back(std::make_pair(0, 200));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 10));

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    boost::thread thread_pin([&] {
                               sleepthreads::RunChangePin(test_elements_,
                                                          std::ref(result_pin),
                                                          new_pin,
                                                          password_,
                                                          sleep_values.at(i));
                             });
    boost::thread thread_password([&] {
                                    sleepthreads::RunChangePassword(test_elements_,
                                                                    std::ref(result_password),
                                                                    new_password,
                                                                    password_,
                                                                    sleep_values.at(i));
                                  });
    thread_pin.join();
    thread_password.join();
    EXPECT_EQ(kSuccess, result_pin);
    EXPECT_EQ(kSuccess, result_password);

    EXPECT_EQ(kSuccess, test_elements_.LogOut());
    ASSERT_EQ(kSuccess, test_elements_.LogIn(keyword_, new_pin, new_password));
    new_pin.swap(pin_);
    new_password.swap(password_);
  }
}

TEST_F(OneUserApiTest, FUNC_ChangeKeywordAndPasswordSimultaneously) {
  std::string new_keyword(RandomAlphaNumericString(5));
  std::string new_password(RandomAlphaNumericString(5));
  int result_keyword(0), result_password(0);

  std::vector<std::pair<int, int>> sleep_values;
  sleep_values.push_back(std::make_pair(0, 200));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 10));

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    boost::thread thread_keyword([&] {
                                   sleepthreads::RunChangeKeyword(test_elements_,
                                                                  std::ref(result_keyword),
                                                                  new_keyword,
                                                                  password_,
                                                                  sleep_values.at(i));
                                 });
    boost::thread thread_password([&] {
                                    sleepthreads::RunChangePassword(test_elements_,
                                                                    std::ref(result_password),
                                                                    new_password,
                                                                    password_,
                                                                    sleep_values.at(i));
                                  });
    thread_keyword.join();
    thread_password.join();
    EXPECT_EQ(kSuccess, result_keyword);
    EXPECT_EQ(kSuccess, result_password);

    EXPECT_EQ(kSuccess, test_elements_.LogOut());
    ASSERT_EQ(kSuccess, test_elements_.LogIn(new_keyword, pin_, new_password));
    new_keyword.swap(keyword_);
    new_password.swap(password_);
  }
}

TEST_F(OneUserApiTest, FUNC_ChangePinAndKeywordSimultaneously) {
  std::string new_pin(CreatePin());
  std::string new_keyword(RandomAlphaNumericString(5));
  int result_pin(0), result_keyword(0);

  std::vector<std::pair<int, int>> sleep_values;
  sleep_values.push_back(std::make_pair(0, 200));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 10));

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    boost::thread thread_pin([&] {
                               sleepthreads::RunChangePin(test_elements_,
                                                          std::ref(result_pin),
                                                          new_pin,
                                                          password_,
                                                          sleep_values.at(i));
                             });
    boost::thread thread_keyword([&] {
                                   sleepthreads::RunChangeKeyword(test_elements_,
                                                                  std::ref(result_keyword),
                                                                  new_keyword,
                                                                  password_,
                                                                  sleep_values.at(i));
                                 });
    thread_pin.join();
    thread_keyword.join();

    EXPECT_EQ(kSuccess, result_pin);
    EXPECT_EQ(kSuccess, result_keyword);

    EXPECT_EQ(kSuccess, test_elements_.LogOut());
    ASSERT_EQ(kSuccess, test_elements_.LogIn(new_keyword, new_pin, password_));
    new_pin.swap(pin_);
    new_keyword.swap(keyword_);
  }
}

TEST_F(OneUserApiTest, FUNC_CreateUserWhenLoggedIn) {
  EXPECT_NE(kSuccess, test_elements_.CreateUser(RandomAlphaNumericString(5),
                                                CreatePin(),
                                                RandomAlphaNumericString(5)));
}

TEST_F(OneUserApiTest, FUNC_LogOutCreateNewUser) {
  EXPECT_EQ(kSuccess, test_elements_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_.CreateUser(RandomAlphaNumericString(5),
                                                CreatePin(),
                                                RandomAlphaNumericString(5)));
}

TEST_F(OneUserApiTest, FUNC_CreateInvalidUsers) {
  std::string new_pin(CreatePin());
  std::string new_keyword(RandomAlphaNumericString(5));
  std::string new_password(RandomAlphaNumericString(5));

  EXPECT_EQ(kSuccess, test_elements_.LogOut());

  // Try to create existing account
  EXPECT_NE(kSuccess, test_elements_.CreateUser(keyword_, pin_, password_));

  // Try to create new account when logged in
  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
  EXPECT_NE(kSuccess, test_elements_.CreateUser(new_keyword, new_pin, new_password));
  EXPECT_EQ(kSuccess, test_elements_.LogOut());

  // Bad Pin
  EXPECT_NE(kSuccess, test_elements_.CreateUser(new_keyword, "", new_password));
  EXPECT_NE(kSuccess, test_elements_.CreateUser(new_keyword, "0000", new_password));
  std::string not_digits_only(RandomAlphaNumericString(4));
  bool is_all_digits(true);
  while (is_all_digits) {
    try {
      boost::lexical_cast<int>(not_digits_only);
      is_all_digits = true;
      not_digits_only = RandomAlphaNumericString(4);
    }
    catch(const std::exception& /*e*/) {
      is_all_digits = false;
    }
  }
  EXPECT_NE(kSuccess, test_elements_.CreateUser(new_keyword, not_digits_only, new_password));
  EXPECT_NE(kSuccess, test_elements_.CreateUser(new_keyword,
                                                CreatePin().erase(3, 1),
                                                new_password));
  EXPECT_NE(kSuccess, test_elements_.CreateUser(new_keyword,
                                                CreatePin().append("1"),
                                                new_password));

  // Bad Keyword
  EXPECT_NE(kSuccess, test_elements_.CreateUser(RandomAlphaNumericString(RandomUint32() % 5),
                                                new_pin,
                                                new_password));
  EXPECT_NE(kSuccess, test_elements_.CreateUser(RandomAlphaNumericString(31),
                                                new_pin,
                                                new_password));
  EXPECT_NE(kSuccess, test_elements_.CreateUser(RandomAlphaNumericString(RandomUint32() % 13 + 2) +
                                                " " +
                                                RandomAlphaNumericString(RandomUint32() % 14 + 2),
                                                new_pin,
                                                new_password));

  // Bad Password
  EXPECT_NE(kSuccess, test_elements_.CreateUser(new_keyword,
                                                new_pin,
                                                RandomAlphaNumericString(RandomUint32() % 5)));
  EXPECT_NE(kSuccess, test_elements_.CreateUser(new_keyword,
                                                new_pin,
                                                RandomAlphaNumericString(31)));
  EXPECT_NE(kSuccess,
            test_elements_.CreateUser(new_keyword,
                                      new_pin,
                                      RandomAlphaNumericString(RandomUint32() % 13 + 2) + " " +
                                      RandomAlphaNumericString(RandomUint32() % 14 + 2)));

  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
}

TEST_F(OneUserApiTest, FUNC_TryChangeCredentialsToInvalid) {
  std::string incorrect_password(RandomAlphaNumericString(RandomUint32() % 26 + 5));
  while (incorrect_password == password_)
    incorrect_password = RandomAlphaNumericString(RandomUint32() % 26 + 5);

  // Check Password
  EXPECT_NE(kSuccess, test_elements_.CheckPassword(incorrect_password));
  EXPECT_NE(kSuccess, test_elements_.CheckPassword(RandomAlphaNumericString(RandomUint32() % 5)));
  EXPECT_NE(kSuccess, test_elements_.CheckPassword(RandomAlphaNumericString(31)));

  // Change PIN
  EXPECT_NE(kSuccess, test_elements_.ChangePin("", password_));
  EXPECT_NE(kSuccess, test_elements_.ChangePin("0000", password_));
  std::string not_digits_only(RandomAlphaNumericString(4));
  bool is_all_digits(true);
  while (is_all_digits) {
    try {
      boost::lexical_cast<int>(not_digits_only);
      is_all_digits = true;
      not_digits_only = RandomAlphaNumericString(4);
    }
    catch(const std::exception& /*e*/) {
      is_all_digits = false;
    }
  }
  EXPECT_NE(kSuccess, test_elements_.ChangePin(not_digits_only, password_));
  EXPECT_NE(kSuccess, test_elements_.ChangePin(CreatePin().erase(3, 1), password_));
  EXPECT_NE(kSuccess, test_elements_.ChangePin(CreatePin().append("1"), password_));
  EXPECT_NE(kSuccess, test_elements_.ChangePin(CreatePin(), incorrect_password));

  // Change Keyword
  EXPECT_NE(kSuccess,
            test_elements_.ChangeKeyword(RandomAlphaNumericString(RandomUint32() % 5), password_));
  EXPECT_NE(kSuccess, test_elements_.ChangeKeyword(RandomAlphaNumericString(31), password_));
  EXPECT_NE(kSuccess,
            test_elements_.ChangeKeyword(RandomAlphaNumericString(RandomUint32() % 13 + 2) + " " +
                                         RandomAlphaNumericString(RandomUint32() % 14 + 2),
                                         password_));
  // Change Password
  EXPECT_NE(kSuccess,
            test_elements_.ChangePassword(RandomAlphaNumericString(RandomUint32() % 5), password_));
  EXPECT_NE(kSuccess, test_elements_.ChangePassword(RandomAlphaNumericString(31), password_));
  EXPECT_NE(kSuccess,
            test_elements_.ChangeKeyword(RandomAlphaNumericString(RandomUint32() % 13 + 2) + " " +
                                         RandomAlphaNumericString(RandomUint32() % 14 + 2),
                                         password_));
}

TEST_F(OneUserApiTest, FUNC_ChangeCredentialsWhenLoggedOut) {
  std::string new_pin(CreatePin());

  EXPECT_EQ(kSuccess, test_elements_.LogOut());

  EXPECT_NE(kSuccess, test_elements_.CheckPassword(password_));

  // Change credentials
  EXPECT_NE(kSuccess, test_elements_.ChangeKeyword(keyword_ + keyword_, password_));
  EXPECT_NE(kSuccess, test_elements_.ChangePin(new_pin, password_));
  EXPECT_NE(kSuccess, test_elements_.ChangePassword(password_ + password_, password_));

  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
}

TEST_F(OneUserApiTest, FUNC_ChangeCredentialsAndLogOut) {
  std::string new_pin(CreatePin());
  std::string new_keyword(RandomAlphaNumericString(5));
  std::string new_password(RandomAlphaNumericString(5));
  int result(0);

  boost::thread thread_pin([&] {
                             sleepthreads::RunChangePin(test_elements_,
                                                        std::ref(result),
                                                        new_pin,
                                                        password_,
                                                        std::make_pair(0, 0));
                           });

  test_elements_.LogOut();
  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, new_pin, password_));

  boost::thread thread_keyword([&] {
                                 sleepthreads::RunChangeKeyword(test_elements_,
                                                                std::ref(result),
                                                                new_keyword,
                                                                password_,
                                                                std::make_pair(0, 0));
                               });

  test_elements_.LogOut();
  EXPECT_EQ(kSuccess, test_elements_.LogIn(new_keyword, new_pin, password_));

  boost::thread thread_password([&] {
                                  sleepthreads::RunChangePassword(test_elements_,
                                                                  std::ref(result),
                                                                  new_password,
                                                                  password_,
                                                                  std::make_pair(0, 0));
                                });

  test_elements_.LogOut();
  EXPECT_EQ(kSuccess, test_elements_.LogIn(new_keyword, new_pin, new_password));
}

TEST_F(TwoInstancesApiTest, DISABLED_FUNC_BasicLogInFromTwoPlaces) {
  EXPECT_EQ(kSuccess, test_elements_.CreateUser(keyword_, pin_, password_));
  EXPECT_EQ(kSuccess, test_elements_.LogOut());

  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
  EXPECT_EQ(kReadOnlyRestrictedSuccess, test_elements_2_.LogIn(keyword_, pin_, password_));

  EXPECT_EQ(kSuccess, test_elements_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_2_.LogOut());

  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
  EXPECT_EQ(kReadOnlyRestrictedSuccess, test_elements_2_.LogIn(keyword_, pin_, password_));

  EXPECT_EQ(kSuccess, test_elements_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_2_.LogOut());

  EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_, pin_, password_));
  EXPECT_EQ(kReadOnlyRestrictedSuccess, test_elements_.LogIn(keyword_, pin_, password_));

  EXPECT_EQ(kSuccess, test_elements_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
}

TEST_F(TwoInstancesApiTest, DISABLED_FUNC_LogInFromTwoPlacesCheckFileSystem) {
  EXPECT_EQ(kSuccess, test_elements_.CreateUser(keyword_, pin_, password_));

  std::string directory;
  fs::path path_directory(CreateTestDirectory(test_elements_.mount_path(), &directory));
  EXPECT_TRUE(fs::exists(path_directory, error_code_));
  EXPECT_EQ(0, error_code_.value());

  std::string file;
  EXPECT_EQ(kSuccess, CreateSmallTestFile(test_elements_.mount_path(), 1, &file));
  EXPECT_TRUE(fs::exists(test_elements_.mount_path() / file, error_code_));
  EXPECT_EQ(0, error_code_.value());

  EXPECT_EQ(kSuccess, test_elements_.LogOut());


  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
  EXPECT_EQ(kReadOnlyRestrictedSuccess, test_elements_2_.LogIn(keyword_, pin_, password_));

  // Directory should exist for both instances
  path_directory = test_elements_.mount_path() / directory;
  EXPECT_TRUE(fs::exists(path_directory, error_code_));
  EXPECT_EQ(0, error_code_.value());

  path_directory = test_elements_2_.mount_path() / directory;
  EXPECT_TRUE(fs::exists(path_directory, error_code_));
  EXPECT_EQ(0, error_code_.value());

  // File should exist for both instances
  fs::path path_file = test_elements_.mount_path() / file;
  EXPECT_TRUE(fs::exists(path_file, error_code_));
  EXPECT_EQ(0, error_code_.value());

  path_file = test_elements_2_.mount_path() / file;
  EXPECT_TRUE(fs::exists(path_file, error_code_));
  EXPECT_EQ(0, error_code_.value());


  std::string directory2;

  // Try to create directory
  path_directory = CreateTestDirectory(test_elements_2_.mount_path(), &directory2);
  EXPECT_FALSE(fs::exists(path_directory, error_code_));
  EXPECT_NE(0, error_code_.value());

  // Try to move directory
  path_directory = test_elements_2_.mount_path() / directory;
  fs::rename(path_directory, test_elements_2_.mount_path() / directory2, error_code_);
  EXPECT_NE(0, error_code_.value());

  // Try to delete directory
  path_directory = test_elements_2_.mount_path() / directory;
  EXPECT_FALSE(fs::remove(path_directory, error_code_));
  EXPECT_NE(0, error_code_.value());


  std::string file2;

  // Try to create file
  EXPECT_NE(kSuccess, CreateSmallTestFile(test_elements_2_.mount_path(), 1, &file2));
  EXPECT_FALSE(fs::exists(test_elements_2_.mount_path() / file2, error_code_));
  EXPECT_NE(0, error_code_.value());

  // Try to move file
  path_file = test_elements_2_.mount_path() / file;
  fs::rename(path_file, test_elements_2_.mount_path() / file2, error_code_);
  EXPECT_NE(0, error_code_.value());

  // Try to delete file
  path_file = test_elements_2_.mount_path() / file;
  EXPECT_FALSE(fs::remove(path_file, error_code_));
  EXPECT_NE(0, error_code_.value());


  EXPECT_EQ(kSuccess, test_elements_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
}

TEST_F(TwoUsersApiTest, DISABLED_FUNC_LogInFromTwoPlacesCheckContacts) {
  // test_elements_1_ - user 1 (full access)
  // test_elements_2_ - user 2 (full access)
  // test_elements_3  - user 1 (read only)
  LifeStuff test_elements_3;
  testresources::TestingVariables testing_variables_3;
  InitialiseAndConnect(test_elements_3,
                       testing_variables_3,
                       *test_dir_);

  std::string public_id_3(RandomAlphaNumericString(5)),
              public_id_4(RandomAlphaNumericString(5));

  EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
  EXPECT_EQ(kReadOnlyRestrictedSuccess, test_elements_3.LogIn(keyword_1_, pin_1_, password_1_));
  EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));

  // Try creating public ID
  EXPECT_EQ(kReadOnlyFailure, test_elements_3.CreatePublicId(public_id_3));
  EXPECT_EQ(kSuccess, test_elements_1_.CreatePublicId(public_id_3));


  // Try adding 2 as a contact
  testing_variables_2_.newly_contacted = false;
  EXPECT_EQ(kReadOnlyFailure, test_elements_3.AddContact(public_id_3, public_id_2_, ""));
  EXPECT_EQ(kSuccess, test_elements_1_.AddContact(public_id_3, public_id_2_, ""));
  int i(0);
  while (!testing_variables_2_.newly_contacted && i < 100) {
    ++i;
    Sleep(bptime::milliseconds(100));
  }
  EXPECT_TRUE(testing_variables_2_.newly_contacted);

  EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  testing_variables_1_.confirmed = false;
  testing_variables_3.confirmed = false;

  // 2 accepts the friend request
  EXPECT_EQ(kSuccess, test_elements_2_.ConfirmContact(public_id_2_, public_id_3));
  i = 0;
  while (!testing_variables_3.confirmed && i < 100) {
    ++i;
    Sleep(bptime::milliseconds(100));
  }

  // RO instance shouldn't get confirmation
  EXPECT_FALSE(testing_variables_3.confirmed);
  EXPECT_EQ(i, 100);

  // RW instance should get confirmation
  EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
  i = 0;
  while (!testing_variables_1_.confirmed && i < 100) {
    ++i;
    Sleep(bptime::milliseconds(100));
  }
  EXPECT_TRUE(testing_variables_1_.confirmed);

  // RO shouldn't be able to remove contact
  EXPECT_EQ(kReadOnlyFailure, test_elements_3.RemoveContact(public_id_3, public_id_2_, ""));


  // 4 adds as friend
  EXPECT_EQ(kSuccess, test_elements_2_.CreatePublicId(public_id_4));
  testing_variables_1_.newly_contacted = false;
  testing_variables_3.newly_contacted = false;
  EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_2_.AddContact(public_id_4, public_id_3, ""));

  // RO instance shouldn't be contacted about contact request
  i = 0;
  while (!testing_variables_3.newly_contacted && i < 100) {
    ++i;
    Sleep(bptime::milliseconds(100));
  }
  EXPECT_FALSE(testing_variables_3.newly_contacted);
  EXPECT_EQ(i, 100);

  // RW instance should be contacted about contact request
  EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
  i = 0;
  while (!testing_variables_1_.newly_contacted && i < 100) {
    ++i;
    Sleep(bptime::milliseconds(100));
  }
  EXPECT_TRUE(testing_variables_1_.newly_contacted);

  // RO instance tries accepting/declining request from 4
  EXPECT_EQ(kReadOnlyFailure, test_elements_3.ConfirmContact(public_id_3, public_id_4));
  EXPECT_EQ(kReadOnlyFailure, test_elements_3.DeclineContact(public_id_3, public_id_4));


  EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_3.LogOut());
}

TEST_F(TwoInstancesApiTest, DISABLED_FUNC_LogInFromTwoPlacesSimultaneously) {
#ifdef MAIDSAFE_LINUX
  EXPECT_EQ(kSuccess, test_elements_.CreateUser(keyword_, pin_, password_));
  EXPECT_EQ(kSuccess, test_elements_.LogOut());

  int result_1(0), result_2(0);
  std::vector<std::pair<int, int>> sleep_values;
  sleep_values.push_back(std::make_pair(0, 200));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 10));

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    boost::thread thread_1([&] { sleepthreads::RunLogIn(test_elements_,
                                                        std::ref(result_1),
                                                        keyword_, pin_,
                                                        password_,
                                                        sleep_values.at(i)); });  // NOLINT (Alison)
    boost::thread thread_2([&] { sleepthreads::RunLogIn(test_elements_2_,
                                                        std::ref(result_2),
                                                        keyword_,
                                                        pin_,
                                                        password_,
                                                        sleep_values.at(i)); });  // NOLINT (Alison)
    thread_1.join();
    thread_2.join();
    EXPECT_TRUE((result_1 == kSuccess && result_2 != kSuccess) ||
                (result_1 != kSuccess && result_2 == kSuccess));
    result_1 = test_elements_.LogOut();
    result_2 = test_elements_2_.LogOut();
    EXPECT_TRUE((result_1 == kSuccess && result_2 != kSuccess) ||
                (result_1 != kSuccess && result_2 == kSuccess));
    EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
    EXPECT_EQ(kSuccess, test_elements_.LogOut());
  }
#endif
}

TEST_F(TwoInstancesApiTest, FUNC_NeverLogIn) {
}

TEST_F(TwoInstancesApiTest, FUNC_CreateSameUserSimultaneously) {
  int result_1(0), result_2(0);
  std::pair<int, int> sleeps(0, 0);
  boost::thread thread_1([&] {
                           sleepthreads::RunCreateUser(test_elements_,
                                                       std::ref(result_1),
                                                       keyword_, pin_,
                                                       password_,
                                                       sleeps);
                         });
  boost::thread thread_2([&] {
                           sleepthreads::RunCreateUser(test_elements_2_,
                                                       std::ref(result_2),
                                                       keyword_,
                                                       pin_,
                                                       password_,
                                                       sleeps);
                         });
  thread_1.join();
  thread_2.join();
  EXPECT_TRUE((result_1 == kSuccess && result_2 != kSuccess) ||
              (result_1 != kSuccess && result_2 == kSuccess));
  result_1 = test_elements_.LogOut();
  result_2 = test_elements_2_.LogOut();
  EXPECT_TRUE((result_1 == kSuccess && result_2 != kSuccess) ||
              (result_1 != kSuccess && result_2 == kSuccess));
  EXPECT_EQ(kSuccess, test_elements_.LogIn(keyword_, pin_, password_));
  EXPECT_EQ(kSuccess, test_elements_.LogOut());
}

TEST_F(TwoUsersApiTest, FUNC_ChangeCredentialsToSameConsecutively) {
#ifdef MAIDSAFE_LINUX
  EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
  EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));

  std::string new_pin(CreatePin());
  std::string new_keyword(RandomAlphaNumericString(5));

  EXPECT_EQ(kSuccess, test_elements_1_.ChangePin(new_pin, password_1_));
  EXPECT_EQ(kSuccess, test_elements_2_.ChangePin(new_pin, password_2_));
  EXPECT_EQ(kSuccess, test_elements_1_.ChangeKeyword(new_keyword, password_1_));
  EXPECT_NE(kSuccess, test_elements_2_.ChangeKeyword(new_keyword, password_2_));

  EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_2_.LogOut());

  EXPECT_EQ(kSuccess, test_elements_1_.LogIn(new_keyword, new_pin, password_1_));
  EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, new_pin, password_2_));
  EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
  EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
#endif
}

TEST_F(TwoUsersApiTest, FUNC_ChangeCredentialsToSameSimultaneously) {
#ifdef MAIDSAFE_LINUX
  std::vector<std::pair<int, int>> sleep_values;
  sleep_values.push_back(std::make_pair(0, 200));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 0));

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));

    std::string new_pin(CreatePin());
    std::string new_keyword(RandomAlphaNumericString(5));

    int result_pin_1(0), result_pin_2(0), result_keyword_1(0), result_keyword_2(0);

    boost::thread thread_pin_1(
        [&] {
          sleepthreads::RunChangePin(test_elements_1_,
                                     std::ref(result_pin_1),
                                     new_pin,
                                     password_1_,
                                     sleep_values.at(i));
        });
    boost::thread thread_pin_2(
        [&] {
          sleepthreads::RunChangePin(test_elements_2_,
                                     std::ref(result_pin_2),
                                     new_pin,
                                     password_2_,
                                     sleep_values.at(i));
        });
    boost::thread thread_keyword_1(
        [&] {
          sleepthreads::RunChangeKeyword(test_elements_1_,
                                         std::ref(result_keyword_1),
                                         new_keyword,
                                         password_1_,
                                         sleep_values.at(i));
        });
    boost::thread thread_keyword_2(
        [&] {
          sleepthreads::RunChangeKeyword(test_elements_2_,
                                         std::ref(result_keyword_2),
                                         new_keyword,
                                         password_2_,
                                         sleep_values.at(i));
        });
    thread_pin_1.join();
    thread_pin_2.join();
    thread_keyword_1.join();
    thread_keyword_2.join();

    if (result_pin_1 == kSuccess)
      pin_1_ = new_pin;
    if (result_pin_2 == kSuccess)
      pin_2_ = new_pin;
    if (result_keyword_1 == kSuccess)
      keyword_1_ = new_keyword;
    if (result_keyword_2 == kSuccess)
      keyword_2_ = new_keyword;

    EXPECT_FALSE(result_pin_1 == kSuccess &&
                 result_pin_2 == kSuccess &&
                 result_keyword_1 == kSuccess &&
                 result_keyword_2 == kSuccess);

    int result_logout_1(test_elements_1_.LogOut());
    int result_logout_2(test_elements_2_.LogOut());

    if (result_logout_1 != kSuccess) {
      if (result_logout_2 != kSuccess) {
        LOG(kError) << "Both test elements failed to log out.";
        break;
      }
      LOG(kError) << "Can't log out of test_elements_1_";
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_2_; credentials 2";
      EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_2_, pin_2_, password_2_));
      EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_2_; credentials 1";
      EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_1_, pin_1_, password_1_));
      EXPECT_EQ(kSuccess, test_elements_2_.LogOut());
      break;
    }
    if (result_logout_2 != kSuccess) {
      LOG(kError) << "Can't log out of test_elements_2_";
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_1_; credentials 1";
      EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_1_, pin_1_, password_1_));
      EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_1_; credentials 2";
      EXPECT_EQ(kSuccess, test_elements_1_.LogIn(keyword_2_, pin_2_, password_2_));
      EXPECT_EQ(kSuccess, test_elements_1_.LogOut());
      break;
    }
  }
#endif
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
