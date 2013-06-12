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

TEST_F(OneUserApiTest, FUNC_CreateLogoutLoginLogout) {
  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }
  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }
}

TEST_F(OneUserApiTest, FUNC_ChangeCredentials) {
  NonEmptyString new_pin(CreatePin());
  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
    EXPECT_EQ(kSuccess, test_elements.CheckPassword(password_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }

  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_));
    EXPECT_EQ(kSuccess, test_elements.CheckPassword(password_));

    // Change credentials
    EXPECT_EQ(kSuccess, test_elements.ChangeKeyword(keyword_ + keyword_, password_));
    EXPECT_EQ(kSuccess, test_elements.ChangePin(new_pin, password_));
    EXPECT_EQ(kSuccess, test_elements.ChangePassword(password_ + password_, password_));

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }

  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements,
                                    keyword_ + keyword_,
                                    new_pin,
                                    password_ + password_));
    EXPECT_EQ(kSuccess, test_elements.ChangeKeyword(keyword_, password_ + password_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }

  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, new_pin, password_ + password_));
    EXPECT_EQ(kSuccess, test_elements.ChangePin(pin_, password_ + password_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }

  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_ + password_));
    EXPECT_EQ(kSuccess, test_elements.ChangePassword(password_, password_ + password_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }

  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_));
    EXPECT_EQ(kSuccess, test_elements.CheckPassword(password_));
    EXPECT_EQ(kSuccess, test_elements.ChangeKeyword(keyword_, password_));
    EXPECT_EQ(kSuccess, test_elements.ChangePin(pin_, password_));
    EXPECT_EQ(kSuccess, test_elements.ChangePassword(password_, password_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }
}

TEST_F(OneUserApiTest, FUNC_ChangePinAndPasswordSimultaneously) {
  NonEmptyString new_pin(CreatePin());
  NonEmptyString new_password(RandomAlphaNumericString(5));
  int result_pin(0), result_password(0);

  std::vector<std::pair<int, int> > sleep_values;
  sleep_values.push_back(std::make_pair(0, 200));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 10));

  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    {
      PopulateSlots(lifestuff_slots_, testing_variables_);
      LifeStuff test_elements(lifestuff_slots_, *test_dir_);
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_));
      std::thread thread_pin([&] {
                               sleepthreads::RunChangePin(test_elements,
                                                          std::ref(result_pin),
                                                          new_pin,
                                                          password_,
                                                          sleep_values.at(i));
                             });
      std::thread thread_password([&] {
                                    sleepthreads::RunChangePassword(test_elements,
                                                                    std::ref(result_password),
                                                                    new_password,
                                                                    password_,
                                                                    sleep_values.at(i));
                                  });
      thread_pin.join();
      thread_password.join();
      EXPECT_EQ(kSuccess, result_pin);
      EXPECT_EQ(kSuccess, result_password);
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
    }
    {
      PopulateSlots(lifestuff_slots_, testing_variables_);
      LifeStuff test_elements(lifestuff_slots_, *test_dir_);
      int result = DoFullLogIn(test_elements, keyword_, new_pin, new_password);
      EXPECT_EQ(kSuccess, result) << "iteration: " << i;
      if (result != kSuccess)
        i = sleep_values.size();
      swap(new_pin, pin_);
      swap(new_password, password_);
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
    }
  }
}

TEST_F(OneUserApiTest, FUNC_ChangeKeywordAndPasswordSimultaneously) {
  NonEmptyString new_keyword(RandomAlphaNumericString(5));
  NonEmptyString new_password(RandomAlphaNumericString(5));
  int result_keyword(0), result_password(0);

  std::vector<std::pair<int, int> > sleep_values;
  sleep_values.push_back(std::make_pair(0, 200));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 10));

  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    {
      PopulateSlots(lifestuff_slots_, testing_variables_);
      LifeStuff test_elements(lifestuff_slots_, *test_dir_);
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_));
      std::thread thread_keyword([&] {
                                   sleepthreads::RunChangeKeyword(test_elements,
                                                                  std::ref(result_keyword),
                                                                  new_keyword,
                                                                  password_,
                                                                  sleep_values.at(i));
                                 });
      std::thread thread_password([&] {
                                    sleepthreads::RunChangePassword(test_elements,
                                                                    std::ref(result_password),
                                                                    new_password,
                                                                    password_,
                                                                    sleep_values.at(i));
                                  });
      thread_keyword.join();
      thread_password.join();
      EXPECT_EQ(kSuccess, result_keyword);
      EXPECT_EQ(kSuccess, result_password);
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
    }
    {
      PopulateSlots(lifestuff_slots_, testing_variables_);
      LifeStuff test_elements(lifestuff_slots_, *test_dir_);
      int result = DoFullLogIn(test_elements, new_keyword, pin_, new_password);
      swap(new_keyword, keyword_);
      swap(new_password, password_);
      EXPECT_EQ(kSuccess, result) << "iteration: " << i;
      if (result != kSuccess)
        i = sleep_values.size();
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
    }
  }
}

TEST_F(OneUserApiTest, FUNC_ChangePinAndKeywordSimultaneously) {
  NonEmptyString new_pin(CreatePin());
  NonEmptyString new_keyword(RandomAlphaNumericString(5));
  int result_pin(0), result_keyword(0);

  std::vector<std::pair<int, int> > sleep_values;
  sleep_values.push_back(std::make_pair(0, 200));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 10));

  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    {
      PopulateSlots(lifestuff_slots_, testing_variables_);
      LifeStuff test_elements(lifestuff_slots_, *test_dir_);
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_));
      std::thread thread_pin([&] {
                               sleepthreads::RunChangePin(test_elements,
                                                          std::ref(result_pin),
                                                          new_pin,
                                                          password_,
                                                          sleep_values.at(i));
                             });
      std::thread thread_keyword([&] {
                                   sleepthreads::RunChangeKeyword(test_elements,
                                                                  std::ref(result_keyword),
                                                                  new_keyword,
                                                                  password_,
                                                                  sleep_values.at(i));
                                 });
      thread_pin.join();
      thread_keyword.join();

      EXPECT_EQ(kSuccess, result_pin);
      EXPECT_EQ(kSuccess, result_keyword);
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
    }
    {
      PopulateSlots(lifestuff_slots_, testing_variables_);
      LifeStuff test_elements(lifestuff_slots_, *test_dir_);
      int result = DoFullLogIn(test_elements, new_keyword, new_pin, password_);
      swap(new_pin, pin_);
      swap(new_keyword, keyword_);
      EXPECT_EQ(kSuccess, result) << "iteration: " << i;
      if (result != kSuccess)
        i = sleep_values.size();
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
    }
  }
}

TEST_F(OneUserApiTest, FUNC_CreateInvalidUsers) {
  NonEmptyString new_pin(CreatePin());
  NonEmptyString new_keyword(RandomAlphaNumericString(5));
  NonEmptyString new_password(RandomAlphaNumericString(5));
  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }

  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    // Try to create existing account
    EXPECT_NE(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));

    // Try to create new account when logged in
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_));
    EXPECT_NE(kSuccess, DoFullCreateUser(test_elements, new_keyword, new_pin, new_password));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }

  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    // Bad Pin
    EXPECT_NE(kSuccess,
              DoFullCreateUser(test_elements, new_keyword, NonEmptyString(" "), new_password));
    EXPECT_NE(kSuccess,
              DoFullCreateUser(test_elements, new_keyword, NonEmptyString("0000"), new_password));
    NonEmptyString not_digits_only(RandomAlphaNumericString(4));
    bool is_all_digits(true);
    while (is_all_digits) {
      try {
        boost::lexical_cast<int>(not_digits_only.string());
        is_all_digits = true;
        not_digits_only = NonEmptyString(RandomAlphaNumericString(4));
      }
      catch(const std::exception& /*e*/) {
        is_all_digits = false;
      }
    }
    EXPECT_NE(kSuccess, DoFullCreateUser(test_elements,
                                         new_keyword,
                                         not_digits_only,
                                         new_password));
    EXPECT_NE(kSuccess, DoFullCreateUser(test_elements,
                                         new_keyword,
                                         NonEmptyString(const_cast<std::string&>(
                                                          CreatePin().string()).erase(3, 1)),
                                         new_password));
    EXPECT_NE(kSuccess, DoFullCreateUser(test_elements,
                                         new_keyword,
                                         NonEmptyString(const_cast<std::string&>(
                                                          CreatePin().string()).append("1")),
                                         new_password));

    // Bad Keyword
    EXPECT_NE(kSuccess, DoFullCreateUser(test_elements,
                                         NonEmptyString(RandomAlphaNumericString(RandomUint32() %
                                                                                 5)),
                                         new_pin,
                                         new_password));
    EXPECT_NE(kSuccess, DoFullCreateUser(test_elements,
                                         NonEmptyString(RandomAlphaNumericString(31)),
                                         new_pin,
                                         new_password));
    EXPECT_NE(kSuccess, DoFullCreateUser(test_elements,
                                         NonEmptyString(RandomAlphaNumericString(
                                                          RandomUint32() % 13 + 2) + " " +
                                                          RandomAlphaNumericString(
                                                          RandomUint32() % 14 + 2)),
                                         new_pin,
                                         new_password));

    // Bad Password
    EXPECT_NE(kSuccess, DoFullCreateUser(test_elements,
                                         new_keyword,
                                         new_pin,
                                         NonEmptyString(RandomAlphaNumericString(
                                                          RandomUint32() % 5))));
    EXPECT_NE(kSuccess, DoFullCreateUser(test_elements,
                                         new_keyword,
                                         new_pin,
                                         NonEmptyString(RandomAlphaNumericString(31))));
    EXPECT_NE(kSuccess,
              DoFullCreateUser(test_elements,
                               new_keyword,
                               new_pin,
                               NonEmptyString(RandomAlphaNumericString(RandomUint32() % 13 + 2) +
                                              " " +
                                              RandomAlphaNumericString(RandomUint32() % 14 + 2))));

    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }
}

TEST_F(OneUserApiTest, FUNC_TryChangeCredentialsToInvalid) {
  NonEmptyString incorrect_password(RandomAlphaNumericString(RandomUint32() % 26 + 5));
  while (incorrect_password == password_)
    incorrect_password = NonEmptyString(RandomAlphaNumericString(RandomUint32() % 26 + 5));

  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));

  // Check Password
  EXPECT_NE(kSuccess, test_elements.CheckPassword(incorrect_password));
  EXPECT_NE(kSuccess, test_elements.CheckPassword(
      NonEmptyString(RandomAlphaNumericString(RandomUint32() % 5))));
  EXPECT_NE(kSuccess, test_elements.CheckPassword(NonEmptyString(RandomAlphaNumericString(31))));

  // Change PIN
  EXPECT_NE(kSuccess, test_elements.ChangePin(NonEmptyString(" "), password_));
  EXPECT_NE(kSuccess, test_elements.ChangePin(NonEmptyString("0000"), password_));
  NonEmptyString not_digits_only(RandomAlphaNumericString(4));
  bool is_all_digits(true);
  while (is_all_digits) {
    try {
      boost::lexical_cast<int>(not_digits_only.string());
      is_all_digits = true;
      not_digits_only = NonEmptyString(RandomAlphaNumericString(4));
    }
    catch(const std::exception& /*e*/) {
      is_all_digits = false;
    }
  }
  EXPECT_NE(kSuccess, test_elements.ChangePin(not_digits_only, password_));
  EXPECT_NE(kSuccess, test_elements.ChangePin(
      NonEmptyString(const_cast<std::string&>(CreatePin().string()).erase(3, 1)), password_));
  EXPECT_NE(kSuccess, test_elements.ChangePin(NonEmptyString(
      const_cast<std::string&>(CreatePin().string()).append("1")), password_));
  EXPECT_NE(kSuccess, test_elements.ChangePin(CreatePin(), incorrect_password));

  // Change Keyword
  EXPECT_NE(kSuccess, test_elements.ChangeKeyword(
      NonEmptyString(RandomAlphaNumericString(RandomUint32() % 5)), password_));
  EXPECT_NE(kSuccess, test_elements.ChangeKeyword(
      NonEmptyString(RandomAlphaNumericString(31)), password_));
  EXPECT_NE(kSuccess, test_elements.ChangeKeyword(NonEmptyString(RandomAlphaNumericString(
      RandomUint32() % 13 + 2) + " " + RandomAlphaNumericString(RandomUint32() % 14 + 2)),
      password_));
  // Change Password
  EXPECT_NE(kSuccess, test_elements.ChangePassword(NonEmptyString(RandomAlphaNumericString(
      RandomUint32() % 5)), password_));
  EXPECT_NE(kSuccess, test_elements.ChangePassword(NonEmptyString(
      RandomAlphaNumericString(31)), password_));
  EXPECT_NE(kSuccess, test_elements.ChangeKeyword(NonEmptyString(RandomAlphaNumericString(
      RandomUint32() % 13 + 2) + " " + RandomAlphaNumericString(RandomUint32() % 14 + 2)),
      password_));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, FUNC_ChangeCredentialsWhenLoggedOut) {
  NonEmptyString new_pin(CreatePin());
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_);

  EXPECT_NE(kSuccess, test_elements.CheckPassword(password_));

  // Change credentials
  EXPECT_NE(kSuccess, test_elements.ChangeKeyword(keyword_ + keyword_, password_));
  EXPECT_NE(kSuccess, test_elements.ChangePin(new_pin, password_));
  EXPECT_NE(kSuccess, test_elements.ChangePassword(password_ + password_, password_));
}

TEST_F(OneUserApiTest, FUNC_ChangeCredentialsAndLogOut) {
  NonEmptyString new_pin(CreatePin());
  NonEmptyString new_keyword(RandomAlphaNumericString(5));
  NonEmptyString new_password(RandomAlphaNumericString(5));
  int result(0);

  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword_, pin_, password_));
    std::thread thread_pin([&test_elements, &result, &new_pin, this] {
                             sleepthreads::RunChangePin(std::ref(test_elements),
                                                        std::ref(result),
                                                        new_pin,
                                                        password_,
                                                        std::make_pair(0, 0));
                           });
    Sleep(boost::posix_time::milliseconds(200));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
    thread_pin.join();
  }

  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, new_pin, password_));
    std::thread thread_keyword([&test_elements, &result, &new_keyword, this] {
                                 sleepthreads::RunChangeKeyword(std::ref(test_elements),
                                                                std::ref(result),
                                                                new_keyword,
                                                                password_,
                                                                std::make_pair(0, 0));
                               });
    Sleep(boost::posix_time::milliseconds(200));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
    thread_keyword.join();
  }

  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, new_keyword, new_pin, password_));
    std::thread thread_password([&test_elements, &result, &new_password, this] {
                                  sleepthreads::RunChangePassword(std::ref(test_elements),
                                                                  std::ref(result),
                                                                  new_password,
                                                                  password_,
                                                                  std::make_pair(0, 0));
                                });
    Sleep(boost::posix_time::milliseconds(200));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
    thread_password.join();
  }
}

TEST_F(OneUserApiTest, FUNC_LoggedInState) {
  // full login and logout (without public ID)
  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(test_elements.state(), kConnected);
    EXPECT_EQ(test_elements.logged_in_state(), kBaseState);
    EXPECT_EQ(kSuccess, test_elements.CreateUser(keyword_, pin_, password_));
    EXPECT_EQ(test_elements.state(), kLoggedIn);
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kSuccess, test_elements.MountDrive());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
    EXPECT_EQ(kStartMessagesAndContactsNoPublicIds, test_elements.StartMessagesAndIntros());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
    EXPECT_EQ(kSuccess, test_elements.StopMessagesAndIntros());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
    EXPECT_EQ(kSuccess, test_elements.UnMountDrive());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kSuccess, test_elements.LogOut());

    EXPECT_EQ(test_elements.state(), kConnected);
    EXPECT_EQ(test_elements.logged_in_state(), kBaseState);
  }

  NonEmptyString keyword2(RandomAlphaNumericString(6));
  NonEmptyString pin2(CreatePin());
  NonEmptyString password2(RandomAlphaNumericString(6));
  NonEmptyString public_id2(RandomAlphaNumericString(5));
  // full login, create public ID, full logout
  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, test_elements.CreateUser(keyword2, pin2, password2));
    EXPECT_EQ(test_elements.state(), kLoggedIn);
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kSuccess, test_elements.MountDrive());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
    EXPECT_EQ(kStartMessagesAndContactsNoPublicIds, test_elements.StartMessagesAndIntros());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
    EXPECT_EQ(kSuccess, test_elements.CreatePublicId(public_id2));
    EXPECT_EQ(test_elements.logged_in_state(),
              kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);
    EXPECT_EQ(kSuccess, test_elements.StopMessagesAndIntros());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
    EXPECT_EQ(kSuccess, test_elements.UnMountDrive());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kSuccess, test_elements.LogOut());

    EXPECT_EQ(test_elements.state(), kConnected);
    EXPECT_EQ(test_elements.logged_in_state(), kBaseState);
  }

  // full login and logout (with public ID)
  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, test_elements.LogIn(keyword2, pin2, password2));
    EXPECT_EQ(test_elements.state(), kLoggedIn);
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kSuccess, test_elements.MountDrive());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
    EXPECT_EQ(kSuccess, test_elements.StartMessagesAndIntros());
    EXPECT_EQ(test_elements.logged_in_state(),
              kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);
    EXPECT_EQ(kSuccess, test_elements.StopMessagesAndIntros());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
    EXPECT_EQ(kSuccess, test_elements.UnMountDrive());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kSuccess, test_elements.LogOut());

    EXPECT_EQ(test_elements.state(), kConnected);
    EXPECT_EQ(test_elements.logged_in_state(), kBaseState);
  }

  // log credentials in and out
  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, test_elements.LogIn(keyword_, pin_, password_));
    EXPECT_EQ(test_elements.state(), kLoggedIn);
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kSuccess, test_elements.LogOut());
    EXPECT_EQ(test_elements.state(), kConnected);
    EXPECT_EQ(test_elements.logged_in_state(), kBaseState);
  }

  // do and undo credentials and drive aspects
  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, test_elements.LogIn(keyword_, pin_, password_));
    EXPECT_EQ(test_elements.state(), kLoggedIn);
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kSuccess, test_elements.MountDrive());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
    EXPECT_EQ(kSuccess, test_elements.UnMountDrive());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kSuccess, test_elements.LogOut());
    EXPECT_EQ(test_elements.state(), kConnected);
    EXPECT_EQ(test_elements.logged_in_state(), kBaseState);
  }
}

TEST_F(OneUserApiTest, FUNC_IncorrectLoginLogoutSequences) {
  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kSuccess, test_elements.CreateUser(keyword_, pin_, password_, fs::path()));
    EXPECT_EQ(test_elements.state(), kLoggedIn);
    EXPECT_EQ(kSuccess, test_elements.MountDrive());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);

    NonEmptyString public_id(RandomAlphaNumericString(5));
    EXPECT_EQ(kSuccess, test_elements.CreatePublicId(public_id));

    // Try logout components in wrong order
    EXPECT_EQ(test_elements.logged_in_state(),
              kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);
    EXPECT_EQ(kWrongLoggedInState, test_elements.UnMountDrive());
    EXPECT_EQ(test_elements.logged_in_state(),
              kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);
    EXPECT_EQ(kWrongLoggedInState, test_elements.LogOut());
    EXPECT_EQ(test_elements.logged_in_state(),
              kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);
    EXPECT_EQ(kSuccess, test_elements.StopMessagesAndIntros());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
    EXPECT_EQ(kWrongLoggedInState, test_elements.LogOut());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
    EXPECT_EQ(kSuccess, test_elements.UnMountDrive());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kSuccess, test_elements.LogOut());

    EXPECT_EQ(test_elements.state(), kConnected);
    EXPECT_EQ(test_elements.logged_in_state(), kBaseState);
  }

  // try login components in wrong order
  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    EXPECT_EQ(kWrongLoggedInState, test_elements.MountDrive());
    EXPECT_EQ(test_elements.state(), kConnected);
    EXPECT_EQ(test_elements.logged_in_state(), kBaseState);
    EXPECT_EQ(kWrongLoggedInState, test_elements.StartMessagesAndIntros());
    EXPECT_EQ(test_elements.state(), kConnected);
    EXPECT_EQ(test_elements.logged_in_state(), kBaseState);
    EXPECT_EQ(kSuccess, test_elements.LogIn(keyword_, pin_, password_));
    EXPECT_EQ(test_elements.state(), kLoggedIn);
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kWrongLoggedInState, test_elements.StartMessagesAndIntros());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kSuccess, test_elements.MountDrive());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
    EXPECT_EQ(kSuccess, test_elements.StartMessagesAndIntros());
    EXPECT_EQ(test_elements.logged_in_state(),
              kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);

    // try repeating logout components
    EXPECT_EQ(kSuccess, test_elements.StopMessagesAndIntros());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
    EXPECT_EQ(kSuccess, test_elements.UnMountDrive());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kWrongLoggedInState, test_elements.UnMountDrive());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kSuccess, test_elements.LogOut());
    EXPECT_EQ(test_elements.state(), kConnected);
    EXPECT_EQ(test_elements.logged_in_state(), kBaseState);
    EXPECT_EQ(kWrongState, test_elements.LogOut());

    EXPECT_EQ(test_elements.state(), kConnected);
    EXPECT_EQ(test_elements.logged_in_state(), kBaseState);
  }

  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    // try repeating login components
    EXPECT_EQ(kSuccess, test_elements.LogIn(keyword_, pin_, password_));
    EXPECT_EQ(test_elements.state(), kLoggedIn);
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kWrongState, test_elements.LogIn(keyword_, pin_, password_));
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn);
    EXPECT_EQ(kSuccess, test_elements.MountDrive());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
    EXPECT_EQ(kWrongLoggedInState, test_elements.MountDrive());
    EXPECT_EQ(test_elements.logged_in_state(), kCredentialsLoggedIn | kDriveMounted);
    EXPECT_EQ(kSuccess, test_elements.StartMessagesAndIntros());
    EXPECT_EQ(test_elements.logged_in_state(),
              kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);
    EXPECT_EQ(kWrongLoggedInState, test_elements.StartMessagesAndIntros());
    EXPECT_EQ(test_elements.logged_in_state(),
              kCredentialsLoggedIn | kDriveMounted | kMessagesAndIntrosStarted);
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }
}

TEST_F(OneUserApiTest, FUNC_LogInFromTwoPlaces) {
  LOG(kInfo) << "\n\nABOUT TO CREATE USER...\n\n";
  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_);
    ASSERT_EQ(kSuccess, test_elements.CreateUser(keyword_, pin_, password_, fs::path()));
    LOG(kInfo) << "\n\nCREATED USER. ABOUT TO LOG OUT...\n\n";
    EXPECT_EQ(kSuccess, test_elements.LogOut());
    LOG(kInfo) << "\n\nLOGGED OUT.\n\n";
  }

  {
    TestingVariables testing_variables2;
    Slots lifestuff_slots2;
    PopulateSlots(lifestuff_slots2, testing_variables2);
    LifeStuff test_elements2(lifestuff_slots2, *test_dir_ / "elements2");
    LOG(kInfo) << "\n\nABOUT TO LOG 2ND INSTANCE IN...\n\n";
    EXPECT_EQ(kSuccess, test_elements2.LogIn(keyword_, pin_, password_));
    EXPECT_EQ(kLoggedIn, test_elements2.state());
    EXPECT_EQ(kCredentialsLoggedIn, test_elements2.logged_in_state());

    LOG(kInfo) << "\n\nABOUT TO LOG 3RD INSTANCE IN...\n\n";
    TestingVariables testing_variables3;
    Slots lifestuff_slots3;
    PopulateSlots(lifestuff_slots3, testing_variables3);
    LifeStuff test_elements3(lifestuff_slots3, *test_dir_ / "elements3");
    EXPECT_EQ(kSuccess, test_elements3.LogIn(keyword_, pin_, password_));
    int i(0);
    while (!testing_variables2.immediate_quit_required && i < 100) {
      ++i;
      Sleep(bptime::milliseconds(100));
    }
    LOG(kInfo) << "\n\nCHECKING STATE OF 2ND AND 3RD INSTANCES...\n\n";
    EXPECT_TRUE(testing_variables2.immediate_quit_required);
    EXPECT_EQ(kConnected, test_elements2.state());
    EXPECT_EQ(kBaseState, test_elements2.logged_in_state());
    EXPECT_EQ(fs::path(), test_elements2.mount_path());
    EXPECT_EQ(kLoggedIn, test_elements3.state());
    EXPECT_EQ(kCredentialsLoggedIn, test_elements3.logged_in_state());

    LOG(kInfo) << "\n\nLOGGING 3RD INSTANCE OUT...\n\n";
    EXPECT_EQ(kSuccess, test_elements3.LogOut());
  }
}

TEST_F(OneUserApiTest, FUNC_LogInAfterCreateUser) {
  PopulateSlots(lifestuff_slots_, testing_variables_);
  LifeStuff test_elements(lifestuff_slots_, *test_dir_ / "elements1");
  LOG(kInfo) << "\n\nABOUT TO CREATE USER...\n\n";
  EXPECT_EQ(kSuccess, test_elements.CreateUser(keyword_, pin_, password_, fs::path()));
  EXPECT_EQ(kLoggedIn, test_elements.state());
  EXPECT_EQ(kCredentialsLoggedIn, test_elements.logged_in_state());

  LOG(kInfo) << "\n\nABOUT TO LOG 2ND INSTANCE IN...\n\n";
  TestingVariables testing_variables2;
  Slots lifestuff_slots2;
  PopulateSlots(lifestuff_slots2, testing_variables2);
  LifeStuff test_elements2(lifestuff_slots2, *test_dir_ / "elements2");
  EXPECT_EQ(kSuccess, test_elements2.LogIn(keyword_, pin_, password_));
  int i(0);
  while (!testing_variables_.immediate_quit_required && i < 100) {
    ++i;
    Sleep(bptime::milliseconds(100));
  }

  LOG(kInfo) << "\n\nCHECKING STATE OF 2ND AND 3RD INSTANCES...\n\n";
  EXPECT_TRUE(testing_variables_.immediate_quit_required);
  EXPECT_EQ(kConnected, test_elements.state());
  EXPECT_EQ(kBaseState, test_elements.logged_in_state());
  EXPECT_EQ(fs::path(), test_elements.mount_path());
  EXPECT_EQ(kLoggedIn, test_elements2.state());
  EXPECT_EQ(kCredentialsLoggedIn, test_elements2.logged_in_state());

  LOG(kInfo) << "\n\nLOGGING 3RD INSTANCE OUT...\n\n";
  EXPECT_EQ(kSuccess, test_elements2.LogOut());
}

TEST_F(OneUserApiTest, FUNC_CreateSameUserSimultaneously) {
  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_ / "elements1");

    TestingVariables testing_variables2;
    Slots lifestuff_slots2;
    PopulateSlots(lifestuff_slots2, testing_variables2);
    LifeStuff test_elements2(lifestuff_slots2, *test_dir_ / "elements2");
    int result_1(0), result_2(0);
    boost::thread thread_1([&] {
                             sleepthreads::RunCreateUser(test_elements,
                                                         std::ref(result_1),
                                                         keyword_,
                                                         pin_,
                                                         password_);
                           });
    boost::thread thread_2([&] {
                             sleepthreads::RunCreateUser(test_elements2,
                                                         std::ref(result_2),
                                                         keyword_,
                                                         pin_,
                                                         password_);
                           });
    thread_1.join();
    thread_2.join();
    EXPECT_TRUE((result_1 == kSuccess && result_2 != kSuccess) ||
                (result_1 != kSuccess && result_2 == kSuccess));
    result_1 = DoFullLogOut(test_elements);
    result_2 = DoFullLogOut(test_elements2);
    EXPECT_TRUE((result_1 == kSuccess && result_2 != kSuccess) ||
                (result_1 != kSuccess && result_2 == kSuccess));
  }
  {
    PopulateSlots(lifestuff_slots_, testing_variables_);
    LifeStuff test_elements(lifestuff_slots_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword_, pin_, password_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  }
}


TEST_F(TwoUsersApiTest, FUNC_ChangeCredentialsToSameConsecutively) {
  NonEmptyString new_pin(CreatePin());
  NonEmptyString new_keyword(RandomAlphaNumericString(5));

  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, test_elements1.ChangePin(new_pin, password_1_));
    EXPECT_EQ(kSuccess, test_elements1.ChangeKeyword(new_keyword, password_1_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }
  {
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
    EXPECT_EQ(kSuccess, test_elements2.ChangePin(new_pin, password_2_));
    EXPECT_NE(kSuccess, test_elements2.ChangeKeyword(new_keyword, password_2_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }
  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, new_keyword, new_pin, password_1_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }
  {
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, new_pin, password_2_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }
}



TEST_F(TwoUsersApiTest, FUNC_ChangePinsToSameThenKeywordsToSameSimultaneously) {
#ifdef MAIDSAFE_LINUX
  ASSERT_NE(keyword_1_, keyword_2_);

  NonEmptyString new_pin;
  bool pins_match(false);
  if (pin_1_ == pin_2_)
    pins_match = true;
  int result_pin_1(0), result_pin_2(0);

  if (!pins_match) {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));

    while (!pins_match) {
      new_pin = CreatePin();
      result_pin_1 = 0;
      result_pin_2 = 0;
      {
        boost::thread thread_pin_1(
              [&] {
              sleepthreads::RunChangePin(test_elements1,
                                         std::ref(result_pin_1),
                                         new_pin,
                                         password_1_);
              });
        boost::thread thread_pin_2(
            [&] {
            sleepthreads::RunChangePin(test_elements2,
                                       std::ref(result_pin_2),
                                       new_pin,
                                       password_2_);
            });
        thread_pin_1.join();
        thread_pin_2.join();
       }
      if (result_pin_1 == kSuccess)
        pin_1_ = new_pin;
      if (result_pin_2 == kSuccess)
        pin_2_ = new_pin;
      if (result_pin_1 == kSuccess && result_pin_2 == kSuccess) {
        pins_match = true;
        LOG(kInfo) << "Matching PINs attained.";
      }
    }
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }
  EXPECT_EQ(pin_1_, pin_2_);

  std::vector<std::pair<int, int> > sleep_values;
  sleep_values.push_back(std::make_pair(0, 200));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 0));

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    int result_logout_1(0), result_logout_2(0);
    {
      PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
      LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
      PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
      LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));

      NonEmptyString new_keyword(RandomAlphaNumericString(5));
      int result_keyword_1(0), result_keyword_2(0);

      boost::thread thread_keyword_1(
          [&] {
            sleepthreads::RunChangeKeyword(test_elements1,
                                           std::ref(result_keyword_1),
                                           new_keyword,
                                           password_1_);
          });
      boost::thread thread_keyword_2(
          [&] {
            sleepthreads::RunChangeKeyword(test_elements2,
                                           std::ref(result_keyword_2),
                                           new_keyword,
                                           password_2_);
          });
      thread_keyword_1.join();
      thread_keyword_2.join();

      if (result_keyword_1 == kSuccess)
        keyword_1_ = new_keyword;
      if (result_keyword_2 == kSuccess)
        keyword_2_ = new_keyword;

      EXPECT_FALSE(result_keyword_1 == kSuccess &&
                   result_keyword_2 == kSuccess);
      EXPECT_NE(keyword_1_, keyword_2_);

      result_logout_1 = DoFullLogOut(test_elements1);
      result_logout_2 = DoFullLogOut(test_elements2);
    }

    EXPECT_EQ(kSuccess, result_logout_1);
    EXPECT_EQ(kSuccess, result_logout_2);

    {
      PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
      LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
    }
    {
      PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
      LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
    }
    if (result_logout_1 != kSuccess || result_logout_2 != kSuccess) {
      break;
    }
  }
#endif
}

TEST_F(TwoUsersApiTest, FUNC_ChangeKeywordsToSameThenPinsToSameSimultaneously) {
#ifdef MAIDSAFE_LINUX
  ASSERT_NE(pin_1_, pin_2_);

  NonEmptyString new_keyword;
  bool keywords_match(false);
  if (keyword_1_ == keyword_2_)
    keywords_match = true;
  int result_keyword_1(0), result_keyword_2(0);

  if (!keywords_match) {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));

    while (!keywords_match) {
      new_keyword = NonEmptyString(RandomAlphaNumericString(5));
      result_keyword_1 = 0;
      result_keyword_2 = 0;

      boost::thread thread_keyword_1(
            [&] {
            sleepthreads::RunChangeKeyword(test_elements1,
                                           std::ref(result_keyword_1),
                                           new_keyword,
                                           password_1_,
                                           std::make_pair(0, 0));
            });
      boost::thread thread_keyword_2(
          [&] {
          sleepthreads::RunChangeKeyword(test_elements2,
                                         std::ref(result_keyword_2),
                                         new_keyword,
                                         password_2_,
                                         std::make_pair(0, 0));
          });
      thread_keyword_1.join();
      thread_keyword_2.join();

      if (result_keyword_1 == kSuccess)
        keyword_1_ = new_keyword;
      if (result_keyword_2 == kSuccess)
        keyword_2_ = new_keyword;
      if (result_keyword_1 == kSuccess && result_keyword_2 == kSuccess) {
        keywords_match = true;
        LOG(kInfo) << "Matching keywords attained.";
      }
    }
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }
  EXPECT_EQ(keyword_1_, keyword_2_);

  std::vector<std::pair<int, int> > sleep_values;
  sleep_values.push_back(std::make_pair(0, 200));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 0));

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    LOG(kError) << "\n\nNew iteration\n";
    int result_logout_1(0), result_logout_2(0);
    {
      PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
      LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
      PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
      LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));

      NonEmptyString new_pin(CreatePin());
      int result_pin_1(0), result_pin_2(0);

      boost::thread thread_pin_1(
          [&] {
            sleepthreads::RunChangePin(test_elements1,
                                       std::ref(result_pin_1),
                                       new_pin,
                                       password_1_,
                                       sleep_values.at(i));
          });
      boost::thread thread_pin_2(
          [&] {
            sleepthreads::RunChangePin(test_elements2,
                                           std::ref(result_pin_2),
                                           new_pin,
                                           password_2_,
                                           sleep_values.at(i));
          });
      thread_pin_1.join();
      thread_pin_2.join();

      if (result_pin_1 == kSuccess)
        pin_1_ = new_pin;
      if (result_pin_2 == kSuccess)
        pin_2_ = new_pin;

      EXPECT_FALSE(result_pin_1 == kSuccess &&
                   result_pin_2 == kSuccess);

      result_logout_1 = DoFullLogOut(test_elements1);
      LOG(kInfo) << "Logged 1 out. Logging 2 out...\n";
      result_logout_2 = DoFullLogOut(test_elements2);
    }

    EXPECT_EQ(kSuccess, result_logout_1);
    EXPECT_EQ(kSuccess, result_logout_2);

    {
      PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
      LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
    }
    {
      PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
      LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
    }
    if (result_logout_1 != kSuccess || result_logout_2 != kSuccess) {
      break;
    }
  }
#endif
}

TEST_F(TwoUsersApiTest, FUNC_ChangePinsAndKeywordsToSameSimultaneously) {
#ifdef MAIDSAFE_LINUX
  ASSERT_NE(keyword_1_, keyword_2_);
  ASSERT_NE(pin_1_, pin_2_);

  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));

    int result_keyword_1(0);
    int result_pin_2(0);

    boost::thread thread_keyword_1(
        [&] {
          sleepthreads::RunChangeKeyword(test_elements1,
                                         std::ref(result_keyword_1),
                                         keyword_2_,
                                         password_1_);
        });
    boost::thread thread_pin_2(
        [&] {
          sleepthreads::RunChangePin(test_elements2,
                                     std::ref(result_pin_2),
                                     pin_1_,
                                     password_2_);
            });
    thread_keyword_1.join();
    thread_pin_2.join();

    if (result_keyword_1 == kSuccess)
      keyword_1_ = keyword_2_;
    if (result_pin_2 == kSuccess)
      pin_2_ = pin_1_;

    EXPECT_FALSE(result_keyword_1 == kSuccess &&
                 result_pin_2 == kSuccess);

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }

  {
    PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
    LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
  }
  {
    PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
    LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
  }
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
    int result_logout_1(0), result_logout_2(0);
    {
      PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
      LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
      PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
      LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));

      NonEmptyString new_pin(CreatePin());
      NonEmptyString new_keyword(RandomAlphaNumericString(5));

      int result_pin_1(0), result_pin_2(0), result_keyword_1(0), result_keyword_2(0);

      boost::thread thread_pin_1(
          [&] {
            sleepthreads::RunChangePin(test_elements1,
                                       std::ref(result_pin_1),
                                       new_pin,
                                       password_1_,
                                       sleep_values.at(i));
          });
      boost::thread thread_pin_2(
          [&] {
            sleepthreads::RunChangePin(test_elements2,
                                       std::ref(result_pin_2),
                                       new_pin,
                                       password_2_,
                                       sleep_values.at(i));
          });
      boost::thread thread_keyword_1(
          [&] {
            sleepthreads::RunChangeKeyword(test_elements1,
                                           std::ref(result_keyword_1),
                                           new_keyword,
                                           password_1_,
                                           sleep_values.at(i));
          });
      boost::thread thread_keyword_2(
          [&] {
            sleepthreads::RunChangeKeyword(test_elements2,
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

      result_logout_1 = DoFullLogOut(test_elements1);
      result_logout_2 = DoFullLogOut(test_elements2);
    }

    EXPECT_EQ(kSuccess, result_logout_1);
    EXPECT_EQ(kSuccess, result_logout_2);

    {
      PopulateSlots(lifestuff_slots_1_, testing_variables_1_);
      LifeStuff test_elements1(lifestuff_slots_1_, *test_dir_ / "elements1");
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements1, keyword_1_, pin_1_, password_1_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements1));
    }
    {
      PopulateSlots(lifestuff_slots_2_, testing_variables_2_);
      LifeStuff test_elements2(lifestuff_slots_2_, *test_dir_ / "elements2");
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements2, keyword_2_, pin_2_, password_2_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements2));
    }
    if (result_logout_1 != kSuccess || result_logout_2 != kSuccess) {
      break;
    }
  }
#endif
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
