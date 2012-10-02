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

namespace {

void InitialiseAndConnectElements(LifeStuff& elements, const fs::path& dir, volatile bool* done) {
  EXPECT_EQ(kSuccess, elements.Initialise([] (std::string) {}, dir));
  EXPECT_EQ(kSuccess,
            elements.ConnectToSignals(ChatFunction(),
                                      FileTransferFunction(),
                                      NewContactFunction(),
                                      ContactConfirmationFunction(),
                                      ContactProfilePictureFunction(),
                                      [&] (const std::string& own_public_id,
                                           const std::string& contact_public_id,
                                           const std::string& timestamp,
                                           ContactPresence cp) {
                                        ContactPresenceSlot(own_public_id,
                                                            contact_public_id,
                                                            timestamp,
                                                            cp,
                                                            done);
                                      },
                                      ContactDeletionFunction(),
                                      LifestuffCardUpdateFunction(),
                                      NetworkHealthFunction(),
                                      ImmediateQuitRequiredFunction()));
}

}  // namespace

TEST(IndependentFullTest, FUNC_CreateLogoutLoginLogout) {
  LifeStuff test_elements;
  std::string keyword(RandomAlphaNumericString(5)),
              pin(CreatePin()),
              password(RandomAlphaNumericString(5));
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  volatile bool done(false);
  InitialiseAndConnectElements(test_elements, *test_dir, &done);

  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements, keyword, pin, password, true));
  Sleep(boost::posix_time::seconds(10));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
  Sleep(boost::posix_time::seconds(10));
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements, keyword, pin, password));
  Sleep(boost::posix_time::seconds(10));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements));
}

TEST_F(OneUserApiTest, FUNC_ChangeCredentials) {
  std::string new_pin(CreatePin());
  EXPECT_EQ(kSuccess, test_elements_.CheckPassword(password_));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, pin_, password_));
  EXPECT_EQ(kSuccess, test_elements_.CheckPassword(password_));

  // Change credentials
  EXPECT_EQ(kSuccess, test_elements_.ChangeKeyword(keyword_ + keyword_, password_));
  EXPECT_EQ(kSuccess, test_elements_.ChangePin(new_pin, password_));
  EXPECT_EQ(kSuccess, test_elements_.ChangePassword(password_ + password_, password_));

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_,
                                  keyword_ + keyword_,
                                  new_pin,
                                  password_ + password_));
  EXPECT_EQ(kSuccess, test_elements_.ChangeKeyword(keyword_, password_ + password_));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, new_pin, password_ + password_));
  EXPECT_EQ(kSuccess, test_elements_.ChangePin(pin_, password_ + password_));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, pin_, password_ + password_));
  EXPECT_EQ(kSuccess, test_elements_.ChangePassword(password_, password_ + password_));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, pin_, password_));
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

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));
    ASSERT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, new_pin, new_password));
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

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));
    ASSERT_EQ(kSuccess, DoFullLogIn(test_elements_, new_keyword, pin_, new_password));
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

    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));
    ASSERT_EQ(kSuccess, DoFullLogIn(test_elements_, new_keyword, new_pin, password_));
    new_pin.swap(pin_);
    new_keyword.swap(keyword_);
  }
}

TEST_F(OneUserApiTest, FUNC_CreateUserWhenLoggedIn) {
  EXPECT_NE(kSuccess, DoFullCreateUser(test_elements_,
                                       RandomAlphaNumericString(5),
                                       CreatePin(),
                                       RandomAlphaNumericString(5),
                                       true));
}

TEST_F(OneUserApiTest, FUNC_LogOutCreateNewUser) {
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements_,
                                       RandomAlphaNumericString(5),
                                       CreatePin(),
                                       RandomAlphaNumericString(5),
                                       true));
}

TEST_F(OneUserApiTest, FUNC_CreateInvalidUsers) {
  std::string new_pin(CreatePin());
  std::string new_keyword(RandomAlphaNumericString(5));
  std::string new_password(RandomAlphaNumericString(5));

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));

  // Try to create existing account
  EXPECT_NE(kSuccess, DoFullCreateUser(test_elements_, keyword_, pin_, password_, true));

  // Try to create new account when logged in
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, pin_, password_));
  EXPECT_NE(kSuccess, DoFullCreateUser(test_elements_, new_keyword, new_pin, new_password, true));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));

  // Bad Pin
  EXPECT_NE(kSuccess, DoFullCreateUser(test_elements_, new_keyword, "", new_password, true));
  EXPECT_NE(kSuccess, DoFullCreateUser(test_elements_, new_keyword, "0000", new_password, true));
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
  EXPECT_NE(kSuccess, DoFullCreateUser(test_elements_,
                                       new_keyword,
                                       not_digits_only,
                                       new_password,
                                       true));
  EXPECT_NE(kSuccess, DoFullCreateUser(test_elements_,
                                       new_keyword,
                                       CreatePin().erase(3, 1),
                                       new_password,
                                       true));
  EXPECT_NE(kSuccess, DoFullCreateUser(test_elements_,
                                       new_keyword,
                                       CreatePin().append("1"),
                                       new_password,
                                       true));

  // Bad Keyword
  EXPECT_NE(kSuccess, DoFullCreateUser(test_elements_,
                                       RandomAlphaNumericString(RandomUint32() % 5),
                                       new_pin,
                                       new_password,
                                       true));
  EXPECT_NE(kSuccess, DoFullCreateUser(test_elements_,
                                       RandomAlphaNumericString(31),
                                       new_pin,
                                       new_password,
                                       true));
  EXPECT_NE(kSuccess, DoFullCreateUser(test_elements_,
                                       RandomAlphaNumericString(RandomUint32() % 13 + 2) +
                                       " " +
                                       RandomAlphaNumericString(RandomUint32() % 14 + 2),
                                       new_pin,
                                       new_password,
                                       true));

  // Bad Password
  EXPECT_NE(kSuccess, DoFullCreateUser(test_elements_,
                                       new_keyword,
                                       new_pin,
                                       RandomAlphaNumericString(RandomUint32() % 5),
                                       true));
  EXPECT_NE(kSuccess, DoFullCreateUser(test_elements_,
                                       new_keyword,
                                       new_pin,
                                       RandomAlphaNumericString(31),
                                       true));
  EXPECT_NE(kSuccess,
            DoFullCreateUser(test_elements_,
                             new_keyword,
                             new_pin,
                             RandomAlphaNumericString(RandomUint32() % 13 + 2) + " " +
                             RandomAlphaNumericString(RandomUint32() % 14 + 2),
                             true));

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, pin_, password_));
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

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));

  EXPECT_NE(kSuccess, test_elements_.CheckPassword(password_));

  // Change credentials
  EXPECT_NE(kSuccess, test_elements_.ChangeKeyword(keyword_ + keyword_, password_));
  EXPECT_NE(kSuccess, test_elements_.ChangePin(new_pin, password_));
  EXPECT_NE(kSuccess, test_elements_.ChangePassword(password_ + password_, password_));

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, pin_, password_));
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

  DoFullLogOut(test_elements_);
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, new_pin, password_));

  boost::thread thread_keyword([&] {
                                 sleepthreads::RunChangeKeyword(test_elements_,
                                                                std::ref(result),
                                                                new_keyword,
                                                                password_,
                                                                std::make_pair(0, 0));
                               });

  DoFullLogOut(test_elements_);
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, new_keyword, new_pin, password_));

  boost::thread thread_password([&] {
                                  sleepthreads::RunChangePassword(test_elements_,
                                                                  std::ref(result),
                                                                  new_password,
                                                                  password_,
                                                                  std::make_pair(0, 0));
                                });

  DoFullLogOut(test_elements_);
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, new_keyword, new_pin, new_password));
}

TEST_F(TwoInstancesApiTest, FUNC_LogInFromTwoPlaces) {
  LOG(kInfo) << "\n\nABOUT TO CREATE USER...\n\n";
  EXPECT_EQ(kSuccess, test_elements_.CreateUser(keyword_, pin_, password_, fs::path(), true));
  // test_elements_
  LOG(kInfo) << "\n\nCREATED USER. ABOUT TO LOG OUT...\n\n";
  EXPECT_EQ(kSuccess, test_elements_.LogOut());
  LOG(kInfo) << "\n\nLOGGED OUT.\n\n";

  LOG(kInfo) << "\n\nSETTING UP 3RD TEST ELEMENTS...\n\n";
  LifeStuff test_elements_3;
  bool immediate_quit_required_3(false);
  EXPECT_EQ(kSuccess, test_elements_3.Initialise([] (std::string) {}, *test_dir_));
  EXPECT_EQ(kSuccess,
            test_elements_3.ConnectToSignals(ChatFunction(),
                                             FileTransferFunction(),
                                             NewContactFunction(),
                                             ContactConfirmationFunction(),
                                             ContactProfilePictureFunction(),
                                             ContactPresenceFunction(),
                                             ContactDeletionFunction(),
                                             LifestuffCardUpdateFunction(),
                                             NetworkHealthFunction(),
                                             [&] {
                                             ImmediateQuitRequiredSlot(
                                               &immediate_quit_required_3);
                                             }));

  testing_variables_2_.immediate_quit_required = false;
  LOG(kInfo) << "\n\nABOUT TO LOG 2ND INSTANCE IN...\n\n";
  EXPECT_EQ(kSuccess, test_elements_2_.LogIn(keyword_, pin_, password_));
  EXPECT_EQ(kLoggedIn, test_elements_2_.state());
  EXPECT_EQ(kCredentialsLoggedIn, test_elements_2_.logged_in_state());

  LOG(kInfo) << "\n\nABOUT TO LOG 3RD INSTANCE IN...\n\n";
  EXPECT_EQ(kSuccess, test_elements_3.LogIn(keyword_, pin_, password_));
  int i(0);
  while (!testing_variables_2_.immediate_quit_required && i < 100) {
    ++i;
    Sleep(bptime::milliseconds(100));
  }
  LOG(kInfo) << "\n\nCHECKING STATE OF 2ND AND 3RD INSTANCES...\n\n";
  EXPECT_TRUE(testing_variables_2_.immediate_quit_required);
  EXPECT_EQ(kConnected, test_elements_2_.state());
  EXPECT_EQ(kBaseState, test_elements_2_.logged_in_state());
  EXPECT_EQ(fs::path(), test_elements_2_.mount_path());
  EXPECT_EQ(kLoggedIn, test_elements_3.state());
  EXPECT_EQ(kCredentialsLoggedIn, test_elements_3.logged_in_state());

  LOG(kInfo) << "\n\nLOGGING 3RD INSTANCE OUT...\n\n";
  EXPECT_EQ(kSuccess, test_elements_3.LogOut());
  LOG(kInfo) << "\n\nFINALISING 3RD INSTANCE...\n\n";
  EXPECT_EQ(kSuccess, test_elements_3.Finalise());
  LOG(kInfo) << "\n\nFINISHED TEST BODY! TAH-DAH!\n\n";
}

TEST_F(TwoInstancesApiTest, DISABLED_FUNC_LogInFromTwoPlacesSimultaneously) {
#ifdef MAIDSAFE_LINUX
  EXPECT_EQ(kSuccess, DoFullCreateUser(test_elements_, keyword_, pin_, password_, true));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));

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
    result_1 = DoFullLogOut(test_elements_);
    result_2 = DoFullLogOut(test_elements_2_);
    EXPECT_TRUE((result_1 == kSuccess && result_2 != kSuccess) ||
                (result_1 != kSuccess && result_2 == kSuccess));
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, pin_, password_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));
  }
#endif
}

TEST_F(TwoInstancesApiTest, FUNC_NeverLogIn) {
}

TEST_F(TwoInstancesApiTest, FUNC_CreateSameUserSimultaneously) {
  int result_1(0), result_2(0);
  boost::thread thread_1([&] {
                           sleepthreads::RunCreateUser(test_elements_,
                                                       std::ref(result_1),
                                                       keyword_, pin_,
                                                       password_);
                         });
  boost::thread thread_2([&] {
                           sleepthreads::RunCreateUser(test_elements_2_,
                                                       std::ref(result_2),
                                                       keyword_,
                                                       pin_,
                                                       password_);
                         });
  thread_1.join();
  thread_2.join();
  EXPECT_TRUE((result_1 == kSuccess && result_2 != kSuccess) ||
              (result_1 != kSuccess && result_2 == kSuccess));
  result_1 = DoFullLogOut(test_elements_);
  result_2 = DoFullLogOut(test_elements_2_);
  EXPECT_TRUE((result_1 == kSuccess && result_2 != kSuccess) ||
              (result_1 != kSuccess && result_2 == kSuccess));
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_, keyword_, pin_, password_));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_));
}

TEST_F(TwoUsersApiTest, FUNC_ChangeCredentialsToSameConsecutively) {
#ifdef MAIDSAFE_LINUX
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));

  std::string new_pin(CreatePin());
  std::string new_keyword(RandomAlphaNumericString(5));

  EXPECT_EQ(kSuccess, test_elements_1_.ChangePin(new_pin, password_1_));
  EXPECT_EQ(kSuccess, test_elements_2_.ChangePin(new_pin, password_2_));
  EXPECT_EQ(kSuccess, test_elements_1_.ChangeKeyword(new_keyword, password_1_));
  EXPECT_NE(kSuccess, test_elements_2_.ChangeKeyword(new_keyword, password_2_));

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, new_keyword, new_pin, password_1_));
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, new_pin, password_2_));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
#endif
}

TEST_F(TwoUsersApiTest, FUNC_ChangePinsToSameThenKeywordsToSameSimultaneously) {
#ifdef MAIDSAFE_LINUX
  ASSERT_NE(keyword_1_, keyword_2_);

  std::string new_pin;
  bool pins_match(false);
  if (pin_1_ == pin_2_)
    pins_match = true;
  int result_pin_1(0), result_pin_2(0);

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));

  while (!pins_match) {
    new_pin = CreatePin();
    result_pin_1 = 0;
    result_pin_2 = 0;

    boost::thread thread_pin_1(
          [&] {
          sleepthreads::RunChangePin(test_elements_1_,
                                     std::ref(result_pin_1),
                                     new_pin,
                                     password_1_);
          });
    boost::thread thread_pin_2(
        [&] {
        sleepthreads::RunChangePin(test_elements_2_,
                                   std::ref(result_pin_2),
                                   new_pin,
                                   password_2_);
        });
    thread_pin_1.join();
    thread_pin_2.join();

    if (result_pin_1 == kSuccess)
      pin_1_ = new_pin;
    if (result_pin_2 == kSuccess)
      pin_2_ = new_pin;
    if (result_pin_1 == kSuccess && result_pin_2 == kSuccess) {
      pins_match = true;
      LOG(kInfo) << "Matching PINs attained.";
    }
  }

  EXPECT_EQ(pin_1_, pin_2_);

  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));

  std::vector<std::pair<int, int> > sleep_values;
  sleep_values.push_back(std::make_pair(0, 200));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 0));

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));

    std::string new_keyword(RandomAlphaNumericString(5));
    int result_keyword_1(0), result_keyword_2(0);

    boost::thread thread_keyword_1(
        [&] {
          sleepthreads::RunChangeKeyword(test_elements_1_,
                                         std::ref(result_keyword_1),
                                         new_keyword,
                                         password_1_);
        });
    boost::thread thread_keyword_2(
        [&] {
          sleepthreads::RunChangeKeyword(test_elements_2_,
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

    int result_logout_1(DoFullLogOut(test_elements_1_));
    int result_logout_2(DoFullLogOut(test_elements_2_));

    if (result_logout_1 != kSuccess) {
      if (result_logout_2 != kSuccess) {
        LOG(kError) << "Both test elements failed to log out.";
        break;
      }
      LOG(kError) << "Can't log out of test_elements_1_";
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_2_; credentials 2";
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_2_; credentials 1";
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_1_, pin_1_, password_1_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
      break;
    }
    if (result_logout_2 != kSuccess) {
      LOG(kError) << "Can't log out of test_elements_2_";
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_1_; credentials 1";
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_1_; credentials 2";
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_2_, pin_2_, password_2_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
      break;
    }
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
  }
#endif
}

TEST_F(TwoUsersApiTest, FUNC_ChangeKeywordsToSameThenPinsToSameSimultaneously) {
#ifdef MAIDSAFE_LINUX
  ASSERT_NE(pin_1_, pin_2_);

  std::string new_keyword;
  bool keywords_match(false);
  if (keyword_1_ == keyword_2_)
    keywords_match = true;
  int result_keyword_1(0), result_keyword_2(0);

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));

  while (!keywords_match) {
    new_keyword = RandomAlphaNumericString(5);
    result_keyword_1 = 0;
    result_keyword_2 = 0;

    boost::thread thread_keyword_1(
          [&] {
          sleepthreads::RunChangeKeyword(test_elements_1_,
                                         std::ref(result_keyword_1),
                                         new_keyword,
                                         password_1_,
                                         std::make_pair(0, 0));
          });
    boost::thread thread_keyword_2(
        [&] {
        sleepthreads::RunChangeKeyword(test_elements_2_,
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
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
  EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));

  std::vector<std::pair<int, int> > sleep_values;
  sleep_values.push_back(std::make_pair(0, 200));
  sleep_values.push_back(std::make_pair(100, 200));
  sleep_values.push_back(std::make_pair(100, 150));
  sleep_values.push_back(std::make_pair(0, 0));

  for (size_t i = 0; i < sleep_values.size(); ++i) {
    LOG(kError) << "\n\nNew iteration\n";
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));

    std::string new_pin(CreatePin());
    int result_pin_1(0), result_pin_2(0);

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
    thread_pin_1.join();
    thread_pin_2.join();

    if (result_pin_1 == kSuccess)
      pin_1_ = new_pin;
    if (result_pin_2 == kSuccess)
      pin_2_ = new_pin;

    EXPECT_FALSE(result_pin_1 == kSuccess &&
                 result_pin_2 == kSuccess);

    int result_logout_1(DoFullLogOut(test_elements_1_));
    LOG(kInfo) << "Logged 1 out. Logging 2 out...\n";
    int result_logout_2(DoFullLogOut(test_elements_2_));

    if (result_logout_1 != kSuccess) {
      if (result_logout_2 != kSuccess) {
        LOG(kError) << "Both test elements failed to log out.";
        break;
      }
      LOG(kError) << "Can't log out of test_elements_1_";
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_2_; credentials 2";
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_2_; credentials 1";
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_1_, pin_1_, password_1_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
      break;
    }
    if (result_logout_2 != kSuccess) {
      LOG(kError) << "Can't log out of test_elements_2_";
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_1_; credentials 1";
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_1_; credentials 2";
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_2_, pin_2_, password_2_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
      break;
    }
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
  }
#endif
}

TEST_F(TwoUsersApiTest, FUNC_ChangePinsAndKeywordsToSameSimultaneously) {
#ifdef MAIDSAFE_LINUX
  ASSERT_NE(keyword_1_, keyword_2_);
  ASSERT_NE(pin_1_, pin_2_);

  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
  EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));

  int result_keyword_1(0);
  int result_pin_2(0);

  boost::thread thread_keyword_1(
      [&] {
        sleepthreads::RunChangeKeyword(test_elements_1_,
                                       std::ref(result_keyword_1),
                                       keyword_2_,
                                       password_1_);
      });
  boost::thread thread_pin_2(
      [&] {
        sleepthreads::RunChangePin(test_elements_2_,
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

  int result_logout_1(DoFullLogOut(test_elements_1_));
  int result_logout_2(DoFullLogOut(test_elements_2_));

  if (result_logout_1 != kSuccess) {
    if (result_logout_2 != kSuccess) {
      LOG(kError) << "Both test elements failed to log out.";
    } else {
      LOG(kError) << "Can't log out of test_elements_1_";
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_2_; credentials 2";
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_2_; credentials 1";
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_1_, pin_1_, password_1_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
    }
  } else if (result_logout_2 != kSuccess) {
    LOG(kError) << "Can't log out of test_elements_2_";
    LOG(kInfo) << "Checking LogIn/LogOut: test_elements_1_; credentials 1";
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
    LOG(kInfo) << "Checking LogIn/LogOut: test_elements_1_; credentials 2";
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_2_, pin_2_, password_2_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
  } else {
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
    EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
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
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
    EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));

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

    int result_logout_1(DoFullLogOut(test_elements_1_));
    int result_logout_2(DoFullLogOut(test_elements_2_));

    if (result_logout_1 != kSuccess) {
      if (result_logout_2 != kSuccess) {
        LOG(kError) << "Both test elements failed to log out.";
        break;
      }
      LOG(kError) << "Can't log out of test_elements_1_";
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_2_; credentials 2";
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_2_, pin_2_, password_2_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_2_; credentials 1";
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_2_, keyword_1_, pin_1_, password_1_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_2_));
      break;
    }
    if (result_logout_2 != kSuccess) {
      LOG(kError) << "Can't log out of test_elements_2_";
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_1_; credentials 1";
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_1_, pin_1_, password_1_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
      LOG(kInfo) << "Checking LogIn/LogOut: test_elements_1_; credentials 2";
      EXPECT_EQ(kSuccess, DoFullLogIn(test_elements_1_, keyword_2_, pin_2_, password_2_));
      EXPECT_EQ(kSuccess, DoFullLogOut(test_elements_1_));
      break;
    }
  }
#endif
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
