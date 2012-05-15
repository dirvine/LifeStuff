/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Unit tests for Session
* Version:      1.0
* Created:      2009-07-23
* Revision:     none
* Compiler:     gcc
* Author:       Team Maidsafe
* Company:      maidsafe.net limited
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

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace maidsafe {

namespace lifestuff {

namespace test {

TEST(UtilsTest, BEH_CreatePin) {
  for (int n = 0; n < 100; ++n) {
    std::string pin(CreatePin());
    EXPECT_EQ(kPinSize, pin.size());
    EXPECT_NE('0', pin.at(0));
  }
}

TEST(UtilsTest, BEH_WordValidity) {
  std::string one_leading(" leadingspace"),
              three_leading("   leadingspaces"),
              one_trailing("trailingspace "),
              three_trailing("trailingspaces   "),
              one_middle("middle space"),
              three_middle("middle   spaces"),
              too_short(RandomAlphaNumericString(4)),
              too_long(RandomAlphaNumericString(31)),
              correct(RandomAlphaNumericString(18));
  EXPECT_FALSE(CheckKeywordValidity(one_leading));
  EXPECT_FALSE(CheckKeywordValidity(three_leading));
  EXPECT_FALSE(CheckKeywordValidity(one_trailing));
  EXPECT_FALSE(CheckKeywordValidity(three_trailing));
  EXPECT_FALSE(CheckKeywordValidity(one_middle));
  EXPECT_FALSE(CheckKeywordValidity(three_middle));
  EXPECT_FALSE(CheckKeywordValidity(too_short));
  EXPECT_FALSE(CheckKeywordValidity(too_long));
  EXPECT_TRUE(CheckKeywordValidity(correct));

  EXPECT_FALSE(CheckPasswordValidity(one_leading));
  EXPECT_FALSE(CheckPasswordValidity(three_leading));
  EXPECT_FALSE(CheckPasswordValidity(one_trailing));
  EXPECT_FALSE(CheckPasswordValidity(three_trailing));
  EXPECT_FALSE(CheckPasswordValidity(one_middle));
  EXPECT_FALSE(CheckPasswordValidity(three_middle));
  EXPECT_FALSE(CheckPasswordValidity(too_short));
  EXPECT_FALSE(CheckPasswordValidity(too_long));
  EXPECT_TRUE(CheckPasswordValidity(correct));
}

TEST(UtilsTest, BEH_PinValidity) {
  std::string too_short("999"),
              too_long("11111"),
              non_number1("a111"), non_number2("1a11"),
              non_number3("11a1"), non_number4("111a"),
              non_number5("aaaa"), non_number6("1aa1"),
              non_number7("a11a"), non_number8("1a1a"),
              all_zeros("0000");
  EXPECT_FALSE(CheckPinValidity(too_short));
  EXPECT_FALSE(CheckPinValidity(too_long));
  EXPECT_FALSE(CheckPinValidity(non_number1));
  EXPECT_FALSE(CheckPinValidity(non_number2));
  EXPECT_FALSE(CheckPinValidity(non_number3));
  EXPECT_FALSE(CheckPinValidity(non_number4));
  EXPECT_FALSE(CheckPinValidity(non_number5));
  EXPECT_FALSE(CheckPinValidity(non_number6));
  EXPECT_FALSE(CheckPinValidity(non_number7));
  EXPECT_FALSE(CheckPinValidity(non_number8));
  EXPECT_FALSE(CheckPinValidity(all_zeros));

  for (int n = 0; n < 100; ++n) {
    std::string pin(CreatePin());
    EXPECT_TRUE(CheckPinValidity(pin)) << pin;
  }

  std::string one_starting_zero("0333"),
              two_starting_zeros("0022"),
              three_starting_zeros("0001");
  EXPECT_TRUE(CheckPinValidity(one_starting_zero));
  EXPECT_TRUE(CheckPinValidity(two_starting_zeros));
  EXPECT_TRUE(CheckPinValidity(three_starting_zeros));
}

TEST(UtilsTest, BEH_GetNameInPath) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  std::string file_name, dir_name, extension_name, extension_dir;

  ASSERT_EQ(kSuccess, CreateSmallTestFile(*test_dir, 1, &file_name));
  extension_name = file_name + ".txt";
  boost::system::error_code ec;
  fs::copy_file(*test_dir / file_name, *test_dir / extension_name, ec);
  ASSERT_EQ(0, ec.value());

  fs::path dir1(CreateTestDirectory(*test_dir, &dir_name));
  ASSERT_FALSE(dir1.empty());
  extension_dir = dir_name + ".txt";
  fs::create_directory(*test_dir / extension_dir, ec);
  ASSERT_EQ(0, ec.value());

  std::string generated_name;
  int file_count(1022);
  for (int n(1); n < file_count; ++n) {
    generated_name = GetNameInPath(*test_dir, file_name);
    ASSERT_EQ(file_name + " (" + IntToString(n) + ")", generated_name);
    fs::copy_file(*test_dir / file_name, *test_dir / generated_name, ec);
    ASSERT_EQ(0, ec.value());

    generated_name = GetNameInPath(*test_dir, extension_name);
    ASSERT_EQ(file_name + " (" + IntToString(n) + ").txt", generated_name);
    fs::copy_file(*test_dir / file_name, *test_dir / generated_name, ec);
    ASSERT_EQ(0, ec.value());

    generated_name = GetNameInPath(*test_dir, dir_name);
    ASSERT_EQ(dir_name + " (" + IntToString(n) + ")", generated_name);
    fs::create_directory(*test_dir / generated_name, ec);
    ASSERT_EQ(0, ec.value());

    generated_name = GetNameInPath(*test_dir, extension_dir);
    ASSERT_EQ(dir_name + " (" + IntToString(n) + ").txt", generated_name);
    fs::create_directory(*test_dir / generated_name, ec);
    ASSERT_EQ(0, ec.value());
  }
}

}  // namespace test

}  // namespace lifestuff

}  // namespace maidsafe
