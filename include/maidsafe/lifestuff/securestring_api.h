/***************************************************************************************************
 *  Copyright 2013 MaidSafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use.  The use of this code is governed by the licence file licence.txt found in the root of    *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit         *
 *  written permission of the board of directors of MaidSafe.net.                                  *
 **************************************************************************************************/

#ifndef MAIDSAFE_LIFESTUFF_SECURESTRING_API_H_
#define MAIDSAFE_LIFESTUFF_SECURESTRING_API_H_

#include <string>
#include <regex>

namespace maidsafe {

namespace lifestuff {

enum class SecureStringReturn : int {
  kFailed = -1,
  kSuccess = 0
};

class SecureStringImpl;

class SecureString {
 public:
  //  Insert <character> at <position>
  SecureStringReturn Insert(uint8_t position, char character);

  //  Remove <length> characters starting at <position>
  SecureStringReturn Remove(uint8_t position, uint8_t length);

  //  <position> matches <character>
  bool HasCharAt(uint8_t position, char character) const;

  //  check against regular expression <regex>
  bool IsValid(const std::regex& regex) const;
  bool IsValid(const std::string& regex) const;

  //  check whether equal to <target> credentials
  bool IsEqualTo(const SecureString& target) const;
  bool IsEqualTo(const std::string& target) const;

  //  check whether contains <target> credentials
  bool Contains(const SecureString& target) const;
  bool Contains(const std::string& target) const;

  //  establishes if is empty/null
  bool IsEmptyOrNull() const;

  //  clears content
  SecureStringReturn Clear();

 private:
  std::unique_ptr<SecureStringImpl> securestring_impl_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_SECURESTRING_API_H_
