/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Definition of system-wide constants/enums/structs
* Version:      1.0
* Created:      2009-01-29-00.15.50
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#ifndef MAIDSAFE_LIFESTUFF_SECURESTRING_API_H_
#define MAIDSAFE_LIFESTUFF_SECURESTRING_API_H_

#include <string>

namespace maidsafe {

namespace lifestuff {

enum class SecureStringReturn : int {
  kSuccess = 0,
  kFailed = 1
};

class SecureStringImpl;

class SecureString {
 public:
  //  Insert <character> at <position>
  SecureStringReturn InsertChar(uint8_t position, char character);

  //  Remove <length> characters starting at <position>
  SecureStringReturn RemoveChars(uint8_t position, uint8_t length);

  //  <position> matches <character>
  bool HasCharAt(uint8_t position, char character) const;

  //  check against regular expression <regex>
  bool IsValid(const std::string& regex) const;

  //  check whether equal to <target> credentials
  bool IsEqualTo(const SecureString& target) const;

  //  check whether contains <target> credentials
  bool Contains(const SecureString& target) const;

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
