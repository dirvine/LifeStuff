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

#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_
#define MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_

#include <memory>

#include "maidsafe/lifestuff/lifestuff.h"

namespace maidsafe {
namespace lifestuff {

// LifeStuff provides a convenient interface for client applications wishing to make use of the
// novinet network, http://novinet.com/. Further details and links can be found at
// http://maidsafe.github.io/LifeStuff/. Secure methods for managing user input are provided. Input
// types Keyword, Pin and Password defined in the MaidSafe-Passport project store encrypted
// strings until plaintext is required, whereupon they are converted to safe strings. Safe strings
// come with operating system dependent non-paging guarantees and overwrite their memory during
// destruction.

class LifeStuffImpl;

class LifeStuff {
 public:
  LifeStuff(const Slots& slots);
  ~LifeStuff();

  // Creates and/or inserts a string of 'characters' at position 'position' in the input string,
  // keyword, pin, password, etc., determined by 'input_field', see LifeStuff.h for the
  // InputField definition. Implicitly accepts Unicode characters converted to std::string.
  void InsertUserInput(uint32_t position, const std::string& characters, InputField input_field);
  // Removes the sequence of characters starting at position 'position' and ending at position
  // 'position' + 'length' from the input string determined by 'input_field'.
  void RemoveUserInput(uint32_t position, uint32_t length, InputField input_field);
  // Clears the currently inserted characters from the input string determined by 'input_field'.
  void ClearUserInput(InputField input_field);
  // Confirms pairs, password/confirmation password, etc., of input strings for equality.
  bool ConfirmUserInput(InputField input_field);

  void CreateUser(const std::string& vault_path, ReportProgressFunction& report_progress);
  void LogIn(ReportProgressFunction& report_progress);
  void LogOut();

  void MountDrive();
  void UnMountDrive();

  void ChangeKeyword();
  void ChangePin();
  void ChangePassword();

  bool logged_in() const;

  std::string mount_path();
  std::string owner_path();

 private:
  std::unique_ptr<LifeStuffImpl> lifestuff_impl_;
};

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_
