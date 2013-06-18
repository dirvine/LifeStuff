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
// http://maidsafe.github.io/LifeStuff/.

class LifeStuffImpl;

class LifeStuff {
 public:
  // Lifestuff constructor, refer to discussion in Lifestuff.h for Slots. Throws
  // CommonErrors::uninitialised if any 'slots' member has not been initialised.
  explicit LifeStuff(const Slots& slots);
  ~LifeStuff();

  // Note: Secure string classes for managing user input are provided by the input types Keyword,
  // Pin and Password defined in the MaidSafe-Passport project,
  // http://maidsafe.github.io/MaidSafe-Passport/. The following four methods throw
  // CommonErrors::unknown for undefined 'input_field' type, otherwise propogate exceptions
  // unhandled.

  // Creates and/or inserts a string of 'characters' at position 'position' in the input type,
  // keyword, pin, password, etc., determined by 'input_field', see LifeStuff.h for the
  // definition of InputField. Implicitly accepts Unicode characters converted to std::string.
  void InsertUserInput(uint32_t position, const std::string& characters, InputField input_field);
  // Removes the sequence of characters starting at position 'position' and ending at position
  // 'position' + 'length' from the input type determined by 'input_field'.
  void RemoveUserInput(uint32_t position, uint32_t length, InputField input_field);
  // Clears the currently inserted characters from the input type determined by 'input_field'.
  void ClearUserInput(InputField input_field);
  // Compares input types, dependent on 'input_field' value, for equality.
  bool ConfirmUserInput(InputField input_field);

  // Creates new user credentials, derived from input keyword, pin and password, that are
  // subsequently retrieved from the network during login. Also sets up a new vault associated
  // with those credentials. Refer to details in Lifestuff.h about ReportProgressFunction.
  // If an exception is thrown during the call, attempts cleanup then rethrows the exception.
  void CreateUser(const std::string& vault_path, ReportProgressFunction& report_progress);
  // Recovers session details subject to validation from input keyword, pin and password, and
  // starts the appropriate vault. Refer to details in Lifestuff.h about ReportProgressFunction.
  // If an exception is thrown during the call, attempts cleanup then rethrows the exception.
  void LogIn(ReportProgressFunction& report_progress);
  // Stops the vault associated with the session and unmounts the virtual drive where applicable.
  void LogOut();

  // Mounts a virtual drive, see http://maidsafe.github.io/MaidSafe-Drive/ for details.
  void MountDrive();
  // Unmounts a mounted virtual drive when user has not logged in.
  void UnMountDrive();

  // The following methods can be used to change a user's credentials.
  void ChangeKeyword();
  void ChangePin();
  void ChangePassword();

  // Returns whether user is logged in or not.
  bool logged_in() const;

  // Root path of mounted virtual drive or empty if unmounted.
  std::string mount_path();
  // Owner directory on mounted virtual drive or invalid if unmounted.
  std::string owner_path();

 private:
  std::unique_ptr<LifeStuffImpl> lifestuff_impl_;
};

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_
