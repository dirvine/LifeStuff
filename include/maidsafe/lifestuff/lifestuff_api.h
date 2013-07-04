/* Copyright 2013 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_
#define MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_

#include <memory>

#include "maidsafe/lifestuff/lifestuff.h"

namespace maidsafe {
namespace lifestuff {

// LifeStuff provides a convenient interface for client applications wishing to make use of the
// novinet network, http://novinet.com/. Further details and links for LifeStuff can be found at
// http://maidsafe.github.io/LifeStuff/. During user account creation, RSA asymmetric encryption
// is applied to user input, producing uniquely identifiable data that is stored on the network.
// It is important to note that in order to subsequently retrieve and decrypt the generated data
// for an account, on login, the exact user input supplied to create the account must be passed,
// otherwise the account will be inaccessible. Restated, no user supplied input is ever transmitted
// or stored on the network, so that no mechanism is in place for it's recovery, it is therefore
// important not only to create strong user details, but also to remember them.

class LifeStuffImpl;

class LifeStuff {
 public:
  // LifeStuff constructor, refer to discussion in lifestuff.h for Slots. Throws
  // CommonErrors::uninitialised if any 'slots' member has not been initialised.
  explicit LifeStuff(const Slots& slots);
  ~LifeStuff();

  // Note: Secure string classes for managing user input are provided by the input types Keyword,
  // Pin and Password defined in the MaidSafe-Passport project,
  // http://maidsafe.github.io/MaidSafe-Passport/. The following four methods throw
  // CommonErrors::unknown for undefined 'input_field' type, otherwise propogate exceptions
  // unhandled.

  // Creates and/or inserts a string of 'characters' at position 'position' in the input type,
  // keyword, pin, password, etc., determined by 'input_field', see lifestuff.h for the
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
  // with those credentials. Refer to details in lifestuff.h about ReportProgressFunction.
  // If an exception is thrown during the call, attempts cleanup then rethrows the exception.
  void CreateUser(const std::string& vault_path, ReportProgressFunction& report_progress);
  // Recovers session details subject to validation from input keyword, pin and password, and
  // starts the appropriate vault. Refer to details in lifestuff.h about ReportProgressFunction.
  // If an exception is thrown during the call, attempts cleanup then rethrows the exception.
  void LogIn(ReportProgressFunction& report_progress);
  // Stops the vault associated with the session and unmounts the virtual drive where applicable.
  void LogOut();

  // Mounts a virtual drive, see http://maidsafe.github.io/MaidSafe-Drive/ for details.
  void MountDrive();
  // Unmounts a mounted virtual drive when user has not logged in.
  void UnMountDrive();

  // The following methods can be used to change a user's credentials.
  void ChangeKeyword(ReportProgressFunction& report_progress);
  void ChangePin(ReportProgressFunction& report_progress);
  void ChangePassword(ReportProgressFunction& report_progress);

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
