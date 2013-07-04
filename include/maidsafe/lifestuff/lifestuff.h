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

#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
#define MAIDSAFE_LIFESTUFF_LIFESTUFF_H_

#include <cstdint>
#include <string>
#include <functional>

namespace maidsafe {
namespace lifestuff {

// Type passed to user input functions in LifeStuff class to determine which variable(s) to
// process.
enum InputField {
  kPin = 0,
  kKeyword,
  kPassword,
  kConfirmationPin,
  kConfirmationKeyword,
  kConfirmationPassword,
  kCurrentPassword
};

// Used in conjunction with ProgressCode to report execution state during various function calls
// via the ReportProgressFunction function, see definition below.
enum Action {
  kCreateUser = 0,
  kLogin,
  kChangeKeyword,
  kChangePin,
  kChangePassword
};
// See above discussion for Action.
enum ProgressCode {
  kInitialiseProcess = 0,
  kCreatingUserCredentials,
  kJoiningNetwork,
  kInitialisingClientComponents,
  kCreatingVault,
  kStartingVault,
  kVerifyingMount,
  kVerifyingUnmount,
  kStoringUserCredentials,
  kRetrievingUserCredentials,
  kConfirmingUserInput
};

// New version update.
typedef std::function<void(const std::string&)> UpdateAvailableFunction;
// Network health.
typedef std::function<void(int32_t)> NetworkHealthFunction;
// Safe to quit.
typedef std::function<void(bool)> OperationsPendingFunction;

// Slots are used to provide useful information back to the client application.
struct Slots {
  UpdateAvailableFunction update_available;
  NetworkHealthFunction network_health;
  OperationsPendingFunction operations_pending;
};

// Some methods may take some time to complete, e.g. Login. The ReportProgressFunction is used to
// relay back to the client application the current execution state.
typedef std::function<void(Action, ProgressCode)> ReportProgressFunction;

// Some internally used constants.
const std::string kAppHomeDirectory(".lifestuff");
const std::string kOwner("Owner");

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
