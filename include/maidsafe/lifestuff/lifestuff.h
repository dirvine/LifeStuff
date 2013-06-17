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

#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
#define MAIDSAFE_LIFESTUFF_LIFESTUFF_H_

#include <cstdint>
#include <string>
#include <functional>

namespace maidsafe {
namespace lifestuff {

enum InputField {
  kPin = 0,
  kKeyword,
  kPassword,
  kConfirmationPin,
  kConfirmationKeyword,
  kConfirmationPassword,
  kCurrentPassword
};

enum Action {
  kCreateUser = 0,
  kLogin,
  kChangeKeyword,
  kChangePin,
  kChangePassword
};

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
  kRetrievingUserCredentials
};

// New version update...
typedef std::function<void(const std::string&)> UpdateAvailableFunction;
// Network health...
typedef std::function<void(int32_t)> NetworkHealthFunction;
// Safe to quit...
typedef std::function<void(bool)> OperationsPendingFunction;
// Report progress...
typedef std::function<void(Action, ProgressCode)> ReportProgressFunction;

struct Slots {
  UpdateAvailableFunction update_available;
  NetworkHealthFunction network_health;
  OperationsPendingFunction operations_pending;
};

const std::string kAppHomeDirectory(".lifestuff");
const std::string kOwner("Owner");

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_H_
