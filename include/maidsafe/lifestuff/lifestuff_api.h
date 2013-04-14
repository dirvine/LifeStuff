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

class LifeStuffImpl;

class LifeStuff {
 public:
  LifeStuff(const Slots& slots);
  ~LifeStuff();

  void InsertUserInput(uint32_t position, const std::string& characters, InputField input_field);
  void RemoveUserInput(uint32_t position, uint32_t length, InputField input_field);
  void ClearUserInput(InputField input_field);
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
