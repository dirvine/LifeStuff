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

#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_
#define MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_

#include "boost/filesystem/path.hpp"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/detail/client_maid.h"
#include "maidsafe/lifestuff/detail/client_mpid.h"

namespace maidsafe {
namespace lifestuff {

class LifeStuffImpl {
 public:
  explicit LifeStuffImpl(const Slots& slots);
  ~LifeStuffImpl();

  void InsertUserInput(uint32_t position, const std::string& characters, InputField input_field);
  void RemoveUserInput(uint32_t position, uint32_t length, InputField input_field);
  void ClearUserInput(InputField input_field);
  bool ConfirmUserInput(InputField input_field);

  void CreateUser(const boost::filesystem::path& vault_path, ReportProgressFunction& report_progress);
  void LogIn(ReportProgressFunction& report_progress);
  void LogOut();
  void MountDrive();
  void UnMountDrive();

  void ChangeKeyword();
  void ChangePin();
  void ChangePassword();

  bool logged_in() const;

  boost::filesystem::path mount_path();
  boost::filesystem::path owner_path();

  void CreatePublicId(const NonEmptyString& public_id);

 private:
  void FinaliseUserInput();
  void ResetInput();
  void ResetConfirmationInput();

  bool logged_in_;
  std::unique_ptr<Keyword> keyword_, confirmation_keyword_;
  std::unique_ptr<Pin> pin_, confirmation_pin_;
  std::unique_ptr<Password> password_, confirmation_password_, current_password_;
  Session session_;
  ClientMaid client_maid_;
  ClientMpid client_mpid_;
};

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_
