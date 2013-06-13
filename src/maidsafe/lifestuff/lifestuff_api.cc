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

#include "maidsafe/lifestuff/lifestuff_api.h"

#include "maidsafe/lifestuff/lifestuff_impl.h"

namespace maidsafe {
namespace lifestuff {

LifeStuff::LifeStuff(const Slots& slots)
  : lifestuff_impl_(new LifeStuffImpl(slots)) {}

LifeStuff::~LifeStuff() {}

void LifeStuff::InsertUserInput(uint32_t position, const std::string& characters, InputField input_field) {
  return lifestuff_impl_->InsertUserInput(position, characters, input_field);
}

void LifeStuff::RemoveUserInput(uint32_t position, uint32_t length, InputField input_field) {
  return lifestuff_impl_->RemoveUserInput(position, length, input_field);
}

void LifeStuff::ClearUserInput(InputField input_field) {
  return lifestuff_impl_->ClearUserInput(input_field);
}

bool LifeStuff::ConfirmUserInput(InputField input_field) {
  return lifestuff_impl_->ConfirmUserInput(input_field);
}

void LifeStuff::CreateUser(const std::string& vault_path, ReportProgressFunction& report_progress) {
  return lifestuff_impl_->CreateUser(vault_path, report_progress);
}

void LifeStuff::LogIn(ReportProgressFunction& report_progress) {
  return lifestuff_impl_->LogIn(report_progress);
}

void LifeStuff::LogOut() {
  return lifestuff_impl_->LogOut();
}

void LifeStuff::MountDrive() {
  return lifestuff_impl_->MountDrive();
}

void LifeStuff::UnMountDrive() {
  return lifestuff_impl_->UnMountDrive();
}

void LifeStuff::ChangeKeyword() {
  return lifestuff_impl_->ChangeKeyword();
}

void LifeStuff::ChangePin() {
  return lifestuff_impl_->ChangePin();
}

void LifeStuff::ChangePassword() {
  return lifestuff_impl_->ChangePassword();
}

bool LifeStuff::logged_in() const {
  return lifestuff_impl_->logged_in();
}

std::string LifeStuff::mount_path() {
  return lifestuff_impl_->mount_path().string();
}

std::string LifeStuff::owner_path() {
  return lifestuff_impl_->owner_path().string();
}

}  // namespace lifestuff
}  // namespace maidsafe
