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

#include "boost/filesystem/fstream.hpp"  // remove these...
#include "boost/filesystem/operations.hpp"

#include "maidsafe/lifestuff/lifestuff_impl.h"

namespace maidsafe {
namespace lifestuff {

LifeStuff::LifeStuff(const Slots& slots)
  : lifestuff_impl_(new LifeStuffImpl(slots)) {}

LifeStuff::~LifeStuff() {}

ReturnCode LifeStuff::InsertUserInput(uint32_t position, char character, InputField input_field) {
  return lifestuff_impl_->InsertUserInput(position, character, input_field);
}

ReturnCode LifeStuff::RemoveUserInput(uint32_t position, uint32_t length, InputField input_field) {
  return lifestuff_impl_->RemoveUserInput(position, length, input_field);
}

ReturnCode LifeStuff::ClearUserInput(InputField input_field) {
  return lifestuff_impl_->ClearUserInput(input_field);
}

bool LifeStuff::ConfirmUserInput(InputField input_field) {
  return lifestuff_impl_->ConfirmUserInput(input_field);
}

ReturnCode LifeStuff::CreateUser(const std::string& vault_path,
                                 ReportProgressFunction& report_progress) {
  return lifestuff_impl_->CreateUser(vault_path, report_progress);
}

ReturnCode LifeStuff::LogIn(ReportProgressFunction& report_progress) {
  return lifestuff_impl_->LogIn(report_progress);
}

ReturnCode LifeStuff::LogOut() {
  return lifestuff_impl_->LogOut();
}

ReturnCode LifeStuff::MountDrive() {
  return lifestuff_impl_->MountDrive();
}

ReturnCode LifeStuff::UnMountDrive() {
  return lifestuff_impl_->UnMountDrive();
}

ReturnCode LifeStuff::ChangeKeyword() {
  return lifestuff_impl_->ChangeKeyword();
}

ReturnCode LifeStuff::ChangePin() {
  return lifestuff_impl_->ChangePin();
}

ReturnCode LifeStuff::ChangePassword() {
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

wchar_t LifeStuff::ReadChar(const std::string& path) {
  std::wstring content;
  try {
    boost::filesystem::wifstream file_in(path, std::ios::in | std::ios::binary);
    if (!file_in.good())
      return wchar_t();
    uintmax_t size(boost::filesystem::file_size(path));
    if (size < 1)
      return wchar_t();
    content.resize(static_cast<unsigned int>(size));
    file_in.read(const_cast<wchar_t*>(content.data()), 1);
    file_in.close();
  }
  catch(...) {
    return wchar_t();
  }
  return content[0];
}

bool LifeStuff::WriteChar(const std::string& path, const wchar_t& character) {
  try {
    if (!boost::filesystem::path(path).has_filename()) {
      return false;
    }
    boost::filesystem::wofstream file_out(path, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!file_out.good()) {
      return false;
    }
    file_out.write(&character, 1);
    file_out.close();
  }
  catch(const std::exception &e) {
    return false;
  }
  return true;
}

std::wstring LifeStuff::ReadString(const std::string& path) {
  std::wstring content;
  try {
    boost::filesystem::wifstream file_in(path, std::ios::in | std::ios::binary);
    if (!file_in.good())
      return std::wstring();
    uintmax_t size(boost::filesystem::file_size(path));
    if (size < 1)
      return std::wstring();
    content.resize(static_cast<unsigned int>(size));
    file_in.read(const_cast<wchar_t*>(content.data()), 1);
    file_in.close();
  }
  catch(...) {
    return std::wstring();
  }
  return content;
}

bool LifeStuff::WriteString(const std::string& path, const std::wstring& character) {
  try {
    if (!boost::filesystem::path(path).has_filename()) {
      return false;
    }
    boost::filesystem::wofstream file_out(path, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!file_out.good()) {
      return false;
    }
    file_out.write(character.data(), character.size());
    file_out.close();
  }
  catch(...) {
    return false;
  }
  return true;
}

}  // namespace lifestuff
}  // namespace maidsafe
