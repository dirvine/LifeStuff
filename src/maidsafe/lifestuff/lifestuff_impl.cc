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

#include "maidsafe/lifestuff/lifestuff_impl.h"

namespace maidsafe {
namespace lifestuff {

namespace {

const int kRetryLimit(10);
const char kCharRegex[] = ".*";
const char kDigitRegex[] = "\\d";

}  // unnamed namespace

LifeStuffImpl::LifeStuffImpl(const Slots& slots)
  : logged_in_(false),
    keyword_(),
    pin_(),
    password_(),
    confirmation_keyword_(),
    confirmation_pin_(),
    confirmation_password_(),
    current_password_(),
    session_(),
    client_maid_(session_, slots),
    client_mpid_() {}

LifeStuffImpl::~LifeStuffImpl() {}

ReturnCode LifeStuffImpl::InsertUserInput(uint32_t position, char character, InputField input_field) {
  try {
    switch (input_field) {
      case kKeyword: {
        if (!keyword_)
          keyword_.reset(new Keyword());
        keyword_->Insert(position, character);
        return kSuccess;
      }
      case kPin: {
        if (!pin_)
          pin_.reset(new Pin());
        pin_->Insert(position, character);
        return kSuccess;
      }
      case kPassword: {
        if (!password_)
          password_.reset(new Password());
        password_->Insert(position, character);
        return kSuccess;
      }
      case kConfirmationKeyword: {
        if (!confirmation_keyword_)
          confirmation_keyword_.reset(new Keyword());
        confirmation_keyword_->Insert(position, character);
        return kSuccess;
      }
      case kConfirmationPin: {
        if (!confirmation_pin_)
          confirmation_pin_.reset(new Pin());
        confirmation_pin_->Insert(position, character);
        return kSuccess;
      }
      case kConfirmationPassword: {
        if (!confirmation_password_)
          confirmation_password_.reset(new Password());
        confirmation_password_->Insert(position, character);
        return kSuccess;
      }
      case kCurrentPassword: {
        if (!current_password_)
          current_password_.reset(new Password());
        current_password_->Insert(position, character);
        return kSuccess;
      }
      default:
        return kUnknownError;
    }
  }
  catch(...) {
    return kFail;
  }
}

ReturnCode LifeStuffImpl::RemoveUserInput(uint32_t position, uint32_t length, InputField input_field) {
  try {
    switch (input_field) {
      case kKeyword: {
        if (!keyword_)
          return kFail;
        keyword_->Remove(position, length);
        return kSuccess;
      }
      case kPin: {
        if (!pin_)
          return kFail;
        pin_->Remove(position, length);
        return kSuccess;
      }
      case kPassword: {
        if (!password_)
          return kFail;
        password_->Remove(position, length);
        return kSuccess;
      }
      case kConfirmationKeyword: {
        if (!confirmation_keyword_)
          return kFail;
        confirmation_keyword_->Remove(position, length);
        return kSuccess;
      }
      case kConfirmationPin: {
        if (!confirmation_pin_)
          return kFail;
        confirmation_pin_->Remove(position, length);
        return kSuccess;
      }
      case kConfirmationPassword: {
        if (!confirmation_password_)
          return kFail;
        confirmation_password_->Remove(position, length);
        return kSuccess;
      }
      case kCurrentPassword: {
        if (!current_password_)
          return kFail;
        current_password_->Remove(position, length);
        return kSuccess;
      }
      default:
        return kUnknownError;
    }
  }
  catch(...) {
    return kFail;
  }
}

ReturnCode LifeStuffImpl::ClearUserInput(InputField input_field) {
  try {
    switch (input_field) {
      case kKeyword: {
        if (keyword_)
          keyword_->Clear();
        return kSuccess;
      }
      case kPin: {
        if (pin_)
          pin_->Clear();
        return kSuccess;
      }
      case kPassword: {
        if (password_)
          password_->Clear();
        return kSuccess;
      }
      case kConfirmationKeyword: {
        if (confirmation_keyword_)
          confirmation_keyword_->Clear();
        return kSuccess;
      }
      case kConfirmationPin: {
        if (confirmation_pin_)
          confirmation_pin_->Clear();
        return kSuccess;
      }
      case kConfirmationPassword: {
        if (confirmation_password_)
          confirmation_password_->Clear();
        return kSuccess;
      }
      case kCurrentPassword: {
        if (current_password_)
          current_password_->Clear();
        return kSuccess;
      }
      default:
        return kUnknownError;
    }
  }
  catch(...) {
    return kFail;
  }
}

bool LifeStuffImpl::ConfirmUserInput(InputField input_field) {
  switch (input_field) {
    case kConfirmationKeyword: {
      if (!keyword_ || !confirmation_keyword_)
        return false;
      if (!keyword_->IsFinalised())
        keyword_->Finalise();
      if (!confirmation_keyword_->IsFinalised())
        confirmation_keyword_->Finalise();
      if (keyword_->string() != confirmation_keyword_->string()) {
        return false;
      }
      return true;
    }
    case kConfirmationPin: {
      if (!pin_ || !confirmation_pin_)
        return false;
      if (!pin_->IsFinalised())
        pin_->Finalise();
      if (!confirmation_pin_->IsFinalised())
        confirmation_pin_->Finalise();
      if (pin_->string() != confirmation_pin_->string()) {
        return false;
      }
      return true;
    }
    case kConfirmationPassword: {
      if (!password_ || !confirmation_password_)
        return false;
      if (!password_->IsFinalised())
        password_->Finalise();
      if (!confirmation_password_->IsFinalised())
        confirmation_password_->Finalise();
      if (password_->string() != confirmation_password_->string()) {
        return false;
      }
      return true;
    }
    case kKeyword: {
      if (!keyword_)
        return false;
      return keyword_->IsValid(boost::regex(kCharRegex));
    }
    case kPin: {
      if (!pin_)
        return false;
      return pin_->IsValid(boost::regex(kDigitRegex));
    }
    case kPassword: {
      if (!password_)
        return false;
      return password_->IsValid(boost::regex(kCharRegex));
    }
    case kCurrentPassword: {
      if (!current_password_)
        return false;
      if (!current_password_->IsFinalised())
        current_password_->Finalise();
      if (password_) {
        password_->Finalise();
        if (!confirmation_password_)
          return false;
        confirmation_password_->Finalise();
        if (password_->string() != confirmation_password_->string()
            || session_.password().string() != current_password_->string())
          return false;
      } else {
        if (session_.password().string() != current_password_->string())
          return false;
      }
      return true;
    }
    default:
      return false;
  }
}

ReturnCode LifeStuffImpl::CreateUser(const boost::filesystem::path& vault_path,
                                     ReportProgressFunction& report_progress) {
  ReturnCode result(FinaliseUserInput());
  if (result != kSuccess)
    return result;
  ResetConfirmationInput();
  result = client_maid_.CreateUser(*keyword_, *pin_, *password_, vault_path, report_progress);
  if (result != kSuccess)
    return result;
  try {
    session_.set_keyword_pin_password(*keyword_, *pin_, *password_);
  }
  catch(...) {
    return kFail;
  }
  ResetInput();
  logged_in_ = true;
  return kSuccess;
}

ReturnCode LifeStuffImpl::LogIn(ReportProgressFunction& report_progress) {
  ReturnCode result(FinaliseUserInput());
  if (result != kSuccess)
    return result;
  result = client_maid_.LogIn(*keyword_, *pin_, *password_, report_progress);

  if (result != kSuccess) {
    ResetInput();
    return result;
  }
  try {
    session_.set_keyword_pin_password(*keyword_, *pin_, *password_);
  }
  catch(...) {
    return kFail;
  }
  ResetInput();
  logged_in_ = true;
  return kSuccess;
}

ReturnCode LifeStuffImpl::LogOut() {
  return client_maid_.LogOut();
}

ReturnCode LifeStuffImpl::MountDrive() {
  return client_maid_.MountDrive();
}

ReturnCode LifeStuffImpl::UnMountDrive() {
  return client_maid_.UnMountDrive();
}

ReturnCode LifeStuffImpl::ChangeKeyword() {
  try {
    if (!ConfirmUserInput(kCurrentPassword))
      return kFail;
    client_maid_.ChangeKeyword(session_.keyword(), *keyword_, session_.pin(), session_.password());
    session_.set_keyword(*keyword_);
    keyword_.reset();
    confirmation_keyword_.reset();
    current_password_.reset();
  }
  catch(...) {
    return kFail;
  }
  return kSuccess;
}

ReturnCode LifeStuffImpl::ChangePin() {
  try {
    if (!ConfirmUserInput(kCurrentPassword))
      return kFail;
    client_maid_.ChangePin(session_.keyword(), session_.pin(), *pin_, session_.password());
    session_.set_pin(*pin_);
    pin_.reset();
    confirmation_pin_.reset();
    current_password_.reset();
  }
  catch(...) {
    return kFail;
  }
  return kSuccess;
}

ReturnCode LifeStuffImpl::ChangePassword() {
  try {
    if (!ConfirmUserInput(kCurrentPassword))
      return kFail;
    client_maid_.ChangePassword(session_.keyword(), session_.pin(), *password_);
    session_.set_password(*password_);
    password_.reset();
    confirmation_password_.reset();
    current_password_.reset();
  }
  catch(...) {
    return kFail;
  }
  return kSuccess;
}

bool LifeStuffImpl::logged_in() const {
  return logged_in_;
}

boost::filesystem::path LifeStuffImpl::mount_path() {
  return client_maid_.mount_path();
}

boost::filesystem::path LifeStuffImpl::owner_path() {
  return client_maid_.owner_path();
}

ReturnCode LifeStuffImpl::FinaliseUserInput() {
  try { keyword_->Finalise(); } catch(...) { return kFail; }
  try { pin_->Finalise(); } catch(...) { return kFail; }
  try { password_->Finalise(); } catch(...) { return kFail; }
  return kSuccess;
}

void LifeStuffImpl::ResetInput() {
  keyword_.reset();
  pin_.reset();
  password_.reset();
}

void LifeStuffImpl::ResetConfirmationInput() {
  confirmation_keyword_.reset();
  confirmation_pin_.reset();
  confirmation_password_.reset();
}

}  // namespace lifestuff
}  // namespace maidsafe
