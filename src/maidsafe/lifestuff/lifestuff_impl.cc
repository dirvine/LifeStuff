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

const int kRetryLimit(10);

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
      return keyword_->IsValid(boost::regex(".*"));
    }
    case kPin: {
      if (!pin_)
        return false;
      return pin_->IsValid(boost::regex("\\d"));
    }
    case kPassword: {
      if (!password_)
        return false;
      return password_->IsValid(boost::regex(".*"));
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


// /*
// * ============================================================================
// *
// * Copyright [2012] maidsafe.net limited
// *
// * Description:  Definition of system-wide constants/enums/structs
// * Version:      1.0
// * Created:      2012-03-27
// * Revision:     none
// * Compiler:     gcc
// * Company:      maidsafe.net limited
// *
// * The following source code is property of maidsafe.net limited and is not
// * meant for external use.  The use of this code is governed by the license
// * file LICENSE.TXT found in the root of this directory and also on
// * www.maidsafe.net.
// *
// * You are not free to copy, amend or otherwise use this source code without
// * the explicit written permission of the board of directors of maidsafe.net.
// *
// * ============================================================================
// */
//
// #include "maidsafe/lifestuff/lifestuff_impl.h"
//
// #include <algorithm>
// #include <functional>
// #include <future>
// #include <utility>
// #include <vector>
//
// #include "maidsafe/common/asio_service.h"
// #include "maidsafe/common/log.h"
// #include "maidsafe/common/utils.h"
//
// #include "maidsafe/lifestuff/lifestuff.h"
// #include "maidsafe/lifestuff/rcs_helper.h"
// #include "maidsafe/lifestuff/return_codes.h"
// #include "maidsafe/lifestuff/detail/message_handler.h"
// #include "maidsafe/lifestuff/detail/public_id.h"
// #include "maidsafe/lifestuff/detail/routings_handler.h"
// #include "maidsafe/lifestuff/detail/user_credentials.h"
// #include "maidsafe/lifestuff/detail/user_storage.h"
//
// namespace maidsafe {
//
// namespace lifestuff {
//
// const int kRetryLimit(10);
// const NonEmptyString kDriveLogo("Lifestuff Drive");
//
// void CheckSlots(Slots& slot_functions) {
//  if (!slot_functions.chat_slot)
//    throw std::invalid_argument("missing chat_slot");
//  if (!slot_functions.file_success_slot)
//    throw std::invalid_argument("missing file_success_slot");
//  if (!slot_functions.file_failure_slot)
//    throw std::invalid_argument("missing file_failure_slot");
//  if (!slot_functions.new_contact_slot)
//    throw std::invalid_argument("missing new_contact_slot");
//  if (!slot_functions.confirmed_contact_slot)
//    throw std::invalid_argument("missing confirmed_contact_slot");
//  if (!slot_functions.profile_picture_slot)
//    throw std::invalid_argument("missing profile_picture_slot");
//  if (!slot_functions.contact_presence_slot)
//    throw std::invalid_argument("missing contact_presence_slot");
//  if (!slot_functions.contact_deletion_slot)
//    throw std::invalid_argument("missing contact_deletion_slot");
//  if (!slot_functions.lifestuff_card_update_slot)
//    throw std::invalid_argument("missing lifestuff_card_update_slot");
//  if (!slot_functions.network_health_slot)
//    throw std::invalid_argument("missing network_health_slot");
//  if (!slot_functions.immediate_quit_required_slot)
//    throw std::invalid_argument("missing immediate_quit_required_slot");
//  if (!slot_functions.update_available_slot)
//    throw std::invalid_argument("missing update_available_slot");
//  if (!slot_functions.operation_progress_slot)
//    throw std::invalid_argument("missing operation_progress_slot");
// }
//
// struct LifeStuffImpl::LoggedInComponents {
//  LoggedInComponents(priv::chunk_store::RemoteChunkStore& remote_chunk_store,
//                     Session& session,
//                     boost::asio::io_service& service);
//  PublicId public_id;
//  MessageHandler message_handler;
//  UserStorage storage;
// };
//
// LifeStuffImpl::LoggedInComponents::LoggedInComponents(
//    priv::chunk_store::RemoteChunkStore& remote_chunk_store,
//    Session& session,
//    boost::asio::io_service& service)
//    : public_id(remote_chunk_store, session, service),
//      message_handler(remote_chunk_store, session, service),
//      storage(remote_chunk_store) {}
//
//
// LifeStuffImpl::LifeStuffImpl(const Slots& slot_functions, const fs::path& base_directory)
//    : thread_count_(kThreads),
//      buffered_path_(),
//      interval_(kSecondsInterval),
//      asio_service_(thread_count_),
//      network_health_signal_(),
//      session_(),
//      remote_chunk_store_(),
//      client_controller_(),
//      client_node_(),
//      routings_handler_(),
//      user_credentials_(),
//      logged_in_components_(),
//      slots_(slot_functions),
//      state_(kZeroth),
//      logged_in_state_(kBaseState),
//      immediate_quit_required_signal_(),
//      single_threaded_class_mutex_() {
//  CheckSlots(slots_);
//
//  // Initialisation
//  asio_service_.Start();
//
//  if (base_directory.empty()) {
//    // Not a test: everything in $HOME/.lifestuff
//    buffered_path_ =  GetHomeDir() / kAppHomeDirectory / RandomAlphaNumericString(16);
//  } else {
//    // Presumably a test
//    buffered_path_ = base_directory / RandomAlphaNumericString(16);
//  }
//
//  int counter(0);
//  std::vector<std::pair<std::string, uint16_t>> bootstrap_endpoints;
//  while (counter++ < kRetryLimit) {
//    Sleep(bptime::milliseconds(100 + RandomUint32() % 1000));
//    client_controller_ = std::make_shared<priv::lifestuff_manager::ClientController>(
//                             slots_.update_available_slot);
//    if (client_controller_->BootstrapEndpoints(bootstrap_endpoints)) {
//      counter = kRetryLimit;
//    } else {
//      LOG(kWarning) << "Failure to initialise client controller. Try #" << counter;
//    }
//  }
//
//  session_.set_bootstrap_endpoints(bootstrap_endpoints);
//
//  state_ = kConnected;
// }
//
// LifeStuffImpl::~LifeStuffImpl() {
//  // !!! DO NOT REMOVE TRY/CATCH. This function MUST NOT THROW !!!
//  try {
//    int result(AttemptCleanQuit());
//    if (result != kSuccess) {
//      LOG(kWarning) << "Quitting has failed in one of the clean up tasks: " << result;
//    }
//
//    boost::system::error_code error_code;
//    fs::remove_all(buffered_path_, error_code);
//    if (error_code) {
//      LOG(kWarning) << "Failed to remove buffered chunk store path: " << error_code.message();
//    }
//
//    asio_service_.Stop();
//  }
//  catch(const std::exception& e) {
//    LOG(kWarning) << "AttemptCleanQuit has failed with exception: " << e.what();
//  }
// }
//
// int LifeStuffImpl::AttemptCleanQuit() {
//  if (state_ == kLoggedIn) {
//    int result;
//    if ((kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted) {
//      result = StopMessagesAndIntros();
//      if (result != kSuccess) {
//        LOG(kWarning) << "Should StopMessagesAndIntros, but failed: " << result;
//        return result;
//      }
//    }
//    if ((kDriveMounted & logged_in_state_) == kDriveMounted) {
//      result = UnMountDrive();
//      if (result != kSuccess) {
//        LOG(kWarning) << "Should UnMountDrive, but failed: " << result;
//        return result;
//      }
//    }
//    if ((kCredentialsLoggedIn & logged_in_state_) == kCredentialsLoggedIn) {
//      result = LogOut();
//      if (result != kSuccess) {
//        LOG(kWarning) << "Should log out, but failed: " << result;
//        return result;
//      }
//    }
//  }
//
//  return kSuccess;
// }
//
// int LifeStuffImpl::MakeAnonymousComponents() {
//  try {
//    remote_chunk_store_ = BuildChunkStore(buffered_path_,
//                                          session_.bootstrap_endpoints(),
//                                          client_node_,
//                                          nullptr);
//  }
//  catch(const std::exception& ex) {
//    LOG(kError) << "Could not initialise chunk store: " << ex.what();
//    return kInitialiseChunkStoreFailure;
//  }
//
//  routings_handler_ = std::make_shared<RoutingsHandler>(
//                          *remote_chunk_store_,
//                          session_,
//                          [this] (const NonEmptyString& message, std::string& response) {
//                            return HandleRoutingsHandlerMessage(message, response);
//                          },
//                          asio_service_.service());
//  user_credentials_ = std::make_shared<UserCredentials>(*remote_chunk_store_,
//                                                        session_,
//                                                        asio_service_.service(),
//                                                        *routings_handler_);
//
//  return kSuccess;
// }
//
// void LifeStuffImpl::ConnectToSignals() {
//  logged_in_components_->message_handler.ConnectToChatSignal(slots_.chat_slot);
//  logged_in_components_->message_handler.ConnectToFileTransferSuccessSignal(
//      slots_.file_success_slot);
//  logged_in_components_->message_handler.ConnectToFileTransferFailureSignal(
//      slots_.file_failure_slot);
//  logged_in_components_->public_id.ConnectToNewContactSignal(slots_.new_contact_slot);
//  logged_in_components_->public_id.ConnectToContactConfirmedSignal(slots_.confirmed_contact_slot);
//  logged_in_components_->message_handler.ConnectToContactProfilePictureSignal(
//      slots_.profile_picture_slot);
//  logged_in_components_->message_handler.ConnectToContactPresenceSignal(
//      slots_.contact_presence_slot);
//  logged_in_components_->public_id.ConnectToContactDeletionProcessedSignal(
//      slots_.contact_deletion_slot);
//  logged_in_components_->public_id.ConnectToLifestuffCardUpdatedSignal(
//      slots_.lifestuff_card_update_slot);
//  immediate_quit_required_signal_.connect(slots_.immediate_quit_required_slot);
//  logged_in_components_->public_id.ConnectToContactDeletionReceivedSignal(
//      [&] (const NonEmptyString& own_public_id,
//           const NonEmptyString& contact_public_id,
//           const std::string& removal_message,
//           const NonEmptyString& /*timestamp*/) {
//         int result(RemoveContact(own_public_id, contact_public_id, removal_message, false));
//         if (result != kSuccess) {
//           LOG(kError) << "Failed to remove contact after receiving contact deletion signal!";
//         }
//     });
// }
//
// // Credential operations
// int LifeStuffImpl::CreateUser(const NonEmptyString& keyword,
//                              const NonEmptyString& pin,
//                              const NonEmptyString& password,
//                              const fs::path& chunk_store) {
//  if (state_ != kConnected) {
//    LOG(kError) << "Make sure that object is initialised and connected";
//    return kWrongState;
//  }
//
//  if ((kCredentialsLoggedIn & logged_in_state_) == kCredentialsLoggedIn ||
//      (kDriveMounted & logged_in_state_) == kDriveMounted ||
//      (kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted) {
//    LOG(kError) << "In unsuitable state to create user: " <<
//                   "make sure user_credentials are logged out, the drive is unmounted and " <<
//                   "messages and intros have been stopped.";
//    return kWrongLoggedInState;
//  }
//
//  slots_.operation_progress_slot(Operation::kCreateUser, SubTask::kInitialiseAnonymousComponents);
//  int result(MakeAnonymousComponents());
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to create anonymous components with result: " << result;
//    return result;
//  }
//
//  slots_.operation_progress_slot(Operation::kCreateUser, SubTask::kCreateUserCredentials);
//  result = user_credentials_->CreateUser(keyword, pin, password);
//  if (result != kSuccess) {
//    if (result == kKeywordSizeInvalid || result == kKeywordPatternInvalid ||
//        result == kPinSizeInvalid || result == kPinPatternInvalid ||
//        result == kPasswordSizeInvalid || result == kPasswordPatternInvalid) {
//      return result;
//    } else {
//      LOG(kError) << "Failed to Create User with result: " << result;
//      return result;
//    }
//  } else {
//    LOG(kInfo) << "user_credentials_->CreateUser success.";
//  }
//
//
//  slots_.operation_progress_slot(Operation::kCreateUser, SubTask::kCreateVault);
//  result = CreateVaultInLocalMachine(chunk_store);
//  if (result != kSuccess)  {
//    LOG(kError) << "Failed to create vault. No LifeStuff for you! (Result: " << result << ")";
//    return result;
//  } else {
//    LOG(kInfo) << "CreateVaultInLocalMachine success.";
//  }
//
//  slots_.operation_progress_slot(Operation::kCreateUser, SubTask::kInitialiseClientComponents);
//  result = SetValidPmidAndInitialisePublicComponents();
//  if (result != kSuccess)  {
//    LOG(kError) << "Failed to set valid PMID with result: " << result;
//    return result;
//  } else {
//    LOG(kInfo) << "SetValidPmidAndInitialisePublicComponents success.";
//  }
//
//  state_ = kLoggedIn;
//  logged_in_state_ = kCredentialsLoggedIn;
//
//  return kSuccess;
// }
//
// int LifeStuffImpl::CreatePublicId(const NonEmptyString& public_id) {
//  int result(CheckStateAndFullAccess());
//  if (result != kSuccess)
//    return result;
//
//  // Check if it's the 1st one
//  bool first_public_id(false);
//  if (session_.PublicIdentities().empty())
//    first_public_id = true;
//
//  result = logged_in_components_->public_id.CreatePublicId(public_id, true);
//  if (result != kSuccess) {
//    if (result == kPublicIdEmpty ||
//        result == kPublicIdLengthInvalid ||
//        result == kPublicIdEndSpaceInvalid ||
//        result == kPublicIdDoubleSpaceInvalid) {
//      return result;
//    } else {
//      LOG(kError) << "Failed to create public ID with result: " << result;
//      return result;
//    }
//  }
//
//  if (first_public_id) {
//    logged_in_components_->public_id.StartUp(interval_);
//    logged_in_components_->message_handler.StartUp(interval_);
//    if ((logged_in_state_ & kMessagesAndIntrosStarted) != kMessagesAndIntrosStarted) {
//      logged_in_state_ = logged_in_state_ ^ kMessagesAndIntrosStarted;
//    }
//  }
//
//  session_.set_changed(true);
//  LOG(kSuccess) << "Success creating public ID: " << public_id.string();
//
//  return kSuccess;
// }
//
// int LifeStuffImpl::LogIn(const NonEmptyString& keyword,
//                         const NonEmptyString& pin,
//                         const NonEmptyString& password) {
//  if (state_ != kConnected) {
//    LOG(kError) << "Make sure that object is initialised and connected";
//    return kWrongState;
//  }
//
//  if ((kCredentialsLoggedIn & logged_in_state_) == kCredentialsLoggedIn ||
//      (kDriveMounted & logged_in_state_) == kDriveMounted ||
//      (kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted) {
//    LOG(kError) << "In unsuitable state to log in: " <<
//                   "make sure user_credentials are logged out, the drive is unmounted and " <<
//                   "messages and intros have been stopped.";
//    return kWrongLoggedInState;
//  }
//
//  slots_.operation_progress_slot(Operation::kLogIn, SubTask::kInitialiseAnonymousComponents);
//  int result(MakeAnonymousComponents());
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to create anonymous components with result: " << result;
//    return result;
//  }
//
//  slots_.operation_progress_slot(Operation::kLogIn, SubTask::kRetrieveUserCredentials);
//  int login_result(user_credentials_->LogIn(keyword, pin, password));
//  if (login_result != kSuccess) {
//    if (login_result == kKeywordSizeInvalid ||
//        login_result == kKeywordPatternInvalid ||
//        login_result == kPinSizeInvalid ||
//        login_result == kPinPatternInvalid ||
//        login_result == kPasswordSizeInvalid ||
//        login_result == kPasswordPatternInvalid ||
//        login_result == kLoginUserNonExistence ||
//        login_result == kLoginAccountCorrupted ||
//        login_result == kLoginSessionNotYetSaved ||
//        login_result == kLoginUsingNextToLastSession) {
//      return login_result;
//    } else {
//      LOG(kError) << "LogIn failed with result: " << login_result;
//      return login_result;
//    }
//  }
//
//  slots_.operation_progress_slot(Operation::kLogIn, SubTask::kInitialiseClientComponents);
//  result = SetValidPmidAndInitialisePublicComponents();
//  if (result != kSuccess)  {
//    LOG(kError) << "Failed to set valid PMID with result: " << result;
//    return result;
//  }
//
//  state_ = kLoggedIn;
//  logged_in_state_ = kCredentialsLoggedIn;
//
//  return login_result;
// }
//
// int LifeStuffImpl::LogOut(bool clear_maid_routing) {
//  std::lock_guard<std::mutex> lock(single_threaded_class_mutex_);
//  if (state_ != kLoggedIn) {
//    LOG(kError) << "Should be logged in to log out.";
//    return kWrongState;
//  }
//  if ((kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted ||
//      (kDriveMounted & logged_in_state_) == kDriveMounted) {
//    LOG(kError) << "In incorrect state to log out. " <<
//        "Make sure messages and intros have been stopped and drive has been unmounted.";
//    return kWrongLoggedInState;
//  }
//  if ((kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn) {
//    LOG(kError) << "In incorrect state to log out. Make user credentials are logged in first.";
//    return kWrongLoggedInState;
//  }
//
//  slots_.operation_progress_slot(Operation::kLogOut, SubTask::kStoreUserCredentials);
//  int result(user_credentials_->Logout());
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to log out with result " << result;
//    return kLogoutCredentialsFailure;
//  }
//
//  slots_.operation_progress_slot(Operation::kLogOut, SubTask::kWaitForNetworkOperations);
//  if (!remote_chunk_store_->WaitForCompletion()) {
//    LOG(kError) << "Failed complete chunk operations.";
//    return kLogoutCompleteChunkFailure;
//  }
//
//  slots_.operation_progress_slot(Operation::kLogOut, SubTask::kCleanUp);
//  client_node_->set_on_network_status(nullptr);
//  client_node_->Stop();
//  if (clear_maid_routing) {
//    Identity maid_id(session_.passport().SignaturePacketDetails(passport::kMaid, true).identity);
//    assert(routings_handler_->DeleteRoutingObject(maid_id));
//  }
//
//  state_ = kConnected;
//  logged_in_state_ = kBaseState;
//
//  return kSuccess;
// }
//
// int LifeStuffImpl::MountDrive() {
//  if ((kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn ||
//      (kDriveMounted & logged_in_state_) == kDriveMounted) {
//    LOG(kError) << "In unsuitable state to mount drive: "
//                << "make sure LogIn has been run and drive is not already mounted.";
//    return kWrongLoggedInState;
//  }
//
//  // TODO(Alison) - give error codes proper names
//  boost::system::error_code error_code;
//  fs::path mount_dir(GetHomeDir() / kAppHomeDirectory / session_.session_name().string());
//  if (!fs::exists(mount_dir, error_code)) {
//    if (error_code) {
//      if (error_code.value() == boost::system::errc::not_connected) {
//        LOG(kError) << "\tHint: Try unmounting the drive manually.";
//        return kMountDriveTryManualUnMount;
//      } else if (error_code != boost::system::errc::no_such_file_or_directory) {
//        if (!fs::create_directories(mount_dir, error_code) || error_code) {
//          LOG(kError) << "Failed to create mount directory at " << mount_dir.string()
//                      << " - " << error_code.value() << ": " << error_code.message();
//          return kMountDriveMountPointCreationFailure;
//        }
//      }
//    }
//  }
//
//  logged_in_components_->storage.MountDrive(buffered_path_ / "encryption_drive_chunks",
//                                            mount_dir,
//                                            &session_,
//                                            kDriveLogo);
//  if (!logged_in_components_->storage.mount_status()) {
//    LOG(kError) << "Failed to mount";
//    return kMountDriveError;
//  }
//
//  logged_in_state_ = logged_in_state_ ^ kDriveMounted;
//  return kSuccess;
// }
//
// int LifeStuffImpl::UnMountDrive() {
//  if ((kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn ||
//      (kDriveMounted & logged_in_state_) != kDriveMounted ||
//      (kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted) {
//    LOG(kError) << "In unsuitable state to unmount drive: " <<
//                   "make sure user_credentials are logged in, drive is mounted and "
//                   "messages and intros have been stopped.";
//    return kWrongLoggedInState;
//  }
//
//  logged_in_components_->storage.UnMountDrive();
//  if (logged_in_components_->storage.mount_status()) {
//    LOG(kError) << "Failed to un-mount.";
//    return kUnMountDriveError;
//  }
//
//  // Delete mount directory
//  boost::system::error_code error_code;
//  fs::remove_all(mount_path(), error_code);
//  if (error_code)
//    LOG(kWarning) << "Failed to delete mount directory: " << mount_path();
//
//  if ((kDriveMounted & logged_in_state_) == kDriveMounted)
//    logged_in_state_ = logged_in_state_ ^ kDriveMounted;
//  return kSuccess;
// }
//
// int LifeStuffImpl::StartMessagesAndIntros() {
//  if ((kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn ||
//      (kDriveMounted & logged_in_state_) != kDriveMounted ||
//      (kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted) {
//     LOG(kError) << "In unsuitable state to start mesages and intros: " <<
//                    "make sure user_credentials are logged in, drive is mounted and " <<
//                    "messages/intros have not been started already.";
//     return kWrongLoggedInState;
//  }
//  if (session_.session_access_level() != kFullAccess) {
//    LOG(kError) << "Shouldn't check for messages/intros when session access level is " <<
//                   session_.session_access_level();
//    return kWrongAccessLevel;
//  }
//  if (session_.PublicIdentities().empty()) {
//    LOG(kInfo) << "Won't check for messages/intros because there is no public ID.";
//    return kStartMessagesAndContactsNoPublicIds;
//  }
//
//  logged_in_components_->public_id.StartUp(interval_);
//  logged_in_components_->message_handler.StartUp(interval_);
//  if ((kMessagesAndIntrosStarted & logged_in_state_) != kMessagesAndIntrosStarted)
//    logged_in_state_ = logged_in_state_ ^ kMessagesAndIntrosStarted;
//  return kSuccess;
// }
//
// int LifeStuffImpl::StopMessagesAndIntros() {
//  if ((kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn ||
//      (kDriveMounted & logged_in_state_) != kDriveMounted) {
//     LOG(kError) << "In unsuitable state to stop messages and intros: " <<
//                    "make sure user_credentials are logged in and drive is mounted.";
//     return kWrongLoggedInState;
//  }
//
//  logged_in_components_->public_id.ShutDown();
//  logged_in_components_->message_handler.ShutDown();
//  if ((kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted)
//    logged_in_state_ = logged_in_state_ ^ kMessagesAndIntrosStarted;
//  return kSuccess;
// }
//
// int LifeStuffImpl::CheckPassword(const NonEmptyString& password) {
//  int result(CheckStateAndFullAccess());
//  if (result != kSuccess)
//    return result;
//
//  return session_.password() == password ? kSuccess : kCheckPasswordFailure;
// }
//
// int LifeStuffImpl::ChangeKeyword(const NonEmptyString& new_keyword,
//                                 const NonEmptyString& password) {
//  std::lock_guard<std::mutex> lock(single_threaded_class_mutex_);
//  int result(CheckStateAndFullAccess());
//  if (result != kSuccess)
//    return result;
//
//  result = CheckPassword(password);
//  if (result != kSuccess) {
//    LOG(kError) << "Password verification failed.";
//    return result;
//  }
//
//  if (new_keyword == session_.keyword()) {
//    LOG(kInfo) << "Same value for old and new.";
//    return kSuccess;
//  }
//
//  result = user_credentials_->ChangeKeyword(new_keyword);
//  if (result == kSuccess || result == kKeywordSizeInvalid || result == kKeywordPatternInvalid) {
//    return result;
//  } else {
//    LOG(kError) << "Changing Keyword failed with result: " << result;
//    return result;
//  }
// }
//
// int LifeStuffImpl::ChangePin(const NonEmptyString& new_pin, const NonEmptyString& password) {
//  std::lock_guard<std::mutex> lock(single_threaded_class_mutex_);
//  int result(CheckStateAndFullAccess());
//  if (result != kSuccess)
//    return result;
//
//  result = CheckPassword(password);
//  if (result != kSuccess) {
//    LOG(kError) << "Password verification failed.";
//    return result;
//  }
//
//  if (new_pin == session_.pin()) {
//    LOG(kInfo) << "Same value for old and new.";
//    return kSuccess;
//  }
//
//  result = user_credentials_->ChangePin(new_pin);
//  if (result == kSuccess || result == kPinSizeInvalid || result == kPinPatternInvalid) {
//    return result;
//  } else {
//    LOG(kError) << "Changing PIN failed with result: " << result;
//    return result;
//  }
// }
//
// int LifeStuffImpl::ChangePassword(const NonEmptyString& new_password,
//                                  const NonEmptyString& current_password) {
//  std::lock_guard<std::mutex> lock(single_threaded_class_mutex_);
//  int result(CheckStateAndFullAccess());
//  if (result != kSuccess)
//    return result;
//
//  result = CheckPassword(current_password);
//  if (result != kSuccess) {
//    LOG(kError) << "Password verification failed.";
//    return result;
//  }
//
//  if (current_password == new_password) {
//    LOG(kInfo) << "Same value for old and new.";
//    return kSuccess;
//  }
//
//  result = user_credentials_->ChangePassword(new_password);
//  if (result == kSuccess || result == kPasswordSizeInvalid || result == kPasswordPatternInvalid) {
//    return result;
//  } else {
//    LOG(kError) << "Changing Password failed with result: " << result;
//    return result;
//  }
// }
//
// int LifeStuffImpl::LeaveLifeStuff() {
//  state_ = kZeroth;
//  // TODO(Alison) - set logged_in_state_ - to which value?
//
//  // Stop Messaging
//  logged_in_components_->message_handler.StopCheckingForNewMessages();
//  logged_in_components_->public_id.StopCheckingForNewContacts();
//
//  // Unmount
//  logged_in_components_->storage.UnMountDrive();
//
//  int result(0);
//  std::vector<NonEmptyString> public_ids(session_.PublicIdentities());
//  // Delete all files
//
//  // Inform everyone of suicide?
//
//  // Delete all public IDs
//  std::for_each(public_ids.begin(),
//                public_ids.end(),
//                [&result, this] (const NonEmptyString& public_id) {
//                  result += logged_in_components_->public_id.DeletePublicId(public_id);
//                });
//
//  // Shut down vaults
//
//  // Delete accounts
//
//  // Remove all user credentials
//  result = user_credentials_->DeleteUserCredentials();
//
//  return kSuccess;
// }
//
// // Contact operations
// int LifeStuffImpl::AddContact(const NonEmptyString& my_public_id,
//                              const NonEmptyString& contact_public_id,
//                              const std::string& message) {
//  int result(PreContactChecksFullAccess(my_public_id));
//  if (result != kSuccess) {
//    LOG(kError) << "Failed pre checks in AddContact.";
//    return result;
//  }
//
//  result = logged_in_components_->public_id.AddContact(my_public_id, contact_public_id, message);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to add contact with result: " << result;
//    return result;
//  }
//  return kSuccess;
// }
//
// int LifeStuffImpl::ConfirmContact(const NonEmptyString& my_public_id,
//                                  const NonEmptyString& contact_public_id) {
//  int result(PreContactChecksFullAccess(my_public_id));
//  if (result != kSuccess) {
//    LOG(kError) << "Failed pre checks in ConfirmContact.";
//    return result;
//  }
//
//  result = logged_in_components_->public_id.ConfirmContact(my_public_id, contact_public_id);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to Confirm Contact with result: " << result;
//    return result;
//  }
//
//  result = logged_in_components_->message_handler.SendPresenceMessage(my_public_id,
//                                                                      contact_public_id,
//                                                                      kOnline);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to send presence message with result: " << result;
//    return result;
//  }
//  return kSuccess;
// }
//
// int LifeStuffImpl::DeclineContact(const NonEmptyString& my_public_id,
//                                  const NonEmptyString& contact_public_id) {
//  int result(PreContactChecksFullAccess(my_public_id));
//  if (result != kSuccess) {
//    LOG(kError) << "Failed pre checks in DeclineContact.";
//    return result;
//  }
//
//  result = logged_in_components_->public_id.RejectContact(my_public_id, contact_public_id);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to decline contact with result: " << result;
//    return result;
//  }
//  return kSuccess;
// }
//
// int LifeStuffImpl::RemoveContact(const NonEmptyString& my_public_id,
//                                 const NonEmptyString& contact_public_id,
//                                 const std::string& removal_message,
//                                 const bool& instigator) {
//  int result(PreContactChecksFullAccess(my_public_id));
//  if (result != kSuccess) {
//    LOG(kError) << "Failed pre checks in RemoveContact.";
//    return result;
//  }
//
//  // Remove the contact
//  NonEmptyString timestamp(IsoTimeWithMicroSeconds());
//  result = logged_in_components_->public_id.RemoveContact(my_public_id,
//                                     contact_public_id,
//                                     removal_message,
//                                     timestamp,
//                                     instigator);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to remove contact with result: " << result;
//    return result;
//  }
//  return kSuccess;
// }
//
// int LifeStuffImpl::ChangeProfilePicture(const NonEmptyString& my_public_id,
//                                        const NonEmptyString& profile_picture_contents) {
//  int result(PreContactChecksFullAccess(my_public_id));
//  if (result != kSuccess) {
//    LOG(kError) << "Failed pre checks in ChangeProfilePicture.";
//    return result;
//  }
//
//  if (profile_picture_contents.string().size() > kFileRecontructionLimit) {
//    LOG(kError) << "Contents of picture inadequate(" << profile_picture_contents.string().size()
//                << "). Good day!";
//    return kChangePictureWrongSize;
//  }
//
//  // Message construction
//  InboxItem message(kContactProfilePicture);
//  message.sender_public_id = my_public_id;
//
//  if (profile_picture_contents != kBlankProfilePicture) {
//    // Write contents
//    fs::path profile_picture_path(mount_path() / std::string(my_public_id.string() +
//                                                             "_profile_picture" +
//                                                             kHiddenFileExtension));
//    result = logged_in_components_->storage.WriteHiddenFile(profile_picture_path,
//                                            profile_picture_contents,
//                                            true);
//    if (result != kSuccess) {
//      LOG(kError) << "Failed to write profile picture file: " << profile_picture_path <<
//                     " with result: " << result;
//      return kChangePictureWriteHiddenFileFailure;
//    }
//
//    // Get datamap
//    std::string data_map;
//    std::string reconstructed;
//    int count(0), limit(10);
//    while (reconstructed != profile_picture_contents.string() && count++ < limit) {
//      data_map.clear();
//      result = logged_in_components_->storage.GetHiddenFileDataMap(profile_picture_path,
//                                                                   &data_map);
//      if ((result != kSuccess || data_map.empty()) && count == limit) {
//        LOG(kError) << "Failed obtaining DM of profile picture: " << result << ", file: "
//                    << profile_picture_path << " with result " << result;
//        return result == kSuccess ? kChangePictureEmptyDataMap : result;
//      }
//
//      reconstructed = logged_in_components_->storage.ConstructFile(NonEmptyString(data_map));
//      Sleep(bptime::milliseconds(500));
//    }
//
//    if (reconstructed != profile_picture_contents.string()) {
//      LOG(kError) << "Failed to reconstruct profile picture file: " << profile_picture_path
//                  << " with result " << result;
//      return kChangePictureReconstructionError;
//    }
//
//    message.content.push_back(NonEmptyString(data_map));
//  } else {
//    message.content.push_back(kBlankProfilePicture);
//  }
//
//  // Set in session
//  const SocialInfoDetail social_info(session_.social_info(my_public_id));
//  if (!social_info.first) {
//    LOG(kError) << "User does not hold such public ID: " << my_public_id.string();
//    return kPublicIdNotFoundFailure;
//  }
//
//  {
//    std::lock_guard<std::mutex> lock(*social_info.first);
//    social_info.second->profile_picture_datamap = message.content[0];
//  }
//  session_.set_changed(true);
//  LOG(kError) << "Session set to changed.";
//
//  // Send to everybody
//  logged_in_components_->message_handler.SendEveryone(message);
//
//  return kSuccess;
// }
//
// NonEmptyString LifeStuffImpl::GetOwnProfilePicture(const NonEmptyString& my_public_id) {
//  // Read contents, put them in a string, give them back. Should not be a file
//  // over a certain size (kFileRecontructionLimit).
//  int result(PreContactChecksFullAccess(my_public_id));
//  if (result != kSuccess) {
//    LOG(kError) << "Failed pre checks in ChangeProfilePicture.";
//    return NonEmptyString();
//  }
//
//  const SocialInfoDetail social_info(session_.social_info(my_public_id));
//  if (!social_info.first) {
//    LOG(kError) << "User does not hold such public ID: " << my_public_id.string();
//    return NonEmptyString();
//  }
//
//  {
//    std::lock_guard<std::mutex> lock(*social_info.first);
//    if (social_info.second->profile_picture_datamap == kBlankProfilePicture) {
//      LOG(kInfo) << "Blank picture in session.";
//      return NonEmptyString();
//    }
//  }
//
//  fs::path profile_picture_path(mount_path() / std::string(my_public_id.string() +
//                                                           "_profile_picture" +
//                                                           kHiddenFileExtension));
//  std::string profile_picture_contents;
//  if (logged_in_components_->storage.ReadHiddenFile(profile_picture_path,
//                                                    &profile_picture_contents) != kSuccess ||
//      profile_picture_contents.empty()) {
//    LOG(kError) << "Failed reading profile picture: " << profile_picture_path;
//    return NonEmptyString();
//  }
//
//  return NonEmptyString(profile_picture_contents);
// }
//
// NonEmptyString LifeStuffImpl::GetContactProfilePicture(const NonEmptyString& my_public_id,
//                                                       const NonEmptyString& contact_public_id) {
//  int result(PreContactChecksFullAccess(my_public_id));
//  if (result != kSuccess) {
//    LOG(kError) << "Failed pre checks in GetContactProfilePicture.";
//    return NonEmptyString();
//  }
//
//  // Look up data map in session.
//  const ContactsHandlerPtr contacts_handler(session_.contacts_handler(my_public_id));
//  if (!contacts_handler) {
//    LOG(kError) << "User does not hold such public ID: " << my_public_id.string();
//    return NonEmptyString();
//  }
//
//  Contact contact;
//  result = contacts_handler->ContactInfo(contact_public_id, &contact);
//  if (result != kSuccess) {
//    LOG(kError) << "No such contact(" << result << "): " << contact_public_id.string();
//    return NonEmptyString();
//  }
//
//  // Might be blank
//  if (contact.profile_picture_data_map == kBlankProfilePicture) {
//    LOG(kInfo) << "Blank image detected. No reconstruction needed.";
//    return kBlankProfilePicture;
//  }
//
//  // Read contents, put them in a string, give them back. Should not be
//  // over a certain size (kFileRecontructionLimit).
//  return NonEmptyString(logged_in_components_->storage.ConstructFile(
//                            contact.profile_picture_data_map));
// }
//
// int LifeStuffImpl::GetLifestuffCard(const NonEmptyString& my_public_id,
//                                    const std::string& contact_public_id,
//                                    SocialInfoMap& social_info) {
//  int result(PreContactChecksFullAccess(my_public_id));
//  if (result != kSuccess) {
//    LOG(kError) << "Failed pre checks in GetLifestuffCard.";
//    return result;
//  }
//
//  result = logged_in_components_->public_id.GetLifestuffCard(my_public_id,
//                                                             contact_public_id,
//                                                             social_info);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to get LifeStuff card with result " << result;
//    return result;
//  }
//  return kSuccess;
// }
//
// int LifeStuffImpl::SetLifestuffCard(const NonEmptyString& my_public_id,
//                                    const SocialInfoMap& social_info) {
//  int result(CheckStateAndFullAccess());
//  if (result != kSuccess)
//    return result;
//
//  result = logged_in_components_->public_id.SetLifestuffCard(my_public_id, social_info);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to set LifeStuff card with result " << result;
//    return result;
//  }
//  return kSuccess;
// }
//
// ContactMap LifeStuffImpl::GetContacts(const NonEmptyString& my_public_id,
//                                       uint16_t bitwise_status) {
//  int result(PreContactChecksFullAccess(my_public_id));
//  if (result != kSuccess) {
//    LOG(kError) << "Failed pre checks in GetContacts.";
//    return ContactMap();
//  }
//
//  const ContactsHandlerPtr contacts_handler(session_.contacts_handler(my_public_id));
//  if (!contacts_handler) {
//    LOG(kError) << "User does not hold such public ID: " << my_public_id.string();
//    return ContactMap();
//  }
//
//  return contacts_handler->GetContacts(bitwise_status);
// }
//
// std::vector<NonEmptyString> LifeStuffImpl::PublicIdsList() const {
//  int result = CheckStateAndFullAccess();
//  if (result != kSuccess)
//    return std::vector<NonEmptyString>();
//
//  return session_.PublicIdentities();
// }
//
// // Messaging
// int LifeStuffImpl::SendChatMessage(const NonEmptyString& sender_public_id,
//                                   const NonEmptyString& receiver_public_id,
//                                   const NonEmptyString& message) {
//  int result(CheckStateAndFullAccess());
//  if (result != kSuccess)
//    return result;
//
//  if (message.string().size() > kMaxChatMessageSize) {
//    LOG(kError) << "Message too large: " << message.string().size();
//    return kSendMessageSizeFailure;
//  }
//
//  InboxItem inbox_item(kChat);
//  inbox_item.receiver_public_id = receiver_public_id;
//  inbox_item.sender_public_id = sender_public_id;
//  inbox_item.content.push_back(message);
//
//  result = logged_in_components_->message_handler.Send(inbox_item);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to send chat message with result " << result;
//    return result;
//  }
//  return kSuccess;
// }
//
// int LifeStuffImpl::SendFile(const NonEmptyString& sender_public_id,
//                            const NonEmptyString& receiver_public_id,
//                            const fs::path& absolute_path) {
//  int result(CheckStateAndFullAccess());
//  if (result != kSuccess)
//    return result;
//
//  std::string serialised_datamap;
//  result = logged_in_components_->storage.GetDataMap(absolute_path, &serialised_datamap);
//  if (result != kSuccess || serialised_datamap.empty()) {
//    LOG(kError) << "Failed to get DM for " << absolute_path << " with result " << result;
//    return result;
//  }
//
//  InboxItem inbox_item(kFileTransfer);
//  inbox_item.receiver_public_id = receiver_public_id;
//  inbox_item.sender_public_id = sender_public_id;
//  inbox_item.content.push_back(NonEmptyString(absolute_path.filename().string()));
//  inbox_item.content.push_back(NonEmptyString(serialised_datamap));
//
//  result = logged_in_components_->message_handler.Send(inbox_item);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to send file with result " << result;
//    return result;
//  }
//
//  return kSuccess;
// }
//
// int LifeStuffImpl::AcceptSentFile(const NonEmptyString& identifier,
//                                  const fs::path& absolute_path,
//                                  std::string* file_name) {
//  int result(CheckStateAndFullAccess());
//  if (result != kSuccess)
//    return result;
//
//  if ((absolute_path.empty() && !file_name) || (!absolute_path.empty() && file_name)) {
//    LOG(kError) << "Wrong parameters given. absolute_path and file_name are mutually exclusive.";
//    return kAcceptFilePathError;
//  }
//
//  std::string saved_file_name, serialised_data_map;
//  if (!logged_in_components_->storage.GetSavedDataMap(identifier,
//                                                      serialised_data_map,
//                                                      saved_file_name)) {
//    LOG(kError) << "Failed to get saved details for identifier " << Base64Substr(identifier);
//    return -1;
//  }
//
//  if (absolute_path.empty()) {
//    fs::path store_path(mount_path() / kMyStuff / kDownloadStuff);
//    if (!VerifyOrCreatePath(store_path)) {
//      LOG(kError) << "Failed finding and creating: " << store_path;
//      return kAcceptFileVerifyCreatePathFailure;
//    }
//    std::string adequate_name(GetNameInPath(store_path, saved_file_name));
//    if (adequate_name.empty()) {
//      LOG(kError) << "No name found to work for saving the file.";
//      return kAcceptFileNameFailure;
//    }
//    result = logged_in_components_->storage.InsertDataMap(store_path / adequate_name,
//                                          NonEmptyString(serialised_data_map));
//
//    if (result != kSuccess) {
//      LOG(kError) << "Failed inserting DM: " << result;
//      return result;
//    }
//    *file_name = adequate_name;
//  } else {
//    result = logged_in_components_->storage.InsertDataMap(absolute_path,
//                                                          NonEmptyString(serialised_data_map));
//    if (result != kSuccess) {
//      LOG(kError) << "Failed inserting DM: " << result;
//      return result;
//    }
//  }
//
//  return kSuccess;
// }
//
// int LifeStuffImpl::RejectSentFile(const NonEmptyString& identifier) {
//  int result(CheckStateAndFullAccess());
//  if (result != kSuccess)
//    return result;
//
//  fs::path hidden_file(mount_path() / std::string(identifier.string() + kHiddenFileExtension));
//  result = logged_in_components_->storage.DeleteHiddenFile(hidden_file);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to reject file with result " << result;
//    return result;
//  }
//  return kSuccess;
// }
//
// // Filesystem
// int LifeStuffImpl::ReadHiddenFile(const fs::path& absolute_path, std::string* content) const {
//  int result(CheckStateAndFullAccess());
//  if (result != kSuccess)
//    return result;
//
//  if (!content) {
//    LOG(kError) << "Content parameter must be valid.";
//    return kReadHiddenFileContentFailure;
//  }
//
//  result = logged_in_components_->storage.ReadHiddenFile(absolute_path, content);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to read hidden file with result " << result;
//    return result;
//  }
//  return kSuccess;
// }
//
// int LifeStuffImpl::WriteHiddenFile(const fs::path& absolute_path,
//                                   const NonEmptyString& content,
//                                   bool overwrite_existing) {
//  int result(CheckStateAndFullAccess());
//  if (result != kSuccess)
//    return result;
//
//  result = logged_in_components_->storage.WriteHiddenFile(absolute_path,
//                                                          content,
//                                                          overwrite_existing);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to write hidden file with result " << result;
//    return result;
//  }
//  return kSuccess;
// }
//
// int LifeStuffImpl::DeleteHiddenFile(const fs::path& absolute_path) {
//  int result(CheckStateAndFullAccess());
//  if (result != kSuccess)
//    return result;
//
//  result = logged_in_components_->storage.DeleteHiddenFile(absolute_path);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to delete hidden file with result " << result;
//    return result;
//  }
//  return kSuccess;
// }
//
// int LifeStuffImpl::SearchHiddenFiles(const fs::path& absolute_path,
//                                     std::vector<std::string>* results) {
//  int result(CheckStateAndFullAccess());
//  if (result != kSuccess)
//    return result;
//
//  result = logged_in_components_->storage.SearchHiddenFiles(absolute_path, results);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to search hidden files with result " << result;
//    return result;
//  }
//  return kSuccess;
// }
//
// int LifeStuffImpl::state() const { return state_; }
//
// int LifeStuffImpl::logged_in_state() const { return logged_in_state_; }
//
// fs::path LifeStuffImpl::mount_path() const {
//  if (state_ != kLoggedIn) {
//    LOG(kError) << "Incorrect state. Should be logged in: " << state_;
//    return fs::path();
//  }
//  if ((kDriveMounted & logged_in_state_) != kDriveMounted) {
//    LOG(kError) << "Incorrect logged_in_state_. Drive should be mounted: " << logged_in_state_;
//    return fs::path();
//  }
//
//  return logged_in_components_->storage.mount_dir();
// }
//
// void LifeStuffImpl::ConnectInternalElements() {
//  logged_in_components_->message_handler.ConnectToParseAndSaveDataMapSignal(
//      [this] (const NonEmptyString& file_name,
//              const NonEmptyString& serialised_data_map,
//              std::string& data_map_hash)->bool {
//        return logged_in_components_->storage.ParseAndSaveDataMap(file_name,
//                                                                  serialised_data_map,
//                                                                  data_map_hash);
//      });
//
//  logged_in_components_->public_id.ConnectToContactConfirmedSignal(
//      [this] (const NonEmptyString& own_public_id,
//              const NonEmptyString& recipient_public_id,
//              const NonEmptyString&) {
//        logged_in_components_->message_handler.InformConfirmedContactOnline(own_public_id,
//                                                                            recipient_public_id);
//      });
// }
//
// int LifeStuffImpl::SetValidPmidAndInitialisePublicComponents() {
//  int result(kSuccess);
//  result = client_node_->Stop();
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to stop client container: " << result;
//    return result;
//  }
//  Fob maid(session_.passport().SignaturePacketDetails(passport::kMaid, true));
//
//  std::vector<boost::asio::ip::udp::endpoint> peer_endpoints;
//  for (auto& element : session_.bootstrap_endpoints()) {
//    boost::asio::ip::udp::endpoint endpoint;
//    endpoint.address(boost::asio::ip::address::from_string(element.first));
//    endpoint.port(element.second);
//    peer_endpoints.push_back(endpoint);
//  }
//  client_node_->set_fob(maid);
//  client_node_->set_account_name(maid.identity);
//  result = client_node_->Start(buffered_path_ / "buffered_chunk_store", peer_endpoints);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to start client container: " << result;
//    return result;
//  }
//
//  remote_chunk_store_ =
//      std::make_shared<pcs::RemoteChunkStore>(client_node_->chunk_store(),
//                                              client_node_->chunk_manager(),
//                                              client_node_->chunk_action_authority());
//
//  routings_handler_->set_remote_chunk_store(*remote_chunk_store_);
//  user_credentials_->set_remote_chunk_store(*remote_chunk_store_);
//
//  logged_in_components_ = std::make_shared<LoggedInComponents>(*remote_chunk_store_,
//                                                               session_,
//                                                               asio_service_.service());
//
//  ConnectInternalElements();
//  state_ = kInitialised;
//
//  ConnectToSignals();
//
//  return kSuccess;
// }
//
// int LifeStuffImpl::CheckStateAndFullAccess() const {
//  if (state_ != kLoggedIn) {
//    LOG(kError) << "Incorrect state. Should be logged in: " << state_;
//    return kWrongState;
//  }
//
//  if ((kDriveMounted & logged_in_state_) != kDriveMounted) {
//    LOG(kError) << "Incorrect state. Drive should be mounted: " << logged_in_state_;
//    return kWrongLoggedInState;
//  }
//
//  SessionAccessLevel session_access_level(session_.session_access_level());
//  if (session_access_level != kFullAccess) {
//    LOG(kError) << "Insufficient access. Should have full access: " << session_access_level;
//    return kWrongAccessLevel;
//  }
//  return kSuccess;
// }
//
// int LifeStuffImpl::PreContactChecksFullAccess(const NonEmptyString &my_public_id) {
//  int result = CheckStateAndFullAccess();
//  if (result != kSuccess)
//    return result;
//
//  if (!session_.OwnPublicId(my_public_id)) {
//    LOG(kError) << "User does not hold such public ID: " << my_public_id.string();
//    return kPublicIdNotFoundFailure;
//  }
//
//  return kSuccess;
// }
//
// void LifeStuffImpl::NetworkHealthSlot(const int& index) { network_health_signal_(index); }
//
// int LifeStuffImpl::CreateVaultInLocalMachine(const fs::path& chunk_store) {
//  Identity account_name(session_.passport().SignaturePacketDetails(passport::kMaid,
//                                                                   true).identity);
//  Fob pmid_keys(session_.passport().SignaturePacketDetails(passport::kPmid, true));
//
//  if (!client_controller_->StartVault(pmid_keys, account_name.string(), chunk_store)) {
//    LOG(kError) << "Failed to create vault through client controller.";
//    return kVaultCreationStartFailure;
//  }
//
//  return kSuccess;
// }
//
// bool LifeStuffImpl::HandleRoutingsHandlerMessage(const NonEmptyString& message,
//                                                 std::string& response) {
//  assert(response.empty());
//  // Check for message from another instance trying to log in
//  OtherInstanceMessage other_instance_message;
//  if (other_instance_message.ParseFromString(message.string())) {
//    switch (other_instance_message.message_type()) {
//      case 1: return HandleLogoutProceedingsMessage(
//                         NonEmptyString(other_instance_message.serialised_message()),
//                         response);
//      default: break;
//    }
//  }
//  return false;
// }
//
// bool LifeStuffImpl::HandleLogoutProceedingsMessage(const NonEmptyString& message,
//                                                   std::string& response) {
//  LogoutProceedings proceedings;
//  if (proceedings.ParseFromString(message.string())) {
//    if (proceedings.has_session_requestor()) {
//      std::string session_marker(proceedings.session_requestor());
//      // Check message is not one we sent out
//      if (user_credentials_->IsOwnSessionTerminationMessage(session_marker)) {
//        LOG(kInfo) << "It's our own message that has been received. Ignoring...";
//        return false;
//      }
//
//      proceedings.set_session_acknowledger(session_marker);
//      proceedings.clear_session_requestor();
//
//      OtherInstanceMessage other_instance_message;
//      other_instance_message.set_message_type(1);
//      other_instance_message.set_serialised_message(proceedings.SerializeAsString());
//      response = other_instance_message.SerializeAsString();
//
//      // Actions to be done to quit
//      std::async(std::launch::async,
//                 [&, session_marker] () {
//                   Fob maid(session_.passport().SignaturePacketDetails(passport::kMaid,
//                                                                               true));
//                   int result(StopMessagesAndIntros());
//                   LOG(kInfo) << "StopMessagesAndIntros: " << result;
//                   result = UnMountDrive();
//                   LOG(kInfo) << "UnMountDrive: " << result;
//                   result = LogOut(false);
//                   LOG(kInfo) << "LogOut: " << result;
//
//                   LogoutProceedings proceedings;
//                   proceedings.set_session_terminated(session_marker);
//                   OtherInstanceMessage other_instance_message;
//                   other_instance_message.set_message_type(1);
//                   other_instance_message.set_serialised_message(proceedings.SerializeAsString());
//                   NonEmptyString session_termination(
//                       other_instance_message.SerializePartialAsString());
//                   assert(routings_handler_->Send(maid.identity,
//                                                  maid.identity,
//                                                  maid.keys.public_key,
//                                                  session_termination,
//                                                  nullptr));
//                   routings_handler_->DeleteRoutingObject(
//                     session_.passport().SignaturePacketDetails(passport::kMaid, true).identity);
//
//                   immediate_quit_required_signal_();
//                 });
//      return true;
//    } else if (proceedings.has_session_terminated()) {
//      // Check message is intended for this instance
//      if (!user_credentials_->IsOwnSessionTerminationMessage(proceedings.session_terminated())) {
//        LOG(kInfo) << "Recieved irrelevant session termination message. Ignoring.";
//        return false;
//      }
//      user_credentials_->LogoutCompletedArrived(proceedings.session_terminated());
//      return false;
//    }
//  }
//
//  return false;
// }
//
// }  // namespace lifestuff
//
// }  // namespace maidsafe
