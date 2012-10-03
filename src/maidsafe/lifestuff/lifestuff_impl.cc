/*
* ============================================================================
*
* Copyright [2012] maidsafe.net limited
*
* Description:  Definition of system-wide constants/enums/structs
* Version:      1.0
* Created:      2012-03-27
* Revision:     none
* Compiler:     gcc
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include "maidsafe/lifestuff/lifestuff_impl.h"

#include <algorithm>
#include <functional>
#include <future>
#include <utility>
#include <vector>

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/rcs_helper.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/message_handler.h"
#include "maidsafe/lifestuff/detail/public_id.h"
#include "maidsafe/lifestuff/detail/routings_handler.h"
#include "maidsafe/lifestuff/detail/user_credentials.h"
#include "maidsafe/lifestuff/detail/user_storage.h"

namespace args = std::placeholders;

namespace maidsafe {

namespace lifestuff {

const int kRetryLimit(10);

LifeStuffImpl::LifeStuffImpl()
    : thread_count_(kThreads),
      buffered_path_(),
      simulation_path_(),
      interval_(kSecondsInterval),
      asio_service_(thread_count_),
      remote_chunk_store_(),
      client_controller_(),
      client_node_(),
      routings_handler_(),
      vault_node_(),
      network_health_signal_(),
      session_(),
      user_credentials_(),
      user_storage_(),
      public_id_(),
      message_handler_(),
      slots_(),
      state_(kZeroth),
      logged_in_state_(kBaseState),
      immediate_quit_required_signal_(),
      vault_cheat_(false) {}

LifeStuffImpl::~LifeStuffImpl() {}

int LifeStuffImpl::Initialise(const UpdateAvailableFunction& software_update_available_function,
                              const fs::path& base_directory,
                              bool vault_cheat) {
  if (state_ != kZeroth) {
    LOG(kError) << "Make sure that object is in the original Zeroth state. Asimov rules.";
    return kWrongState;
  }

  if (!software_update_available_function) {
    LOG(kError) << "No function provided for SW update. Unacceptable. Good day!";
    return kInitialiseUpdateFunctionFailure;
  }

  // Initialisation
  asio_service_.Start();

  fs::path base_path, buffered_chunk_store_path, network_simulation_path;
  if (base_directory.empty()) {
    // Not a test: everything in $HOME/.lifestuff
    base_path = GetHomeDir() / kAppHomeDirectory;
    buffered_chunk_store_path = base_path / RandomAlphaNumericString(16);
    boost::system::error_code error_code;
    network_simulation_path = fs::temp_directory_path(error_code) / "lifestuff_simulation";
  } else {
    // Presumably a test
    base_path = base_directory;
    buffered_chunk_store_path = base_path / RandomAlphaNumericString(16);
    network_simulation_path = base_path / "simulated_network";
  }

  std::vector<std::pair<std::string, uint16_t>> bootstrap_endpoints;
  if (!vault_cheat) {
    int counter(0);
    while (counter++ < kRetryLimit) {
      Sleep(bptime::milliseconds(100 + RandomUint32() % 1000));
      client_controller_.reset(
          new priv::process_management::ClientController(software_update_available_function));
      if (client_controller_->BootstrapEndpoints(bootstrap_endpoints) &&
          !bootstrap_endpoints.empty())
        counter = kRetryLimit;
      else
        LOG(kWarning) << "Failure to initialise client controller. Try #" << counter;
    }
    if (bootstrap_endpoints.empty()) {
      LOG(kWarning) << "Failure to initialise client controller. No bootstrap contacts.";
      return kInitialiseBootstrapsFailure;
    }
  }


  remote_chunk_store_ = BuildChunkStore(buffered_chunk_store_path,
                                        bootstrap_endpoints,
                                        client_node_,
                                        [&] (const int& health) { NetworkHealthSlot(health); });
  if (!remote_chunk_store_) {
    LOG(kError) << "Could not initialise chunk store.";
    return kInitialiseChunkStoreFailure;
  }

  buffered_path_ = buffered_chunk_store_path;

  routings_handler_ = std::make_shared<RoutingsHandler>(
                          *remote_chunk_store_,
                          session_,
                          [&] (const std::string& message, std::string& response) {
                            return HandleRoutingsHandlerMessage(message, response);
                          });
  user_credentials_ = std::make_shared<UserCredentials>(*remote_chunk_store_,
                                                        session_,
                                                        asio_service_.service(),
                                                        *routings_handler_);

  state_ = kInitialised;
  vault_cheat_ = vault_cheat;

  return kSuccess;
}

int LifeStuffImpl::ConnectToSignals(
    const bool& set_slots,
    const ChatFunction& chat_slot,
    const FileTransferFunction& file_slot,
    const NewContactFunction& new_contact_slot,
    const ContactConfirmationFunction& confirmed_contact_slot,
    const ContactProfilePictureFunction& profile_picture_slot,
    const ContactPresenceFunction& contact_presence_slot,
    const ContactDeletionFunction& contact_deletion_function,
    const LifestuffCardUpdateFunction& lifestuff_card_update_function,
    const NetworkHealthFunction& network_health_function,
    const ImmediateQuitRequiredFunction& immediate_quit_required_function) {
  if (state_ != kInitialised) {
    LOG(kError) << "Make sure that object is initialised";
    return kWrongState;
  }

  if (set_slots) {
    uint32_t connects(0);
    if (chat_slot) {
      ++connects;
      slots_.chat_slot = chat_slot;
    }
    if (file_slot) {
      ++connects;
      slots_.file_slot = file_slot;
    }
    if (new_contact_slot) {
      ++connects;
      slots_.new_contact_slot = new_contact_slot;
    }
    if (confirmed_contact_slot) {
      ++connects;
      slots_.confirmed_contact_slot = confirmed_contact_slot;
    }
    if (profile_picture_slot) {
      ++connects;
      slots_.profile_picture_slot = profile_picture_slot;
    }
    if (contact_presence_slot) {
      ++connects;
      slots_.contact_presence_slot = contact_presence_slot;
    }
    if (contact_deletion_function) {
      ++connects;
      slots_.contact_deletion_function = contact_deletion_function;
    }
    if (lifestuff_card_update_function) {
      ++connects;
      slots_.lifestuff_card_update_function = lifestuff_card_update_function;
    }
    if (network_health_function) {
      ++connects;
      slots_.network_health_function = network_health_function;
    }
    if (immediate_quit_required_function) {
      ++connects;
      slots_.immediate_quit_required_function = immediate_quit_required_function;
    }
    if (connects == 0) {
      LOG(kError) << "No signals connected.";
      return kSetSlotsFailure;
    }
    state_ = kConnected;
    return kSuccess;
  }

  if (!message_handler_ || !public_id_ || !user_storage_) {
    LOG(kError) << "Unable to connect to signals.";
    return kConnectSignalsFailure;
  }

  message_handler_->ConnectToChatSignal(chat_slot);
  message_handler_->ConnectToFileTransferSignal(file_slot);
  public_id_->ConnectToNewContactSignal(new_contact_slot);
  public_id_->ConnectToContactConfirmedSignal(confirmed_contact_slot);
  message_handler_->ConnectToContactProfilePictureSignal(profile_picture_slot);
  message_handler_->ConnectToContactPresenceSignal(contact_presence_slot);
  public_id_->ConnectToContactDeletionProcessedSignal(contact_deletion_function);
  public_id_->ConnectToLifestuffCardUpdatedSignal(lifestuff_card_update_function);
  immediate_quit_required_signal_.connect(immediate_quit_required_function);
  public_id_->ConnectToContactDeletionReceivedSignal([&] (const std::string& own_public_id,
                                                          const std::string& contact_public_id,
                                                          const std::string& removal_message,
                                                          const std::string& timestamp) {
                                                       int result(RemoveContact(own_public_id,
                                                                                contact_public_id,
                                                                                removal_message,
                                                                                timestamp,
                                                                                false));
                                                       if (result != kSuccess)
                                                         LOG(kError) << "Failed to remove contact "
                                                                        "after receiving contact "
                                                                        "deletion signal!";
                                                     });
  return kSuccess;
}

int LifeStuffImpl::Finalise() {
  if (state_ != kConnected) {
    LOG(kError) << "Need to be connected to finalise.";
    return kWrongState;
  }

  boost::system::error_code error_code;
  fs::remove_all(buffered_path_, error_code);
  if (error_code)
    LOG(kWarning) << "Failed to remove buffered chunk store path.";

  asio_service_.Stop();
//  remote_chunk_store_.reset();
//  node_.reset();
//  message_handler_.reset();
//  public_id_.reset();
//  user_credentials_.reset();
//  user_storage_.reset();
  state_ = kZeroth;

  return kSuccess;
}

/// Credential operations
int LifeStuffImpl::CreateUser(const std::string& keyword,
                              const std::string& pin,
                              const std::string& password,
                              const fs::path& chunk_store) {
  if (state_ != kConnected) {
    LOG(kError) << "Make sure that object is initialised and connected";
    return kWrongState;
  }

  if ((kCredentialsLoggedIn & logged_in_state_) == kCredentialsLoggedIn ||
      (kDriveMounted & logged_in_state_) == kDriveMounted ||
      (kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted) {
    LOG(kError) << "In unsuitable state to create user: " <<
                   "make sure user_credentials are logged out, the drive is unmounted and " <<
                   "messages and intros have been stopped.";
    return kWrongLoggedInState;
  }
  session_.Reset();

  int result(user_credentials_->CreateUser(keyword, pin, password));
  if (result != kSuccess) {
    if (result == kKeywordSizeInvalid || result == kKeywordPatternInvalid ||
        result == kPinSizeInvalid || result == kPinPatternInvalid ||
        result == kPasswordSizeInvalid || result == kPasswordPatternInvalid) {
      return result;
    } else {
      LOG(kError) << "Failed to Create User with result: " << result;
      return result;
    }
  }

  result = CreateVaultInLocalMachine(chunk_store);
  if (result != kSuccess)  {
    LOG(kError) << "Failed to create vault. No LifeStuff for you! (Result: " << result << ")";
    return result;
  }

  result = SetValidPmidAndInitialisePublicComponents();
  if (result != kSuccess)  {
    LOG(kError) << "Failed to set valid PMID with result: " << result;
    return result;
  }

  routings_handler_ = std::make_shared<RoutingsHandler>(*remote_chunk_store_,
                                                        session_,
                                                        ValidatedMessageFunction());

  state_ = kLoggedIn;
  logged_in_state_ = kCreating | kCredentialsLoggedIn;

  return kSuccess;
}

int LifeStuffImpl::CreatePublicId(const std::string& public_id) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  // Check if it's the 1st one
  bool first_public_id(false);
  if (session_.PublicIdentities().empty())
    first_public_id = true;

  result = public_id_->CreatePublicId(public_id, true);
  if (result != kSuccess) {
    if (result == kPublicIdEmpty ||
        result == kPublicIdLengthInvalid ||
        result == kPublicIdEndSpaceInvalid ||
        result == kPublicIdDoubleSpaceInvalid) {
      return result;
    } else {
      LOG(kError) << "Failed to create public ID with result: " << result;
      return result;
    }
  }

  if (first_public_id) {
    public_id_->StartUp(interval_);
    message_handler_->StartUp(interval_);
    if ((logged_in_state_ & kMessagesAndIntrosStarted) != kMessagesAndIntrosStarted) {
      logged_in_state_ = logged_in_state_ ^ kMessagesAndIntrosStarted;
    }
  }

  session_.set_changed(true);

  return kSuccess;
}

int LifeStuffImpl::LogIn(const std::string& keyword,
                         const std::string& pin,
                         const std::string& password) {
  if (state_ != kConnected) {
    LOG(kError) << "Make sure that object is initialised and connected";
    return kWrongState;
  }

  if ((kCredentialsLoggedIn & logged_in_state_) == kCredentialsLoggedIn ||
      (kDriveMounted & logged_in_state_) == kDriveMounted ||
      (kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted) {
    LOG(kError) << "In unsuitable state to log in: " <<
                   "make sure user_credentials are logged out, the drive is unmounted and " <<
                   "messages and intros have been stopped.";
    return kWrongLoggedInState;
  }
  session_.Reset();

  int login_result(user_credentials_->LogIn(keyword, pin, password));
  if (login_result != kSuccess) {
    if (login_result == kKeywordSizeInvalid ||
        login_result == kKeywordPatternInvalid ||
        login_result == kPinSizeInvalid ||
        login_result == kPinPatternInvalid ||
        login_result == kPasswordSizeInvalid ||
        login_result == kPasswordPatternInvalid ||
        login_result == kLoginUserNonExistence ||
        login_result == kLoginAccountCorrupted ||
        login_result == kLoginSessionNotYetSaved ||
        login_result == kLoginUsingNextToLastSession) {
      return login_result;
    } else {
      LOG(kError) << "LogIn failed with result: " << login_result;
      return login_result;
    }
  }

  int result(SetValidPmidAndInitialisePublicComponents());
  if (result != kSuccess)  {
    LOG(kError) << "Failed to set valid PMID with result: " << result;
    return result;
  }

  state_ = kLoggedIn;
  logged_in_state_ = kCredentialsLoggedIn;

  return login_result;
}

int LifeStuffImpl::LogOut() {
  if (state_ != kLoggedIn) {
    LOG(kError) << "Should be logged in to log out.";
    return kWrongState;
  }
  if ((kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted ||
      (kDriveMounted & logged_in_state_) == kDriveMounted) {
    LOG(kError) << "In incorrect state to log out. " <<
                   "Make sure messages and intros have been stopped and drive has been unmounted.";
    return kWrongLoggedInState;
  }
  if ((kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn) {
    LOG(kError) << "In incorrect state to log out. " <<
                   "Make user credentials are logged in first.";
    return kWrongLoggedInState;
  }

  int result(user_credentials_->Logout());
  if (result != kSuccess) {
    LOG(kError) << "Failed to log out with result " << result;
    return kLogoutCredentialsFailure;
  }

  if (!remote_chunk_store_->WaitForCompletion()) {
    LOG(kError) << "Failed complete chunk operations.";
    return kLogoutCompleteChunkFailure;
  }

  session_.Reset();

  state_ = kConnected;
  logged_in_state_ = kBaseState;

  return kSuccess;
}

int LifeStuffImpl::CreateAndMountDrive() {
  if ((kCreating & logged_in_state_) != kCreating ||
      (kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn ||
      (kDriveMounted & logged_in_state_) == kDriveMounted) {
    LOG(kError) << "In unsuitable state to create and mount drive: " <<
                   "make sure a CreateUser has just been run and drive is not already mounted.";
    return kWrongLoggedInState;
  }

  boost::system::error_code error_code;
  fs::path mount_dir(GetHomeDir() / kAppHomeDirectory / session_.session_name());
  if (!fs::exists(mount_dir, error_code)) {
    fs::create_directories(mount_dir, error_code);
    if (error_code) {
      LOG(kError) << "Failed to create app directories - " << error_code.value()
                  << ": " << error_code.message();
      return kCreateDirectoryError;
    }
  }

  user_storage_->MountDrive(mount_dir, &session_, true, false);
  if (!user_storage_->mount_status()) {
    LOG(kError) << "Failed to mount";
    return kMountDriveOnCreationError;
  }

  fs::path mount_path(user_storage_->mount_dir());
  fs::create_directories(mount_path / kMyStuff / kDownloadStuff, error_code);
  if (error_code) {
    LOG(kError) << "Failed creating My Stuff: " << error_code.message();
    user_storage_->UnMountDrive();
    return kCreateMyStuffError;
  }

  logged_in_state_ = logged_in_state_ ^ kDriveMounted;
  return kSuccess;
}

int LifeStuffImpl::MountDrive() {
  if ((kCreating & logged_in_state_) == kCreating ||
      (kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn ||
      (kDriveMounted & logged_in_state_) == kDriveMounted) {
    LOG(kError) << "In unsuitable state to mount drive: "
                << "make sure LogIn has been run and drive is not already mounted.";
    return kWrongLoggedInState;
  }

  // TODO(Alison) - give error codes proper names
  boost::system::error_code error_code;
  fs::path mount_dir(GetHomeDir() / kAppHomeDirectory / session_.session_name());
  if (!fs::exists(mount_dir, error_code)) {
    if (error_code) {
      if (error_code.value() == boost::system::errc::not_connected) {
        LOG(kError) << "\tHint: Try unmounting the drive manually.";
        return kMountDriveTryManualUnMount;
      } else if (error_code != boost::system::errc::no_such_file_or_directory) {
        if (!fs::create_directories(mount_dir, error_code) || error_code) {
          LOG(kError) << "Failed to create mount directory at " << mount_dir.string()
                      << " - " << error_code.value() << ": " << error_code.message();
          return kMountDriveMountPointCreationFailure;
        }
      }
    }
  }

  user_storage_->MountDrive(mount_dir, &session_, false, false);
  if (!user_storage_->mount_status()) {
    LOG(kError) << "Failed to mount";
    return kMountDriveError;
  }

  logged_in_state_ = logged_in_state_ ^ kDriveMounted;
  return kSuccess;
}

int LifeStuffImpl::UnMountDrive() {
  if ((kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn ||
      (kDriveMounted & logged_in_state_) != kDriveMounted ||
      (kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted) {
    LOG(kError) << "In unsuitable state to unmount drive: " <<
                   "make sure user_credentials are logged in, drive is mounted and "
                   "messages and intros have been stopped.";
    return kWrongLoggedInState;
  }

  user_storage_->UnMountDrive();
  if (user_storage_->mount_status()) {
    LOG(kError) << "Failed to un-mount.";
    return kUnMountDriveError;
  }

  // Delete mount directory
  boost::system::error_code error_code;
  fs::remove_all(mount_path(), error_code);
  if (error_code)
    LOG(kWarning) << "Failed to delete mount directory: " << mount_path();

  if ((kDriveMounted & logged_in_state_) == kDriveMounted)
    logged_in_state_ = logged_in_state_ ^ kDriveMounted;
  return kSuccess;
}

int LifeStuffImpl::StartMessagesAndIntros() {
  if ((kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn ||
      (kDriveMounted & logged_in_state_) != kDriveMounted ||
      (kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted) {
     LOG(kError) << "In unsuitable state to start mesages and intros: " <<
                    "make sure user_credentials are logged in, drive is mounted and " <<
                    "messages/intros have not been started already.";
     return kWrongLoggedInState;
  }
  if (session_.session_access_level() != kFullAccess) {
    LOG(kError) << "Shouldn't check for messages/intros when session access level is " <<
                   session_.session_access_level();
    return kWrongAccessLevel;
  }
  if (session_.PublicIdentities().empty()) {
    LOG(kInfo) << "Won't check for messages/intros because there is no public ID.";
    return kStartMessagesAndContactsNoPublicIds;
  }

  public_id_->StartUp(interval_);
  message_handler_->StartUp(interval_);
  if ((kMessagesAndIntrosStarted & logged_in_state_) != kMessagesAndIntrosStarted)
    logged_in_state_ = logged_in_state_ ^ kMessagesAndIntrosStarted;
  return kSuccess;
}

int LifeStuffImpl::StopMessagesAndIntros() {
  if ((kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn ||
      (kDriveMounted & logged_in_state_) != kDriveMounted) {
     LOG(kError) << "In unsuitable state to stop messages and intros: " <<
                    "make sure user_credentials are logged in and drive is mounted.";
     return kWrongLoggedInState;
  }

  public_id_->ShutDown();
  message_handler_->ShutDown();
  if ((kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted)
    logged_in_state_ = logged_in_state_ ^ kMessagesAndIntrosStarted;
  return kSuccess;
}

int LifeStuffImpl::CheckPassword(const std::string& password) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  return session_.password() == password ? kSuccess : kCheckPasswordFailure;
}

int LifeStuffImpl::ChangeKeyword(const std::string& new_keyword, const std::string& password) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  result = CheckPassword(password);
  if (result != kSuccess) {
    LOG(kError) << "Password verification failed.";
    return result;
  }

  if (new_keyword.compare(session_.keyword()) == 0) {
    LOG(kInfo) << "Same value for old and new.";
    return kSuccess;
  }

  result = user_credentials_->ChangeKeyword(new_keyword);
  if (result == kSuccess || result == kKeywordSizeInvalid || result == kKeywordPatternInvalid) {
    return result;
  } else {
    LOG(kError) << "Changing Keyword failed with result: " << result;
    return result;
  }
}

int LifeStuffImpl::ChangePin(const std::string& new_pin, const std::string& password) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  result = CheckPassword(password);
  if (result != kSuccess) {
    LOG(kError) << "Password verification failed.";
    return result;
  }

  if (new_pin.compare(session_.pin()) == 0) {
    LOG(kInfo) << "Same value for old and new.";
    return kSuccess;
  }

  result = user_credentials_->ChangePin(new_pin);
  if (result == kSuccess || result == kPinSizeInvalid || result == kPinPatternInvalid) {
    return result;
  } else {
    LOG(kError) << "Changing PIN failed with result: " << result;
    return result;
  }
}

int LifeStuffImpl::ChangePassword(const std::string& new_password,
                                  const std::string& current_password) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  result = CheckPassword(current_password);
  if (result != kSuccess) {
    LOG(kError) << "Password verification failed.";
    return result;
  }

  if (current_password.compare(new_password) == 0) {
    LOG(kInfo) << "Same value for old and new.";
    return kSuccess;
  }

  result = user_credentials_->ChangePassword(new_password);
  if (result == kSuccess || result == kPasswordSizeInvalid || result == kPasswordPatternInvalid) {
    return result;
  } else {
    LOG(kError) << "Changing Password failed with result: " << result;
    return result;
  }
}

int LifeStuffImpl::LeaveLifeStuff() {
  state_ = kZeroth;
  // TODO(Alison) - set logged_in_state_ - to which value?

  // Stop Messaging
  message_handler_->StopCheckingForNewMessages();
  public_id_->StopCheckingForNewContacts();

  // Unmount
  user_storage_->UnMountDrive();

  int result(0);
  std::vector<std::string> public_ids(session_.PublicIdentities());
  // Delete all files

  // Inform everyone of suicide?

  // Delete all public IDs
  std::for_each(public_ids.begin(),
                public_ids.end(),
                [&result, this] (const std::string& public_id) {
                  result += public_id_->DeletePublicId(public_id);
                });

  // Shut down vaults

  // Delete accounts

  // Remove all user credentials
  result = user_credentials_->DeleteUserCredentials();

  return kSuccess;
}

/// Contact operations
int LifeStuffImpl::AddContact(const std::string& my_public_id,
                              const std::string& contact_public_id,
                              const std::string& message) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in AddContact.";
    return result;
  }

  result = public_id_->AddContact(my_public_id, contact_public_id, message);
  if (result != kSuccess) {
    LOG(kError) << "Failed to add contact with result: " << result;
    return result;
  }
  return kSuccess;
}

int LifeStuffImpl::ConfirmContact(const std::string& my_public_id,
                                  const std::string& contact_public_id) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in ConfirmContact.";
    return result;
  }

  result = public_id_->ConfirmContact(my_public_id, contact_public_id);
  if (result != kSuccess) {
    LOG(kError) << "Failed to Confirm Contact with result: " << result;
    return result;
  }

  result = message_handler_->SendPresenceMessage(my_public_id, contact_public_id, kOnline);
  if (result != kSuccess) {
    LOG(kError) << "Failed to send presence message with result: " << result;
    return result;
  }
  return kSuccess;
}

int LifeStuffImpl::DeclineContact(const std::string& my_public_id,
                                  const std::string& contact_public_id) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in DeclineContact.";
    return result;
  }

  result = public_id_->RejectContact(my_public_id, contact_public_id);
  if (result != kSuccess) {
    LOG(kError) << "Failed to decline contact with result: " << result;
    return result;
  }
  return kSuccess;
}

int LifeStuffImpl::RemoveContact(const std::string& my_public_id,
                                 const std::string& contact_public_id,
                                 const std::string& removal_message,
                                 const std::string& timestamp,
                                 const bool& instigator) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in RemoveContact.";
    return result;
  }

  // Remove the contact
  result = public_id_->RemoveContact(my_public_id,
                                     contact_public_id,
                                     removal_message,
                                     timestamp,
                                     instigator);
  if (result != kSuccess) {
    LOG(kError) << "Failed to remove contact with result: " << result;
    return result;
  }
  return kSuccess;
}

int LifeStuffImpl::ChangeProfilePicture(const std::string& my_public_id,
                                        const std::string& profile_picture_contents) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in ChangeProfilePicture.";
    return result;
  }

  if (profile_picture_contents.empty() ||
      profile_picture_contents.size() > kFileRecontructionLimit) {
    LOG(kError) << "Contents of picture inadequate(" << profile_picture_contents.size()
                << "). Good day!";
    return kChangePictureWrongSize;
  }

  // Message construction
  InboxItem message(kContactProfilePicture);
  message.sender_public_id = my_public_id;

  if (profile_picture_contents != kBlankProfilePicture) {
    // Write contents
    fs::path profile_picture_path(mount_path() / std::string(my_public_id +
                                                             "_profile_picture" +
                                                             kHiddenFileExtension));
    result = user_storage_->WriteHiddenFile(profile_picture_path, profile_picture_contents, true);
    if (result != kSuccess) {
      LOG(kError) << "Failed to write profile picture file: " << profile_picture_path <<
                     " with result: " << result;
      return kChangePictureWriteHiddenFileFailure;
    }

    // Get datamap
    std::string data_map;
    std::string reconstructed;
    int count(0), limit(10);
    while (reconstructed != profile_picture_contents && count++ < limit) {
      data_map.clear();
      result = user_storage_->GetHiddenFileDataMap(profile_picture_path, &data_map);
      if ((result != kSuccess || data_map.empty()) && count == limit) {
        LOG(kError) << "Failed obtaining DM of profile picture: " << result << ", file: "
                    << profile_picture_path << " with result " << result;
        return result == kSuccess ? kChangePictureEmptyDataMap : result;
      }

      reconstructed = user_storage_->ConstructFile(data_map);
      Sleep(bptime::milliseconds(500));
    }

    if (reconstructed != profile_picture_contents) {
      LOG(kError) << "Failed to reconstruct profile picture file: " << profile_picture_path
                  << " with result " << result;
      return kChangePictureReconstructionError;
    }

    message.content.push_back(data_map);
  } else {
    message.content.push_back(kBlankProfilePicture);
  }

  // Set in session
  const SocialInfoDetail social_info(session_.social_info(my_public_id));
  if (!social_info.first) {
    LOG(kError) << "User does not hold such public ID: " << my_public_id;
    return kPublicIdNotFoundFailure;
  }

  {
    std::lock_guard<std::mutex> loch(*social_info.first);
    social_info.second->at(kPicture) = message.content[0];
  }
  session_.set_changed(true);
  LOG(kError) << "Session set to changed.";

  // Send to everybody
  message_handler_->SendEveryone(message);

  return kSuccess;
}

std::string LifeStuffImpl::GetOwnProfilePicture(const std::string& my_public_id) {
  // Read contents, put them in a string, give them back. Should not be a file
  // over a certain size (kFileRecontructionLimit).
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in ChangeProfilePicture.";
    return "";
  }

  const SocialInfoDetail social_info(session_.social_info(my_public_id));
  if (!social_info.first) {
    LOG(kError) << "User does not hold such public ID: " << my_public_id;
    return "";
  }

  {
    std::lock_guard<std::mutex> loch(*social_info.first);
    if (social_info.second->at(kPicture) == kBlankProfilePicture) {
      LOG(kInfo) << "Blank picture in session.";
      return "";
    }
  }

  fs::path profile_picture_path(mount_path() / std::string(my_public_id +
                                                           "_profile_picture" +
                                                           kHiddenFileExtension));
  std::string profile_picture_contents;
  if (user_storage_->ReadHiddenFile(profile_picture_path, &profile_picture_contents) != kSuccess ||
      profile_picture_contents.empty()) {
    LOG(kError) << "Failed reading profile picture: " << profile_picture_path;
    return "";
  }

  return profile_picture_contents;
}

std::string LifeStuffImpl::GetContactProfilePicture(const std::string& my_public_id,
                                                    const std::string& contact_public_id) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in GetContactProfilePicture.";
    return "";
  }

  // Look up data map in session.
  const ContactsHandlerPtr contacts_handler(session_.contacts_handler(my_public_id));
  if (!contacts_handler) {
    LOG(kError) << "User does not hold such public ID: " << my_public_id;
    return "";
  }

  Contact contact;
  result = contacts_handler->ContactInfo(contact_public_id, &contact);
  if (result != kSuccess || contact.profile_picture_data_map.empty()) {
    LOG(kError) << "No such contact(" << result << "): " << contact_public_id;
    return "";
  }

  // Might be blank
  if (contact.profile_picture_data_map == kBlankProfilePicture) {
    LOG(kInfo) << "Blank image detected. No reconstruction needed.";
    return kBlankProfilePicture;
  }

  // Read contents, put them in a string, give them back. Should not be
  // over a certain size (kFileRecontructionLimit).
  return user_storage_->ConstructFile(contact.profile_picture_data_map);
}

int LifeStuffImpl::GetLifestuffCard(const std::string& my_public_id,
                                    const std::string& contact_public_id,
                                    SocialInfoMap& social_info) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in GetLifestuffCard.";
    return result;
  }

  result = public_id_->GetLifestuffCard(my_public_id, contact_public_id, social_info);
  if (result != kSuccess) {
    LOG(kError) << "Failed to get LifeStuff card with result " << result;
    return result;
  }
  return kSuccess;
}

int LifeStuffImpl::SetLifestuffCard(const std::string& my_public_id,
                                    const SocialInfoMap& social_info) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  result = public_id_->SetLifestuffCard(my_public_id, social_info);
  if (result != kSuccess) {
    LOG(kError) << "Failed to set LifeStuff card with result " << result;
    return result;
  }
  return kSuccess;
}

ContactMap LifeStuffImpl::GetContacts(const std::string& my_public_id, uint16_t bitwise_status) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in GetContacts.";
    return ContactMap();
  }

  const ContactsHandlerPtr contacts_handler(session_.contacts_handler(my_public_id));
  if (!contacts_handler) {
    LOG(kError) << "User does not hold such public ID: " << my_public_id;
    return ContactMap();
  }

  return contacts_handler->GetContacts(bitwise_status);
}

std::vector<std::string> LifeStuffImpl::PublicIdsList() const {
  int result = CheckStateAndFullAccess();
  if (result != kSuccess)
    return std::vector<std::string>();

  return session_.PublicIdentities();
}

/// Messaging
int LifeStuffImpl::SendChatMessage(const std::string& sender_public_id,
                                   const std::string& receiver_public_id,
                                   const std::string& message) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  if (message.size() > kMaxChatMessageSize) {
    LOG(kError) << "Message too large: " << message.size();
    return kSendMessageSizeFailure;
  }

  InboxItem inbox_item(kChat);
  inbox_item.receiver_public_id = receiver_public_id;
  inbox_item.sender_public_id = sender_public_id;
  inbox_item.content.push_back(message);

  result = message_handler_->Send(inbox_item);
  if (result != kSuccess) {
    LOG(kError) << "Failed to send chat message with result " << result;
    return result;
  }
  return kSuccess;
}

int LifeStuffImpl::SendFile(const std::string& sender_public_id,
                            const std::string& receiver_public_id,
                            const fs::path& absolute_path) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  std::string serialised_datamap;
  result = user_storage_->GetDataMap(absolute_path, &serialised_datamap);
  if (result != kSuccess || serialised_datamap.empty()) {
    LOG(kError) << "Failed to get DM for " << absolute_path << " with result " << result;
    return result;
  }

  InboxItem inbox_item(kFileTransfer);
  inbox_item.receiver_public_id = receiver_public_id;
  inbox_item.sender_public_id = sender_public_id;
  inbox_item.content.push_back(absolute_path.filename().string());
  inbox_item.content.push_back(serialised_datamap);

  result = message_handler_->Send(inbox_item);
  if (result != kSuccess) {
    LOG(kError) << "Failed to send file with result " << result;
    return result;
  }

  return kSuccess;
}

int LifeStuffImpl::AcceptSentFile(const std::string& identifier,
                                  const fs::path& absolute_path,
                                  std::string* file_name) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  if ((absolute_path.empty() && !file_name) || (!absolute_path.empty() && file_name)) {
    LOG(kError) << "Wrong parameters given. absolute_path and file_name are mutually exclusive.";
    return kAcceptFilePathError;
  }


  std::string saved_file_name, serialised_data_map;
  if (!user_storage_->GetSavedDataMap(identifier, &serialised_data_map, &saved_file_name)) {
    LOG(kError) << "Failed to get saved details for identifier " << Base64Substr(identifier);
    return -1;
  }

  if (absolute_path.empty()) {
    fs::path store_path(mount_path() / kMyStuff / kDownloadStuff);
    if (!VerifyOrCreatePath(store_path)) {
      LOG(kError) << "Failed finding and creating: " << store_path;
      return kAcceptFileVerifyCreatePathFailure;
    }
    std::string adequate_name(GetNameInPath(store_path, saved_file_name));
    if (adequate_name.empty()) {
      LOG(kError) << "No name found to work for saving the file.";
      return kAcceptFileNameFailure;
    }
    result = user_storage_->InsertDataMap(store_path / adequate_name, serialised_data_map);

    if (result != kSuccess) {
      LOG(kError) << "Failed inserting DM: " << result;
      return result;
    }
    *file_name = adequate_name;
  } else {
    result = user_storage_->InsertDataMap(absolute_path, serialised_data_map);
    if (result != kSuccess) {
      LOG(kError) << "Failed inserting DM: " << result;
      return result;
    }
  }

  return kSuccess;
}

int LifeStuffImpl::RejectSentFile(const std::string& identifier) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  fs::path hidden_file(mount_path() / std::string(identifier + kHiddenFileExtension));
  result = user_storage_->DeleteHiddenFile(hidden_file);
  if (result != kSuccess) {
    LOG(kError) << "Failed to reject file with result " << result;
    return result;
  }
  return kSuccess;
}

/// Filesystem
int LifeStuffImpl::ReadHiddenFile(const fs::path& absolute_path, std::string* content) const {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  if (!content) {
    LOG(kError) << "Content parameter must be valid.";
    return kReadHiddenFileContentFailure;
  }

  result = user_storage_->ReadHiddenFile(absolute_path, content);
  if (result != kSuccess) {
    LOG(kError) << "Failed to read hidden file with result " << result;
    return result;
  }
  return kSuccess;
}

int LifeStuffImpl::WriteHiddenFile(const fs::path& absolute_path,
                                   const std::string& content,
                                   bool overwrite_existing) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  result = user_storage_->WriteHiddenFile(absolute_path, content, overwrite_existing);
  if (result != kSuccess) {
    LOG(kError) << "Failed to write hidden file with result " << result;
    return result;
  }
  return kSuccess;
}

int LifeStuffImpl::DeleteHiddenFile(const fs::path& absolute_path) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  result = user_storage_->DeleteHiddenFile(absolute_path);
  if (result != kSuccess) {
    LOG(kError) << "Failed to delete hidden file with result " << result;
    return result;
  }
  return kSuccess;
}

int LifeStuffImpl::SearchHiddenFiles(const fs::path& absolute_path,
                                     std::vector<std::string>* results) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  result = user_storage_->SearchHiddenFiles(absolute_path, results);
  if (result != kSuccess) {
    LOG(kError) << "Failed to search hidden files with result " << result;
    return result;
  }
  return kSuccess;
}

///
int LifeStuffImpl::state() const { return state_; }

int LifeStuffImpl::logged_in_state() const { return logged_in_state_; }

fs::path LifeStuffImpl::mount_path() const {
  if (state_ != kLoggedIn) {
    LOG(kError) << "Incorrect state. Should be logged in: " << state_;
    return fs::path();
  }
  if ((kDriveMounted & logged_in_state_) != kDriveMounted) {
    LOG(kError) << "Incorrect logged_in_state_. Drive should be mounted: " << logged_in_state_;
    return fs::path();
  }

  return user_storage_->mount_dir();
}

void LifeStuffImpl::ConnectInternalElements() {
  message_handler_->ConnectToParseAndSaveDataMapSignal(
      [&] (const std::string& file_name,
           const std::string& serialised_data_map,
           std::string* data_map_hash)->bool {
        return user_storage_->ParseAndSaveDataMap(file_name, serialised_data_map, data_map_hash);
      });

  public_id_->ConnectToContactConfirmedSignal(
      [&] (const std::string& own_public_id, const std::string& recipient_public_id,
           const std::string&) {
        message_handler_->InformConfirmedContactOnline(own_public_id, recipient_public_id);
      });
}

int LifeStuffImpl::SetValidPmidAndInitialisePublicComponents() {
  int result(kSuccess);
  result = client_node_->Stop();
  if (result != kSuccess) {
      LOG(kError) << "Failed to stop client container: " << result;
    return result;
  }
  asymm::Keys maid(session_.passport().SignaturePacketDetails(passport::kMaid, true));
  assert(!maid.identity.empty());

  client_node_->set_keys(maid);
  client_node_->set_account_name(maid.identity);
  result = client_node_->Start(buffered_path_ / "buffered_chunk_store");
  if (result != kSuccess) {
      LOG(kError) << "Failed to start client container: " << result;
    return result;
  }

  remote_chunk_store_ = std::make_shared<pcs::RemoteChunkStore>(client_node_->chunk_store(),
                                                                client_node_->chunk_manager(),
                                                                client_node_->chunk_action_authority());

  routings_handler_->set_remote_chunk_store(*remote_chunk_store_);
  user_credentials_->set_remote_chunk_store(*remote_chunk_store_);

  public_id_ = std::make_shared<PublicId>(remote_chunk_store_, session_, asio_service_.service());

  message_handler_ = std::make_shared<MessageHandler>(remote_chunk_store_,
                                                      session_,
                                                      asio_service_.service());

  user_storage_ = std::make_shared<UserStorage>(remote_chunk_store_);

  ConnectInternalElements();
  state_ = kInitialised;

  result = ConnectToSignals(false,
                            slots_.chat_slot,
                            slots_.file_slot,
                            slots_.new_contact_slot,
                            slots_.confirmed_contact_slot,
                            slots_.profile_picture_slot,
                            slots_.contact_presence_slot,
                            slots_.contact_deletion_function,
                            slots_.lifestuff_card_update_function,
                            slots_.network_health_function,
                            slots_.immediate_quit_required_function);
  return result;
}

int LifeStuffImpl::CheckStateAndFullAccess() const {
  if (state_ != kLoggedIn) {
    LOG(kError) << "Incorrect state. Should be logged in: " << state_;
    return kWrongState;
  }

  if ((kDriveMounted & logged_in_state_) != kDriveMounted) {
    LOG(kError) << "Incorrect state. Drive should be mounted: " << logged_in_state_;
    return kWrongLoggedInState;
  }

  SessionAccessLevel session_access_level(session_.session_access_level());
  if (session_access_level != kFullAccess) {
    LOG(kError) << "Insufficient access. Should have full access: " << session_access_level;
    return kWrongAccessLevel;
  }
  return kSuccess;
}

int LifeStuffImpl::PreContactChecksFullAccess(const std::string &my_public_id) {
  int result = CheckStateAndFullAccess();
  if (result != kSuccess)
    return result;

  if (!session_.OwnPublicId(my_public_id)) {
    LOG(kError) << "User does not hold such public ID: " << my_public_id;
    return kPublicIdNotFoundFailure;
  }

  return kSuccess;
}

void LifeStuffImpl::NetworkHealthSlot(const int& index) {
  network_health_signal_(index);
}


int LifeStuffImpl::CreateVaultInLocalMachine(const fs::path& chunk_store) {
  std::string account_name(session_.passport().SignaturePacketDetails(passport::kMaid,
                                                                      true).identity);
  asymm::Keys pmid_keys(session_.passport().SignaturePacketDetails(passport::kPmid, true));
  assert(!account_name.empty());
  assert(!pmid_keys.identity.empty());

  if (vault_cheat_) {
    vault_node_.set_do_backup_state(false);
    vault_node_.set_do_synchronise(true);
    vault_node_.set_do_check_integrity(false);
    vault_node_.set_do_announce_chunks(false);
    std::string account_name(session_.passport().SignaturePacketDetails(passport::kMaid,
                                                                        true).identity);
    LOG(kSuccess) << "Account name for vault " << Base32Substr(account_name);
    vault_node_.set_account_name(account_name);
    vault_node_.set_keys(session_.passport().SignaturePacketDetails(passport::kPmid, true));

    int result(vault_node_.Start(buffered_path_ / ("client_vault" + RandomAlphaNumericString(8))));
    if (result != kSuccess) {
      LOG(kError) << "Failed to create vault through cheat: " << result;
      return kVaultCreationStartFailure;
    }
  } else {
    if (!client_controller_->StartVault(pmid_keys, account_name, chunk_store)) {
      LOG(kError) << "Failed to create vault through client controller.";
      return kVaultCreationStartFailure;
    }
  }

  return kSuccess;
}

bool LifeStuffImpl::HandleRoutingsHandlerMessage(const std::string& message,
                                                 std::string& response) {
  assert(response.empty());
  // Check for message from another instance trying to log in
  OtherInstanceMessage other_instance_message;
  if (other_instance_message.ParseFromString(message)) {
    switch (other_instance_message.message_type()) {
      case 1: return HandleLogoutProceedingsMessage(other_instance_message.serialised_message(),
                                                    response);
      default: break;
    }
  }
  return false;
}

bool LifeStuffImpl::HandleLogoutProceedingsMessage(const std::string& message,
                                                   std::string& response) {
  LogoutProceedings proceedings;
  if (proceedings.ParseFromString(message)) {
    if (proceedings.has_session_requestor()) {
      std::string session_marker(proceedings.session_requestor());
      // Check message is not one we sent out
      if (user_credentials_->IsOwnSessionTerminationMessage(session_marker)) {
        LOG(kInfo) << "It's our own message the has been received. Ignoring...";
        return false;
      }

      proceedings.set_session_acknowledger(session_marker);
      proceedings.clear_session_requestor();

      OtherInstanceMessage other_instance_message;
      other_instance_message.set_message_type(1);
      other_instance_message.set_serialised_message(proceedings.SerializeAsString());
      response = other_instance_message.SerializeAsString();

      // Actions to be done to quit
      std::async(std::launch::async,
                 [&, session_marker] () {
                   asymm::Keys maid(session_.passport().SignaturePacketDetails(passport::kMaid,
                                                                               true));
                   int result(StopMessagesAndIntros());
                   LOG(kInfo) << "StopMessagesAndIntros: " << result;
                   result = UnMountDrive();
                   LOG(kInfo) << "UnMountDrive: " << result;
                   result = LogOut();
                   LOG(kInfo) << "LogOut: " << result;

                   LogoutProceedings proceedings;
                   proceedings.set_session_terminated(session_marker);
                   OtherInstanceMessage other_instance_message;
                   other_instance_message.set_message_type(1);
                   other_instance_message.set_serialised_message(proceedings.SerializeAsString());
                   std::string session_termination(
                       other_instance_message.SerializePartialAsString());
                   assert(routings_handler_->Send(maid.identity,
                                                  maid.identity,
                                                  maid.public_key,
                                                  session_termination,
                                                  nullptr));

                   immediate_quit_required_signal_();
                 });
      return true;
    } else if (proceedings.has_session_terminated()) {
      // Check message is intended for this instance
      if (!user_credentials_->IsOwnSessionTerminationMessage(proceedings.session_terminated())) {
        LOG(kInfo) << "Recieved irrelevant session termination message. Ignoring.";
        return false;
      }
      user_credentials_->LogoutCompletedArrived(proceedings.session_terminated());
      return false;
    }
  }

  return false;
}

}  // namespace lifestuff

}  // namespace maidsafe
