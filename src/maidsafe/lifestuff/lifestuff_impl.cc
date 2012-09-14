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
#include <list>
#include <utility>
#include <vector>

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/data_map.h"

#include "maidsafe/lifestuff/rcs_helper.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/message_handler.h"
#include "maidsafe/lifestuff/detail/public_id.h"
#include "maidsafe/lifestuff/detail/user_credentials.h"
#include "maidsafe/lifestuff/detail/user_storage.h"

namespace args = std::placeholders;

namespace maidsafe {

namespace lifestuff {

const int kRetryLimit(10);

LifeStuffImpl::LifeStuffImpl()
    : thread_count_(kThreads),
      buffered_path_(),
#ifdef LOCAL_TARGETS_ONLY
      simulation_path_(),
#endif
      interval_(kSecondsInterval),
      asio_service_(thread_count_),
      remote_chunk_store_(),
#ifndef LOCAL_TARGETS_ONLY
      client_controller_(),
      node_(),
      routings_handler_(),
#endif
      network_health_signal_(),
      session_(),
      user_credentials_(),
      user_storage_(),
      public_id_(),
      message_handler_(),
      slots_(),
      state_(kZeroth),
      logged_in_state_(kBaseState) {}

LifeStuffImpl::~LifeStuffImpl() {}

int LifeStuffImpl::Initialise(const UpdateAvailableFunction& software_update_available_function,
                              const fs::path& base_directory) {
  if (state_ != kZeroth) {
    LOG(kError) << "Make sure that object is in the original Zeroth state. Asimov rules.";
    return kGeneralError;
  }

  if (!software_update_available_function) {
    LOG(kError) << "No function provided for SW update. Unacceptable. Good day!";
    return kGeneralError;
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

#ifdef LOCAL_TARGETS_ONLY
  remote_chunk_store_ = BuildChunkStore(buffered_chunk_store_path,
                                        network_simulation_path,
                                        asio_service_.service());
  simulation_path_ = network_simulation_path;
#else
  int counter(0);
  std::vector<std::pair<std::string, uint16_t>> bootstrap_endpoints;
  while (counter++ < kRetryLimit) {
    Sleep(bptime::milliseconds(100 + RandomUint32() % 1000));
    client_controller_.reset(
        new priv::process_management::ClientController(software_update_available_function));
    if (client_controller_->BootstrapEndpoints(bootstrap_endpoints) && !bootstrap_endpoints.empty())
      counter = kRetryLimit;
    else
      LOG(kWarning) << "Failure to initialise client controller. Try #" << counter;
  }

  if (bootstrap_endpoints.empty()) {
    LOG(kWarning) << "Failure to initialise client controller. No bootstrap contacts.";
    return kGeneralError;
  }

  remote_chunk_store_ = BuildChunkStore(buffered_chunk_store_path,
                                        bootstrap_endpoints,
                                        node_,
                                        [&] (const int& index) { NetworkHealthSlot(index); });  // NOLINT (Dan)
#endif
  if (!remote_chunk_store_) {
    LOG(kError) << "Could not initialise chunk store.";
    return kGeneralError;
  }

  buffered_path_ = buffered_chunk_store_path;

  user_credentials_.reset(new UserCredentials(*remote_chunk_store_,
                                              session_,
                                              asio_service_.service()));

  state_ = kInitialised;

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
    return kGeneralError;
  }

  if (set_slots) {
    int connects(0);
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
      return kGeneralError;
    }
    ImmediateQuitRequiredFunction must_die = [&] {
                                               LOG(kInfo) << "Immediate quit required! " <<
                                                             "Stopping activity.";
                                               StopMessagesAndIntros();
                                               UnMountDrive();
                                               LogOut();
                                             };
    user_credentials_->ConnectToImmediateQuitRequiredSignal(must_die);
    state_ = kConnected;
    return kSuccess;
  }

  if (!message_handler_ || !public_id_ || !user_storage_) {
    LOG(kError) << "Unable to connect to signals.";
    return kGeneralError;
  }

  message_handler_->ConnectToChatSignal(chat_slot);
  message_handler_->ConnectToFileTransferSignal(file_slot);
  public_id_->ConnectToNewContactSignal(new_contact_slot);
  public_id_->ConnectToContactConfirmedSignal(confirmed_contact_slot);
  message_handler_->ConnectToContactProfilePictureSignal(profile_picture_slot);
  message_handler_->ConnectToContactPresenceSignal(contact_presence_slot);
  public_id_->ConnectToContactDeletionProcessedSignal(contact_deletion_function);
  public_id_->ConnectToLifestuffCardUpdatedSignal(lifestuff_card_update_function);
  user_credentials_->ConnectToImmediateQuitRequiredSignal(immediate_quit_required_function);
  public_id_->ConnectToContactDeletionReceivedSignal(
      [&] (const std::string& own_public_id,
           const std::string& contact_public_id,
           const std::string& removal_message,
           const std::string& timestamp) {
        int result(RemoveContact(own_public_id,
                                 contact_public_id,
                                 removal_message,
                                 timestamp,
                                 false));
        if (result != kSuccess)
          LOG(kError) << "Failed to remove contact after receiving contact deletion signal!";
      });
  return kSuccess;
}

int LifeStuffImpl::Finalise() {
  if (state_ != kConnected) {
    LOG(kError) << "Need to be connected to finalise.";
    return kGeneralError;
  }

  boost::system::error_code error_code;
  fs::remove_all(buffered_path_, error_code);
  if (error_code)
    LOG(kWarning) << "Failed to remove buffered chunk store path.";

  asio_service_.Stop();
  remote_chunk_store_.reset();
#ifndef LOCAL_TARGETS_ONLY
  node_.reset();
#endif
  message_handler_.reset();
  public_id_.reset();
  user_credentials_.reset();
  user_storage_.reset();
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
    return kGeneralError;
  }

  if ((kCredentialsLoggedIn & logged_in_state_) == kCredentialsLoggedIn ||
      (kDriveMounted & logged_in_state_) == kDriveMounted ||
      (kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted) {
    LOG(kError) << "In unsuitable state to create user: " <<
                   "make sure user_credentials are logged out, the drive is unmounted and " <<
                   "messages and intros have been stopped.";
    return kWrongOrderFailure;
  }
  // TODO(Alison) - should we reset session here?

  int result(user_credentials_->CreateUser(keyword, pin, password));
  if (result != kSuccess) {
    LOG(kError) << "Failed to Create User.";
    return result;
  }

  result = SetValidPmidAndInitialisePublicComponents();
  if (result != kSuccess)  {
    LOG(kError) << "Failed to set valid PMID";
    return result;
  }

#ifdef LOCAL_TARGETS_ONLY
  LOG(kInfo) << "The chunkstore path for the ficticious vault is " << chunk_store;
#else
  result = CreateVaultInLocalMachine(chunk_store);
  if (result != kSuccess)  {
    LOG(kError) << "Failed to create vault. No LifeStuff for you!";
    return result;
  }

  routings_handler_ = std::make_shared<RoutingsHandler>(*remote_chunk_store_,
                                                        session_,
                                                        ValidatedMessageSignal());
#endif

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
    LOG(kError) << "Failed to create public ID.";
    return result;
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
    return kGeneralError;
  }

  if ((kCredentialsLoggedIn & logged_in_state_) == kCredentialsLoggedIn ||
      (kDriveMounted & logged_in_state_) == kDriveMounted ||
      (kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted) {
    LOG(kError) << "In unsuitable state to log in: " <<
                   "make sure user_credentials are logged out, the drive is unmounted and " <<
                   "messages and intros have been stopped.";
    return kWrongOrderFailure;
  }
  session_.Reset();

  int login_result(user_credentials_->LogIn(keyword, pin, password));
  if (login_result != kSuccess && login_result != kReadOnlyRestrictedSuccess) {
    LOG(kError) << "LogIn failed with result: " << login_result;
    return login_result;
  }

  int result(SetValidPmidAndInitialisePublicComponents());
  if (result != kSuccess)  {
    LOG(kError) << "Failed to set valid PMID";
    return result;
  }

  state_ = kLoggedIn;
  logged_in_state_ = kCredentialsLoggedIn;

  return login_result;
}

int LifeStuffImpl::LogOut() {
  if (state_ != kLoggedIn) {
    LOG(kError) << "Should be logged in to log out.";
    return kGeneralError;
  }
  if ((kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted ||
      (kDriveMounted & logged_in_state_) == kDriveMounted) {
    LOG(kError) << "In incorrect state to log out. " <<
                   "Make sure messages and intros have been stopped and drive has been unmounted.";
    return kWrongOrderFailure;
  }
  if ((kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn) {
    LOG(kError) << "In incorrect state to log out. " <<
                   "Make user credentials are logged in first.";
    return kWrongOrderFailure;
  }

  if (user_credentials_->Logout() != kSuccess) {
    LOG(kError) << "Failed to log out.";
    return kGeneralError;
  }

  if (!remote_chunk_store_->WaitForCompletion()) {
    LOG(kError) << "Failed complete chunk operations.";
    return kGeneralError;
  }

  session_.Reset();

  state_ = kConnected;
  logged_in_state_ = kBaseState;

  return kSuccess;
}

int LifeStuffImpl::CreateAndMountDrive() {
  if (session_.session_access_level() == kReadOnly) {
    LOG(kError) << "Can't create and mount drive when session is read only!";
    return kGeneralError;
  }

  if ((kCreating & logged_in_state_) != kCreating ||
      (kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn ||
      (kDriveMounted & logged_in_state_) == kDriveMounted) {
    LOG(kError) << "In unsuitable state to create and mount drive: " <<
                   "make sure a CreateUser has just been run and drive is not already mounted.";
    return kWrongOrderFailure;
  }

  boost::system::error_code error_code;
  fs::path mount_dir(GetHomeDir() / kAppHomeDirectory / session_.session_name());
  if (!fs::exists(mount_dir, error_code)) {
    fs::create_directories(mount_dir, error_code);
    if (error_code) {
      LOG(kError) << "Failed to create app directories - " << error_code.value()
                  << ": " << error_code.message();
      return kGeneralError;
    }
  }

  user_storage_->MountDrive(mount_dir, &session_, true, false);
  if (!user_storage_->mount_status()) {
    LOG(kError) << "Failed to mount";
    return kGeneralError;
  }

  fs::path mount_path(user_storage_->mount_dir());
  fs::create_directories(mount_path / kMyStuff / kDownloadStuff, error_code);
  if (error_code) {
    LOG(kError) << "Failed creating My Stuff: " << error_code.message();
    user_storage_->UnMountDrive();
    return kGeneralError;
  }

  fs::create_directory(mount_path / kSharedStuff, error_code);
  if (error_code) {
    LOG(kError) << "Failed creating Shared Stuff: " << error_code.message();
    user_storage_->UnMountDrive();
    return kGeneralError;
  }

  logged_in_state_ = logged_in_state_ ^ kDriveMounted;
  return kSuccess;
}

int LifeStuffImpl::MountDrive(bool read_only) {
  if (!read_only && session_.session_access_level() == kReadOnly) {
    LOG(kError) << "Can't mount drive with full access when session is read only!";
    return kGeneralError;
  }

  if ((kCreating & logged_in_state_) == kCreating ||
      (kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn ||
      (kDriveMounted & logged_in_state_) == kDriveMounted) {
    LOG(kError) << "In unsuitable state to mount drive: " <<
                   "make sure LogIn has been run and drive is not already mounted.";
    return kWrongOrderFailure;
  }

  boost::system::error_code error_code;
  fs::path mount_dir(GetHomeDir() / kAppHomeDirectory / session_.session_name());
  if (!fs::exists(mount_dir, error_code)) {
    if (error_code) {
      if (error_code.value() == boost::system::errc::not_connected) {
        LOG(kError) << "\tHint: Try unmounting the drive manually.";
        return kGeneralError;
      } else if (error_code != boost::system::errc::no_such_file_or_directory) {
        if (!fs::create_directories(mount_dir, error_code) || error_code) {
          LOG(kError) << "Failed to create mount directory at " << mount_dir.string()
                      << " - " << error_code.value() << ": " << error_code.message();
          return kGeneralError;
        }
      }
    }
  }

  user_storage_->MountDrive(mount_dir, &session_, false, read_only);
  if (!user_storage_->mount_status()) {
    LOG(kError) << "Failed to mount";
    return kGeneralError;
  }

  logged_in_state_ = logged_in_state_ ^ kDriveMounted;
  if (read_only)
    return kReadOnlyRestrictedSuccess;
  return kSuccess;
}

int LifeStuffImpl::UnMountDrive() {
  if ((kCredentialsLoggedIn & logged_in_state_) != kCredentialsLoggedIn ||
      (kDriveMounted & logged_in_state_) != kDriveMounted ||
      (kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted) {
    LOG(kError) << "In unsuitable state to unmount drive: " <<
                   "make sure user_credentials are logged in, drive is mounted and "
                   "messages and intros have been stopped.";
    return kWrongOrderFailure;
  }

  user_storage_->UnMountDrive();
  if (user_storage_->mount_status()) {
    LOG(kError) << "Failed to un-mount.";
    return kGeneralError;
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
     return kWrongOrderFailure;
  }
  if (session_.session_access_level() != kFullAccess) {
    LOG(kError) << "Shouldn't check for messages/intros when session access level is " <<
                   session_.session_access_level();
    return kGeneralError;
  }
  if (session_.PublicIdentities().empty()) {
    LOG(kInfo) << "Won't check for messages/intros because there is no public ID.";
    return kNoPublicIds;
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
     return kWrongOrderFailure;
  }

  public_id_->ShutDown();
  message_handler_->ShutDown();
  if ((kMessagesAndIntrosStarted & logged_in_state_) == kMessagesAndIntrosStarted)
    logged_in_state_ = logged_in_state_ ^ kMessagesAndIntrosStarted;
  return kSuccess;
}

int LifeStuffImpl::CheckPassword(const std::string& password) {
  int result(CheckStateAndReadOnlyAccess());
  if (result != kSuccess)
    return result;

  return session_.password() == password ? kSuccess : kGeneralError;
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

  return user_credentials_->ChangeKeyword(new_keyword);
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

  return user_credentials_->ChangePin(new_pin);
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

  return user_credentials_->ChangePassword(new_password);
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

  return public_id_->AddContact(my_public_id, contact_public_id, message);
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
    LOG(kError) << "Failed to Confirm Contact.";
    return result;
  }

  return message_handler_->SendPresenceMessage(my_public_id, contact_public_id, kOnline);
}

int LifeStuffImpl::DeclineContact(const std::string& my_public_id,
                                  const std::string& contact_public_id) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in DeclineContact.";
    return result;
  }

  return public_id_->RejectContact(my_public_id, contact_public_id);
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
  if (result != kSuccess)
    LOG(kError) << "Failed remove contact in RemoveContact.";

  return result;
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
    return kGeneralError;
  }

  // Message construction
  InboxItem message(kContactProfilePicture);
  message.sender_public_id = my_public_id;

  if (profile_picture_contents != kBlankProfilePicture) {
    // Write contents
    fs::path profile_picture_path(mount_path() / std::string(my_public_id +
                                                             "_profile_picture" +
                                                             kHiddenFileExtension));
    if (user_storage_->WriteHiddenFile(profile_picture_path, profile_picture_contents, true) !=
        kSuccess) {
      LOG(kError) << "Failed to write profile picture file: " << profile_picture_path;
      return kGeneralError;
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
                    << profile_picture_path;
        return result;
      }

      reconstructed = user_storage_->ConstructFile(data_map);
      Sleep(bptime::milliseconds(500));
    }

    if (reconstructed != profile_picture_contents) {
      LOG(kError) << "Failed to reconstruct profile picture file: " << profile_picture_path;
      return kGeneralError;
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
    std::unique_lock<std::mutex> loch(*social_info.first);
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
  int result(PreContactChecksReadOnly(my_public_id));
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
    std::unique_lock<std::mutex> loch(*social_info.first);
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
  int result(PreContactChecksReadOnly(my_public_id));
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
  int result(PreContactChecksReadOnly(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in GetLifestuffCard.";
    return result;
  }
  return public_id_->GetLifestuffCard(my_public_id, contact_public_id, social_info);
}

int LifeStuffImpl::SetLifestuffCard(const std::string& my_public_id,
                                    const SocialInfoMap& social_info) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  return public_id_->SetLifestuffCard(my_public_id, social_info);
}

ContactMap LifeStuffImpl::GetContacts(const std::string& my_public_id, uint16_t bitwise_status) {
  int result(PreContactChecksReadOnly(my_public_id));
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
  int result = CheckStateAndReadOnlyAccess();
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
    return kGeneralError;
  }

  InboxItem inbox_item(kChat);
  inbox_item.receiver_public_id = receiver_public_id;
  inbox_item.sender_public_id = sender_public_id;
  inbox_item.content.push_back(message);

  return message_handler_->Send(inbox_item);
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
    LOG(kError) << "Failed to get DM for " << absolute_path << ": " << result;
    return result;
  }

  InboxItem inbox_item(kFileTransfer);
  inbox_item.receiver_public_id = receiver_public_id;
  inbox_item.sender_public_id = sender_public_id;
  inbox_item.content.push_back(absolute_path.filename().string());
  inbox_item.content.push_back(serialised_datamap);

  result = message_handler_->Send(inbox_item);
  if (result != kSuccess) {
    LOG(kError) << "Failed to send message: " << result;
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

  if ((absolute_path.empty() && !file_name) ||
      (!absolute_path.empty() && file_name)) {
    LOG(kError) << "Wrong parameters given. absolute_path and file_name are mutually exclusive.";
    return kGeneralError;
  }

  std::string serialised_identifier, saved_file_name, serialised_data_map;
  result = user_storage_->ReadHiddenFile(mount_path() /
                                         std::string(identifier + kHiddenFileExtension),
                                         &serialised_identifier);
  if (result != kSuccess || serialised_identifier.empty()) {
    LOG(kError) << "No such identifier found: " << result;
    return result == kSuccess ? kGeneralError : result;
  }

  GetFilenameData(serialised_identifier, &saved_file_name, &serialised_data_map);
  if (saved_file_name.empty() || serialised_data_map.empty()) {
    LOG(kError) << "Failed to get filename or datamap.";
    return kGeneralError;
  }

  drive::DataMapPtr data_map_ptr(ParseSerialisedDataMap(serialised_data_map));
  if (!data_map_ptr) {
    LOG(kError) << "Corrupted DM in file";
    return kGeneralError;
  }

  if (absolute_path.empty()) {
    fs::path store_path(mount_path() / kMyStuff / kDownloadStuff);
    if (!VerifyOrCreatePath(store_path)) {
      LOG(kError) << "Failed finding and creating: " << store_path;
      return kGeneralError;
    }
    std::string adequate_name(GetNameInPath(store_path, saved_file_name));
    if (adequate_name.empty()) {
      LOG(kError) << "No name found to work for saving the file.";
      return kGeneralError;
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
  return user_storage_->DeleteHiddenFile(hidden_file);
}

/// Filesystem
int LifeStuffImpl::ReadHiddenFile(const fs::path& absolute_path, std::string* content) const {
  int result(CheckStateAndReadOnlyAccess());
  if (result != kSuccess)
    return result;

  if (!content) {
    LOG(kError) << "Content parameter must be valid.";
    return kGeneralError;
  }

  return user_storage_->ReadHiddenFile(absolute_path, content);
}

int LifeStuffImpl::WriteHiddenFile(const fs::path& absolute_path,
                                   const std::string& content,
                                   bool overwrite_existing) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  return user_storage_->WriteHiddenFile(absolute_path, content, overwrite_existing);
}

int LifeStuffImpl::DeleteHiddenFile(const fs::path& absolute_path) {
  int result(CheckStateAndFullAccess());
  if (result != kSuccess)
    return result;

  return user_storage_->DeleteHiddenFile(absolute_path);
}

int LifeStuffImpl::SearchHiddenFiles(const fs::path& absolute_path,
                                     std::vector<std::string>* results) {
  int result(CheckStateAndReadOnlyAccess());
  if (result != kSuccess)
    return result;

  return user_storage_->SearchHiddenFiles(absolute_path, results);
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
#ifndef LOCAL_TARGETS_ONLY
  result = node_->Stop();
  if (result != kSuccess) {
    LOG(kError) << "Failed to stop client container: " << result;
    return result;
  }
  std::shared_ptr<asymm::Keys> pmid(new asymm::Keys(
      session_.passport().SignaturePacketDetails(passport::kPmid, true)));
  if (!pmid || pmid->identity.empty()) {
    LOG(kError) << "Failed to obtain valid PMID keys.";
    return -1;
  }
  node_->set_keys(pmid);
  result = node_->Start(buffered_path_ / "buffered_chunk_store");
  if (result != kSuccess) {
    LOG(kError) << "Failed to start client container: " << result;
    return result;
  }

  remote_chunk_store_.reset(new pcs::RemoteChunkStore(node_->chunk_store(),
                                                      node_->chunk_manager(),
                                                      node_->chunk_action_authority()));
  user_credentials_.reset(new UserCredentials(*remote_chunk_store_,
                                              session_,
                                              asio_service_.service()));
#endif

  public_id_.reset(new PublicId(remote_chunk_store_, session_, asio_service_.service()));

  message_handler_.reset(new MessageHandler(remote_chunk_store_,
                                            session_,
                                            asio_service_.service()));

  user_storage_.reset(new UserStorage(remote_chunk_store_));

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

int LifeStuffImpl::CheckStateAndReadOnlyAccess() const {
  if (state_ != kLoggedIn) {
    LOG(kError) << "Incorrect state. Should be logged in: " << state_;
    return kGeneralError;
  }

  if ((kDriveMounted & logged_in_state_) != kDriveMounted) {
    LOG(kError) << "Incorrect state. Drive should be mounted: " << logged_in_state_;
    return kGeneralError;
  }

  SessionAccessLevel session_access_level(session_.session_access_level());
  if (session_access_level != kFullAccess && session_access_level != kReadOnly) {
    LOG(kError) << "Insufficient access. Should have at least read access: " <<
                   session_access_level;
    return kGeneralError;
  }
  return kSuccess;
}

int LifeStuffImpl::CheckStateAndFullAccess() const {
  if (state_ != kLoggedIn) {
    LOG(kError) << "Incorrect state. Should be logged in: " << state_;
    return kGeneralError;
  }

  if ((kDriveMounted & logged_in_state_) != kDriveMounted) {
    LOG(kError) << "Incorrect state. Drive should be mounted: " << logged_in_state_;
    return kGeneralError;
  }

  SessionAccessLevel session_access_level(session_.session_access_level());
  if (session_access_level != kFullAccess) {
    LOG(kError) << "Insufficient access. Should have full access: " << session_access_level;
    if (session_access_level == kReadOnly)
      return kReadOnlyFailure;
    return kGeneralError;
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

int LifeStuffImpl::PreContactChecksReadOnly(const std::string &my_public_id) {
  int result = CheckStateAndReadOnlyAccess();
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


#ifndef LOCAL_TARGETS_ONLY
int LifeStuffImpl::CreateVaultInLocalMachine(const fs::path& chunk_store) {
  std::string account_name(session_.passport().SignaturePacketDetails(passport::kMaid,
                                                                      true).identity);
  asymm::Keys pmid_keys(session_.passport().SignaturePacketDetails(passport::kPmid, true));
  if (account_name.empty() || pmid_keys.identity.empty()) {
    LOG(kError) << "Failed to obtain credentials to start vault from session.";
    return kVaultCreationFailure;
  }

  if (!client_controller_->StartVault(pmid_keys, account_name, chunk_store)) {
    LOG(kError) << "Failed to create vault.";
    return kVaultCreationFailure;
  }

  return kSuccess;
}

int LifeStuffImpl::EstablishMaidRoutingObject(
    const std::vector<std::pair<std::string, uint16_t>>& bootstrap_endpoints) {  // NOLINT (Dan)
  asymm::Keys maid(session_.passport().SignaturePacketDetails(passport::kMaid, true));
  if (!routings_handler_->AddRoutingObject(maid, bootstrap_endpoints, maid.identity)) {
    LOG(kError) << "Failed to adding MAID routing.";
    return kGeneralError;
  }

  return kSuccess;
}
#endif

}  // namespace lifestuff

}  // namespace maidsafe
