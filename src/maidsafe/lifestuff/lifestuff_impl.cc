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
      vault_node_(),
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
    const PrivateShareInvitationFunction& private_share_invitation_function,
    const PrivateShareDeletionFunction& private_share_deletion_function,
    const PrivateMemberAccessChangeFunction& private_access_change_function,
    const OpenShareInvitationFunction& open_share_invitation_function,
    const ShareRenamedFunction& share_renamed_function,
    const ShareChangedFunction& share_changed_function,
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
    if (private_share_invitation_function) {
      ++connects;
      slots_.private_share_invitation_function = private_share_invitation_function;
    }
    if (private_share_deletion_function) {
      ++connects;
      slots_.private_share_deletion_function = private_share_deletion_function;
    }
    if (private_access_change_function) {
      ++connects;
      slots_.private_access_change_function = private_access_change_function;
    }
    if (open_share_invitation_function) {
      ++connects;
      slots_.open_share_invitation_function = open_share_invitation_function;
    }
    if (share_renamed_function) {
      ++connects;
      slots_.share_renamed_function = share_renamed_function;
    }
    if (share_changed_function) {
      ++connects;
      slots_.share_changed_function = share_changed_function;
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
  message_handler_->ConnectToPrivateShareInvitationSignal(private_share_invitation_function);
  message_handler_->ConnectToPrivateShareDeletionSignal(private_share_deletion_function);
  message_handler_->ConnectToPrivateMemberAccessChangeSignal(private_access_change_function);
  message_handler_->ConnectToOpenShareInvitationSignal(open_share_invitation_function);
  user_storage_->ConnectToShareRenamedSignal(share_renamed_function);
  user_storage_->ConnectToShareChangedSignal(share_changed_function);
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
                              const fs::path& chunk_store,
                              bool vault_cheat) {
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
  result = CreateVaultInLocalMachine(chunk_store, vault_cheat);
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
  // Leave all shares
  std::vector<std::string> public_ids(session_.PublicIdentities());
  std::for_each(public_ids.begin(),
                public_ids.end(),
                [&result, this] (const std::string& public_id) {
                  const ShareInformationDetail share_info(session_.share_information(public_id));
                  if (share_info.first) {
                    std::unique_lock<std::mutex> loch(*share_info.first);
                    std::for_each(share_info.second->begin(),
                                  share_info.second->end(),
                                  [&public_id, &result, this]
                                      (const ShareInformation::value_type& element) {
                                    if (element.second.share_type <= kOpenOwner)
                                      result += LeaveOpenShare(public_id, element.first);
                                    else if (element.second.share_type < kPrivateOwner)
                                      result += LeavePrivateShare(public_id, element.first);
                                    else if (element.second.share_type == kPrivateOwner)
                                      result += DeletePrivateShare(public_id, element.first, true);
                                  });
                  }
                });

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

  // For private shares, if share_members can be fetched, indicates owner
  // otherwise, only the owner(inviter) of the share can be fetched
  std::vector<std::string> share_names;
  GetPrivateSharesIncludingMember(my_public_id, contact_public_id, &share_names);
  StringIntMap contact_to_remove;
  contact_to_remove.insert(std::make_pair(contact_public_id, kShareRemover));
  for (auto it = share_names.begin(); it != share_names.end(); ++it) {
    StringIntMap results;
    result = EditPrivateShareMembers(my_public_id, contact_to_remove, *it, &results, false);
    LOG(kInfo) << "Removing " << contact_public_id << " from " << (*it) << ", result: " << result;
  }
  share_names.clear();
  user_storage_->GetPrivateSharesContactBeingOwner(my_public_id, contact_public_id, &share_names);
  for (auto it = share_names.begin(); it != share_names.end(); ++it) {
    result = LeavePrivateShare(my_public_id, *it, false);
    LOG(kInfo) << "Removing oneself from " << (*it) << ", result: " << result;
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

  if ((absolute_path.empty() && !file_name) || (!absolute_path.empty() && file_name)) {
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

/// Private Shares
int LifeStuffImpl::CreatePrivateShareFromExistingDirectory(
    const std::string& my_public_id,
    const fs::path& directory_in_lifestuff_drive,
    const StringIntMap& contacts,
    std::string* share_name,
    StringIntMap* results) {
  if (!share_name) {
    LOG(kError) << "Share name parameter must be valid.";
    return kGeneralError;
  }
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in CreatePrivateShareFromExistingDirectory.";
    return result;
  }
  boost::system::error_code error_code;
  if (!fs::exists(directory_in_lifestuff_drive, error_code) || error_code) {
    LOG(kError) << "Target Directory doesn't exist";
    return kNoShareTarget;
  }
  fs::path store_path(mount_path() / kSharedStuff);
  if (!VerifyOrCreatePath(store_path)) {
    LOG(kError) << "Failed to verify or create path to shared stuff.";
    return false;
  }

  *share_name = directory_in_lifestuff_drive.filename().string();
  std::string generated_name(GetNameInPath(store_path, *share_name));
  if (generated_name.empty()) {
    LOG(kError) << "Failed to generate name for share.";
    return kGeneralError;
  }

  *share_name = generated_name;
  fs::path share_dir(store_path / generated_name);
  result = user_storage_->CreateShare(my_public_id,
                                      directory_in_lifestuff_drive,
                                      share_dir,
                                      contacts,
                                      drive::kMsPrivateShare,
                                      results);
  if (result == kSuccess) {
    const ShareInformationDetail share_information(session_.share_information(my_public_id));
    if (!share_information.first) {
      LOG(kError) << "The user holds no such publc identity: " << my_public_id;
      return kPublicIdNotFoundFailure;
    }

    auto insert_result(share_information.second->insert(
                           std::make_pair(*share_name, ShareDetails(kPrivateOwner))));
    if (!insert_result.second) {
      LOG(kError) << "Failed to insert share to session.";
      return kGeneralError;
    }
    session_.set_changed(true);
  }
  return result;
}

int LifeStuffImpl::CreateEmptyPrivateShare(const std::string& my_public_id,
                                           const StringIntMap& contacts,
                                           std::string* share_name,
                                           StringIntMap* results) {
  if (!share_name) {
    LOG(kError) << "Share name must be provided.";
    return kGeneralError;
  }

  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in CreateEmptyPrivateShare.";
    return result;
  }

  fs::path store_path(mount_path() / kSharedStuff);
  if (!VerifyOrCreatePath(store_path)) {
    LOG(kError) << "Failed to verify or create path to shared stuff.";
    return false;
  }

  std::string generated_name(GetNameInPath(store_path, *share_name));
  if (generated_name.empty()) {
    LOG(kError) << "Failed to generate name for share.";
    return kGeneralError;
  }

  *share_name = generated_name;
  fs::path share_dir(store_path / generated_name);
  result = user_storage_->CreateShare(my_public_id,
                                      fs::path(),
                                      share_dir,
                                      contacts,
                                      drive::kMsPrivateShare,
                                      results);
  if (result == kSuccess) {
    const ShareInformationDetail share_information(session_.share_information(my_public_id));
    if (!share_information.first) {
      LOG(kError) << "The user holds no such publc identity: " << my_public_id;
      return kPublicIdNotFoundFailure;
    }

    bool session_changed(false);
    {
      std::unique_lock<std::mutex> loch(*share_information.first);
      auto insert_result(share_information.second->insert(
                             std::make_pair(*share_name, ShareDetails(kPrivateOwner))));
      if (!insert_result.second) {
        LOG(kError) << "Failed to insert share to session.";
        return kGeneralError;
      }
      session_changed = true;
    }

    if (session_changed)
      session_.set_changed(true);
  }
  return result;
}

int LifeStuffImpl::GetPrivateShareList(const std::string& my_public_id, StringIntMap* share_names) {
  if (!share_names) {
    LOG(kError) << "Share names parameter must be valid.";
    return kGeneralError;
  }

  int result(PreContactChecksReadOnly(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in GetPrivateShareList.";
    return result;
  }

  const ShareInformationDetail share_information(session_.share_information(my_public_id));
  if (!share_information.first) {
    LOG(kError) << "The user holds no such publc identity: " << my_public_id;
    return kPublicIdNotFoundFailure;
  }

  {
    std::unique_lock<std::mutex> loch(*share_information.first);
    std::for_each(share_information.second->begin(),
                  share_information.second->end(),
                  [=] (const ShareInformation::value_type& element) {
                    if (element.second.share_type > kOpenOwner)
                      share_names->insert(std::make_pair(element.first,
                                                         element.second.share_type - 3));
                  });
  }

  return kSuccess;
}

int LifeStuffImpl::GetPrivateShareMembers(const std::string& my_public_id,
                                          const std::string& share_name,
                                          StringIntMap* share_members) {
  if (!share_members) {
    LOG(kError) << "Share members parameter must be valid.";
    return kGeneralError;
  }
  int result(PreContactChecksReadOnly(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in GetPrivateShareMemebers.";
    return result;
  }

  fs::path share_dir(mount_path() / kSharedStuff / share_name);
  result = user_storage_->GetAllShareUsers(share_dir, share_members);
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in GetPrivateShareMemebers.";
    return result;
  }

  auto it(share_members->find(my_public_id));
  share_members->erase(it);

  return kSuccess;
}

int LifeStuffImpl::GetPrivateSharesIncludingMember(const std::string& my_public_id,
                                                   const std::string& contact_public_id,
                                                   std::vector<std::string>* share_names) {
  if (!share_names) {
    LOG(kError) << "Share names parameter must be valid.";
    return kGeneralError;
  }
  int result(PreContactChecksReadOnly(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in GetPrivateShareList.";
    return result;
  }

  const ShareInformationDetail share_information(session_.share_information(my_public_id));
  if (!share_information.first) {
    LOG(kError) << "The user holds no such publc identity: " << my_public_id;
    return kPublicIdNotFoundFailure;
  }

  std::vector<std::string> all_share_names;
  {
    std::unique_lock<std::mutex> loch(*share_information.first);
    std::for_each(share_information.second->begin(),
                  share_information.second->end(),
                  [&all_share_names] (const ShareInformation::value_type& element) {
                    if (element.second.share_type > kOpenOwner)
                      all_share_names.push_back(element.first);
                  });
  }

  for (auto it = all_share_names.begin(); it != all_share_names.end(); ++it) {
    StringIntMap share_members;
    fs::path share_dir(mount_path() / kSharedStuff / (*it));
    result = user_storage_->GetAllShareUsers(share_dir, &share_members);
    if (result != kSuccess) {
      LOG(kError) << "Failed to get members for " << share_dir.string();
    } else {
      for (auto itr = share_members.begin(); itr != share_members.end(); ++itr) {
        if ((*itr).first == contact_public_id) {
          share_names->push_back(*it);
          break;
        }
      }
    }
  }
  return kSuccess;
}

int LifeStuffImpl::AcceptPrivateShareInvitation(const std::string& my_public_id,
                                                const std::string& contact_public_id,
                                                const std::string& share_id,
                                                std::string* share_name) {
  if (!share_name) {
    LOG(kError) << "Share name parameter must be valid.";
    return kGeneralError;
  }

  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in AcceptPrivateShareInvitation.";
    return result;
  }
  std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)) +
                        kHiddenFileExtension);
  fs::path hidden_file(mount_path() / kSharedStuff / temp_name);
  std::string serialised_share_data;
  result = user_storage_->ReadHiddenFile(hidden_file, &serialised_share_data);
  if (result != kSuccess || serialised_share_data.empty()) {
    LOG(kError) << "No such identifier found: " << result;
    if (result == drive::kNoMsHidden)
      return kNoShareTarget;
    return result == kSuccess ? kGeneralError : result;
  }
  Message message;
  if (!message.ParseFromString(serialised_share_data)) {
    LOG(kError) << "Failed to parse data in hidden file for private share.";
    return kGeneralError;
  }

  // fs::path relative_path(message.content(1));
  std::string directory_id(message.content(kDirectoryId));
  asymm::Keys share_keyring;
  ShareDetails share_details(kPrivateReadOnlyMember);
  if (!message.content(kKeysIdentity).empty()) {
    share_keyring.identity = message.content(kKeysIdentity);
    share_keyring.validation_token = message.content(kKeysValidationToken);
    asymm::DecodePrivateKey(message.content(kKeysPrivateKey), &(share_keyring.private_key));
    asymm::DecodePublicKey(message.content(kKeysPublicKey), &(share_keyring.public_key));
    share_details.share_type = kPrivateReadWriteMember;
  }
  // remove the temp share invitation file no matter insertion succeed or not
  result = user_storage_->DeleteHiddenFile(hidden_file);
  if (result != kSuccess) {
    LOG(kWarning) << "Failed to delete hidden file.";
  }
  fs::path share_dir(mount_path() / kSharedStuff / *share_name);
  result = user_storage_->InsertShare(share_dir,
                                      share_id,
                                      contact_public_id,
                                      share_name,
                                      directory_id,
                                      share_keyring);
  if (result == kSuccess) {
    const ShareInformationDetail share_information(session_.share_information(my_public_id));
    if (!share_information.first) {
      LOG(kError) << "The user holds no such publc identity: " << my_public_id;
      return kPublicIdNotFoundFailure;
    }

    {
      std::unique_lock<std::mutex> loch(*share_information.first);
      auto insert_result(share_information.second->insert(std::make_pair(*share_name,
                                                                         share_details)));
      if (!insert_result.second) {
        LOG(kError) << "Failed to insert share into session.";
        return kGeneralError;
      }
    }

    session_.set_changed(true);
  }
  asymm::Keys keys;
  StringIntMap contacts;
  contacts.insert(std::make_pair(message.sender_public_id(), 0));
  // Non-empty share_name implies acceptance...
  result = user_storage_->InformContactsOperation(kRespondToShareInvitation,
                                                  my_public_id,
                                                  contacts,
                                                  share_id,
                                                  *share_name,
                                                  "",
                                                  keys,
                                                  "");
  return result;
}

int LifeStuffImpl::RejectPrivateShareInvitation(const std::string& my_public_id,
                                                const std::string& share_id) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in RejectPrivateShareInvitation.";
    return result;
  }
  std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)) +
                        kHiddenFileExtension);
  fs::path hidden_file(mount_path() / kSharedStuff / temp_name);
  std::string serialised_share_data;
  result = user_storage_->ReadHiddenFile(hidden_file, &serialised_share_data);
  if (result != kSuccess || serialised_share_data.empty()) {
    LOG(kError) << "No such identifier found: " << result;
    if (result == drive::kNoMsHidden)
      return kNoShareTarget;
    return result == kSuccess ? kGeneralError : result;
  }
  Message message;
  if (!message.ParseFromString(serialised_share_data))
    LOG(kError) << "Failed to parse data in hidden file for private share.";
  result = user_storage_->DeleteHiddenFile(hidden_file);
  if (result != kSuccess) {
    LOG(kWarning) << "Failed to delete hidden file.";
  }
  asymm::Keys keys;
  StringIntMap contacts;
  contacts.insert(std::make_pair(message.sender_public_id(), 0));
  // Empty share_name implies rejection...
  result = user_storage_->InformContactsOperation(kRespondToShareInvitation,
                                                  my_public_id,
                                                  contacts,
                                                  share_id,
                                                  "",
                                                  "",
                                                  keys,
                                                  "");
  return result;
}

int LifeStuffImpl::EditPrivateShareMembers(const std::string& my_public_id,
                                           const StringIntMap& public_ids,
                                           const std::string& share_name,
                                           StringIntMap* results,
                                           bool inform_contacts) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess)
    return result;
  if (!results) {
    LOG(kError) << "Results parameter invalid.";
    return kGeneralError;
  }
  StringIntMap share_members;
  result = GetPrivateShareMembers(my_public_id, share_name, &share_members);
  if (result != kSuccess) {
    LOG(kError) << "Failed to get share members for " << share_name;
    return result;
  }
  std::vector<std::string> member_ids;
  for (auto it = share_members.begin(); it != share_members.end(); ++it)
    member_ids.push_back(it->first);
  StringIntMap members_to_add, members_to_upgrade, members_to_downgrade;
  std::vector<std::string> members_to_remove;
  for (auto it = public_ids.begin(); it != public_ids.end(); ++it) {
    auto itr(std::find(member_ids.begin(), member_ids.end(), it->first));
    if (itr != member_ids.end()) {
      if (it->second == kShareRemover)  // Remove existing share user.
        members_to_remove.push_back(*itr);
      if (share_members[it->first] != it->second) {
        if (it->second == kShareReadOnly)  // Downgrade existing share user.
          members_to_downgrade.insert(*it);
        if (it->second >= kShareReadWrite)  // Upgrade existing share user.
          members_to_upgrade.insert(*it);
      }
    } else {
      members_to_add.insert(*it);  // Add non-existing share user.
    }
  }

  fs::path share_dir(mount_path() / kSharedStuff / share_name),
           shared_relative_path(drive::RelativePath(mount_path(), share_dir));

  std::string share_id, new_share_id, new_directory_id;
  asymm::Keys new_key_ring;
  bool downgraded_members_informed(false), upgraded_members_informed(false);
  // Remove members...
  if (!members_to_remove.empty()) {
    result = user_storage_->RemoveShareUsers(my_public_id,
                                             share_dir,
                                             members_to_remove);
    if (result != kSuccess) {
      LOG(kError) << "Failed to remove share members for " << share_name;
      for (auto it = members_to_remove.begin(); it != members_to_remove.end(); ++it)
        results->insert(std::make_pair(*it, result));
    } else {
      for (auto it = members_to_remove.begin(); it != members_to_remove.end(); ++it)
        results->insert(std::make_pair(*it, kSuccess));
    }
    asymm::Keys key_ring;
    share_members.clear();
    result = user_storage_->GetShareDetails(shared_relative_path,
                                            nullptr,
                                            &key_ring,
                                            &share_id,
                                            nullptr,
                                            &share_members,
                                            nullptr);
    if (result != kSuccess) {
      LOG(kError) << "Failed to get share details for " << share_name;
    } else {
      result = user_storage_->MoveShare(my_public_id,
                                        share_id,
                                        shared_relative_path,
                                        key_ring,
                                        true,
                                        &new_share_id,
                                        &new_directory_id,
                                        &new_key_ring);
      if (result != kSuccess) {
        LOG(kError) << "Failed to move share " << share_name;
      }

      if (inform_contacts) {
        int inform_remaining_result(kSuccess);
        std::for_each(members_to_remove.begin(),
                      members_to_remove.end(),
                      [&](const std::string& member) {
                          share_members.erase(member);
                      });
        if (!members_to_downgrade.empty()) {
          std::for_each(members_to_downgrade.begin(),
                        members_to_downgrade.end(),
                        [&](const StringIntMap::value_type& member) {
                          share_members.erase(member.first);
                        });
          results->clear();
          result = user_storage_->DowngradeShareUsersRights(my_public_id,
                                                            share_dir,
                                                            members_to_downgrade,
                                                            results);
          if (result != kSuccess) {
            LOG(kError) << "Failed to downgrade share members for " << share_name;
          }
          result = user_storage_->InformContactsOperation(kPrivateShareMembershipDowngrade,
                                                          my_public_id,
                                                          *results,
                                                          share_id,
                                                          "",
                                                          new_directory_id,
                                                          asymm::Keys(),
                                                          new_share_id);
          if (result != kSuccess) {
            LOG(kError) << "Failed to inform contacts of downgrade for " << share_name;
            return result;
          }
          downgraded_members_informed = true;
        }
        if (!members_to_upgrade.empty()) {
          std::for_each(members_to_upgrade.begin(),
                        members_to_upgrade.end(),
                        [&](const StringIntMap::value_type& member) {
                          share_members.erase(member.first);
                        });
          results->clear();
          result = user_storage_->UpgradeShareUsersRights(my_public_id,
                                                          share_dir,
                                                          members_to_upgrade,
                                                          results);
          if (result != kSuccess) {
            LOG(kError) << "Failed to upgrade share members for " << share_name;
          }
          result = user_storage_->InformContactsOperation(kPrivateShareMembershipUpgrade,
                                                          my_public_id,
                                                          members_to_upgrade,
                                                          share_id,
                                                          "",
                                                          new_directory_id,
                                                          new_key_ring,
                                                          new_share_id);
          if (result != kSuccess) {
            LOG(kError) << "Failed to inform contacts of upgrade for " << share_name;
            return result;
          }
          upgraded_members_informed = true;
        }
        result = user_storage_->InformContactsOperation(kPrivateShareKeysUpdate,
                                                        my_public_id,
                                                        share_members,
                                                        share_id,
                                                        "",
                                                        new_directory_id,
                                                        new_key_ring,
                                                        new_share_id);
        if (result != kSuccess) {
          LOG(kError) << "Failed to inform remaining contacts of share: " << Base32Substr(share_id)
                      << ", with result of : " << result;
          inform_remaining_result = result;
        }
        StringIntMap removed_members;
        for (auto it = members_to_remove.begin(); it != members_to_remove.end(); ++it) {
          removed_members.insert(std::make_pair(*it, kShareReadOnly));
        }
        result = user_storage_->InformContactsOperation(kPrivateShareDeletion,
                                                        my_public_id,
                                                        removed_members,
                                                        share_id);
        if (result != kSuccess) {
          LOG(kError) << "Failed to inform removed contacts of share: " << Base32Substr(share_id)
                      << ", with result of : " << result;
          return result;
        }
        if (inform_remaining_result != kSuccess) {
          return inform_remaining_result;
        }
      } else {
        BOOST_ASSERT(members_to_downgrade.empty());
        BOOST_ASSERT(members_to_upgrade.empty());
        BOOST_ASSERT(members_to_add.empty());
        BOOST_ASSERT(members_to_remove.size() == 1);
        return kSuccess;
      }
    }
  }
  // Downgrade members...
  if (!members_to_downgrade.empty()) {
    if (!downgraded_members_informed) {
      result = user_storage_->DowngradeShareUsersRights(my_public_id,
                                                        share_dir,
                                                        members_to_downgrade,
                                                        results);
      if (result != kSuccess) {
        LOG(kError) << "Failed to downgrade rights: " << result;
        return result;
      }
      asymm::Keys old_key_ring;
      share_members.clear();
      result = user_storage_->GetShareDetails(shared_relative_path,
                                              nullptr,
                                              &old_key_ring,
                                              &share_id,
                                              nullptr,
                                              &share_members,
                                              nullptr);
      if (result != kSuccess) {
        LOG(kError) << "Failed to get share details for " << share_name << ", path: "
                    << shared_relative_path;
      } else {
        result = user_storage_->MoveShare(my_public_id,
                                          share_id,
                                          shared_relative_path,
                                          old_key_ring,
                                          true,
                                          &new_share_id,
                                          &new_directory_id,
                                          &new_key_ring);
        if (result != kSuccess) {
          LOG(kError) << "Failed to move share " << share_name;
        }
        asymm::Keys key_ring;
        std::for_each(members_to_downgrade.begin(),
                      members_to_downgrade.end(),
                      [&](const StringIntMap::value_type& member) {
                        share_members.erase(member.first);
                      });
        if (!members_to_upgrade.empty()) {
          std::for_each(members_to_upgrade.begin(),
                        members_to_upgrade.end(),
                        [&](const StringIntMap::value_type& member) {
                          share_members.erase(member.first);
                        });
          results->clear();
          result = user_storage_->UpgradeShareUsersRights(my_public_id,
                                                          share_dir,
                                                          members_to_upgrade,
                                                          results);
          if (result != kSuccess) {
            LOG(kError) << "Failed to upgrade share members for " << share_name;
          }
          result = user_storage_->InformContactsOperation(kPrivateShareMembershipUpgrade,
                                                          my_public_id,
                                                          members_to_upgrade,
                                                          share_id,
                                                          "",
                                                          new_directory_id,
                                                          new_key_ring,
                                                          new_share_id);
          if (result != kSuccess) {
            LOG(kError) << "Failed to inform contacts of upgrade for " << share_name;
            return result;
          }
          upgraded_members_informed = true;
        }
        result = user_storage_->InformContactsOperation(kPrivateShareMembershipDowngrade,
                                                        my_public_id,
                                                        *results,
                                                        share_id,
                                                        "",
                                                        new_directory_id,
                                                        key_ring,
                                                        new_share_id);
        if (result != kSuccess) {
          LOG(kError) << "Failed to inform contacts of downgrade for " << share_name;
          return result;
        }
        result = user_storage_->InformContactsOperation(kPrivateShareKeysUpdate,
                                                        my_public_id,
                                                        share_members,
                                                        share_id,
                                                        "",
                                                        new_directory_id,
                                                        new_key_ring,
                                                        new_share_id);
        if (result != kSuccess) {
          LOG(kError) << "Failed to inform remaining contacts of share: " << Base32Substr(share_id)
                      << ", with result of : " << result;
        }
      }
    }
  }
  // Upgrade members...
  if (!members_to_upgrade.empty()) {
    if (!upgraded_members_informed) {
      result = user_storage_->GetShareDetails(shared_relative_path,
                                              nullptr,
                                              &new_key_ring,
                                              &share_id,
                                              nullptr,
                                              nullptr,
                                              nullptr);
      results->clear();
      result = user_storage_->UpgradeShareUsersRights(my_public_id,
                                                      share_dir,
                                                      members_to_upgrade,
                                                      results);
      if (result != kSuccess) {
        LOG(kError) << "Failed to upgrade share members for " << share_name;
      }
      result = user_storage_->InformContactsOperation(kPrivateShareMembershipUpgrade,
                                                      my_public_id,
                                                      members_to_upgrade,
                                                      share_id,
                                                      "",
                                                      "",
                                                      new_key_ring,
                                                      "");
      if (result != kSuccess) {
        LOG(kError) << "Failed to inform contacts of upgrade for " << share_name;
        return result;
      }
    }
  }
  // Add new members...
  if (!members_to_add.empty()) {
    StringIntMap add_users_results;
    result += user_storage_->AddShareUsers(my_public_id,
                                           share_dir,
                                           members_to_add,
                                           drive::kMsPrivateShare,
                                           &add_users_results);
    results->insert(add_users_results.begin(), add_users_results.end());
  }
  return kSuccess;
}

int LifeStuffImpl::DeletePrivateShare(const std::string& my_public_id,
                                      const std::string& share_name,
                                      bool delete_data) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in DeletePrivateShare.";
    return result;
  }

  fs::path share_dir(mount_path() / kSharedStuff / share_name);
  result = user_storage_->StopShare(my_public_id, share_dir, delete_data);
  if (result == kSuccess) {
    const ShareInformationDetail share_information(session_.share_information(my_public_id));
    if (!share_information.first) {
      LOG(kError) << "The user holds no such publc identity: " << my_public_id;
      return kPublicIdNotFoundFailure;
    }

    {
      std::unique_lock<std::mutex> loch(*share_information.first);
      share_information.second->erase(share_name);
    }
    session_.set_changed(true);
  }
  return result;
}

int LifeStuffImpl::LeavePrivateShare(const std::string& my_public_id,
                                     const std::string& share_name,
                                     bool inform_contacts) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks in LeavePrivateShare.";
    return result;
  }

  fs::path share_dir(mount_path() / kSharedStuff / share_name);
  result = user_storage_->RemoveShare(share_dir, my_public_id, inform_contacts);
  if (result == kSuccess) {
    const ShareInformationDetail share_information(session_.share_information(my_public_id));
    if (!share_information.first) {
      LOG(kError) << "The user holds no such publc identity: " << my_public_id;
      return kPublicIdNotFoundFailure;
    }

    {
      std::unique_lock<std::mutex> loch(*share_information.first);
      share_information.second->erase(share_name);
    }
    session_.set_changed(true);
  }
  return result;
}

int LifeStuffImpl::CreateOpenShareFromExistingDirectory(const std::string& my_public_id,
                                                        const fs::path& lifestuff_directory,
                                                        const std::vector<std::string>& contacts,
                                                        std::string* share_name,
                                                        StringIntMap* results) {
  if (!share_name) {
    LOG(kError) << "Parameter share name must be valid.";
    return kGeneralError;
  }

  boost::system::error_code error_code;
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks.";
    return result;
  }
  if (!fs::exists(lifestuff_directory)) {
    LOG(kError) << "Share directory nonexistant.";
    return kGeneralError;
  }
  fs::path share_path(mount_path() / kSharedStuff);
  if (!VerifyOrCreatePath(share_path)) {
    LOG(kError) << "Failed to verify or create path to shared stuff.";
    return false;
  }

  *share_name = lifestuff_directory.filename().string();
  std::string generated_name(GetNameInPath(share_path, *share_name));
  if (generated_name.empty()) {
    LOG(kError) << "Failed to generate name for share.";
    return kGeneralError;
  }

  *share_name = generated_name;
  fs::path share(share_path / generated_name);
  StringIntMap liaisons;
  for (uint32_t i = 0; i != contacts.size(); ++i)
    liaisons.insert(std::make_pair(contacts[i], 1));
  result = user_storage_->CreateOpenShare(my_public_id,
                                          lifestuff_directory,
                                          share,
                                          liaisons,
                                          results);
  if (result != kSuccess) {
    LOG(kError) << "Failed to create open share: " << result;
    return result;
  } else {
    const ShareInformationDetail share_information(session_.share_information(my_public_id));
    if (!share_information.first) {
      LOG(kError) << "The user holds no such publc identity: " << my_public_id;
      return kPublicIdNotFoundFailure;
    }

    bool session_changed(false);
    {
      std::unique_lock<std::mutex> loch(*share_information.first);
      auto insert_result(share_information.second->insert(
                             std::make_pair(*share_name, ShareDetails(kOpenOwner))));
      if (!insert_result.second) {
        LOG(kError) << "Failed to insert share into session.";
        return kGeneralError;
      }
      session_changed = true;
    }

    if (session_changed)
      session_.set_changed(true);
  }
  return kSuccess;
}

int LifeStuffImpl::CreateEmptyOpenShare(const std::string& my_public_id,
                                        const std::vector<std::string>& contacts,
                                        std::string* share_name,
                                        StringIntMap* results) {
  if (!share_name) {
    LOG(kError) << "Parameter share name must be valid.";
    return kGeneralError;
  }
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks.";
    return result;
  }

  fs::path share_path(mount_path() / kSharedStuff);
  if (!VerifyOrCreatePath(share_path)) {
    LOG(kError) << "Failed to verify or create path to shared stuff.";
    return false;
  }
  std::string generated_name(GetNameInPath(share_path, *share_name));
  if (generated_name.empty()) {
    LOG(kError) << "Failed to generate name for share.";
    return kGeneralError;
  }

  *share_name = generated_name;
  fs::path share(share_path / generated_name);
  StringIntMap liaisons;
  for (uint32_t i = 0; i != contacts.size(); ++i)
    liaisons.insert(std::make_pair(contacts[i], 1));
  result = user_storage_->CreateOpenShare(my_public_id, fs::path(), share, liaisons, results);
  if (result == kSuccess) {
    const ShareInformationDetail share_information(session_.share_information(my_public_id));
    if (!share_information.first) {
      LOG(kError) << "The user holds no such publc identity: " << my_public_id;
      return kPublicIdNotFoundFailure;
    }

    bool session_changed(false);
    {
      std::unique_lock<std::mutex> loch(*share_information.first);
      auto insert_result(share_information.second->insert(
                             std::make_pair(*share_name, ShareDetails(kOpenOwner))));
      if (!insert_result.second) {
        LOG(kError) << "Failed to insert share into session.";
        return kGeneralError;
      }

      session_changed = true;
    }

    if (session_changed)
      session_.set_changed(true);
  }

  return result;
}

int LifeStuffImpl::InviteMembersToOpenShare(const std::string& my_public_id,
                                            const std::vector<std::string>& contacts,
                                            const std::string& share_name,
                                            StringIntMap* results) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks.";
    return result;
  }
  StringIntMap liaisons;
  fs::path share(mount_path() / drive::kMsShareRoot / share_name);
  for (uint32_t i = 0; i != contacts.size(); ++i)
    liaisons.insert(std::make_pair(contacts[i], 1));
  return user_storage_->OpenShareInvitation(my_public_id, share, liaisons, results);
}

int LifeStuffImpl::GetOpenShareList(const std::string& my_public_id,
                                    std::vector<std::string>* share_names) {
  if (!share_names) {
    LOG(kError) << "Parameter share name must be valid.";
    return kGeneralError;
  }
  int result(PreContactChecksReadOnly(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks.";
    return result;
  }

  const ShareInformationDetail share_information(session_.share_information(my_public_id));
  if (!share_information.first) {
    LOG(kError) << "the user holds no such publc identity: " << my_public_id;
    return kPublicIdNotFoundFailure;
  }

  {
    std::unique_lock<std::mutex> loch(*share_information.first);
    std::for_each(share_information.second->begin(),
                  share_information.second->end(),
                  [=] (const ShareInformation::value_type& element) {
                    if (element.second.share_type <= kOpenOwner)
                      share_names->push_back(element.first);
                  });
  }

  return kSuccess;
}

int LifeStuffImpl::GetOpenShareMembers(const std::string& my_public_id,
                                       const std::string& share_name,
                                       StringIntMap* share_members) {
  if (!share_members) {
    LOG(kError) << "Parameter share name must be valid.";
    return kGeneralError;
  }

  int result(PreContactChecksReadOnly(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks.";
    return result;
  }
  fs::path share_dir(mount_path() / kSharedStuff / share_name);
  result = user_storage_->GetAllShareUsers(share_dir, share_members);
  if (result != kSuccess) {
    LOG(kError) << "Failed to get open share members.";
    return result;
  }

  share_members->erase(my_public_id);

  return kSuccess;
}

int LifeStuffImpl::AcceptOpenShareInvitation(const std::string& my_public_id,
                                             const std::string& contact_public_id,
                                             const std::string& share_id,
                                             std::string* share_name) {
  if (!share_name) {
    LOG(kError) << "Parameter share name must be valid.";
    return kGeneralError;
  }
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks.";
    return result;
  }
  // Read hidden file...
  std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)));
  temp_name += kHiddenFileExtension;
  fs::path hidden_file(mount_path() / kSharedStuff / temp_name);
  std::string serialised_share_data;
  result = user_storage_->ReadHiddenFile(hidden_file, &serialised_share_data);
  if (result != kSuccess || serialised_share_data.empty()) {
    LOG(kError) << "No such identifier found: " << result;
    return result == kSuccess ? kGeneralError : result;
  }
  Message message;
  message.ParseFromString(serialised_share_data);
  // fs::path relative_path(message.content(kShareName));
  std::string directory_id(message.content(kDirectoryId));
  asymm::Keys share_keyring;
  share_keyring.identity = message.content(kKeysIdentity);
  share_keyring.validation_token = message.content(kKeysValidationToken);
  asymm::DecodePrivateKey(message.content(kKeysPrivateKey), &(share_keyring.private_key));
  asymm::DecodePublicKey(message.content(kKeysPublicKey), &(share_keyring.public_key));
  // Delete hidden file...
  user_storage_->DeleteHiddenFile(hidden_file);
  fs::path share_dir(mount_path() / kSharedStuff / *share_name);
  result = user_storage_->InsertShare(share_dir,
                                      share_id,
                                      contact_public_id,
                                      share_name,
                                      directory_id,
                                      share_keyring);
  if (result != kSuccess) {
    LOG(kError) << "Failed to insert share, result " << result;
    return result;
  }
  StringIntMap contacts;
  contacts.insert(std::make_pair(my_public_id, 1));
  result = user_storage_->AddOpenShareUser(share_dir, contacts);
  if (result != kSuccess) {
    LOG(kError) << "Failed to add user to open share, result " << result;
  } else {
    const ShareInformationDetail share_information(session_.share_information(my_public_id));
    if (!share_information.first) {
      LOG(kError) << "The user holds no such publc identity: " << my_public_id;
      return kPublicIdNotFoundFailure;
    }

    {
      std::unique_lock<std::mutex> loch(*share_information.first);
      share_information.second->insert(std::make_pair(*share_name,
                                                      ShareDetails(kOpenReadWriteMember)));
    }
    session_.set_changed(true);
  }
  asymm::Keys keys;
  contacts.clear();
  contacts.insert(std::make_pair(message.sender_public_id(), 0));
  result = user_storage_->InformContactsOperation(kRespondToShareInvitation,
                                                  my_public_id,
                                                  contacts,
                                                  share_id,
                                                  *share_name,
                                                  "",
                                                  keys,
                                                  "");
  return result;
}

int LifeStuffImpl::RejectOpenShareInvitation(const std::string& my_public_id,
                                             const std::string& share_id) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks.";
    return result;
  }
  std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)));
  temp_name += kHiddenFileExtension;
  fs::path hidden_file(mount_path() / kSharedStuff / temp_name);
  std::string serialised_share_data;
  result = user_storage_->ReadHiddenFile(hidden_file, &serialised_share_data);
  if (result != kSuccess || serialised_share_data.empty()) {
    LOG(kError) << "No such identifier found: " << result;
    if (result == drive::kNoMsHidden)
      return kNoShareTarget;
    return result == kSuccess ? kGeneralError : result;
  }
  Message message;
  if (!message.ParseFromString(serialised_share_data))
    LOG(kError) << "Failed to parse data in hidden file for private share.";

  result = user_storage_->DeleteHiddenFile(hidden_file);
  if (result != kSuccess) {
    LOG(kWarning) << "Failed to delete hidden file.";
  }
  asymm::Keys keys;
  StringIntMap contacts;
  contacts.insert(std::make_pair(message.sender_public_id(), 0));
  result = user_storage_->InformContactsOperation(kRespondToShareInvitation,
                                                  my_public_id,
                                                  contacts,
                                                  share_id,
                                                  "",
                                                  "",
                                                  keys,
                                                  "");
  return result;
}

int LifeStuffImpl::LeaveOpenShare(const std::string& my_public_id, const std::string& share_name) {
  int result(PreContactChecksFullAccess(my_public_id));
  if (result != kSuccess) {
    LOG(kError) << "Failed pre checks.";
    return result;
  }
  fs::path share(mount_path() / kSharedStuff / share_name);
  StringIntMap members;
  result = GetOpenShareMembers(my_public_id, share_name, &members);
  if (result != kSuccess) {
    LOG(kError) << "Failed to get members of share " << share;
    return result;
  }
  if (members.size() == 0) {
    result = user_storage_->DeleteHiddenFile(share / drive::kMsShareUsers);
    if (result != kSuccess) {
      LOG(kError) << "Failed to delete " << share / drive::kMsShareUsers;
      return result;
    }

    result = user_storage_->RemoveShare(share);
    if (result != kSuccess) {
      LOG(kError) << "Failed to remove share " << share;
      return result;
    }
  } else {
    std::vector<std::string> member_list(1, my_public_id);
    result = user_storage_->RemoveOpenShareUsers(share, member_list);
    if (result != kSuccess) {
      LOG(kError) << "Failed to remove share user " << my_public_id << " from share " << share;
      return result;
    }
    result = user_storage_->RemoveShare(share);
    if (result != kSuccess) {
      LOG(kError) << "Failed to remove share " << share;
      return result;
    }
  }
  const ShareInformationDetail share_information(session_.share_information(my_public_id));
  if (!share_information.first) {
    LOG(kError) << "The user holds no such publc identity: " << my_public_id;
    return kPublicIdNotFoundFailure;
  }

  {
    std::unique_lock<std::mutex> loch(*share_information.first);
    share_information.second->erase(share_name);
  }
  session_.set_changed(true);

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

  message_handler_->ConnectToShareInvitationResponseSignal(
      [&] (const std::string& user_id,
           const std::string& share_name,
           const std::string&,
           const std::string& share_id,
           const std::string&) {
        user_storage_->InvitationResponse(user_id, share_name, share_id);
      });

  message_handler_->ConnectToSavePrivateShareDataSignal(
      [&] (const std::string& serialised_share_data, const std::string& share_id)->bool {
        return user_storage_->SavePrivateShareData(serialised_share_data, share_id);
      });

  message_handler_->ConnectToDeletePrivateShareDataSignal(
      [&] (const std::string& share_id)->bool {
        return user_storage_->DeletePrivateShareData(share_id);
      });

  message_handler_->ConnectToPrivateShareUserLeavingSignal(
      [&] (const std::string&, const std::string& share_id, const std::string& user_id) {
        user_storage_->UserLeavingShare(share_id, user_id);
      });

  message_handler_->ConnectToSaveOpenShareDataSignal(
      [&] (const std::string& serialised_share_data, const std::string& share_id)->bool {
        return user_storage_->SaveOpenShareData(serialised_share_data, share_id);
      });

  message_handler_->ConnectToPrivateShareDeletionSignal(
      [&] (const std::string&,
           const std::string&,
           const std::string& share_name,
           const std::string&,
           const std::string&) {
        user_storage_->ShareDeleted(share_name);
      });

  message_handler_->ConnectToPrivateShareUpdateSignal(
      [&] (const std::string& share_id,
           const std::string* new_share_id,
           const std::string* new_directory_id,
           const asymm::Keys* new_key_ring,
           int* access_right) {
        user_storage_->UpdateShare(share_id,
                                   new_share_id,
                                   new_directory_id,
                                   new_key_ring,
                                   access_right);
      });

  message_handler_->ConnectToPrivateMemberAccessLevelSignal(
      [&] (const std::string&,
           const std::string&,
           const std::string&,
           const std::string& share_id,
           const std::string& directory_id,
           const std::string& new_share_id,
           const asymm::Keys& key_ring,
           int access_right,
           const std::string&) {
        MemberAccessChangeSlot(share_id, directory_id, new_share_id, key_ring, access_right);
      });

  message_handler_->ConnectToPrivateShareDetailsSignal(
      [&] (const std::string& share_id, fs::path* relative_path) {
      return user_storage_->GetShareDetails(share_id,
                                            relative_path,
                                            nullptr,
                                            nullptr,
                                            nullptr);
      });

  public_id_->ConnectToContactConfirmedSignal(
      [&] (const std::string& own_public_id, const std::string& recipient_public_id,
           const std::string&) {
        message_handler_->InformConfirmedContactOnline(own_public_id, recipient_public_id);
      });

  user_storage_->ConnectToShareRenamedSignal(
      [this] (const std::string& old_share_name, const std::string& new_share_name) {
        this->ShareRenameSlot(old_share_name, new_share_name);
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
  asymm::Keys maid(session_.passport().SignaturePacketDetails(passport::kMaid, true));
  if (maid.identity.empty()) {
    LOG(kError) << "Failed to obtain valid PMID keys.";
    return -1;
  }

  node_->set_keys(maid);
  node_->set_account_name(maid.identity);
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

  user_storage_.reset(new UserStorage(remote_chunk_store_, *message_handler_));

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
                            slots_.private_share_invitation_function,
                            slots_.private_share_deletion_function,
                            slots_.private_access_change_function,
                            slots_.open_share_invitation_function,
                            slots_.share_renamed_function,
                            slots_.share_changed_function,
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

void LifeStuffImpl::ShareRenameSlot(const std::string& old_share_name,
                                    const std::string& new_share_name) {
  std::vector<std::string> identities(session_.PublicIdentities());
  bool modified(false);
  for (auto it(identities.begin()); it != identities.end(); ++it) {
    const ShareInformationDetail share_information(session_.share_information(*it));
    if (!share_information.first) {
      LOG(kError) << "The user holds no such publc identity: " << *it;
      return;
    }

    std::unique_lock<std::mutex> loch(*share_information.first);
    auto itr(share_information.second->find(old_share_name));
    if (itr != share_information.second->end()) {
      share_information.second->insert(std::make_pair(new_share_name, (*itr).second));
      share_information.second->erase(old_share_name);
      modified = true;
    }
  }
  if (modified)
    session_.set_changed(true);
}

void LifeStuffImpl::MemberAccessChangeSlot(const std::string& share_id,
                                           const std::string& directory_id,
                                           const std::string& new_share_id,
                                           const asymm::Keys& key_ring,
                                           int access_right) {
  std::string share_name(user_storage_->MemberAccessChange(share_id,
                                                           directory_id,
                                                           new_share_id,
                                                           key_ring,
                                                           access_right));
  if (!share_name.empty()) {
    std::vector<std::string> identities(session_.PublicIdentities());
    for (auto it(identities.begin()); it != identities.end(); ++it) {
      const ShareInformationDetail share_information(session_.share_information(*it));
      if (!share_information.first) {
        LOG(kError) << "The user holds no such publc identity: " << (*it);
        return;
      }

      bool session_changed(false);
      {
        std::unique_lock<std::mutex> loch(*share_information.first);
        auto itr(share_information.second->find(share_name));
        if (itr != share_information.second->end()) {
          if (access_right == kShareReadOnly &&
                  ((*itr).second.share_type == kOpenReadWriteMember ||
                  (*itr).second.share_type == kPrivateReadWriteMember)) {
            (*itr).second.share_type -= 1;
            session_changed = true;
          } else if (access_right == kShareReadWrite &&
                         ((*itr).second.share_type == kOpenReadOnlyMember ||
                         (*itr).second.share_type == kPrivateReadOnlyMember)) {
            (*itr).second.share_type += 1;
            session_changed = true;
          }
        }
      }

      if (session_changed)
        session_.set_changed(true);
    }
  }
}

void LifeStuffImpl::NetworkHealthSlot(const int& index) {
  network_health_signal_(index);
}


#ifndef LOCAL_TARGETS_ONLY
int LifeStuffImpl::CreateVaultInLocalMachine(const fs::path& chunk_store, bool vault_cheat) {
  std::string account_name(session_.passport().SignaturePacketDetails(passport::kMaid,
                                                                      true).identity);
  asymm::Keys pmid_keys(session_.passport().SignaturePacketDetails(passport::kPmid, true));
  if (account_name.empty() || pmid_keys.identity.empty()) {
    LOG(kError) << "Failed to obtain credentials to start vault from session.";
    return kVaultCreationFailure;
  }

  if (vault_cheat) {
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
      return kVaultCreationFailure;
    }
  } else {
    if (!client_controller_->StartVault(pmid_keys, account_name, chunk_store)) {
      LOG(kError) << "Failed to create vault through client controller.";
      return kVaultCreationFailure;
    }
  }

  return kSuccess;
}

int LifeStuffImpl::EstablishMaidRoutingObject(
    const std::vector<std::pair<std::string, uint16_t> >& bootstrap_endpoints) {  // NOLINT (Dan)
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
