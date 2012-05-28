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
#include <vector>

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/utils.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/dht/contact.h"
#endif

#include "maidsafe/encrypt/data_map.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/rcs_helper.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/message_handler.h"
#include "maidsafe/lifestuff/detail/public_id.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/user_credentials.h"
#include "maidsafe/lifestuff/detail/user_storage.h"
namespace args = std::placeholders;

namespace maidsafe {

namespace lifestuff {

LifeStuffImpl::LifeStuffImpl()
    : thread_count_(kThreads),
      state_(kZeroth),
      buffered_path_(),
#ifdef LOCAL_TARGETS_ONLY
      simulation_path_(),
#endif
      interval_(kSecondsInterval),
      asio_service_(),
      remote_chunk_store_(),
#ifndef LOCAL_TARGETS_ONLY
      client_container_(),
#endif
      session_(),
      user_credentials_(),
      user_storage_(),
      public_id_(),
      message_handler_(),
      slots_(),
      save_session_mutex_(),
      saving_session_(false) {}

LifeStuffImpl::~LifeStuffImpl() {}

int LifeStuffImpl::Initialise(const boost::filesystem::path &base_directory) {
  if (state_ != kZeroth) {
    DLOG(ERROR) << "Make sure that object is in the original Zeroth state. "
                << "Asimov rules.";
    return kGeneralError;
  }

  // Initialisation
  asio_service_.Start(thread_count_);
  session_.reset(new Session);

  fs::path base_path, buffered_chunk_store_path, network_simulation_path;
  if (base_directory.empty()) {
    // Not a test: everything in $HOME/.lifestuff
    base_path = GetHomeDir() / kAppHomeDirectory;
    buffered_chunk_store_path = base_path / RandomAlphaNumericString(16);
    boost::system::error_code error_code;
    network_simulation_path = fs::temp_directory_path(error_code) /
                              "lifestuff_simulation";
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
  remote_chunk_store_ = BuildChunkStore(buffered_chunk_store_path,
                                        &client_container_);
#endif
  if (!remote_chunk_store_) {
    DLOG(ERROR) << "Could not initialise chunk store.";
    return kGeneralError;
  }

  buffered_path_ = buffered_chunk_store_path;

  user_credentials_.reset(new UserCredentials(remote_chunk_store_, session_));

  state_ = kInitialised;

  return kSuccess;
}

int LifeStuffImpl::ConnectToSignals(
    const ChatFunction &chat_slot,
    const FileTransferFunction &file_slot,
    const NewContactFunction &new_contact_slot,
    const ContactConfirmationFunction &confirmed_contact_slot,
    const ContactProfilePictureFunction &profile_picture_slot,
    const ContactPresenceFunction &contact_presence_slot,
    const ContactDeletionFunction &contact_deletion_function,
    const PrivateShareInvitationFunction &private_share_invitation_function,
    const PrivateShareDeletionFunction &private_share_deletion_function,
    const PrivateMemberAccessLevelFunction &private_access_level_function,
    const OpenShareInvitationFunction &open_share_invitation_function,
    const ShareRenamedFunction &share_renamed_function) {
  if (state_ != kInitialised) {
    DLOG(ERROR) << "Make sure that object is initialised";
    return kGeneralError;
  }

  int connects(0);
  if (chat_slot) {
    slots_.chat_slot = chat_slot;
    ++connects;
    if (message_handler_)
      message_handler_->ConnectToChatSignal(chat_slot);
  }
  if (file_slot) {
    slots_.file_slot = file_slot;
    ++connects;
    if (message_handler_)
      message_handler_->ConnectToFileTransferSignal(file_slot);
  }
  if (new_contact_slot) {
    slots_.new_contact_slot = new_contact_slot;
    ++connects;
    if (public_id_)
      public_id_->ConnectToNewContactSignal(new_contact_slot);
  }
  if (confirmed_contact_slot) {
    slots_.confirmed_contact_slot = confirmed_contact_slot;
    ++connects;
    if (public_id_)
      public_id_->ConnectToContactConfirmedSignal(confirmed_contact_slot);
  }
  if (profile_picture_slot) {
    slots_.profile_picture_slot = profile_picture_slot;
    ++connects;
    if (message_handler_)
      message_handler_->ConnectToContactProfilePictureSignal(
          profile_picture_slot);
  }
  if (contact_presence_slot) {
    slots_.contact_presence_slot = contact_presence_slot;
    ++connects;
    if (message_handler_)
      message_handler_->ConnectToContactPresenceSignal(contact_presence_slot);
  }
  if (contact_deletion_function) {
    slots_.contact_deletion_function = contact_deletion_function;
    ++connects;
    if (message_handler_)
      message_handler_->ConnectToContactDeletionSignal(
          contact_deletion_function);
  }
  if (private_share_invitation_function) {
    slots_.private_share_invitation_function =
        private_share_invitation_function;
    ++connects;
    if (message_handler_)
      message_handler_->ConnectToPrivateShareInvitationSignal(
          private_share_invitation_function);
  }
  if (private_share_deletion_function) {
    slots_.private_share_deletion_function =
        private_share_deletion_function;
    ++connects;
    if (message_handler_)
      message_handler_->ConnectToPrivateShareDeletionSignal(
          private_share_deletion_function);
  }
  if (private_access_level_function) {
    slots_.private_access_level_function = private_access_level_function;
    ++connects;
    if (message_handler_)
      message_handler_->ConnectToPrivateMemberAccessLevelSignal(
          private_access_level_function);
  }
  if (open_share_invitation_function) {
    slots_.open_share_invitation_function = open_share_invitation_function;
    ++connects;
    if (message_handler_)
      message_handler_->ConnectToOpenShareInvitationSignal(
          open_share_invitation_function);
  }
  if (share_renamed_function) {
    slots_.share_renamed_function = share_renamed_function;
    ++connects;
    if (user_storage_)
      user_storage_->ConnectToShareRenamedSignal(share_renamed_function);
  }

  if (connects > 0) {
    state_ = kConnected;
    return kSuccess;
  }

  return kGeneralError;
}

int LifeStuffImpl::Finalise() {
  if (state_ != kLoggedOut) {
    DLOG(ERROR) << "Need to be logged out to finalise.";
    return kGeneralError;
  }

  boost::system::error_code error_code;
  fs::remove_all(buffered_path_, error_code);
  if (error_code)
    DLOG(WARNING) << "Failed to remove buffered chunk store path.";

  asio_service_.Stop();
  remote_chunk_store_.reset();
#ifndef LOCAL_TARGETS_ONLY
  client_container_.reset();
#endif
  message_handler_.reset();
  public_id_.reset();
  session_.reset();
  user_credentials_.reset();
  user_storage_.reset();
  state_ = kZeroth;

  return kSuccess;
}

/// Credential operations
int LifeStuffImpl::CreateUser(const std::string &keyword,
                              const std::string &pin,
                              const std::string &password) {
  if (state_ != kConnected) {
    DLOG(ERROR) << "Make sure that object is initialised and connected";
    return kGeneralError;
  }

  int result(user_credentials_->CreateUser(keyword, pin, password));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to Create User.";
    return result;
  }

  result = SetValidPmidAndInitialisePublicComponents();
  if (result != kSuccess)  {
    DLOG(ERROR) << "Failed to set valid PMID";
    return result;
  }

  boost::system::error_code error_code;
  fs::path mount_dir(GetHomeDir() /
                     kAppHomeDirectory /
                     session_->session_name());
  if (!fs::exists(mount_dir, error_code)) {
    fs::create_directories(mount_dir, error_code);
    if (error_code) {
      DLOG(ERROR) << "Failed to create app directories - " << error_code.value()
                  << ": " << error_code.message();
      return kGeneralError;
    }
  }

  user_storage_->MountDrive(mount_dir, session_, true);
  if (!user_storage_->mount_status()) {
    DLOG(ERROR) << "Failed to mount";
    return kGeneralError;
  }

  fs::path mount_path(user_storage_->mount_dir());
  fs::create_directories(mount_path / kMyStuff / kDownloadStuff,
                         error_code);
  if (error_code) {
    DLOG(ERROR) << "Failed creating My Stuff: " << error_code.message();
    return kGeneralError;
  }
  fs::create_directory(mount_path / kSharedStuff, error_code);
  if (error_code) {
    DLOG(ERROR) << "Failed creating Shared Stuff: " << error_code.message();
    return kGeneralError;
  }
  result = user_credentials_->SaveSession();
  if (result != kSuccess) {
    DLOG(WARNING) << "Failed to save session.";
  }

  state_ = kLoggedIn;

  return kSuccess;
}

int LifeStuffImpl::CreatePublicId(const std::string &public_id) {
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Wrong state to create a public ID.";
    return kGeneralError;
  }

  // Check if it's the 1st one
  bool first_public_id(false);
  if (session_->contact_handler_map().empty())
    first_public_id = true;

  int result(public_id_->CreatePublicId(public_id, true));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to create public ID.";
    return result;
  }

  if (first_public_id) {
    public_id_->StartCheckingForNewContacts(interval_);
    message_handler_->StartUp(interval_);
  }

  InvokeDoSession();

  return kSuccess;
}

int LifeStuffImpl::LogIn(const std::string &keyword,
                         const std::string &pin,
                         const std::string &password) {
  if (!(state_ == kConnected || state_ == kLoggedOut)) {
    DLOG(ERROR) << "Make sure that object is initialised and connected";
    return kGeneralError;
  }

  int result(user_credentials_->LogIn(keyword, pin, password));
  if (result != kSuccess) {
    DLOG(ERROR) << "User doesn't exist.";
    return result;
  }

  result =SetValidPmidAndInitialisePublicComponents();
  if (result != kSuccess)  {
    DLOG(ERROR) << "Failed to set valid PMID";
    return result;
  }

  boost::system::error_code error_code;
  fs::path mount_dir(GetHomeDir() /
                     kAppHomeDirectory /
                     session_->session_name());
  if (!fs::exists(mount_dir, error_code)) {
    if (error_code) {
      if (error_code.value() == boost::system::errc::not_connected) {
        DLOG(ERROR) << "\tHint: Try unmounting the drive manually.";
        return kGeneralError;
      } else if (error_code != boost::system::errc::no_such_file_or_directory) {
        if (!fs::create_directories(mount_dir, error_code) || error_code) {
          DLOG(ERROR) << "Failed to create mount directory at "
                      << mount_dir.string() << " - " << error_code.value()
                      << ": " << error_code.message();
          return kGeneralError;
        }
      }
    }
  }

  user_storage_->MountDrive(mount_dir, session_, false);

  if (!user_storage_->mount_status()) {
    DLOG(ERROR) << "Failed to mount";
    return kGeneralError;
  }

  if (!session_->contact_handler_map().empty()) {
    public_id_->StartUp(interval_);
    message_handler_->StartUp(interval_);
  }

  state_ = kLoggedIn;

  return kSuccess;
}

int LifeStuffImpl::LogOut() {
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Should be logged in to log out.";
    return kGeneralError;
  }

  bool saving_session(true);
  while (saving_session) {
    {
      boost::mutex::scoped_lock loch_tangy(save_session_mutex_);
      saving_session = saving_session_;
    }
    Sleep(bptime::milliseconds(100));
  }

  user_storage_->UnMountDrive();
  if (user_storage_->mount_status()) {
    DLOG(ERROR) << "Failed to un-mount.";
    return kGeneralError;
  }

  public_id_->ShutDown();
  message_handler_->ShutDown();

  if (user_credentials_->Logout() != kSuccess) {
    DLOG(ERROR) << "Failed to log out.";
    return kGeneralError;
  }

  if (!remote_chunk_store_->WaitForCompletion()) {
    DLOG(ERROR) << "Failed complete chunk operations.";
    return kGeneralError;
  }

  // Delete mount directory
  boost::system::error_code error_code;
  fs::remove_all(mount_path(), error_code);
  if (error_code)
    DLOG(WARNING) << "Failed to delete mount directory: "
                  << mount_path();
  session_->Reset();

  state_ = kLoggedOut;

  return kSuccess;
}

int LifeStuffImpl::CheckPassword(const std::string &password) {
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Should be logged in to log out.";
    return kGeneralError;
  }

  return session_->password() == password ? kSuccess : kGeneralError;
}

int LifeStuffImpl::ChangeKeyword(const std::string &new_keyword,
                                 const std::string &password) {
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Should be logged in to log out.";
    return kGeneralError;
  }

  int result(CheckPassword(password));
  if (result != kSuccess) {
    DLOG(ERROR) << "Password verification failed.";
    return result;
  }

  if (new_keyword.compare(session_->keyword()) == 0) {
    DLOG(INFO) << "Same value for old and new.";
    return kSuccess;
  }

  return user_credentials_->ChangeKeyword(new_keyword);
}

int LifeStuffImpl::ChangePin(const std::string &new_pin,
                             const std::string &password) {
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Should be logged in to log out.";
    return kGeneralError;
  }

  int result(CheckPassword(password));
  if (result != kSuccess) {
    DLOG(ERROR) << "Password verification failed.";
    return result;
  }

  if (new_pin.compare(session_->pin()) == 0) {
    DLOG(INFO) << "Same value for old and new.";
    return kSuccess;
  }

  return user_credentials_->ChangePin(new_pin);
}

int LifeStuffImpl::ChangePassword(const std::string &new_password,
                                  const std::string &current_password) {
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Should be logged in to log out.";
    return kGeneralError;
  }

  int result(CheckPassword(current_password));
  if (result != kSuccess) {
    DLOG(ERROR) << "Password verification failed.";
    return result;
  }

  if (current_password.compare(new_password) == 0) {
    DLOG(INFO) << "Same value for old and new.";
    return kSuccess;
  }

  return user_credentials_->ChangePassword(new_password);
}

/// Contact operations
int LifeStuffImpl::AddContact(const std::string &my_public_id,
                              const std::string &contact_public_id) {
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in AddContact.";
    return result;
  }

  return public_id_->SendContactInfo(my_public_id, contact_public_id, true);
}

int LifeStuffImpl::ConfirmContact(const std::string &my_public_id,
                                  const std::string &contact_public_id) {
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in ConfirmContact.";
    return result;
  }

  result = public_id_->ConfirmContact(my_public_id, contact_public_id, true);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to Confirm Contact.";
    return result;
  }

  return message_handler_->SendPresenceMessage(my_public_id,
                                               contact_public_id,
                                               kOnline);
}

int LifeStuffImpl::DeclineContact(const std::string &my_public_id,
                                  const std::string &contact_public_id) {
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in DeclineContact.";
    return result;
  }

  return public_id_->ConfirmContact(my_public_id, contact_public_id, false);
}

int LifeStuffImpl::RemoveContact(const std::string &my_public_id,
                                 const std::string &contact_public_id,
                                 const std::string &removal_message) {
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in RemoveContact.";
    return result;
  }

  // For private shares, if share_members can be fetched, indicates owner
  // otherwise, only the owner(inviter) of the share can be fetched
  std::vector<std::string> share_names;
  GetPrivateSharesIncludingMember(my_public_id,
                                  contact_public_id,
                                  &share_names);
  StringIntMap contact_to_remove;
  contact_to_remove.insert(std::make_pair(contact_public_id, kShareRemover));
  for (auto it = share_names.begin(); it != share_names.end(); ++it) {
    StringIntMap results;
    EditPrivateShareMembers(my_public_id, contact_to_remove, *it, &results);
  }
  share_names.clear();
  user_storage_->GetPrivateSharesContactBeingOwner(my_public_id,
                                                   contact_public_id,
                                                   &share_names);
  for (auto it = share_names.begin(); it != share_names.end(); ++it)
    LeavePrivateShare(my_public_id, *it);

  // Send message to removal
  InboxItem inbox_item(kContactDeletion);
  inbox_item.receiver_public_id = contact_public_id;
  inbox_item.sender_public_id = my_public_id;
  inbox_item.content.push_back(removal_message);

  result = message_handler_->Send(inbox_item);
  if (result != kSuccess)
    DLOG(ERROR) << "Failed in sending out removal message.";

  // Remove the contact
  result = public_id_->RemoveContact(my_public_id, contact_public_id);
  if (result != kSuccess)
    DLOG(ERROR) << "Failed remove contact in RemoveContact.";

  return result;
}

int LifeStuffImpl::ChangeProfilePicture(
    const std::string &my_public_id,
    const std::string &profile_picture_contents) {
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in ChangeProfilePicture.";
    return result;
  }

  if (profile_picture_contents.empty() ||
      profile_picture_contents.size() > kFileRecontructionLimit) {
    DLOG(ERROR) << "Contents of picture inadequate("
                << profile_picture_contents.size() << "). Good day!";
    return kGeneralError;
  }

  // Message construction
  InboxItem message(kContactProfilePicture);
  message.sender_public_id = my_public_id;

  if (profile_picture_contents != kBlankProfilePicture) {
    // Write contents
    fs::path profile_picture_path(mount_path() /
                                  std::string(my_public_id +
                                              "_profile_picture" +
                                              kHiddenFileExtension));
    if (WriteHiddenFile(profile_picture_path,
                        profile_picture_contents,
                        true) !=
        kSuccess) {
      DLOG(ERROR) << "Failed to write profile picture file: "
                  << profile_picture_path;
      return kGeneralError;
    }


    // Get datamap
    std::string data_map;
    std::string reconstructed;
    int count(0), limit(100);
    while (reconstructed != profile_picture_contents && count++ < limit) {
      data_map.clear();
      result = user_storage_->GetHiddenFileDataMap(profile_picture_path,
                                                   &data_map);
      if ((result != kSuccess || data_map.empty()) && count == limit) {
        DLOG(ERROR) << "Failed obtaining DM of profile picture: " << result
                    << ", file: " << profile_picture_path;
        return result;
      }

      reconstructed = user_storage_->ConstructFile(data_map);
      Sleep(bptime::milliseconds(50));
    }
    message.content.push_back(data_map);
  } else {
    message.content.push_back(kBlankProfilePicture);
  }

  // Set in session
  session_->set_profile_picture_data_map(my_public_id, message.content[0]);

  // Send to everybody
  message_handler_->SendEveryone(message);

  return kSuccess;
}

std::string LifeStuffImpl::GetOwnProfilePicture(
    const std::string &my_public_id) {
  // Read contents, put them in a string, give them back. Should not be a file
  // over a certain size (kFileRecontructionLimit).
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in ChangeProfilePicture.";
    return "";
  }

  fs::path profile_picture_path(mount_path() /
                                std::string(my_public_id +
                                            "_profile_picture" +
                                            kHiddenFileExtension));
  std::string profile_picture_contents;
  if (ReadHiddenFile(profile_picture_path,
                     &profile_picture_contents) != kSuccess ||
      profile_picture_contents.empty()) {
    DLOG(ERROR) << "Failed reading profile picture: " << profile_picture_path;
    return "";
  }

  return profile_picture_contents;
}

std::string LifeStuffImpl::GetContactProfilePicture(
    const std::string &my_public_id,
    const std::string &contact_public_id) {
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in GetContactProfilePicture.";
    return "";
  }

  // Look up data map in session.
  Contact contact;
  result = session_->contact_handler_map()
               [my_public_id]->ContactInfo(contact_public_id, &contact);
  if (result != kSuccess || contact.profile_picture_data_map.empty()) {
    DLOG(ERROR) << "No such contact(" << result << "): " << contact_public_id;
    return "";
  }

  // Might be blank
  if (contact.profile_picture_data_map == kBlankProfilePicture) {
    DLOG(INFO) << "Blank image detected. No reconstruction needed.";
    return kBlankProfilePicture;
  }

  // Read contents, put them in a string, give them back. Should not be
  // over a certain size (kFileRecontructionLimit).
  return user_storage_->ConstructFile(contact.profile_picture_data_map);
}

ContactMap LifeStuffImpl::GetContacts(const std::string &my_public_id,
                                      uint16_t bitwise_status) {
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in GetContacts.";
    return ContactMap();
  }

  return session_->contact_handler_map()
             [my_public_id]->GetContacts(bitwise_status);
}

std::vector<std::string> LifeStuffImpl::PublicIdsList() const {
  std::vector<std::string> public_ids;
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << state_;
    return public_ids;
  }


  // Retrieve all keys
  std::transform(session_->contact_handler_map().begin(),
                 session_->contact_handler_map().end(),
                 std::back_inserter(public_ids),
                 std::bind(&ContactHandlerMap::value_type::first, args::_1));


  return public_ids;
}

/// Messaging
int LifeStuffImpl::SendChatMessage(const std::string &sender_public_id,
                                   const std::string &receiver_public_id,
                                   const std::string &message) {
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << state_;
    return kGeneralError;
  }

  if (message.size() > kMaxChatMessageSize) {
    DLOG(ERROR) << "Message too large: " << message.size();
    return kGeneralError;
  }

  InboxItem inbox_item(kChat);
  inbox_item.receiver_public_id = receiver_public_id;
  inbox_item.sender_public_id = sender_public_id;
  inbox_item.content.push_back(message);

  return message_handler_->Send(inbox_item);
}

int LifeStuffImpl::SendFile(const std::string &sender_public_id,
                            const std::string &receiver_public_id,
                            const fs::path &absolute_path) {
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << state_;
    return kGeneralError;
  }

  std::string serialised_datamap;
  int result(user_storage_->GetDataMap(absolute_path, &serialised_datamap));
  if (result != kSuccess || serialised_datamap.empty()) {
    DLOG(ERROR) << "Failed to get DM for " << absolute_path << ": " << result;
    return result;
  }

  InboxItem inbox_item(kFileTransfer);
  inbox_item.receiver_public_id = receiver_public_id;
  inbox_item.sender_public_id = sender_public_id;
  inbox_item.content.push_back(absolute_path.filename().string());
  inbox_item.content.push_back(serialised_datamap);

  result = message_handler_->Send(inbox_item);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to send message: " << result;
    return result;
  }

  return kSuccess;
}

int LifeStuffImpl::AcceptSentFile(const std::string &identifier,
                                  const fs::path &absolute_path,
                                  std::string *file_name) {
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << state_;
    return kGeneralError;
  }

  if ((absolute_path.empty() && !file_name) ||
      (!absolute_path.empty() && file_name)) {
    DLOG(ERROR) << "Wrong parameters given. absolute_path and file_name are "
                << "mutually exclusive.";
    return kGeneralError;
  }

  std::string serialised_identifier, saved_file_name, serialised_data_map;
  int result(user_storage_->ReadHiddenFile(mount_path() /
                                               std::string(identifier +
                                                    kHiddenFileExtension),
                                           &serialised_identifier));
  if (result != kSuccess || serialised_identifier.empty()) {
    DLOG(ERROR) << "No such identifier found: " << result;
    return result == kSuccess ? kGeneralError : result;
  }

  GetFilenameData(serialised_identifier,
                  &saved_file_name,
                  &serialised_data_map);
  if (saved_file_name.empty() || serialised_data_map.empty()) {
    DLOG(ERROR) << "Failed to get filename or datamap.";
    return kGeneralError;
  }

  drive::DataMapPtr data_map_ptr(ParseSerialisedDataMap(serialised_data_map));
  if (!data_map_ptr) {
    DLOG(ERROR) << "Corrupted DM in file";
    return kGeneralError;
  }

  if (absolute_path.empty()) {
    fs::path store_path(mount_path() / kMyStuff / kDownloadStuff);
    if (!VerifyOrCreatePath(store_path)) {
      DLOG(ERROR) << "Failed finding and creating: " << store_path;
      return kGeneralError;
    }
    std::string adequate_name(GetNameInPath(store_path, saved_file_name));
    if (adequate_name.empty()) {
      DLOG(ERROR) << "No name found to work for saving the file.";
      return kGeneralError;
    }
    result = user_storage_->InsertDataMap(store_path / adequate_name,
                                          serialised_data_map);

    if (result != kSuccess) {
      DLOG(ERROR) << "Failed inserting DM: " << result;
      return result;
    }
    *file_name = adequate_name;
  } else {
    result = user_storage_->InsertDataMap(absolute_path, serialised_data_map);
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed inserting DM: " << result;
      return result;
    }
  }

  return kSuccess;
}

int LifeStuffImpl::RejectSentFile(const std::string &identifier) {
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << state_;
    return kGeneralError;
  }

  fs::path hidden_file(mount_path() /
                       std::string(identifier + kHiddenFileExtension));
  return user_storage_->DeleteHiddenFile(hidden_file);
}

/// Filesystem
int LifeStuffImpl::ReadHiddenFile(const fs::path &absolute_path,
                                  std::string *content) const {
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << state_;
    return kGeneralError;
  }

  if (!content) {
    DLOG(ERROR) << "Content parameter must be valid.";
    return kGeneralError;
  }

  return user_storage_->ReadHiddenFile(absolute_path, content);
}

int LifeStuffImpl::WriteHiddenFile(const fs::path &absolute_path,
                                   const std::string &content,
                                   bool overwrite_existing) {
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << state_;
    return kGeneralError;
  }

  return user_storage_->WriteHiddenFile(absolute_path,
                                        content,
                                        overwrite_existing);
}

int LifeStuffImpl::DeleteHiddenFile(const fs::path &absolute_path) {
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << state_;
    return kGeneralError;
  }

  return user_storage_->DeleteHiddenFile(absolute_path);
}

/// Private Shares
int LifeStuffImpl::CreatePrivateShareFromExistingDirectory(
    const std::string &my_public_id,
    const fs::path &directory_in_lifestuff_drive,
    const StringIntMap &contacts,
    std::string *share_name,
    StringIntMap *results) {
  if (!share_name) {
    DLOG(ERROR) << "Share name parameter must be valid.";
    return kGeneralError;
  }
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in "
                << "CreatePrivateShareFromExistingDirectory.";
    return result;
  }
  boost::system::error_code error_code;
  if (!fs::exists(directory_in_lifestuff_drive, error_code) || error_code) {
    DLOG(ERROR) << "Target Directory doesn't exist";
    return kNoShareTarget;
  }
  fs::path store_path(mount_path() / kSharedStuff);
  if (!VerifyOrCreatePath(store_path)) {
    DLOG(ERROR) << "Failed to verify or create path to shared stuff.";
    return false;
  }

  *share_name = directory_in_lifestuff_drive.filename().string();
  std::string generated_name(GetNameInPath(store_path, *share_name));
  if (generated_name.empty()) {
    DLOG(ERROR) << "Failed to generate name for share.";
    return kGeneralError;
  }

  *share_name = generated_name;
  fs::path share_dir(store_path / generated_name);
  return user_storage_->CreateShare(my_public_id,
                                    directory_in_lifestuff_drive,
                                    share_dir,
                                    contacts,
                                    drive::kMsPrivateShare,
                                    results);
}

int LifeStuffImpl::CreateEmptyPrivateShare(const std::string &my_public_id,
                                           const StringIntMap &contacts,
                                           std::string *share_name,
                                           StringIntMap *results) {
  if (!share_name) {
    DLOG(ERROR) << "Share name must be provided.";
    return kGeneralError;
  }

  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in CreateEmptyPrivateShare.";
    return result;
  }

  fs::path store_path(mount_path() / kSharedStuff);
  if (!VerifyOrCreatePath(store_path)) {
    DLOG(ERROR) << "Failed to verify or create path to shared stuff.";
    return false;
  }

  std::string generated_name(GetNameInPath(store_path, *share_name));
  if (generated_name.empty()) {
    DLOG(ERROR) << "Failed to generate name for share.";
    return kGeneralError;
  }

  *share_name = generated_name;
  fs::path share_dir(store_path / generated_name);
  return user_storage_->CreateShare(my_public_id,
                                    fs::path(),
                                    share_dir,
                                    contacts,
                                    drive::kMsPrivateShare,
                                    results);
}

int LifeStuffImpl::GetPrivateShareList(const std::string &my_public_id,
                                       StringIntMap *share_names) {
  if (!share_names) {
    DLOG(ERROR) << "Share names parameter must be valid.";
    return kGeneralError;
  }

  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in GetPrivateShareList.";
    return result;
  }

  return user_storage_->GetAllShares(share_names);
}

int LifeStuffImpl::GetPrivateShareMembers(const std::string &my_public_id,
                                          const std::string &share_name,
                                          StringIntMap *share_members) {
  if (!share_members) {
    DLOG(ERROR) << "Share members parameter must be valid.";
    return kGeneralError;
  }
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in GetPrivateShareMemebers.";
    return result;
  }

  fs::path share_dir(mount_path() / kSharedStuff / share_name);
  result = user_storage_->GetAllShareUsers(share_dir, share_members);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in GetPrivateShareMemebers.";
    return result;
  }

  auto it(share_members->find(my_public_id));
  share_members->erase(it);

  return kSuccess;
}

int LifeStuffImpl::GetPrivateSharesIncludingMember(
    const std::string &my_public_id,
    const std::string &contact_public_id,
    std::vector<std::string> *share_names) {
  if (!share_names) {
    DLOG(ERROR) << "Share names parameter must be valid.";
    return kGeneralError;
  }
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in GetPrivateShareList.";
    return result;
  }

  StringIntMap all_share_names;
  result = user_storage_->GetAllShares(&all_share_names);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed getting all shares in "
                << "GetPrivateSharesIncludingMember.";
    return result;
  }

  for (auto it = all_share_names.begin(); it != all_share_names.end(); ++it) {
    StringIntMap share_members;
    fs::path share_dir(mount_path() / kSharedStuff / (*it).first);
    result = user_storage_->GetAllShareUsers(share_dir, &share_members);
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed to get members for " << share_dir.string();
    } else {
      std::vector<std::string> member_ids;
      for (auto itr = share_members.begin();
           itr != share_members.end(); ++itr)
        member_ids.push_back((*itr).first);
      auto itr(std::find(member_ids.begin(),
                         member_ids.end(),
                         contact_public_id));
      if (itr != member_ids.end())
        share_names->push_back((*it).first);
    }
  }
  return kSuccess;
}

int LifeStuffImpl::AcceptPrivateShareInvitation(
    const std::string &my_public_id,
    const std::string &contact_public_id,
    const std::string &share_id,
    std::string *share_name) {
  if (!share_name) {
    DLOG(ERROR) << "Share name parameter must be valid.";
    return kGeneralError;
  }

  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in AcceptPrivateShareInvitation.";
    return result;
  }
  std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)) +
                        kHiddenFileExtension);
  fs::path hidden_file(mount_path() / kSharedStuff / temp_name);
  std::string serialised_share_data;
  result = user_storage_->ReadHiddenFile(hidden_file, &serialised_share_data);
  if (result != kSuccess || serialised_share_data.empty()) {
    DLOG(ERROR) << "No such identifier found: " << result;
    return result == kSuccess ? kGeneralError : result;
  }
  Message message;
  if (!message.ParseFromString(serialised_share_data)) {
    DLOG(ERROR) << "Failed to parse data in hidden file for private share.";
    return kGeneralError;
  }

  fs::path relative_path(message.content(1));
  std::string directory_id(message.content(2));
  asymm::Keys share_keyring;
  if (message.content_size() > 3) {
    share_keyring.identity = message.content(3);
    share_keyring.validation_token = message.content(4);
    asymm::DecodePrivateKey(message.content(5), &(share_keyring.private_key));
    asymm::DecodePublicKey(message.content(6), &(share_keyring.public_key));
  }

  // remove the temp share invitation file no matter insertion succeed or not
  user_storage_->DeleteHiddenFile(hidden_file);

  fs::path share_dir(mount_path() / kSharedStuff / *share_name);
  return user_storage_->InsertShare(share_dir,
                                    share_id,
                                    contact_public_id,
                                    share_name,
                                    directory_id,
                                    share_keyring);
}

int LifeStuffImpl::RejectPrivateShareInvitation(const std::string &my_public_id,
                                                const std::string &share_id) {
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in RejectPrivateShareInvitation.";
    return result;
  }
  std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)) +
                        kHiddenFileExtension);
  fs::path hidden_file(mount_path() / kSharedStuff / temp_name);
  return user_storage_->DeleteHiddenFile(hidden_file);
}

int LifeStuffImpl::EditPrivateShareMembers(const std::string &my_public_id,
                                           const StringIntMap &public_ids,
                                           const std::string &share_name,
                                           StringIntMap *results) {
  if (!results) {
    DLOG(ERROR) << "Results parameter must be valid.";
    return kGeneralError;
  }

  StringIntMap share_members;
  int result(GetPrivateShareMembers(my_public_id, share_name, &share_members));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failure to get members.";
    return result;
  }

  std::vector<std::string> member_ids;
  for (auto it = share_members.begin(); it != share_members.end(); ++it)
    member_ids.push_back((*it).first);

  StringIntMap members_to_add, members_to_upgrade, members_to_downgrade;
  std::vector<std::string> members_to_remove;
  for (auto it = public_ids.begin(); it != public_ids.end(); ++it) {
    auto itr(std::find(member_ids.begin(), member_ids.end(), (*it).first));
    if (itr != member_ids.end()) {
      // -1 indicates removing the existing member
      // 0 indicates downgrading the existing member
      // 1 indicates upgrading the existing member
      if ((*it).second == kShareRemover)
        members_to_remove.push_back(*itr);
      if (share_members[(*it).first] != (*it).second) {
        if ((*it).second == kShareReadOnly)
          members_to_downgrade.insert(*it);
        if ((*it).second >= kShareReadWrite)
          members_to_upgrade.insert(*it);
      }
    } else {
      // a non-existing user indicates an adding
      members_to_add.insert(*it);
    }
  }
  fs::path share_dir(mount_path() / kSharedStuff / share_name);
  // Add new users
  if (!members_to_add.empty()) {
    StringIntMap add_users_results;
    result += user_storage_->AddShareUsers(my_public_id,
                                           share_dir,
                                           members_to_add,
                                           drive::kMsPrivateShare,
                                           &add_users_results);
    results->insert(add_users_results.begin(), add_users_results.end());
  }
  // Remove users
  if (!members_to_remove.empty()) {
    result = user_storage_->RemoveShareUsers(my_public_id,
                                             share_dir,
                                             members_to_remove,
                                             drive::kMsPrivateShare);
    if (result == kSuccess) {
      for (auto it = members_to_remove.begin();
           it != members_to_remove.end();
           ++it)
        results->insert(std::make_pair(*it, kSuccess));
    } else {
      for (auto it = members_to_remove.begin();
           it != members_to_remove.end();
           ++it)
        results->insert(std::make_pair(*it, result));
    }
  }
  // Upgrade users
  if (!members_to_upgrade.empty()) {
    for (auto it = members_to_upgrade.begin();
         it != members_to_upgrade.end(); ++it) {
      result = user_storage_->SetShareUsersRights(
                          my_public_id, share_dir, (*it).first, (*it).second,
                          drive::kMsPrivateShare);
      results->insert(std::make_pair((*it).first, result));
    }
  }
  // Downgrade users
  if (!members_to_downgrade.empty()) {
    result = user_storage_->DowngradeShareUsersRights(my_public_id,
                                                      share_dir,
                                                      members_to_downgrade,
                                                      results,
                                                      drive::kMsPrivateShare);
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed to downgrade rights: " << result;
      return result;
    }
  }
  return kSuccess;
}

int LifeStuffImpl::DeletePrivateShare(const std::string &my_public_id,
                                      const std::string &share_name,
                                      bool delete_data) {
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in DeletePrivateShare.";
    return result;
  }

  fs::path share_dir(mount_path() / kSharedStuff / share_name);
  return user_storage_->StopShare(my_public_id, share_dir, delete_data);
}

int LifeStuffImpl::LeavePrivateShare(const std::string &my_public_id,
                                     const std::string &share_name) {
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in LeavePrivateShare.";
    return result;
  }

  fs::path share_dir(mount_path() / kSharedStuff / share_name);
  return user_storage_->RemoveShare(share_dir, my_public_id);
}

int LifeStuffImpl::CreateOpenShareFromExistingDirectory(
    const std::string &my_public_id,
    const fs::path &directory_in_lifestuff_drive,
    const std::vector<std::string> &contacts,
    std::string *share_name,
    StringIntMap *results) {
  if (!share_name) {
    DLOG(ERROR) << "Parameter share name must be valid.";
    return kGeneralError;
  }

  boost::system::error_code error_code;
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks.";
    return result;
  }
  if (!fs::exists(directory_in_lifestuff_drive)) {
    DLOG(ERROR) << "Share directory nonexistant.";
    return kGeneralError;
  }
  fs::path share_path(mount_path() / kSharedStuff);
  if (!VerifyOrCreatePath(share_path)) {
    DLOG(ERROR) << "Failed to verify or create path to shared stuff.";
    return false;
  }

  std::string generated_name(GetNameInPath(share_path, *share_name));
  if (generated_name.empty()) {
    DLOG(ERROR) << "Failed to generate name for share.";
    return kGeneralError;
  }

  *share_name = generated_name;
  fs::path share(share_path / generated_name);
  StringIntMap liaisons;
  for (uint32_t i = 0; i != contacts.size(); ++i)
    liaisons.insert(std::make_pair(contacts[i], 1));
  result = user_storage_->CreateOpenShare(my_public_id,
                                          directory_in_lifestuff_drive,
                                          share,
                                          liaisons,
                                          results);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to create open share: " << result;
    return result;
  }
  return kSuccess;
}

int LifeStuffImpl::CreateEmptyOpenShare(
    const std::string &my_public_id,
    const std::vector<std::string> &contacts,
    std::string *share_name,
    StringIntMap *results) {
  if (!share_name) {
    DLOG(ERROR) << "Parameter share name must be valid.";
    return kGeneralError;
  }
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks.";
    return result;
  }

  fs::path share_path(mount_path() / kSharedStuff);
  if (!VerifyOrCreatePath(share_path)) {
    DLOG(ERROR) << "Failed to verify or create path to shared stuff.";
    return false;
  }
  std::string generated_name(GetNameInPath(share_path, *share_name));
  if (generated_name.empty()) {
    DLOG(ERROR) << "Failed to generate name for share.";
    return kGeneralError;
  }

  *share_name = generated_name;
  fs::path share(share_path / generated_name);
  StringIntMap liaisons;
  for (uint32_t i = 0; i != contacts.size(); ++i)
    liaisons.insert(std::make_pair(contacts[i], 1));
  return user_storage_->CreateOpenShare(my_public_id,
                                        fs::path(),
                                        share,
                                        liaisons,
                                        results);
}

int LifeStuffImpl::InviteMembersToOpenShare(
    const std::string &my_public_id,
    const std::vector<std::string> &contacts,
    const std::string &share_name,
    StringIntMap *results) {
  StringIntMap liaisons;
  fs::path share(mount_path() / drive::kMsShareRoot / share_name);
  for (uint32_t i = 0; i != contacts.size(); ++i)
    liaisons.insert(std::make_pair(contacts[i], 1));
  return user_storage_->OpenShareInvitation(my_public_id,
                                            share,
                                            liaisons,
                                            results);
}

int LifeStuffImpl::GetOpenShareList(const std::string &my_public_id,
                                    std::vector<std::string> *share_names) {
  if (!share_names) {
    DLOG(ERROR) << "Parameter share name must be valid.";
    return kGeneralError;
  }
  StringIntMap shares;
  int result(GetPrivateShareList(my_public_id, &shares));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get open share list.";
    return result;
  }
  share_names->clear();
  auto end(shares.end());
  for (auto it = shares.begin(); it != end; ++it)
    share_names->push_back(it->first);
  return kSuccess;
}

int LifeStuffImpl::GetOpenShareMembers(
    const std::string &my_public_id,
    const std::string &share_name,
    std::vector<std::string> *share_members) {
  if (!share_members) {
    DLOG(ERROR) << "Parameter share name must be valid.";
    return kGeneralError;
  }
  StringIntMap share_users;
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks.";
    return result;
  }
  fs::path share_dir(mount_path() / kSharedStuff / share_name);
  result = user_storage_->GetAllShareUsers(share_dir, &share_users);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get open share members.";
    return result;
  }
  share_members->clear();
  auto end(share_users.end());
  for (auto it = share_users.begin(); it != end; ++it)
    if (it->first != my_public_id)
      share_members->push_back(it->first);
  return kSuccess;
}

int LifeStuffImpl::AcceptOpenShareInvitation(
    const std::string &my_public_id,
    const std::string &contact_public_id,
    const std::string &share_id,
    std::string *share_name) {
  if (!share_name) {
    DLOG(ERROR) << "Parameter share name must be valid.";
    return kGeneralError;
  }
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks.";
    return result;
  }
  // Read hidden file...
  std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)));
  fs::path hidden_file(mount_path() /
                       kSharedStuff /
                       std::string(temp_name + kHiddenFileExtension));
  std::string serialised_share_data;
  result = user_storage_->ReadHiddenFile(hidden_file,
                &serialised_share_data);
  if (result != kSuccess || serialised_share_data.empty()) {
    DLOG(ERROR) << "No such identifier found: " << result;
    return result == kSuccess ? kGeneralError : result;
  }
  Message message;
  message.ParseFromString(serialised_share_data);
  fs::path relative_path(message.content(1));
  std::string directory_id(message.content(2));
  asymm::Keys share_keyring;
  share_keyring.identity = message.content(3);
  share_keyring.validation_token = message.content(4);
  asymm::DecodePrivateKey(message.content(5), &(share_keyring.private_key));
  asymm::DecodePublicKey(message.content(6), &(share_keyring.public_key));
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
    DLOG(ERROR) << "Failed to insert share, result " << result;
    return result;
  }
  StringIntMap contacts;
  contacts.insert(std::make_pair(my_public_id, 1));
  result = user_storage_->AddOpenShareUser(share_dir, contacts);
  if (result != kSuccess)
    DLOG(ERROR) << "Failed to add user to open share, result " << result;
  return result;
}

int LifeStuffImpl::RejectOpenShareInvitation(const std::string &my_public_id,
                                             const std::string &share_id) {
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks.";
    return result;
  }
  std::string temp_name(EncodeToBase32(crypto::Hash<crypto::SHA1>(share_id)));
  fs::path hidden_file(mount_path() /
                       kSharedStuff /
                       std::string(temp_name + kHiddenFileExtension));
  return user_storage_->DeleteHiddenFile(hidden_file);
}

int LifeStuffImpl::LeaveOpenShare(const std::string &my_public_id,
                                  const std::string &share_name) {
  int result(PreContactChecks(my_public_id));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks.";
    return result;
  }
  fs::path share(mount_path() / kSharedStuff / share_name);
  std::vector<std::string> members;
  result = GetOpenShareMembers(my_public_id, share_name, &members);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to get members of share " << share;
    return result;
  }
  if (members.size() == 0) {
    result = user_storage_->DeleteHiddenFile(share / drive::kMsShareUsers);
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed to delete " << share / drive::kMsShareUsers;
      return result;
    }
    boost::system::error_code error_code;
    try {
      fs::remove_all(share, error_code);
      if (error_code) {
        DLOG(ERROR) << "Failed to remove share directory "
                    << share << " " << error_code.value();
        return error_code.value();
      }
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "Exception thrown removing share directory " << share
                  << ": " << e.what();
      return kGeneralError;
    }
    BOOST_ASSERT(!fs::exists(share, error_code));
    /*result = user_storage_->RemoveShare(share);
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed to remove share " << share;
      return result;
    }*/

    // TODO(Team): Should this block exist? Doesn't RemoveShare eliminate the
    //             entry from the listing?
    /*try {
      boost::system::error_code error_code;
      int count(0), limit(30);
      while (count++ < limit && fs::exists(share, error_code) && !error_code)
        Sleep(bptime::milliseconds(100));
      if (count == limit) {
        DLOG(ERROR) << "Failed to disappear directory.";
        return kGeneralError;
      }
      fs::remove_all(share, error_code);
      if (error_code) {
        DLOG(ERROR) << "Failed to remove share directory "
                    << share << " " << error_code.value();
        return error_code.value();
      }
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "Exception thrown removing share directory " << share
                  << ": " << e.what();
      return kGeneralError;
    }*/
  } else {
    members.clear();
    members.push_back(my_public_id);
    result = user_storage_->RemoveOpenShareUsers(share, members);
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed to remove share user " << my_public_id
                  << " from share " << share;
      return result;
    }
    result = user_storage_->RemoveShare(share);
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed to remove share " << share;
      return result;
    }
  }
  return kSuccess;
}

///
int LifeStuffImpl::state() const { return state_; }

fs::path LifeStuffImpl::mount_path() const {
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Wrong state: " << state_;
    return fs::path();
  }

  return user_storage_->mount_dir();
}

void LifeStuffImpl::ConnectInternalElements() {
  message_handler_->ConnectToParseAndSaveDataMapSignal(
      boost::bind(&UserStorage::ParseAndSaveDataMap, user_storage_.get(),
                  _1, _2, _3));

  message_handler_->ConnectToSavePrivateShareDataSignal(
      boost::bind(&UserStorage::SavePrivateShareData,
                  user_storage_.get(), _1, _2));

  message_handler_->ConnectToPrivateShareUserLeavingSignal(
      boost::bind(&UserStorage::UserLeavingShare,
                  user_storage_.get(), _2, _3));

  message_handler_->ConnectToSaveOpenShareDataSignal(
      boost::bind(&UserStorage::SaveOpenShareData,
                  user_storage_.get(), _1, _2));

  message_handler_->ConnectToPrivateShareDeletionSignal(
      boost::bind(&UserStorage::ShareDeleted, user_storage_.get(), _3));

  message_handler_->ConnectToPrivateShareUpdateSignal(
      boost::bind(&UserStorage::UpdateShare, user_storage_.get(),
                  _1, _2, _3, _4));

  message_handler_->ConnectToPrivateMemberAccessLevelSignal(
      boost::bind(&UserStorage::MemberAccessChange,
                  user_storage_.get(), _4, _5));

  public_id_->ConnectToContactConfirmedSignal(
      boost::bind(&MessageHandler::InformConfirmedContactOnline,
                  message_handler_.get(), _1, _2));

  message_handler_->ConnectToContactDeletionSignal(
      boost::bind(&PublicId::RemoveContactHandle,
                  public_id_.get(), _1, _2));

  message_handler_->ConnectToPrivateShareDetailsSignal(
      boost::bind(&UserStorage::GetShareDetails, user_storage_.get(),
                  _1, _2, nullptr, nullptr, nullptr));
}

int LifeStuffImpl::SetValidPmidAndInitialisePublicComponents() {
  int result(kSuccess);
#ifndef LOCAL_TARGETS_ONLY
  std::vector<dht::Contact> bootstrap_contacts;
  result = client_container_->Stop(&bootstrap_contacts);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to stop client container: " << result;
    return result;
  }
  client_container_->set_key_pair(session_->GetPmidKeys());
  if (!client_container_->InitClientContainer(
          buffered_path_ / "buffered_chunk_store", 10, 4)) {
    DLOG(ERROR) << "Failed to initialise cliento container.";
    return kGeneralError;
  }
  result = client_container_->Start(bootstrap_contacts);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to start client container: " << result;
    return result;
  }

  remote_chunk_store_.reset(
      new pcs::RemoteChunkStore(client_container_->chunk_store(),
                                client_container_->chunk_manager(),
                                client_container_->chunk_action_authority()));
  user_credentials_.reset(new UserCredentials(remote_chunk_store_, session_));
#endif

  public_id_.reset(new PublicId(remote_chunk_store_,
                                session_,
                                asio_service_.service()));

  message_handler_.reset(new MessageHandler(remote_chunk_store_,
                                            session_,
                                            asio_service_.service()));

  user_storage_.reset(new UserStorage(remote_chunk_store_, message_handler_));

  ConnectInternalElements();
  state_ = kInitialised;

  result = ConnectToSignals(slots_.chat_slot,
                            slots_.file_slot,
                            slots_.new_contact_slot,
                            slots_.confirmed_contact_slot,
                            slots_.profile_picture_slot,
                            slots_.contact_presence_slot,
                            slots_.contact_deletion_function,
                            slots_.private_share_invitation_function,
                            slots_.private_share_deletion_function,
                            slots_.private_access_level_function,
                            slots_.open_share_invitation_function,
                            slots_.share_renamed_function);
  return result;
}

int LifeStuffImpl::PreContactChecks(const std::string &my_public_id) {
  if (state_ != kLoggedIn) {
    DLOG(ERROR) << "Incorrect state. Should be logged in.";
    return kGeneralError;
  }

  auto it(session_->contact_handler_map().find(my_public_id));
  if (it == session_->contact_handler_map().end()) {
    DLOG(ERROR) << "No such public ID.";
    return kGeneralError;
  }

  return kSuccess;
}

void LifeStuffImpl::InvokeDoSession() {
  {
    boost::mutex::scoped_lock loch_(save_session_mutex_);
    saving_session_ = true;
    asio_service_.service().post(std::bind(&LifeStuffImpl::DoSaveSession,
                                           this));
  }
}

void LifeStuffImpl::DoSaveSession() {
  int result(user_credentials_->SaveSession());
  DLOG(INFO) << "Save session result: " << result;
  {
    boost::mutex::scoped_lock loch_lussa(save_session_mutex_);
    saving_session_ = false;
  }
}

}  // namespace lifestuff

}  // namespace maidsafe
