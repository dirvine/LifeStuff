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

#include "maidsafe/lifestuff/lifestuff_api.h"

#include <algorithm>
#include <vector>

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/return_codes.h"

#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/message_handler.h"
#include "maidsafe/lifestuff/public_id.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/user_credentials.h"
#include "maidsafe/lifestuff/user_storage.h"

namespace maidsafe {

namespace lifestuff {

struct LifeStuff::Elements {
  Elements() : thread_count(kThreads),
               state(kZeroth),
               base_directory(),
               interval(kSecondsInterval),
               asio_service(),
               session(),
               user_credentials(),
               user_storage(),
               public_id(),
               message_handler() {}

  int thread_count;
  LifeStuffState state;
  boost::filesystem::path base_directory;
  bptime::seconds interval;
  AsioService asio_service;
  std::shared_ptr<Session> session;
  std::shared_ptr<UserCredentials> user_credentials;
  std::shared_ptr<UserStorage> user_storage;
  std::shared_ptr<PublicId> public_id;
  std::shared_ptr<MessageHandler> message_handler;
};

LifeStuff::LifeStuff() : lifestuff_elements(new Elements) {}

LifeStuff::~LifeStuff() {}

int LifeStuff::Initialise(const boost::filesystem::path &base_directory) {
  if (lifestuff_elements->state != kZeroth) {
    DLOG(ERROR) << "Make sure that object is in the original Zeroth state. "
                << "Asimov rules.";
    return kGeneralError;
  }

  // Initialisation
  lifestuff_elements->asio_service.Start(lifestuff_elements->thread_count);
  lifestuff_elements->session.reset(new Session);
  lifestuff_elements->user_credentials.reset(
      new UserCredentials(lifestuff_elements->asio_service.service(),
                          lifestuff_elements->session));
  lifestuff_elements->user_credentials->Init(base_directory);

  lifestuff_elements->public_id.reset(
      new PublicId(lifestuff_elements->user_credentials->remote_chunk_store(),
                   lifestuff_elements->session,
                   lifestuff_elements->asio_service.service()));

  lifestuff_elements->message_handler.reset(
      new MessageHandler(
          lifestuff_elements->user_credentials->remote_chunk_store(),
          lifestuff_elements->session,
          lifestuff_elements->asio_service.service()));

  lifestuff_elements->user_storage.reset(
      new UserStorage(
          lifestuff_elements->user_credentials->remote_chunk_store(),
          lifestuff_elements->message_handler));

  lifestuff_elements->base_directory = base_directory;
  lifestuff_elements->state = kInitialised;

  return kSuccess;
}

int LifeStuff::ConnectToSignals(
    drive::DriveChangedSlotPtr drive_change_slot,
    drive::ShareChangedSlotPtr share_change_slot,
    const ChatFunction &chat_slot,
    const FileTransferFunction &file_slot,
    const ShareFunction &share_slot,
    const NewContactFunction &new_contact_slot,
    const ContactConfirmationFunction &confirmed_contact_slot,
    const ContactProfilePictureFunction &profile_picture_slot,
    const ContactPresenceFunction &contact_presence_slot) {
  if (lifestuff_elements->state != kInitialised) {
    DLOG(ERROR) << "Make sure that object is initialised";
    return kGeneralError;
  }

  int connects(0);
  if (drive_change_slot) {
    lifestuff_elements->user_storage->ConnectToDriveChanged(drive_change_slot);
    ++connects;
  }
  if (share_change_slot) {
    lifestuff_elements->user_storage->ConnectToShareChanged(share_change_slot);
    ++connects;
  }
  if (chat_slot) {
    lifestuff_elements->message_handler->ConnectToChatSignal(chat_slot);
    ++connects;
  }
  if (file_slot) {
    lifestuff_elements->message_handler->ConnectToFileTransferSignal(file_slot);
    ++connects;
  }
  if (share_slot) {
    lifestuff_elements->message_handler->ConnectToShareSignal(share_slot);
    ++connects;
  }
  if (new_contact_slot) {
    lifestuff_elements->public_id->ConnectToNewContactSignal(new_contact_slot);
    ++connects;
  }
  if (confirmed_contact_slot) {
    lifestuff_elements->public_id->ConnectToContactConfirmedSignal(
        confirmed_contact_slot);
    ++connects;
  }
  if (profile_picture_slot) {
    lifestuff_elements->message_handler->ConnectToContactProfilePictureSignal(
        profile_picture_slot);
    ++connects;
  }
  if (contact_presence_slot) {
    lifestuff_elements->message_handler->ConnectToContactPresenceSignal(
        contact_presence_slot);
    ++connects;
  }

  if (connects > 0) {
    lifestuff_elements->state = kConnected;
    return kSuccess;
  }

  return kGeneralError;
}

int LifeStuff::CreateUser(const std::string &username,
                          const std::string &pin,
                          const std::string &password) {
  if (lifestuff_elements->state != kConnected) {
    DLOG(ERROR) << "Make sure that object is initialised and connected";
    return kGeneralError;
  }

  if (!lifestuff_elements->user_credentials->CreateUser(username,
                                                        pin,
                                                        password)) {
    DLOG(ERROR) << "Failed to Create User.";
    return kGeneralError;
  }

  lifestuff_elements->user_storage->MountDrive(
      lifestuff_elements->base_directory,
      lifestuff_elements->session,
      true);
  if (!lifestuff_elements->user_storage->mount_status()) {
    DLOG(ERROR) << "Failed to mount";
    return kGeneralError;
  }

  lifestuff_elements->state = kLoggedIn;

  return kSuccess;
}

int LifeStuff::CreatePublicId(const std::string &public_id) {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Wrong state to create a public ID.";
    return kGeneralError;
  }

  // Check if it's the 1st one
  bool first_public_id(false);
  if (lifestuff_elements->session->contact_handler_map().empty())
    first_public_id = true;

  int result(lifestuff_elements->public_id->CreatePublicId(public_id, true));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to create public ID.";
    return result;
  }

  if (first_public_id) {
    lifestuff_elements->public_id->StartCheckingForNewContacts(
        lifestuff_elements->interval);
    lifestuff_elements->message_handler->StartUp(
        lifestuff_elements->interval);
  }

  return kSuccess;
}

int LifeStuff::LogIn(const std::string &username,
                     const std::string &pin,
                     const std::string &password) {
  if (lifestuff_elements->state != kConnected) {
    DLOG(ERROR) << "Make sure that object is initialised and connected";
    return kGeneralError;
  }

  int result(lifestuff_elements->user_credentials->CheckUserExists(username,
                                                                   pin));
  if (result != kUserExists) {
    DLOG(ERROR) << "User doesn't exist.";
    return result;
  }

  if (!lifestuff_elements->user_credentials->ValidateUser(password)) {
    DLOG(ERROR) << "Wrong password.";
    return kGeneralError;
  }

  lifestuff_elements->user_storage->MountDrive(
      lifestuff_elements->base_directory,
      lifestuff_elements->session,
      false);

  if (!lifestuff_elements->user_storage->mount_status()) {
    DLOG(ERROR) << "Failed to mount";
    return kGeneralError;
  }

  if (!lifestuff_elements->session->contact_handler_map().empty()) {
    lifestuff_elements->public_id->StartCheckingForNewContacts(
        lifestuff_elements->interval);
    lifestuff_elements->message_handler->StartUp(lifestuff_elements->interval);
  }

  lifestuff_elements->state = kLoggedIn;

  return kSuccess;
}

int LifeStuff::LogOut() {
  if (lifestuff_elements->state != kLoggedIn) {
    DLOG(ERROR) << "Should be logged in to log out.";
    return kGeneralError;
  }

  lifestuff_elements->user_storage->UnMountDrive();
  if (lifestuff_elements->user_storage->mount_status()) {
    DLOG(ERROR) << "Failed to un-mount.";
    return kGeneralError;
  }

  lifestuff_elements->public_id->StopCheckingForNewContacts();
  lifestuff_elements->message_handler->ShutDown();

  if (!lifestuff_elements->user_credentials->Logout()) {
    DLOG(ERROR) << "Failed to log out.";
    return kGeneralError;
  }

  if (!lifestuff_elements->user_credentials->remote_chunk_store()
          ->WaitForCompletion()) {
    DLOG(ERROR) << "Failed complete chunk operations.";
    return kGeneralError;
  }
  lifestuff_elements->session->Reset();

  lifestuff_elements->state = kLoggedOut;

  return kSuccess;
}

int LifeStuff::Finalise() {
  if (lifestuff_elements->state != kLoggedOut) {
    DLOG(ERROR) << "Need to be logged out to finalise.";
    return kGeneralError;
  }

  lifestuff_elements->asio_service.Stop();
  lifestuff_elements->base_directory = fs::path();
  lifestuff_elements->message_handler.reset();
  lifestuff_elements->public_id.reset();
  lifestuff_elements->session.reset();
  lifestuff_elements->user_credentials.reset();
  lifestuff_elements->user_storage.reset();
  lifestuff_elements->state = kZeroth;

  return kSuccess;
}

/// Contact operations
int PreContactChecks(const LifeStuffState &state,
                     const std::string &my_public_id,
                     std::shared_ptr<Session> session) {
  if (state != kLoggedIn) {
    DLOG(ERROR) << "Incorrect state. Should be logged in.";
    return kGeneralError;
  }

  auto it(session->contact_handler_map().find(my_public_id));
  if (it == session->contact_handler_map().end()) {
    DLOG(ERROR) << "No such public ID.";
    return kGeneralError;
  }

  return kSuccess;
}

int LifeStuff::AddContact(const std::string &my_public_id,
                          const std::string &contact_public_id) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in AddContact.";
    return result;
  }

  return lifestuff_elements->public_id->SendContactInfo(my_public_id,
                                                        contact_public_id,
                                                        true);
}

int LifeStuff::ConfirmContact(const std::string &my_public_id,
                              const std::string &contact_public_id) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in ConfirmContact.";
    return result;
  }

  return lifestuff_elements->public_id->ConfirmContact(my_public_id,
                                                       contact_public_id,
                                                       true);
}

int LifeStuff::DeclineContact(const std::string &my_public_id,
                              const std::string &contact_public_id) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in DeclineContact.";
    return result;
  }

  return lifestuff_elements->public_id->ConfirmContact(my_public_id,
                                                       contact_public_id,
                                                       false);
}

int LifeStuff::RemoveContact(const std::string &my_public_id,
                             const std::string &contact_public_id) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in RemoveContact.";
    return result;
  }

  return lifestuff_elements->public_id->RemoveContact(my_public_id,
                                                      contact_public_id);
}

int LifeStuff::ChangeProfilePicture(
    const std::string &my_public_id,
    const std::string &profile_picture_contents) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
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

  // Write contents somewhere
  fs::path profile_picture_path(lifestuff_elements->user_storage->mount_dir() /
                                fs::path("/").make_preferred() /
                                std::string(my_public_id +
                                            ".profile_picture"));
  if (!WriteFile(profile_picture_path, profile_picture_contents)) {
    DLOG(ERROR) << "Failed to write profile picture file: "
                << profile_picture_path;
    return kGeneralError;
  }

  // Get datamap
  std::string data_map;
  result = lifestuff_elements->user_storage->GetDataMap(profile_picture_path,
                                                        &data_map);
  if (result != kSuccess || data_map.empty()) {
    DLOG(ERROR) << "Failed obtaining DM of profile picture: " << result
                << ", file: " << profile_picture_path;
    return result;
  }

  // Set in session
  lifestuff_elements->session->set_profile_picture_data_map(data_map);

  // Message construction
  InboxItem message(kContactProfilePicture);
  message.sender_public_id = my_public_id;
  message.content.push_back(data_map);
  message.timestamp = boost::lexical_cast<std::string>(GetDurationSinceEpoch());

  // Send to everybody


  return kSuccess;
}

std::string LifeStuff::GetOwnProfilePicture(const std::string &my_public_id) {
  // Read contents, put them in a string, give them back. Should not be a file
  // over a certain size (kFileRecontructionLimit).
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in ChangeProfilePicture.";
    return "";
  }

  fs::path profile_picture_path(lifestuff_elements->user_storage->mount_dir() /
                                fs::path("/").make_preferred() /
                                std::string(my_public_id +
                                            ".profile_picture"));
  std::string profile_picture_contents;
  if (!ReadFile(profile_picture_path, &profile_picture_contents) ||
      profile_picture_contents.empty()) {
    DLOG(ERROR) << "Failed reading profile picture: " << profile_picture_path;
    return "";
  }

  return profile_picture_contents;
}

std::string LifeStuff::GetContactProfilePicture(
    const std::string &my_public_id,
    const std::string &contact_public_id) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in GetContactProfilePicture.";
    return "";
  }

  // Look up data map in session.
  Contact contact;
  result = lifestuff_elements->session->contact_handler_map()
               [my_public_id]->ContactInfo(contact_public_id, &contact);
  if (result != kSuccess || contact.profile_picture_data_map.empty()) {
    DLOG(ERROR) << "No such contact(" << result << "): " << contact_public_id;
    return "";
  }

  // Read contents, put them in a string, give them back. Should not be
  // over a certain size (kFileRecontructionLimit).
  return lifestuff_elements->user_storage->ConstructFile(
            contact.profile_picture_data_map);
}


ContactMap LifeStuff::GetContacts(const std::string &my_public_id,
                                  uint16_t bitwise_status) {
  int result(PreContactChecks(lifestuff_elements->state,
                              my_public_id,
                              lifestuff_elements->session));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed pre checks in GetContacts.";
    return ContactMap();
  }

  return lifestuff_elements->session->contact_handler_map()
             [my_public_id]->GetContacts(bitwise_status);
}

std::vector<std::string> LifeStuff::PublicIdsList() const {
  std::vector<std::string> public_ids;

  // Retrieve all keys
  std::transform(lifestuff_elements->session->contact_handler_map().begin(),
                 lifestuff_elements->session->contact_handler_map().end(),
                 std::back_inserter(public_ids),
                 std::bind(&ContactHandlerMap::value_type::first, args::_1));


  return public_ids;
}

/// Filesystem
int LifeStuff::ReadHiddenFile(const fs::path &absolute_path,
                                std::string *content) const {
  return lifestuff_elements->user_storage->ReadHiddenFile(absolute_path,
                                                          content);
}

int LifeStuff::WriteHiddenFile(const fs::path &absolute_path,
                                 const std::string &content,
                                 bool overwrite_existing) {
  return lifestuff_elements->user_storage->WriteHiddenFile(absolute_path,
                                                           content,
                                                           overwrite_existing);
}

int LifeStuff::DeleteHiddenFile(const fs::path &absolute_path) {
  return lifestuff_elements->user_storage->DeleteHiddenFile(absolute_path);
}

///
int LifeStuff::state() const { return lifestuff_elements->state; }

fs::path LifeStuff::mount_path() const {
  return lifestuff_elements->user_storage->mount_dir();
}


}  // namespace lifestuff

}  // namespace maidsafe
