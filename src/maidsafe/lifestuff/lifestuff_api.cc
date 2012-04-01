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

#include "maidsafe/common/asio_service.h"

#include "maidsafe/lifestuff/log.h"
#include "maidsafe/lifestuff/return_codes.h"

#include "maidsafe/lifestuff/message_handler.h"
#include "maidsafe/lifestuff/public_id.h"
#include "maidsafe/lifestuff/session.h"
#include "maidsafe/lifestuff/user_credentials.h"
#include "maidsafe/lifestuff/user_storage.h"

namespace maidsafe {

namespace lifestuff {

enum LifeStuffState {
  kZeroth,
  kInitialised,
  kConnected,
  kLoggedIn,
  kLoggedOut
};

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

int LifeStuff::Initialise(const boost::filesystem::path &base_directory) {
  if (lifestuff_elements->state != kZeroth) {
    DLOG(ERROR) << "Make sure that object is in the original Zeroth state. "
                << "Asimov rules.";
    return kGeneralError;
  }

  // Initialisation
  lifestuff_elements->asio_service.Start(lifestuff_elements->thread_count);
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
    DLOG(ERROR) << "Make sure that object is initialised and connected";
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

  int result(lifestuff_elements->user_credentials->CreateUser(username,
                                                              pin,
                                                              password));
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to Create User: " << result;
    return result;
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

  int result(lifestuff_elements->user_credentials->Logout());
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed to log out.";
    return result;
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

}  // namespace lifestuff

}  // namespace maidsafe
