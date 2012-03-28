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
#include "maidsafe/lifestuff/ye_olde_signal_to_callback_converter.h"

namespace maidsafe {

namespace lifestuff {

struct LifeStuffElements {
  explicit LifeStuffElements(int thread_count_in = 10)
      : thread_count(thread_count_in),
        initialised(false),
        connected(false),
        asio_service(),
        session(),
        converter(),
        user_credentials(),
        user_storage(),
        public_id(),
        message_handler() {}

  int thread_count;
  bool initialised;
  bool connected;
  AsioService asio_service;
  std::shared_ptr<Session> session;
  std::shared_ptr<YeOldeSignalToCallbackConverter> converter;
  std::shared_ptr<UserCredentials> user_credentials;
  std::shared_ptr<UserStorage> user_storage;
  std::shared_ptr<PublicId> public_id;
  std::shared_ptr<MessageHandler> message_handler;
};

// Forward declarations
// int CreateUser(const boost::filesystem::path &base_directory,
//                const std::string &username,
//                const std::string &pin,
//                const std::string &password,
//                drive::DriveChangedSlotPtr drive_change_slot,
//                LifeStuffElements &lifestuff_elements) {
//   InitPrivateElements(base_directory, lifestuff_elements);
//   lifestuff_elements.user_storage->ConnectToDriveChanged(drive_change_slot);
//
//   int result(lifestuff_elements.user_credentials->CreateUser(username,
//                                                              pin,
//                                                              password));
//   if (result != kSuccess) {
//     DLOG(ERROR) << "Failed to Create User: " << result;
//     return result;
//   }
//
//   lifestuff_elements.user_storage->MountDrive(base_directory,
//                                               lifestuff_elements.session,
//                                               true);
//   if (!lifestuff_elements.user_storage->mount_status())
//     return kGeneralError;
//
//   return kSuccess;
// }

// int CreatePublicId(const std::string &public_id,
//                    drive::ShareChangedSlotPtr share_change_slot,
//                    TwoStringsSlot new_contact_slot,
//                    OneStringSlot contact_confirmation_slot,
//                    std::map<Message::ContentType,
//                             MessageHandler::NewMessageSignal::slot_type>
//                        message_slots,
//                    LifeStuffElements &lifestuff_elements) {
//   if (!(lifestuff_elements.public_id && lifestuff_elements.message_handler))
//     InitPublicElements(lifestuff_elements);
//
//   lifestuff_elements.public_id->CreatePublicId(public_id, true);
//   lifestuff_elements.public_id->StartCheckingForNewContacts(
//       bptime::seconds(kIntervalSeconds));
//   lifestuff_elements.message_handler->StartCheckingForNewMessages(
//       bptime::seconds(kIntervalSeconds));
//
//   return kSuccess;
// }

}  // namespace lifestuff

}  // namespace maidsafe
