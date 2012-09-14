/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
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

#include "maidsafe/lifestuff/detail/message_handler.h"

#include "maidsafe/lifestuff/lifestuff.h"

namespace maidsafe {

namespace lifestuff {

/// Extra library connections
bs2::connection MessageHandler::ConnectToChatSignal(const ChatFunction& function) {
  return chat_signal_.connect(function);
}

bs2::connection MessageHandler::ConnectToFileTransferSignal(const FileTransferFunction& function) {
  return file_transfer_signal_.connect(function);
}

bs2::connection MessageHandler::ConnectToContactPresenceSignal(
    const ContactPresenceFunction& function) {
  return contact_presence_signal_.connect(function);
}

bs2::connection MessageHandler::ConnectToContactProfilePictureSignal(
    const ContactProfilePictureFunction& function) {
  return contact_profile_picture_signal_.connect(function);
}


/// Intra library connections
bs2::connection MessageHandler::ConnectToParseAndSaveDataMapSignal(
    const ParseAndSaveDataMapSignal::slot_type& function) {
  return parse_and_save_data_map_signal_.connect(function);
}

}  // namespace lifestuff

}  // namespace maidsafe
