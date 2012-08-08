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

bs2::connection MessageHandler::ConnectToPrivateShareInvitationSignal(
    const PrivateShareInvitationFunction& function) {
  return private_share_invitation_signal_.connect(function);
}

bs2::connection MessageHandler::ConnectToPrivateShareDeletionSignal(
    const PrivateShareDeletionFunction& function) {
  return private_share_deletion_signal_.connect(function);
}

bs2::connection MessageHandler::ConnectToPrivateMemberAccessChangeSignal(
    const PrivateMemberAccessChangeFunction& function) {
  return private_member_access_change_signal_.connect(function);
}

bs2::connection MessageHandler::ConnectToOpenShareInvitationSignal(
    const OpenShareInvitationFunction& function) {
  return open_share_invitation_signal_.connect(function);
}

bs2::connection MessageHandler::ConnectToShareInvitationResponseSignal(
    const ShareInvitationResponseFunction& function) {
  return share_invitation_response_signal_.connect(function);
}

/// Intra and extra library connections
bs2::connection MessageHandler::ConnectToPrivateShareUserLeavingSignal(
    const PrivateShareUserLeavingSignal::slot_type& function) {
  return private_share_user_leaving_signal_.connect(function);
}

/// Intra library connections
bs2::connection MessageHandler::ConnectToParseAndSaveDataMapSignal(
    const ParseAndSaveDataMapSignal::slot_type& function) {
  return parse_and_save_data_map_signal_.connect(function);
}

bs2::connection MessageHandler::ConnectToPrivateShareDetailsSignal(
  boost::function<int(const std::string& share_id,  // NOLINT (Dan)
                      fs::path* relative_path)> function) {
  return private_share_details_signal_.connect(function);
}

bs2::connection MessageHandler::ConnectToPrivateShareUpdateSignal(
    const PrivateShareUpdateSignal::slot_type& function) {
  return private_share_update_signal_.connect(function);
}

bs2::connection MessageHandler::ConnectToPrivateMemberAccessLevelSignal(
    const PrivateMemberAccessLevelSignal::slot_type& function) {
  return private_member_access_level_signal_.connect(function);
}

bs2::connection MessageHandler::ConnectToSavePrivateShareDataSignal(
    const SavePrivateShareDataSignal::slot_type& function) {
  return save_private_share_data_signal_.connect(function);
}

bs2::connection MessageHandler::ConnectToDeletePrivateShareDataSignal(
    const DeletePrivateShareDataSignal::slot_type& function) {
  return delete_private_share_data_signal_.connect(function);
}

bs2::connection MessageHandler::ConnectToSaveOpenShareDataSignal(
    const SaveOpenShareDataSignal::slot_type& function) {
  return save_open_share_data_signal_.connect(function);
}

}  // namespace lifestuff

}  // namespace maidsafe
