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
#include <functional>
#include <vector>

#include "maidsafe/lifestuff/lifestuff_impl.h"

namespace maidsafe {

namespace lifestuff {

LifeStuff::LifeStuff() : lifestuff_impl(new LifeStuffImpl) {}

LifeStuff::~LifeStuff() {}

int LifeStuff::Initialise(const fs::path& base_directory) {
  return lifestuff_impl->Initialise(base_directory);
}

int LifeStuff::ConnectToSignals(
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
    const ShareChangedFunction& share_changed_function) {
  return lifestuff_impl->ConnectToSignals(chat_slot,
                                          file_slot,
                                          new_contact_slot,
                                          confirmed_contact_slot,
                                          profile_picture_slot,
                                          contact_presence_slot,
                                          contact_deletion_function,
                                          private_share_invitation_function,
                                          private_share_deletion_function,
                                          private_access_change_function,
                                          open_share_invitation_function,
                                          share_renamed_function,
                                          share_changed_function);
}

int LifeStuff::Finalise() {
  return lifestuff_impl->Finalise();
}

/// Credential operations
int LifeStuff::CreateUser(const std::string& username,
                          const std::string& pin,
                          const std::string& password) {
  return lifestuff_impl->CreateUser(username, pin, password);
}

int LifeStuff::CreatePublicId(const std::string& public_id) {
  return lifestuff_impl->CreatePublicId(public_id);
}

int LifeStuff::LogIn(const std::string& username,
                     const std::string& pin,
                     const std::string& password) {
  return lifestuff_impl->LogIn(username, pin, password);
}

int LifeStuff::LogOut() {
  return lifestuff_impl->LogOut();
}

int LifeStuff::CheckPassword(const std::string& password) {
  return lifestuff_impl->CheckPassword(password);
}

int LifeStuff::ChangeKeyword(const std::string& new_keyword, const std::string& password) {
  return lifestuff_impl->ChangeKeyword(new_keyword, password);
}

int LifeStuff::ChangePin(const std::string& new_pin, const std::string& password) {
  return lifestuff_impl->ChangePin(new_pin, password);
}

int LifeStuff::ChangePassword(const std::string& new_password,
                              const std::string& current_password) {
  return lifestuff_impl->ChangePassword(new_password, current_password);
}

int LifeStuff::LeaveLifeStuff() {
  return lifestuff_impl->LeaveLifeStuff();
}

/// Contact operations
int LifeStuff::AddContact(const std::string& my_public_id,
                          const std::string& contact_public_id,
                          const std::string& message) {
  return lifestuff_impl->AddContact(my_public_id, contact_public_id, message);
}

int LifeStuff::ConfirmContact(const std::string& my_public_id,
                              const std::string& contact_public_id) {
  return lifestuff_impl->ConfirmContact(my_public_id, contact_public_id);
}

int LifeStuff::DeclineContact(const std::string& my_public_id,
                              const std::string& contact_public_id) {
  return lifestuff_impl->DeclineContact(my_public_id, contact_public_id);
}

int LifeStuff::RemoveContact(const std::string& my_public_id,
                             const std::string& contact_public_id,
                             const std::string& removal_message) {
  return lifestuff_impl->RemoveContact(my_public_id, contact_public_id, removal_message, "", true);
}

int LifeStuff::ChangeProfilePicture(const std::string& my_public_id,
                                    const std::string& profile_picture_contents) {
  return lifestuff_impl->ChangeProfilePicture(my_public_id, profile_picture_contents);
}

std::string LifeStuff::GetOwnProfilePicture(const std::string& my_public_id) {
  return lifestuff_impl->GetOwnProfilePicture(my_public_id);
}

std::string LifeStuff::GetContactProfilePicture(const std::string& my_public_id,
                                                const std::string& contact_public_id) {
  return lifestuff_impl->GetContactProfilePicture(my_public_id, contact_public_id);
}

ContactMap LifeStuff::GetContacts(const std::string& my_public_id, uint16_t bitwise_status) {
  return lifestuff_impl->GetContacts(my_public_id, bitwise_status);
}

std::vector<std::string> LifeStuff::PublicIdsList() const {
  return lifestuff_impl->PublicIdsList();
}

/// Messaging
int LifeStuff::SendChatMessage(const std::string& sender_public_id,
                               const std::string& receiver_public_id,
                               const std::string& message) {
  return lifestuff_impl->SendChatMessage(sender_public_id, receiver_public_id, message);
}

int LifeStuff::SendFile(const std::string& sender_public_id,
                        const std::string& receiver_public_id,
                        const fs::path& absolute_path) {
  return lifestuff_impl->SendFile(sender_public_id, receiver_public_id, absolute_path);
}

int LifeStuff::AcceptSentFile(const std::string& identifier,
                              const fs::path& absolute_path,
                              std::string* file_name) {
  return lifestuff_impl->AcceptSentFile(identifier, absolute_path, file_name);
}

int LifeStuff::RejectSentFile(const std::string& identifier) {
  return lifestuff_impl->RejectSentFile(identifier);
}

/// Filesystem
int LifeStuff::ReadHiddenFile(const fs::path& absolute_path,
                              std::string* content) const {
  return lifestuff_impl->ReadHiddenFile(absolute_path, content);
}

int LifeStuff::WriteHiddenFile(const fs::path& absolute_path,
                               const std::string& content,
                               bool overwrite_existing) {
  return lifestuff_impl->WriteHiddenFile(absolute_path, content, overwrite_existing);
}

int LifeStuff::DeleteHiddenFile(const fs::path& absolute_path) {
  return lifestuff_impl->DeleteHiddenFile(absolute_path);
}

int LifeStuff::SearchHiddenFiles(const fs::path& absolute_path,
                                 const std::string& regex,
                                 std::list<std::string>* results) {
  return lifestuff_impl->SearchHiddenFiles(absolute_path, regex, results);
}

/// Private Shares
int LifeStuff::CreatePrivateShareFromExistingDirectory(const std::string& my_public_id,
                                                       const fs::path& directory_in_lifestuff_drive,
                                                       const StringIntMap& contacts,
                                                       std::string* share_name,
                                                       StringIntMap* results) {
  return lifestuff_impl->CreatePrivateShareFromExistingDirectory(my_public_id,
                                                                 directory_in_lifestuff_drive,
                                                                 contacts,
                                                                 share_name,
                                                                 results);
}

int LifeStuff::CreateEmptyPrivateShare(const std::string& my_public_id,
                                       const StringIntMap& contacts,
                                       std::string* share_name,
                                       StringIntMap* results) {
  return lifestuff_impl->CreateEmptyPrivateShare(my_public_id, contacts, share_name, results);
}

int LifeStuff::GetPrivateShareList(const std::string& my_public_id, StringIntMap* share_names) {
  return lifestuff_impl->GetPrivateShareList(my_public_id, share_names);
}

int LifeStuff::GetPrivateShareMembers(const std::string& my_public_id,
                                      const std::string& share_name,
                                      StringIntMap* share_members) {
  return lifestuff_impl->GetPrivateShareMembers(my_public_id, share_name, share_members);
}

int LifeStuff::GetPrivateSharesIncludingMember(const std::string& my_public_id,
                                               const std::string& contact_public_id,
                                               std::vector<std::string>* share_names) {
  return lifestuff_impl->GetPrivateSharesIncludingMember(my_public_id,
                                                         contact_public_id,
                                                         share_names);
}

int LifeStuff::AcceptPrivateShareInvitation(const std::string& my_public_id,
                                            const std::string& contact_public_id,
                                            const std::string& share_id,
                                            std::string* share_name) {
  return lifestuff_impl->AcceptPrivateShareInvitation(my_public_id,
                                                      contact_public_id,
                                                      share_id,
                                                      share_name);
}

int LifeStuff::RejectPrivateShareInvitation(const std::string& my_public_id,
                                            const std::string& share_id) {
  return lifestuff_impl->RejectPrivateShareInvitation(my_public_id, share_id);
}

int LifeStuff::EditPrivateShareMembers(const std::string& my_public_id,
                                       const StringIntMap& public_ids,
                                       const std::string& share_name,
                                       StringIntMap* results) {
  return lifestuff_impl->EditPrivateShareMembers(my_public_id, public_ids, share_name, results);
}

int LifeStuff::DeletePrivateShare(const std::string& my_public_id,
                                  const std::string& share_name,
                                  bool delete_data) {
  return lifestuff_impl->DeletePrivateShare(my_public_id, share_name, delete_data);
}

int LifeStuff::LeavePrivateShare(const std::string& my_public_id,
                                 const std::string& share_name) {
  return lifestuff_impl->LeavePrivateShare(my_public_id, share_name);
}

int LifeStuff::CreateOpenShareFromExistingDirectory(const std::string& my_public_id,
                                                    const fs::path& directory_in_lifestuff_drive,
                                                    const std::vector<std::string>& contacts,
                                                    std::string* share_name,
                                                    StringIntMap* results) {
  return lifestuff_impl->CreateOpenShareFromExistingDirectory(my_public_id,
                                                              directory_in_lifestuff_drive,
                                                              contacts,
                                                              share_name,
                                                              results);
}

int LifeStuff::CreateEmptyOpenShare(const std::string& my_public_id,
                                    const std::vector<std::string>& contacts,
                                    std::string* share_name,
                                    StringIntMap* results) {
  return lifestuff_impl->CreateEmptyOpenShare(my_public_id, contacts, share_name, results);
}

int LifeStuff::InviteMembersToOpenShare(const std::string& my_public_id,
                                        const std::vector<std::string>& contacts,
                                        const std::string& share_name,
                                        StringIntMap* results) {
  return lifestuff_impl->InviteMembersToOpenShare(my_public_id, contacts, share_name, results);
}

int LifeStuff::GetOpenShareList(const std::string& my_public_id,
                                std::vector<std::string>* shares_names) {
  return lifestuff_impl->GetOpenShareList(my_public_id, shares_names);
}

int LifeStuff::GetOpenShareMembers(const std::string& my_public_id,
                                   const std::string& share_name,
                                   StringIntMap* share_members) {
  return lifestuff_impl->GetOpenShareMembers(my_public_id, share_name, share_members);
}

int LifeStuff::AcceptOpenShareInvitation(const std::string& my_public_id,
                                         const std::string& contact_public_id,
                                         const std::string& share_id,
                                         std::string* share_name) {
  return lifestuff_impl->AcceptOpenShareInvitation(my_public_id,
                                                   contact_public_id,
                                                   share_id,
                                                   share_name);
}

int LifeStuff::RejectOpenShareInvitation(const std::string& my_public_id,
                                         const std::string& share_id) {
  return lifestuff_impl->RejectOpenShareInvitation(my_public_id, share_id);
}

int LifeStuff::LeaveOpenShare(const std::string& my_public_id,
                              const std::string& share_name) {
  return lifestuff_impl->LeaveOpenShare(my_public_id, share_name);
}

///
int LifeStuff::state() const { return lifestuff_impl->state(); }

fs::path LifeStuff::mount_path() const { return lifestuff_impl->mount_path(); }

}  // namespace lifestuff

}  // namespace maidsafe
