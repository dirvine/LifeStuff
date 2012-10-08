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

LifeStuff::LifeStuff() : lifestuff_impl_(new LifeStuffImpl) {}

LifeStuff::~LifeStuff() {}

int LifeStuff::Initialise(const UpdateAvailableFunction& software_update_available_function,
                          const fs::path& base_directory,
                          bool vault_cheat) {
  return lifestuff_impl_->Initialise(software_update_available_function,
                                     base_directory,
                                     vault_cheat);
}

int LifeStuff::ConnectToSignals(
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
  return lifestuff_impl_->ConnectToSignals(true,
                                           chat_slot,
                                           file_slot,
                                           new_contact_slot,
                                           confirmed_contact_slot,
                                           profile_picture_slot,
                                           contact_presence_slot,
                                           contact_deletion_function,
                                           lifestuff_card_update_function,
                                           network_health_function,
                                           immediate_quit_required_function);
}

int LifeStuff::Finalise() {
  return lifestuff_impl_->Finalise();
}

/// Credential operations
int LifeStuff::CreateUser(const std::string& keyword,
                          const std::string& pin,
                          const std::string& password,
                          const fs::path& chunk_store) {
  return lifestuff_impl_->CreateUser(keyword, pin, password, chunk_store);
}

int LifeStuff::CreatePublicId(const std::string& public_id) {
  return lifestuff_impl_->CreatePublicId(public_id);
}

int LifeStuff::LogIn(const std::string& keyword,
                     const std::string& pin,
                     const std::string& password) {
  return lifestuff_impl_->LogIn(keyword, pin, password);
}

int LifeStuff::LogOut() {
  return lifestuff_impl_->LogOut();
}

int LifeStuff::MountDrive() {
  return lifestuff_impl_->MountDrive();
}

int LifeStuff::UnMountDrive() {
  return lifestuff_impl_->UnMountDrive();
}

int LifeStuff::StartMessagesAndIntros() {
  return lifestuff_impl_->StartMessagesAndIntros();
}

int LifeStuff::StopMessagesAndIntros() {
  return lifestuff_impl_->StopMessagesAndIntros();
}

int LifeStuff::CheckPassword(const std::string& password) {
  return lifestuff_impl_->CheckPassword(password);
}

int LifeStuff::ChangeKeyword(const std::string& new_keyword, const std::string& password) {
  return lifestuff_impl_->ChangeKeyword(new_keyword, password);
}

int LifeStuff::ChangePin(const std::string& new_pin, const std::string& password) {
  return lifestuff_impl_->ChangePin(new_pin, password);
}

int LifeStuff::ChangePassword(const std::string& new_password,
                              const std::string& current_password) {
  return lifestuff_impl_->ChangePassword(new_password, current_password);
}

int LifeStuff::LeaveLifeStuff() {
  return lifestuff_impl_->LeaveLifeStuff();
}

/// Contact operations
int LifeStuff::AddContact(const std::string& my_public_id,
                          const std::string& contact_public_id,
                          const std::string& message) {
  return lifestuff_impl_->AddContact(my_public_id, contact_public_id, message);
}

int LifeStuff::ConfirmContact(const std::string& my_public_id,
                              const std::string& contact_public_id) {
  return lifestuff_impl_->ConfirmContact(my_public_id, contact_public_id);
}

int LifeStuff::DeclineContact(const std::string& my_public_id,
                              const std::string& contact_public_id) {
  return lifestuff_impl_->DeclineContact(my_public_id, contact_public_id);
}

int LifeStuff::RemoveContact(const std::string& my_public_id,
                             const std::string& contact_public_id,
                             const std::string& removal_message) {
  return lifestuff_impl_->RemoveContact(my_public_id, contact_public_id, removal_message, "", true);
}

int LifeStuff::ChangeProfilePicture(const std::string& my_public_id,
                                    const std::string& profile_picture_contents) {
  return lifestuff_impl_->ChangeProfilePicture(my_public_id, profile_picture_contents);
}

std::string LifeStuff::GetOwnProfilePicture(const std::string& my_public_id) {
  return lifestuff_impl_->GetOwnProfilePicture(my_public_id);
}

std::string LifeStuff::GetContactProfilePicture(const std::string& my_public_id,
                                                const std::string& contact_public_id) {
  return lifestuff_impl_->GetContactProfilePicture(my_public_id, contact_public_id);
}

int LifeStuff::GetLifestuffCard(const std::string& my_public_id,
                                const std::string& contact_public_id,
                                SocialInfoMap& social_info) {
  return lifestuff_impl_->GetLifestuffCard(my_public_id, contact_public_id, social_info);
}

int LifeStuff::SetLifestuffCard(const std::string& my_public_id, const SocialInfoMap& social_info) {
  return lifestuff_impl_->SetLifestuffCard(my_public_id, social_info);
}

ContactMap LifeStuff::GetContacts(const std::string& my_public_id, uint16_t bitwise_status) {
  return lifestuff_impl_->GetContacts(my_public_id, bitwise_status);
}

std::vector<std::string> LifeStuff::PublicIdsList() const {
  return lifestuff_impl_->PublicIdsList();
}

/// Messaging
int LifeStuff::SendChatMessage(const std::string& sender_public_id,
                               const std::string& receiver_public_id,
                               const std::string& message) {
  return lifestuff_impl_->SendChatMessage(sender_public_id, receiver_public_id, message);
}

int LifeStuff::SendFile(const std::string& sender_public_id,
                        const std::string& receiver_public_id,
                        const fs::path& absolute_path) {
  return lifestuff_impl_->SendFile(sender_public_id, receiver_public_id, absolute_path);
}

int LifeStuff::AcceptSentFile(const std::string& identifier,
                              const fs::path& absolute_path,
                              std::string* file_name) {
  return lifestuff_impl_->AcceptSentFile(identifier, absolute_path, file_name);
}

int LifeStuff::RejectSentFile(const std::string& identifier) {
  return lifestuff_impl_->RejectSentFile(identifier);
}

/// Filesystem
int LifeStuff::ReadHiddenFile(const fs::path& absolute_path,
                              std::string* content) const {
  return lifestuff_impl_->ReadHiddenFile(absolute_path, content);
}

int LifeStuff::WriteHiddenFile(const fs::path& absolute_path,
                               const std::string& content,
                               bool overwrite_existing) {
  return lifestuff_impl_->WriteHiddenFile(absolute_path, content, overwrite_existing);
}

int LifeStuff::DeleteHiddenFile(const fs::path& absolute_path) {
  return lifestuff_impl_->DeleteHiddenFile(absolute_path);
}

int LifeStuff::SearchHiddenFiles(const fs::path& absolute_path,
                                 std::vector<std::string>* results) {
  return lifestuff_impl_->SearchHiddenFiles(absolute_path, results);
}

///
int LifeStuff::state() const { return lifestuff_impl_->state(); }

int LifeStuff::logged_in_state() const { return lifestuff_impl_->logged_in_state(); }

fs::path LifeStuff::mount_path() const { return lifestuff_impl_->mount_path(); }

}  // namespace lifestuff

}  // namespace maidsafe
