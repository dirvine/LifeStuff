/***************************************************************************************************
 *  Copyright 2013 MaidSafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use.  The use of this code is governed by the licence file licence.txt found in the root of    *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit         *
 *  written permission of the board of directors of MaidSafe.net.                                  *
 **************************************************************************************************/

#include "maidsafe/lifestuff/lifestuff_api.h"

#include <algorithm>
#include <functional>
#include <vector>

#include "maidsafe/lifestuff/lifestuff_impl.h"

namespace maidsafe {
namespace lifestuff {

LifeStuff::LifeStuff()
  : lifestuff_impl_(new LifeStuffImpl()) {}

LifeStuff::~LifeStuff() {}


void LifeStuff::LogIn(const Keyword& keyword, const Pin& pin, const Password& password) {
  lifestuff_impl_->LogIn(keyword, pin, password);
}

void LifeStuff::LogOut() {
  lifestuff_impl_->LogOut();
}

void LifeStuff::MountDrive() {
  lifestuff_impl_->MountDrive();
}

void LifeStuff::UnMountDrive() {
  lifestuff_impl_->UnMountDrive();
}

}  // namespace lifestuff
}  // namespace maidsafe


//
//#include "maidsafe/lifestuff/lifestuff_api.h"
//
//#include <algorithm>
//#include <functional>
//#include <vector>
//
//#include "maidsafe/lifestuff/lifestuff_impl.h"
//
//namespace maidsafe {
//
//namespace lifestuff {
//
//LifeStuff::LifeStuff(const Slots& slot_functions, const fs::path& base_directory)
//  : lifestuff_impl_(std::make_shared<LifeStuffImpl>(slot_functions, base_directory)) {}
//
//LifeStuff::~LifeStuff() {}
//
///// Credential operations
//int LifeStuff::CreateUser(const NonEmptyString& keyword,
//                          const NonEmptyString& pin,
//                          const NonEmptyString& password,
//                          const fs::path& chunk_store) {
//  return lifestuff_impl_->CreateUser(keyword, pin, password, chunk_store);
//}
//
//int LifeStuff::CreatePublicId(const NonEmptyString& public_id) {
//  return lifestuff_impl_->CreatePublicId(public_id);
//}
//
//int LifeStuff::LogIn(const NonEmptyString& keyword,
//                     const NonEmptyString& pin,
//                     const NonEmptyString& password) {
//  return lifestuff_impl_->LogIn(keyword, pin, password);
//}
//
//int LifeStuff::LogOut() {
//  return lifestuff_impl_->LogOut();
//}
//
//int LifeStuff::MountDrive() {
//  return lifestuff_impl_->MountDrive();
//}
//
//int LifeStuff::UnMountDrive() {
//  return lifestuff_impl_->UnMountDrive();
//}
//
//int LifeStuff::StartMessagesAndIntros() {
//  return lifestuff_impl_->StartMessagesAndIntros();
//}
//
//int LifeStuff::StopMessagesAndIntros() {
//  return lifestuff_impl_->StopMessagesAndIntros();
//}
//
//int LifeStuff::CheckPassword(const NonEmptyString& password) {
//  return lifestuff_impl_->CheckPassword(password);
//}
//
//int LifeStuff::ChangeKeyword(const NonEmptyString& new_keyword, const NonEmptyString& password) {
//  return lifestuff_impl_->ChangeKeyword(new_keyword, password);
//}
//
//int LifeStuff::ChangePin(const NonEmptyString& new_pin, const NonEmptyString& password) {
//  return lifestuff_impl_->ChangePin(new_pin, password);
//}
//
//int LifeStuff::ChangePassword(const NonEmptyString& new_password,
//                              const NonEmptyString& current_password) {
//  return lifestuff_impl_->ChangePassword(new_password, current_password);
//}
//
//int LifeStuff::LeaveLifeStuff() {
//  return lifestuff_impl_->LeaveLifeStuff();
//}
//
///// Contact operations
//int LifeStuff::AddContact(const NonEmptyString& my_public_id,
//                          const NonEmptyString& contact_public_id,
//                          const std::string& message) {
//  return lifestuff_impl_->AddContact(my_public_id, contact_public_id, message);
//}
//
//int LifeStuff::ConfirmContact(const NonEmptyString& my_public_id,
//                              const NonEmptyString& contact_public_id) {
//  return lifestuff_impl_->ConfirmContact(my_public_id, contact_public_id);
//}
//
//int LifeStuff::DeclineContact(const NonEmptyString& my_public_id,
//                              const NonEmptyString& contact_public_id) {
//  return lifestuff_impl_->DeclineContact(my_public_id, contact_public_id);
//}
//
//int LifeStuff::RemoveContact(const NonEmptyString& my_public_id,
//                             const NonEmptyString& contact_public_id,
//                             const std::string& removal_message) {
//  return lifestuff_impl_->RemoveContact(my_public_id, contact_public_id, removal_message, true);
//}
//
//int LifeStuff::ChangeProfilePicture(const NonEmptyString& my_public_id,
//                                    const NonEmptyString& profile_picture_contents) {
//  return lifestuff_impl_->ChangeProfilePicture(my_public_id, profile_picture_contents);
//}
//
//NonEmptyString LifeStuff::GetOwnProfilePicture(const NonEmptyString& my_public_id) {
//  return lifestuff_impl_->GetOwnProfilePicture(my_public_id);
//}
//
//NonEmptyString LifeStuff::GetContactProfilePicture(const NonEmptyString& my_public_id,
//                                                const NonEmptyString& contact_public_id) {
//  return lifestuff_impl_->GetContactProfilePicture(my_public_id, contact_public_id);
//}
//
//int LifeStuff::GetLifestuffCard(const NonEmptyString& my_public_id,
//                                const std::string& contact_public_id,
//                                SocialInfoMap& social_info) {
//  return lifestuff_impl_->GetLifestuffCard(my_public_id, contact_public_id, social_info);
//}
//
//int LifeStuff::SetLifestuffCard(const NonEmptyString& my_public_id,
//                                const SocialInfoMap& social_info) {
//  return lifestuff_impl_->SetLifestuffCard(my_public_id, social_info);
//}
//
//ContactMap LifeStuff::GetContacts(const NonEmptyString& my_public_id, uint16_t bitwise_status) {
//  return lifestuff_impl_->GetContacts(my_public_id, bitwise_status);
//}
//
//std::vector<NonEmptyString> LifeStuff::PublicIdsList() const {
//  return lifestuff_impl_->PublicIdsList();
//}
//
///// Messaging
//int LifeStuff::SendChatMessage(const NonEmptyString& sender_public_id,
//                               const NonEmptyString& receiver_public_id,
//                               const NonEmptyString& message) {
//  return lifestuff_impl_->SendChatMessage(sender_public_id, receiver_public_id, message);
//}
//
//int LifeStuff::SendFile(const NonEmptyString& sender_public_id,
//                        const NonEmptyString& receiver_public_id,
//                        const fs::path& absolute_path) {
//  return lifestuff_impl_->SendFile(sender_public_id, receiver_public_id, absolute_path);
//}
//
//int LifeStuff::AcceptSentFile(const NonEmptyString& identifier,
//                              const fs::path& absolute_path,
//                              std::string* file_name) {
//  return lifestuff_impl_->AcceptSentFile(identifier, absolute_path, file_name);
//}
//
//int LifeStuff::RejectSentFile(const NonEmptyString& identifier) {
//  return lifestuff_impl_->RejectSentFile(identifier);
//}
//
///// Filesystem
//int LifeStuff::ReadHiddenFile(const fs::path& absolute_path,
//                              std::string* content) const {
//  return lifestuff_impl_->ReadHiddenFile(absolute_path, content);
//}
//
//int LifeStuff::WriteHiddenFile(const fs::path& absolute_path,
//                               const NonEmptyString& content,
//                               bool overwrite_existing) {
//  return lifestuff_impl_->WriteHiddenFile(absolute_path, content, overwrite_existing);
//}
//
//int LifeStuff::DeleteHiddenFile(const fs::path& absolute_path) {
//  return lifestuff_impl_->DeleteHiddenFile(absolute_path);
//}
//
//int LifeStuff::SearchHiddenFiles(const fs::path& absolute_path,
//                                 std::vector<std::string>* results) {
//  return lifestuff_impl_->SearchHiddenFiles(absolute_path, results);
//}
//
/////
//int LifeStuff::state() const { return lifestuff_impl_->state(); }
//
//int LifeStuff::logged_in_state() const { return lifestuff_impl_->logged_in_state(); }
//
//fs::path LifeStuff::mount_path() const { return lifestuff_impl_->mount_path(); }
//
//}  // namespace lifestuff
//
//}  // namespace maidsafe
