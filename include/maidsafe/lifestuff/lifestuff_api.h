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

#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_
#define MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_

#include <list>
#include <map>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/log.h"

#include "maidsafe/lifestuff/lifestuff.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

class LifeStuffImpl;

class LifeStuff {
 public:
  LifeStuff();
  ~LifeStuff();

  /// State operations
  int Initialise(const UpdateAvailableFunction& software_update_available_function,
                 const fs::path& base_directory = fs::path());
  int ConnectToSignals(const ChatFunction& chat_slot,
                       const FileTransferFunction& file_slot,
                       const NewContactFunction& new_contact_slot,
                       const ContactConfirmationFunction& confirmed_contact_slot,
                       const ContactProfilePictureFunction& profile_picture_slot,
                       const ContactPresenceFunction& contact_presence_slot,
                       const ContactDeletionFunction& contact_deletion_function,
                       const LifestuffCardUpdateFunction& lifestuff_card_update_function,
                       const NetworkHealthFunction& network_health_function,
                       const ImmediateQuitRequiredFunction& immediate_quit_required_function);

  int Finalise();

  /// Credential operations
  int CreateUser(const std::string& keyword,
                 const std::string& pin,
                 const std::string& password,
                 const fs::path& chunk_store = fs::path(),
                 bool vault_cheat = false);
  int CreatePublicId(const std::string& public_id);
  int LogIn(const std::string& keyword, const std::string& pin, const std::string& password);
  int LogOut();
  int CreateAndMountDrive();
  int MountDrive();
  int UnMountDrive();
  int StartMessagesAndIntros();
  int StopMessagesAndIntros();

  int CheckPassword(const std::string& password);
  int ChangeKeyword(const std::string& new_keyword, const std::string& password);
  int ChangePin(const std::string& new_pin, const std::string& password);
  int ChangePassword(const std::string& new_password, const std::string& current_password);
  int ChangePublicId(const std::string& public_id, const std::string& password);

  int LeaveLifeStuff();  // ='(

  /// Contact operations
  int AddContact(const std::string& my_public_id, const std::string& contact_public_id,
                 const std::string& message = "");
  int ConfirmContact(const std::string& my_public_id, const std::string& contact_public_id);
  int DeclineContact(const std::string& my_public_id, const std::string& contact_public_id);
  int RemoveContact(const std::string& my_public_id,
                    const std::string& contact_public_id,
                    const std::string& removal_message);
  int ChangeProfilePicture(const std::string& my_public_id,
                           const std::string& profile_picture_contents);
  std::string GetOwnProfilePicture(const std::string& my_public_id);
  std::string GetContactProfilePicture(const std::string& my_public_id,
                                       const std::string& contact_public_id);
  int GetLifestuffCard(const std::string& my_public_id,
                       const std::string& contact_public_id,
                       SocialInfoMap& social_info);
  int SetLifestuffCard(const std::string& my_public_id, const SocialInfoMap& social_info);
  ContactMap GetContacts(const std::string& my_public_id,
                         uint16_t bitwise_status = kConfirmed | kRequestSent);
  std::vector<std::string> PublicIdsList() const;

  /// Messaging
  int SendChatMessage(const std::string& sender_public_id,
                      const std::string& receiver_public_id,
                      const std::string& message);
  int SendFile(const std::string& sender_public_id,
               const std::string& receiver_public_id,
               const fs::path& absolute_path);
  int AcceptSentFile(const std::string& identifier,
                     const fs::path& absolute_path = fs::path(),
                     std::string* file_name = nullptr);
  int RejectSentFile(const std::string& identifier);

  /// Filesystem
  int ReadHiddenFile(const fs::path& absolute_path, std::string* content) const;
  int WriteHiddenFile(const fs::path& absolute_path,
                      const std::string& content,
                      bool overwrite_existing);
  int DeleteHiddenFile(const fs::path& absolute_path);
  int SearchHiddenFiles(const fs::path& absolute_path,
                        std::vector<std::string>* results);

  ///
  int state() const;
  int logged_in_state() const;
  fs::path mount_path() const;

 private:
  std::shared_ptr<LifeStuffImpl> lifestuff_impl_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_
