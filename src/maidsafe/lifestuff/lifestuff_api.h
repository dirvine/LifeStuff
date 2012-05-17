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

#include <map>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/version.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 400
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif

namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff {

class LifeStuffImpl;

class LifeStuff {
 public:
  LifeStuff();
  ~LifeStuff();

  /// State operations
  int Initialise(const fs::path &base_directory = fs::path());
  int ConnectToSignals(
      const ChatFunction &chat_slot,
      const FileTransferFunction &file_slot,
      const NewContactFunction &new_contact_slot,
      const ContactConfirmationFunction &confirmed_contact_slot,
      const ContactProfilePictureFunction &profile_picture_slot,
      const ContactPresenceFunction &contact_presence_slot,
      const ContactDeletionFunction &contact_deletion_function,
      const PrivateShareInvitationFunction &share_invitation_function,
      const PrivateShareDeletionFunction &share_deletion_function,
      const PrivateMemberAccessLevelFunction &access_level_function,
      const OpenShareInvitationFunction &open_share_invitation_function);
  int Finalise();

  /// Credential operations
  int CreateUser(const std::string &username,
                 const std::string &pin,
                 const std::string &password);
  int CreatePublicId(const std::string &public_id);
  int LogIn(const std::string &username,
            const std::string &pin,
            const std::string &password);
  int LogOut();

  int CheckPassword(const std::string &password);
  int ChangeKeyword(const std::string &old_username,
                    const std::string &new_username,
                    const std::string &password);
  int ChangePin(const std::string &old_pin,
                const std::string &new_pin,
                const std::string &password);
  int ChangePassword(const std::string &old_password,
                     const std::string &new_password);
  int ChangePublicId(const std::string &public_id,
                     const std::string &password);

  /// Contact operations
  int AddContact(const std::string &my_public_id,
                 const std::string &contact_public_id);
  int ConfirmContact(const std::string &my_public_id,
                     const std::string &contact_public_id);
  int DeclineContact(const std::string &my_public_id,
                     const std::string &contact_public_id);
  int RemoveContact(const std::string &my_public_id,
                    const std::string &contact_public_id,
                    const std::string &removal_message);
  int ChangeProfilePicture(const std::string &my_public_id,
                           const std::string &profile_picture_contents);
  std::string GetOwnProfilePicture(const std::string &my_public_id);
  std::string GetContactProfilePicture(const std::string &my_public_id,
                                       const std::string &contact_public_id);
  ContactMap GetContacts(const std::string &my_public_id,
                         uint16_t bitwise_status = kConfirmed | kRequestSent);
  std::vector<std::string> PublicIdsList() const;

  /// Messaging
  int SendChatMessage(const std::string &sender_public_id,
                      const std::string &receiver_public_id,
                      const std::string &message);
  int SendFile(const std::string &sender_public_id,
               const std::string &receiver_public_id,
               const fs::path &absolute_path);
  int AcceptSentFile(const std::string &identifier,
                     const fs::path &absolute_path = fs::path(),
                     std::string *file_name = nullptr);
  int RejectSentFile(const std::string &identifier);

  /// Filesystem
  int ReadHiddenFile(const fs::path &absolute_path, std::string *content) const;
  int WriteHiddenFile(const fs::path &absolute_path,
                      const std::string &content,
                      bool overwrite_existing);
  int DeleteHiddenFile(const fs::path &absolute_path);

  /// Private Shares
  // If error code is given, map of rsults should be empty. If nobody added,
  // revert everything. Directory has to be moved, not copied. If directory
  // already exists in shared stuff, append ending as dropbox does. If a
  // contact is passed in as owner, it should fail for that contact.
  int CreatePrivateShareFromExistingDirectory(
      const std::string &my_public_id,
      const fs::path &directory_in_lifestuff_drive,
      const StringIntMap &contacts,
      std::string *share_name,
      StringIntMap *results);
  int CreateEmptyPrivateShare(const std::string &my_public_id,
                              const StringIntMap &contacts,
                              std::string *share_name,
                              StringIntMap *results);
  int GetPrivateShareList(const std::string &my_public_id,
                          StringIntMap *shares_names);
  // For owners only
  int GetPrivateShareMembers(const std::string &my_public_id,
                             const std::string &share_name,
                             StringIntMap *shares_members);
  int GetPrivateSharesIncludingMember(const std::string &my_public_id,
                                      const std::string &contact_public_id,
                                      std::vector<std::string> *shares_names);
  // Should create a directory adapting to other possible shares
  int AcceptPrivateShareInvitation(const std::string &my_public_id,
                                   const std::string &contact_public_id,
                                   const std::string &share_id,
                                   std::string *share_name);
  int RejectPrivateShareInvitation(const std::string &my_public_id,
                                   const std::string &share_id);
  // Only for owners
  int EditPrivateShareMembers(const std::string &my_public_id,
                              const StringIntMap &public_ids,
                              const std::string &share_name,
                              StringIntMap *results);
  // Only for owners
  int DeletePrivateShare(const std::string &my_public_id,
                         const std::string &share_name,
                         bool delete_data);
  // Should work for RO and full access. Only for non-owners
  int LeavePrivateShare(const std::string &my_public_id,
                        const std::string &share_name);

  /// Open Shares
  int CreateOpenShareFromExistingDirectory(
        const std::string &my_public_id,
        const fs::path &directory_in_lifestuff_drive,
        const std::vector<std::string> &contacts,
        std::string *share_name,
        StringIntMap *results);
  int CreateEmptyOpenShare(const std::string &my_public_id,
                           const std::vector<std::string> &contacts,
                           std::string *share_name,
                           StringIntMap *results);
  int InviteMembersToOpenShare(const std::string &my_public_id,
                               const std::vector<std::string> &contacts,
                               const std::string &share_name,
                               StringIntMap *results);
  int GetOpenShareList(const std::string &my_public_id,
                       std::vector<std::string> *shares_names);
  int GetOpenShareMembers(const std::string &my_public_id,
                          const std::string &share_name,
                          std::vector<std::string> *shares_members);
  int AcceptOpenShareInvitation(const std::string &my_public_id,
                                const std::string &contact_public_id,
                                const std::string &share_id,
                                std::string *share_name);
  int RejectOpenShareInvitation(const std::string &my_public_id,
                                const std::string &share_id);
  int LeaveOpenShare(const std::string &my_public_id,
                     const std::string &share_name);

  ///
  int state() const;
  fs::path mount_path() const;

 private:
  std::shared_ptr<LifeStuffImpl> lifestuff_impl;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_API_H_
