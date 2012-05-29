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

#ifndef MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_
#define MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_

#include <map>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#ifndef LOCAL_TARGETS_ONLY
#include "maidsafe/pd/client/client_container.h"
#endif

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/detail/contacts.h"

#include "maidsafe/lifestuff/detail/utils.h"

namespace fs = boost::filesystem;
namespace bptime = boost::posix_time;
namespace pcs = maidsafe::priv::chunk_store;

namespace maidsafe {

namespace lifestuff {

class Session;
class UserCredentials;
class UserStorage;
class PublicId;
class MessageHandler;

struct Slots {
  Slots()
      : chat_slot(),
        file_slot(),
        new_contact_slot(),
        confirmed_contact_slot(),
        profile_picture_slot(),
        contact_presence_slot(),
        contact_deletion_function(),
        private_share_invitation_function(),
        private_share_deletion_function(),
        private_access_level_function(),
        open_share_invitation_function(),
        share_renamed_function(),
        share_changed_function() {}
  ChatFunction chat_slot;
  FileTransferFunction file_slot;
  NewContactFunction new_contact_slot;
  ContactConfirmationFunction confirmed_contact_slot;
  ContactProfilePictureFunction profile_picture_slot;
  ContactPresenceFunction contact_presence_slot;
  ContactDeletionFunction contact_deletion_function;
  PrivateShareInvitationFunction private_share_invitation_function;
  PrivateShareDeletionFunction private_share_deletion_function;
  PrivateMemberAccessLevelFunction private_access_level_function;
  OpenShareInvitationFunction open_share_invitation_function;
  ShareRenamedFunction share_renamed_function;
  ShareChangedFunction share_changed_function;
};

class LifeStuffImpl {
 public:
  LifeStuffImpl();
  ~LifeStuffImpl();

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
      const OpenShareInvitationFunction &open_share_invitation_function,
      const ShareRenamedFunction &share_renamed_function,
      const ShareChangedFunction &share_changed_function);
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
  int ChangeKeyword(const std::string &new_username,
                    const std::string &password);
  int ChangePin(const std::string &new_pin,
                const std::string &password);
  int ChangePassword(const std::string &new_password,
                     const std::string &current_password);
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
                          StringIntMap *share_names);
  // For owners only
  int GetPrivateShareMembers(const std::string &my_public_id,
                             const std::string &share_name,
                             StringIntMap *share_members);
  int GetPrivateSharesIncludingMember(const std::string &my_public_id,
                                      const std::string &contact_public_id,
                                      std::vector<std::string> *share_names);
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
                       std::vector<std::string> *share_names);
  int GetOpenShareMembers(const std::string &my_public_id,
                          const std::string &share_name,
                          std::vector<std::string> *share_members);
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
  int thread_count_;
  LifeStuffState state_;
  fs::path buffered_path_;
#ifdef LOCAL_TARGETS_ONLY
  fs::path simulation_path_;
#endif
  bptime::seconds interval_;
  AsioService asio_service_;
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store_;
#ifndef LOCAL_TARGETS_ONLY
  std::shared_ptr<pd::ClientContainer> client_container_;
#endif
  std::shared_ptr<Session> session_;
  std::shared_ptr<UserCredentials> user_credentials_;
  std::shared_ptr<UserStorage> user_storage_;
  std::shared_ptr<PublicId> public_id_;
  std::shared_ptr<MessageHandler> message_handler_;
  Slots slots_;

  // Session saving control
  boost::mutex save_session_mutex_;
  bool saving_session_;

  void ConnectInternalElements();
  int SetValidPmidAndInitialisePublicComponents();
  int PreContactChecks(const std::string &my_public_id);
  void InvokeDoSession();
  void DoSaveSession();
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_LIFESTUFF_IMPL_H_
