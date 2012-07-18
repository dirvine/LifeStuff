/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Version:      1.0
* Created:      2011-04-18
* Author:       Team
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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_USER_STORAGE_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_USER_STORAGE_H_

#include <list>
#include <map>
#include <string>
#include <vector>

#include "boost/filesystem.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#ifdef WIN32
#  include "maidsafe/drive/win_drive.h"
#else
#  include "maidsafe/drive/unix_drive.h"
#endif
#include "maidsafe/drive/return_codes.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"


#include "maidsafe/passport/passport_config.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/utils.h"

#ifdef WIN32
  typedef maidsafe::drive::CbfsDriveInUserSpace MaidDriveInUserSpace;
#else
  typedef maidsafe::drive::FuseDriveInUserSpace MaidDriveInUserSpace;
#endif

namespace fs = boost::filesystem;
namespace pca = maidsafe::priv::chunk_actions;
namespace pcs = maidsafe::priv::chunk_store;

namespace maidsafe {

namespace lifestuff {

class MessageHandler;
class Session;

class UserStorage {
 public:
  UserStorage(std::shared_ptr<pcs::RemoteChunkStore> chunk_store,
              MessageHandler& message_handler);
  virtual ~UserStorage() {}

  virtual void MountDrive(const fs::path &mount_dir_path,
                          Session* session,
                          bool creation,
                          const std::string &drive_logo = "LifeStuff Drive");
  virtual void UnMountDrive();
  virtual fs::path mount_dir();
  virtual bool mount_status();

  // ********************* File / Folder Transfers *****************************
  bool ParseAndSaveDataMap(const std::string &file_name,
                           const std::string &serialised_data_map,
                           std::string *data_map_hash);
  int GetDataMap(const fs::path &absolute_path, std::string *serialised_data_map) const;
  int InsertDataMap(const fs::path &absolute_path, const std::string &serialised_data_map);
  int GetDirectoryListing(const fs::path &absolute_path,
                          std::string *parent_id,
                          std::string *directory_id) const;
  int InsertDirectoryListing(const fs::path &absolute_path,
                             const std::string &parent_id,
                             const std::string &directory_id);

  // ****************************** Shares *************************************
  bool SavePrivateShareData(const std::string &serialised_share_data, const std::string &share_id);
  bool DeletePrivateShareData(const std::string &share_id);
  bool SaveOpenShareData(const std::string &serialised_share_data, const std::string &share_id);
  int CreateShare(const std::string &sender_public_username,
                  const fs::path &drive_path,
                  const fs::path &share_path,
                  const StringIntMap &contacts,
                  bool private_share,
                  StringIntMap *contacts_results = nullptr);
  int CreateOpenShare(const std::string &sender_public_username,
                      const fs::path &drive_path,
                      const fs::path &share_path,
                      const StringIntMap &contacts,
                      StringIntMap *contacts_results = nullptr);
  int GetAllShares(StringIntMap *shares_names);
  int InsertShare(const fs::path &absolute_path,
                  const std::string &share_id,
                  const std::string &inviter_id,
                  std::string *share_name,
                  const std::string &directory_id,
                  const asymm::Keys &share_keyring);
  int StopShare(const std::string &sender_public_username,
                const fs::path &absolute_path,
                bool delete_data);
  int RemoveShare(const fs::path &absolute_path, const std::string &sender_public_username = "");
  void ShareDeleted(const std::string &share_id);
  int UpdateShare(const std::string &share_id,
                  const std::string *new_share_id,
                  const std::string *new_directory_id,
                  const asymm::Keys *new_key_ring,
                  int* access_right);
  int AddShareUsers(const std::string &sender_public_username,
                    const fs::path &absolute_path,
                    const StringIntMap &contacts,
                    bool private_share,
                    StringIntMap *contacts_results = nullptr);
  int AddOpenShareUser(const fs::path &absolute_path, const StringIntMap &contacts);
  int OpenShareInvitation(const std::string &sender_public_username,
                          const fs::path &absolute_path,
                          const StringIntMap &contacts,
                          StringIntMap *contacts_results);
  int GetAllShareUsers(const fs::path &absolute_path, StringIntMap *all_share_users) const;
  int RemoveShareUsers(const std::string &sender_public_username,
                       const fs::path &absolute_path,
                       const std::vector<std::string> &user_ids,
                       bool private_share);
  int UserLeavingShare(const std::string &share_id, const std::string &user_id);
  void InvitationResponse(const std::string &user_id,
                          const std::string &share_name,
                          const std::string &share_id);
  int RemoveOpenShareUsers(const fs::path &absolute_path,
                           const std::vector<std::string> &user_ids);
  int GetShareUsersRights(const fs::path &absolute_path,
                          const std::string &user_id,
                          int *admin_rights) const;
  int SetShareUsersRights(const std::string &sender_public_username,
                          const fs::path &absolute_path,
                          const std::string &user_id,
                          int admin_rights,
                          bool private_share);
  int GetShareDetails(const std::string &share_id,
                      fs::path *relative_path,
                      asymm::Keys *share_keyring,
                      std::string *directory_id,
                      StringIntMap *share_users) const;
  int GetShareDetails(const fs::path &relative_path,
                      fs::path *share_name,
                      asymm::Keys *share_keyring,
                      std::string *share_id,
                      std::string *directory_id,
                      std::map<std::string, int> *share_users,
                      std::string *owner_id) const;
  std::string MemberAccessChange(const std::string &share_id,
                                 const std::string &directory_id,
                                 const std::string &new_share_id,
                                 const asymm::Keys &key_ring,
                                 int access_right);
  int MovingShare(const std::string &sender_public_username,
                  const std::string &share_id,
                  const fs::path &relative_path,
                  const asymm::Keys &old_key_ring,
                  bool private_share,
                  const StringIntMap &contacts,
                  std::string *new_share_id_return = nullptr);
  int DowngradeShareUsersRights(const std::string &sender_public_username,
                                const fs::path &absolute_path,
                                const StringIntMap &contacts,
                                StringIntMap *results,
                                bool private_share);
  int GetPrivateSharesContactBeingOwner(const std::string &my_public_id,
                                        const std::string &contact_public_id,
                                        std::vector<std::string> *shares_names);
  // **************************** File Notes ***********************************
  int GetNotes(const fs::path &absolute_path, std::vector<std::string> *notes) const;
  int AddNote(const fs::path &absolute_path, const std::string &note);

  // *************************** Hidden Files **********************************
  int ReadHiddenFile(const fs::path &absolute_path, std::string *content) const;
  int WriteHiddenFile(const fs::path &absolute_path,
                      const std::string &content,
                      bool overwrite_existing);
  int DeleteHiddenFile(const fs::path &absolute_path);
  int SearchHiddenFiles(const fs::path &absolute_path,
                        const std::string &regex,
                        std::list<std::string> *results);
  int GetHiddenFileDataMap(const boost::filesystem3::path &absolute_path, std::string *data_map);

  // ************************* Signals Handling ********************************
  bs2::connection ConnectToDriveChanged(drive::DriveChangedSlotPtr slot) const;
  bs2::connection ConnectToShareChangedSignal(const ShareChangedFunction &function);
  bs2::connection ConnectToShareRenamedSignal(const ShareRenamedFunction &function);

  std::string ConstructFile(const std::string &serialised_data_map);

 private:
  UserStorage &operator=(const UserStorage&);
  UserStorage(const UserStorage&);
  int InformContactsOperation(InboxItemType item_type,
                              const std::string &sender_public_username,
                              const StringIntMap &contacts,
                              const std::string &share_id,
                              const std::string &absolute_path = "",
                              const std::string &directory_id = "",
                              const asymm::Keys &key_ring = asymm::Keys(),
                              const std::string &new_share_id = "",
                              StringIntMap *contacts_results = nullptr);
  int InformContacts(InboxItemType item_type,
                     const std::string &sender_public_username,
                     const StringIntMap &contacts,
                     const std::string &share_id,
                     const std::string &share_name,
                     const std::string &directory_id,
                     const asymm::Keys &key_ring = asymm::Keys(),
                     const std::string &new_share_id = "",
                     StringIntMap *contacts_results = nullptr);

  bool mount_status_;
  std::shared_ptr<pcs::RemoteChunkStore> chunk_store_;
  std::shared_ptr<MaidDriveInUserSpace> drive_in_user_space_;
  ShareRenamedFunction share_renamed_function_;
  ShareChangedFunction share_changed_function_;
  Session* session_;
  MessageHandler& message_handler_;
  fs::path mount_dir_;
  std::shared_ptr<boost::thread> mount_thread_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_USER_STORAGE_H_
