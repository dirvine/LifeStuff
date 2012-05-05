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

#ifndef MAIDSAFE_LIFESTUFF_USER_STORAGE_H_
#define MAIDSAFE_LIFESTUFF_USER_STORAGE_H_

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

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#include "maidsafe/pki/packet.h"

#include "maidsafe/passport/passport_config.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"

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
              std::shared_ptr<MessageHandler> message_handler);
  virtual ~UserStorage() {}

  virtual void MountDrive(const fs::path &mount_dir_path,
                          std::shared_ptr<Session> session,
                          bool creation,
                          const std::string &drive_logo = "LifeStuff Drive");
  virtual void UnMountDrive();
  virtual fs::path mount_dir();
  virtual bool mount_status();

  // ********************* File / Folder Transfers *****************************
  bool ParseAndSaveDataMap(const std::string &file_name,
                           const std::string &serialised_data_map,
                           std::string *data_map_hash);
  int GetDataMap(const fs::path &absolute_path,
                 std::string *serialised_data_map) const;
  int InsertDataMap(const fs::path &absolute_path,
                    const std::string &serialised_data_map);
  int GetDirectoryListing(const fs::path &absolute_path,
                          std::string *parent_id,
                          std::string *directory_id) const;
  int InsertDirectoryListing(const fs::path &absolute_path,
                             const std::string &parent_id,
                             const std::string &directory_id);

  // ****************************** Shares *************************************
  bool SaveShareData(const std::string &serialised_share_data,
                     const std::string &share_id);
  bool SaveOpenShareData(const std::string &serialised_share_data,
                         const std::string &share_id);
  int CreateShare(const std::string &sender_public_username,
                  const fs::path &absolute_path,
                  const StringIntMap &contacts,
                  bool private_share,
                  StringIntMap *contacts_results = nullptr);
  int CreateOpenShare(const std::string &sender_public_username,
                      const fs::path &absolute_path,
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
                const fs::path &absolute_path);
  int RemoveShare(const fs::path &absolute_path,
                  const std::string &sender_public_username = "");
  void LeaveShare(const std::string &sender_public_username,
                  const std::string &share_id);
  int UpdateShare(const std::string &share_id,
                  const std::string *new_share_id,
                  const std::string *new_directory_id,
                  const asymm::Keys *new_key_ring);
  int AddShareUsers(const std::string &sender_public_username,
                    const fs::path &absolute_path,
                    const StringIntMap &contacts,
                    bool private_share,
                    StringIntMap *contacts_results = nullptr);
  int AddOpenShareUser(const fs::path &absolute_path,
                       const StringIntMap &contacts);
  int OpenShareInvitation(const std::string &sender_public_username,
                          const fs::path &absolute_path,
                          const StringIntMap &contacts,
                          StringIntMap *contacts_results);
  int GetAllShareUsers(const fs::path &absolute_path,
                       StringIntMap *all_share_users) const;
  int RemoveShareUsers(const std::string &sender_public_username,
                       const fs::path &absolute_path,
                       const std::vector<std::string> &user_ids,
                       bool private_share);
  int UserLeavingShare(const std::string &share_id,
                       const std::string &user_id);
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
                      StringIntMap *share_users);
  void  MemberAccessChange(const std::string &my_public_id,
                           const std::string &sender_public_username,
                           const std::string &share_id,
                           int access_right);
  int MovingShare(const std::string &sender_public_username,
                  const std::string &share_id,
                  const fs::path &relative_path,
                  const asymm::Keys &old_key_ring,
                  bool private_share,
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
  int GetNotes(const fs::path &absolute_path,
               std::vector<std::string> *notes) const;
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
  int GetHiddenFileDataMap(const boost::filesystem3::path &absolute_path,
                           std::string *data_map);

  // ************************* Signals Handling ********************************
  bs2::connection ConnectToDriveChanged(drive::DriveChangedSlotPtr slot) const;
  bs2::connection ConnectToShareChanged(drive::ShareChangedSlotPtr slot) const;

  std::string ConstructFile(const std::string &serialised_data_map);

 private:
  template<typename Operation>
  int InformContactsOperation(
        const std::string &sender_public_username,
        const StringIntMap &contacts,
        const std::string &share_id,
        const std::string &absolute_path = "",
        const std::string &directory_id = "",
        const asymm::Keys &key_ring = asymm::Keys(),
        const std::string &new_share_id = "",
        StringIntMap *contacts_results = nullptr);
  template<uint32_t ItemType>
  int InformContacts(
        const std::string &sender_public_username,
        const StringIntMap &contacts,
        const std::string &share_id,
        // const std::string &absolute_path = "",
        const fs::path &relative_path = "",
        const std::string &directory_id = "",
        const asymm::Keys &key_ring = asymm::Keys(),
        const std::string &new_share_id = "",
        StringIntMap *contacts_results = nullptr);
  pcs::RemoteChunkStore::ValidationData PopulateValidationData(
      const asymm::Keys &key_ring);

  bool mount_status_;
  std::shared_ptr<pcs::RemoteChunkStore> chunk_store_;
  std::shared_ptr<MaidDriveInUserSpace> drive_in_user_space_;
  std::shared_ptr<Session> session_;
  std::shared_ptr<MessageHandler> message_handler_;
  fs::path mount_dir_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_USER_STORAGE_H_
