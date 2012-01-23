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

#include <string>
#include "boost/filesystem.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/pki/packet.h"

#include "maidsafe/passport/passport_config.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/version.h"
#include "maidsafe/lifestuff/utils.h"
#include "maidsafe/lifestuff/contacts.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/store_components/packet_manager.h"

#ifdef WIN32
#  include "maidsafe/drive/win_drive.h"
#else
#  include "maidsafe/drive/unix_drive.h"
#endif


#if MAIDSAFE_LIFESTUFF_VERSION != 111
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif

#ifdef WIN32
  typedef maidsafe::drive::CbfsDriveInUserSpace MaidDriveInUserSpace;
#else
  typedef maidsafe::drive::FuseDriveInUserSpace MaidDriveInUserSpace;
#endif

namespace fs = boost::filesystem;

namespace maidsafe {

class ChunkStore;

namespace lifestuff {

class PacketManager;
class Session;

class UserStorage {
 public:
  explicit UserStorage(std::shared_ptr<ChunkStore> chunk_store,
                       std::shared_ptr<PacketManager> packet_manager);
  virtual ~UserStorage() {}

  virtual void MountDrive(const fs::path &mount_dir_path,
                          const std::string &session_name,
                          std::shared_ptr<Session> session,
                          bool creation);
  virtual void UnMountDrive();
  virtual fs::path g_mount_dir();
  virtual bool mount_status();

  // ********************* File / Folder Transfers *****************************
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
  int SetShareDetails(const fs::path &absolute_path,
                      const std::string &share_id,
                      const asymm::Keys &share_keyring,
                      const std::string &this_user_id,
                      std::string *directory_id);
  int CreateShare(const fs::path &absolute_path,
                  std::map<Contact, bool> contacts,
                  std::string *directory_id,
                  std::string *share_id);
  int InsertShare(const fs::path &absolute_path,
                  const std::string &directory_id,
                  const std::string &share_id,
                  const asymm::Keys &share_keyring);
  int AddShareUser(const fs::path &absolute_path,
                   const std::string &user_id,
                   bool admin_rights);
  void GetAllShareUsers(const fs::path &absolute_path,
                        std::map<std::string, bool> *all_share_users) const;
  int RemoveShareUser(const fs::path &absolute_path,
                      const std::string &user_id);
  int GetShareUsersRights(const fs::path &absolute_path,
                          const std::string &user_id,
                          bool *admin_rights) const;
  int SetShareUsersRights(const fs::path &absolute_path,
                          const std::string &user_id,
                          bool admin_rights);

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

 private:
  bool mount_status_;
  std::shared_ptr<ChunkStore> chunk_store_;
  std::shared_ptr<MaidDriveInUserSpace> drive_in_user_space_;
  std::shared_ptr<PacketManager> packet_manager_;
  std::shared_ptr<Session> session_;
  fs::path g_mount_dir_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_USER_STORAGE_H_
