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
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "boost/filesystem.hpp"
#include "boost/asio/io_service.hpp"

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

class Session;

class UserStorage {
 public:
  explicit UserStorage(std::shared_ptr<pcs::RemoteChunkStore> chunk_store);
  virtual ~UserStorage() {}

  virtual void MountDrive(const fs::path& mount_dir_path,
                          Session* session,
                          bool creation,
                          bool read_only,
                          const std::string& drive_logo = "LifeStuff Drive");
  virtual void UnMountDrive();
  virtual fs::path mount_dir();
  virtual bool mount_status();

  // ********************* File / Folder Transfers *****************************
  bool ParseAndSaveDataMap(const std::string& file_name,
                           const std::string& serialised_data_map,
                           std::string* data_map_hash);
  bool GetSavedDataMap(const std::string& data_map_hash,
                       std::string* serialised_data_map,
                       std::string* file_name);
  int GetDataMap(const fs::path& absolute_path, std::string* serialised_data_map);
  int InsertDataMap(const fs::path& absolute_path, const std::string& serialised_data_map);

  // **************************** File Notes ***********************************
  int GetNotes(const fs::path& absolute_path, std::vector<std::string>* notes);
  int AddNote(const fs::path& absolute_path, const std::string& note);

  // *************************** Hidden Files **********************************
  int ReadHiddenFile(const fs::path& absolute_path, std::string* content);
  int WriteHiddenFile(const fs::path& absolute_path,
                      const std::string& content,
                      bool overwrite_existing);
  int DeleteHiddenFile(const fs::path& absolute_path);
  int SearchHiddenFiles(const fs::path& absolute_path,
                        std::vector<std::string>* results);
  int GetHiddenFileDataMap(const boost::filesystem::path& absolute_path, std::string* data_map);

  // ************************* Signals Handling ********************************
  bs2::connection ConnectToDriveChanged(drive::DriveChangedSlotPtr slot) const;

  std::string ConstructFile(const std::string& serialised_data_map);

 private:
  UserStorage &operator=(const UserStorage&);
  UserStorage(const UserStorage&);

  bool mount_status_;
  std::shared_ptr<pcs::RemoteChunkStore> chunk_store_;
  std::shared_ptr<MaidDriveInUserSpace> drive_in_user_space_;
  ShareRenamedFunction share_renamed_function_;
  ShareChangedFunction share_changed_function_;
  Session* session_;
  fs::path mount_dir_;
  std::thread mount_thread_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_USER_STORAGE_H_
