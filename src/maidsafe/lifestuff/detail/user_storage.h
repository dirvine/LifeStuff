/***************************************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use.  The use of this code is governed by the licence file licence.txt found in the root of    *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit         *
 *  written permission of the board of directors of MaidSafe.net.                                  *
 **************************************************************************************************/

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_USER_STORAGE_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_USER_STORAGE_H_

#include "boost/filesystem/path.hpp"

#ifdef WIN32
#  include "maidsafe/drive/win_drive.h"
#else
#  include "maidsafe/drive/unix_drive.h"
#endif
#include "maidsafe/drive/return_codes.h"

#include "maidsafe/data_store/permanent_store.h"

#include "maidsafe/nfs/nfs.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

#ifdef WIN32
  typedef maidsafe::drive::CbfsDriveInUserSpace MaidDrive;
#else
  typedef maidsafe::drive::FuseDriveInUserSpace MaidDrive;
#endif

namespace maidsafe {
namespace lifestuff {

class UserStorage {
 public:
  typedef maidsafe::nfs::ClientMaidNfs ClientNfs;
  typedef maidsafe::data_store::PermanentStore PermanentStore;
  typedef std::unique_ptr<PermanentStore> PermanentStorePtr;
  typedef passport::Maid Maid;

  explicit UserStorage();
  ~UserStorage() {}

  void MountDrive(ClientNfs& client_nfs, Session& session);
  void UnMountDrive(Session& session);

  bool ParseAndSaveDataMap(const NonEmptyString& file_name,
                           const NonEmptyString& serialised_data_map,
                           std::string& data_map_hash);
  bool GetSavedDataMap(const NonEmptyString& data_map_hash,
                       std::string& serialised_data_map,
                       std::string& file_name);
  int GetDataMap(const fs::path& absolute_path, std::string* serialised_data_map);
  int InsertDataMap(const fs::path& absolute_path, const NonEmptyString& serialised_data_map);

  int GetNotes(const fs::path& absolute_path, std::vector<std::string>* notes);
  int AddNote(const fs::path& absolute_path, const std::string& note);

  int ReadHiddenFile(const fs::path& absolute_path, std::string* content);
  int WriteHiddenFile(const fs::path& absolute_path,
                      const NonEmptyString& content,
                      bool overwrite_existing);
  int DeleteHiddenFile(const fs::path& absolute_path);
  int SearchHiddenFiles(const fs::path& absolute_path,
                        std::vector<std::string>* results);
  int GetHiddenFileDataMap(const boost::filesystem::path& absolute_path, std::string* data_map);

  std::string ConstructFile(const NonEmptyString& serialised_data_map);

  boost::filesystem::path mount_path();
  boost::filesystem::path owner_path();
  bool mount_status();

  bs2::connection ConnectToDriveChanged(drive::DriveChangedSlotPtr slot) const;

 private:
  UserStorage &operator=(const UserStorage&);
  UserStorage(const UserStorage&);

  bool ReadConfigFile(const fs::path& absolute_path, std::string* content);
  bool WriteConfigFile(const fs::path& absolute_path,
                       const NonEmptyString& content,
                       bool overwrite_existing);

  bool mount_status_;
  PermanentStorePtr data_store_;
  boost::filesystem::path mount_path_;
  std::unique_ptr<MaidDrive> drive_;
  std::thread mount_thread_;
};

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_USER_STORAGE_H_
