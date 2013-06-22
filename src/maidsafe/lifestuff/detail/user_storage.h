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
#  ifdef HAVE_CBFS
#    include "maidsafe/drive/win_drive.h"
#  else
#    include "maidsafe/drive/dummy_win_drive.h"
#  endif
#else
#  include "maidsafe/drive/unix_drive.h"
#endif
#include "maidsafe/drive/return_codes.h"

#include "maidsafe/data_store/permanent_store.h"

#include "maidsafe/nfs/nfs.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"


namespace maidsafe {

namespace lifestuff {

#ifdef WIN32
#  ifdef HAVE_CBFS
typedef drive::CbfsDriveInUserSpace MaidDrive;
#  else
typedef drive::DummyWinDriveInUserSpace MaidDrive;
#  endif
#else
typedef drive::FuseDriveInUserSpace MaidDrive;
#endif

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

  boost::filesystem::path mount_path();
  boost::filesystem::path owner_path();
  bool mount_status();

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
