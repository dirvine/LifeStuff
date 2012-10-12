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

#include "maidsafe/lifestuff/detail/user_storage.h"

#include <limits>
#include <list>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/utils/utilities.h"

#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/self_encryptor.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace args = std::placeholders;
namespace fs = boost::filesystem;
namespace utils = maidsafe::priv::utilities;

namespace maidsafe {

namespace lifestuff {

UserStorage::UserStorage(std::shared_ptr<pcs::RemoteChunkStore> chunk_store)
    : mount_status_(false),
      chunk_store_(chunk_store),
      file_chunk_store_(),
      drive_in_user_space_(),
      share_renamed_function_(),
      share_changed_function_(),
      session_(),
      mount_dir_(),
      mount_thread_() {}

void UserStorage::MountDrive(const fs::path& file_chunk_store_path,
                             const fs::path& mount_dir_path,
                             Session* session,
                             const std::string& drive_logo) {
  if (mount_status_) {
    LOG(kInfo) << "Already mounted.";
    return;
  }

  if (!file_chunk_store_.Init(file_chunk_store_path)) {
    LOG(kError) << "Failed to initialise needed file chunkstore.";
    return;
  }

  if (!fs::exists(mount_dir_path))
    fs::create_directory(mount_dir_path);

  session_ = session;
  asymm::Keys key_ring(session->passport().SignaturePacketDetails(passport::kMaid, true));
  assert(!key_ring.identity.empty());
  drive_in_user_space_ = std::make_shared<MaidDriveInUserSpace>(*chunk_store_,
                                                                file_chunk_store_,
                                                                key_ring);

  int result(kGeneralError);
  if (!session->has_drive_data()) {
    session->set_unique_user_id(crypto::Hash<crypto::SHA512>(session->session_name()));
    result = drive_in_user_space_->Init(session->unique_user_id(), "");
    session->set_root_parent_id(drive_in_user_space_->root_parent_id());
  } else {
    result = drive_in_user_space_->Init(session->unique_user_id(), session->root_parent_id());
  }

  if (result != kSuccess) {
    LOG(kError) << "Failed to Init Drive: " << result;
    return;
  }

#ifdef WIN32
  std::uint32_t drive_letters, mask = 0x4, count = 2;
  drive_letters = GetLogicalDrives();
  while ((drive_letters & mask) != 0) {
    mask <<= 1;
    ++count;
  }
  if (count > 25) {
    LOG(kError) << "No available drive letters.";
    return;
  }
  char drive_name[3] = {'A' + static_cast<char>(count), ':', '\0'};
  mount_dir_ = drive_name;
  result = drive_in_user_space_->Mount(mount_dir_,
                                       drive_logo,
                                       session->max_space(),
                                       session->used_space(),
                                       false);
  if (result != kSuccess) {
    LOG(kError) << "Failed to Mount Drive: " << result;
    return;
  }
  mount_status_ = true;
#else
  mount_dir_ = mount_dir_path;
  mount_thread_ = std::move(std::thread([this, drive_logo] {
                                          drive_in_user_space_->Mount(mount_dir_,
                                                                      drive_logo,
                                                                      session_->max_space(),
                                                                      session_->used_space(),
                                                                      false);
                                        }));
  mount_status_ = drive_in_user_space_->WaitUntilMounted();
#endif
}

void UserStorage::UnMountDrive() {
  if (!mount_status_)
    return;
  int64_t max_space(0), used_space(0);
#ifdef WIN32
  std::static_pointer_cast<MaidDriveInUserSpace>(drive_in_user_space_)->Unmount(max_space,
                                                                                used_space);
#else
  drive_in_user_space_->Unmount(max_space, used_space);
  drive_in_user_space_->WaitUntilUnMounted();
  mount_thread_.join();
  boost::system::error_code error_code;
  fs::remove_all(mount_dir_, error_code);
#endif
  session_->set_max_space(max_space);  // unnecessary
  session_->set_used_space(used_space);
  mount_status_ = false;
}

fs::path UserStorage::mount_dir() {
#ifdef WIN32
  return mount_dir_ / fs::path("/").make_preferred();
#else
  return mount_dir_;
#endif
}

bool UserStorage::mount_status() {
  return mount_status_;
}

bool UserStorage::ParseAndSaveDataMap(const std::string& file_name,
                                      const std::string& serialised_data_map,
                                      std::string* data_map_hash) {
  encrypt::DataMapPtr data_map(ParseSerialisedDataMap(serialised_data_map));
  if (!data_map) {
    LOG(kError) << "Serialised DM doesn't parse.";
    return false;
  }

  *data_map_hash = EncodeToBase32(crypto::Hash<crypto::SHA1>(serialised_data_map)) +
                                  boost::lexical_cast<std::string>(
                                      GetDurationSinceEpoch().total_microseconds());
  std::string filename_data(PutFilenameData(file_name));
  if (filename_data.empty()) {
    LOG(kError) << "No suitable filename given: " << file_name;
    return false;
  }

  int result(WriteHiddenFile(mount_dir() / std::string(*data_map_hash + kHiddenFileExtension),
                             filename_data + serialised_data_map,
                             true));
  if (result != kSuccess) {
    LOG(kError) << "Failed to create file: " << result;
    return false;
  }

  return true;
}

bool UserStorage::GetSavedDataMap(const std::string& data_map_hash,
                                  std::string* serialised_data_map,
                                  std::string* file_name) {
  std::string serialised_identifier;
  int result(ReadHiddenFile(mount_dir() / std::string(data_map_hash + kHiddenFileExtension),
                            &serialised_identifier));
  if (result != kSuccess || serialised_identifier.empty()) {
    LOG(kError) << "No such identifier found.";
    return false;
  }

  GetFilenameData(serialised_identifier, file_name, serialised_data_map);
  if (file_name->empty() || serialised_data_map->empty()) {
    LOG(kError) << "Failed to get filename or datamap.";
    return false;
  }

  drive::DataMapPtr data_map_ptr(ParseSerialisedDataMap(*serialised_data_map));
  if (!data_map_ptr) {
    LOG(kError) << "Corrupted DM in file";
    return false;
  }

  return true;
}


int UserStorage::GetDataMap(const fs::path& absolute_path, std::string* serialised_data_map) {
  return drive_in_user_space_->GetDataMap(drive::RelativePath(mount_dir(), absolute_path),
                                          serialised_data_map);
}

int UserStorage::InsertDataMap(const fs::path& absolute_path,
                               const std::string& serialised_data_map) {
  return drive_in_user_space_->InsertDataMap(drive::RelativePath(mount_dir(), absolute_path),
                                             serialised_data_map);
}

int UserStorage::GetNotes(const fs::path& absolute_path, std::vector<std::string>* notes) {
  return drive_in_user_space_->GetNotes(drive::RelativePath(mount_dir(), absolute_path), notes);
}

int UserStorage::AddNote(const fs::path& absolute_path, const std::string& note) {
  return drive_in_user_space_->AddNote(drive::RelativePath(mount_dir(), absolute_path), note);
}

int UserStorage::ReadHiddenFile(const fs::path& absolute_path, std::string* content) {
  return drive_in_user_space_->ReadHiddenFile(drive::RelativePath(mount_dir(), absolute_path),
                                              content);
}

int UserStorage::WriteHiddenFile(const fs::path& absolute_path,
                                 const std::string& content,
                                 bool overwrite_existing) {
  return drive_in_user_space_->WriteHiddenFile(drive::RelativePath(mount_dir(), absolute_path),
                                               content,
                                               overwrite_existing);
}

int UserStorage::DeleteHiddenFile(const fs::path& absolute_path) {
  return drive_in_user_space_->DeleteHiddenFile(drive::RelativePath(mount_dir(), absolute_path));
}

int UserStorage::SearchHiddenFiles(const fs::path& absolute_path,
                                   std::vector<std::string>* results) {
  return drive_in_user_space_->SearchHiddenFiles(drive::RelativePath(mount_dir(), absolute_path),
                                                 results);
}

int UserStorage::GetHiddenFileDataMap(const boost::filesystem::path& absolute_path,
                                      std::string* data_map) {
  return drive_in_user_space_->GetDataMapHidden(drive::RelativePath(mount_dir(), absolute_path),
                                                data_map);
}

bs2::connection UserStorage::ConnectToDriveChanged(drive::DriveChangedSlotPtr slot) const {
  return drive_in_user_space_->ConnectToDriveChanged(slot);
}

std::string UserStorage::ConstructFile(const std::string& serialised_data_map) {
  encrypt::DataMapPtr data_map(ParseSerialisedDataMap(serialised_data_map));
  if (!data_map) {
    LOG(kError) << "Data map didn't parse.";
    return "";
  }

  uint32_t file_size(data_map->chunks.empty() ?
                     static_cast<uint32_t>(data_map->content.size()) : 0);
  auto it(data_map->chunks.begin());
  while (it != data_map->chunks.end()) {
    if (kFileRecontructionLimit < (file_size + (*it).size)) {
      LOG(kError) << "File too large to read.";
      return "";
    }
    file_size += (*it).size;
    ++it;
  }

  // TODO(Team): decide based on the size whether to go ahead.
  // Update: It's now only possible to read a file up to uint32_t size.
  // if (file_size > 'some limit')
  //   return "";

  encrypt::SelfEncryptor self_encryptor(data_map, *chunk_store_, file_chunk_store_);
  std::unique_ptr<char[]> contents(new char[file_size]);
  if (!self_encryptor.Read(contents.get(), file_size, 0)) {
    LOG(kError) << "Failure to read contents from SE: " << file_size;
    return "";
  }
  std::string file_content(contents.get(), file_size);

  return file_content;
}

}  // namespace lifestuff

}  // namespace maidsafe
