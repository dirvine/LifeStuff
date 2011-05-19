/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Nov 13, 2008
 *      Author: Team
 */

#include "maidsafe/lifestuff/client/localstoremanager.h"

#include "boost/filesystem/fstream.hpp"
#include "boost/filesystem.hpp"
#include "boost/scoped_ptr.hpp"
#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/pki/maidsafevalidator.h"
#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/lifestuff/client/sessionsingleton.h"
#include "maidsafe/lifestuff/client/clientutils.h"
#include "maidsafe/lifestuff/client/lifestuff_messages.pb.h"

namespace fs3 = boost::filesystem3;

namespace maidsafe {

namespace lifestuff {

namespace {

void PrintDebugInfo(const std::string &packet_name,
                    const std::string &value1,
                    const std::string &value2,
                    const std::string &op_type,
                    passport::PacketType system_packet_type) {
  std::string packet_type(maidsafe::passport::DebugString(system_packet_type));
  if (value2.empty())
    DLOG(WARNING) << "LSM::" << op_type << " - " << packet_type
                  << " - <key, value>(" << HexSubstr(packet_name) << ", "
                  << HexSubstr(value1) << ")" << std::endl;
  else
    DLOG(WARNING) << "LSM::" << op_type << " - " << packet_type << " - <key>("
                  << HexSubstr(packet_name) << ") value("
                  << HexSubstr(value1) << " --> " << HexSubstr(value2)
                  << ")" << std::endl;
}

}

typedef boost::function<void(const std::string&)> VoidFunctorOneString;

void ExecuteSuccessCallback(const VoidFunctorOneString &cb,
                            boost::mutex *mutex) {
  boost::mutex::scoped_lock gaurd(*mutex);
  std::string ser_result;
//  GenericResponse result;
//  result.set_result(kAck);
//  result.SerializeToString(&ser_result);
  cb(ser_result);
}

void ExecuteFailureCallback(const VoidFunctorOneString &cb,
                            boost::mutex *mutex) {
  boost::mutex::scoped_lock gaurd(*mutex);
  std::string ser_result;
//  GenericResponse result;
//  result.set_result(kNack);
//  result.SerializeToString(&ser_result);
  cb(ser_result);
}

void ExecReturnCodeCallback(const VoidFuncOneInt &cb,
                            const ReturnCode rc) {
  cb(rc);
}

void ExecReturnLoadPacketCallback(const LoadPacketFunctor &cb,
                                  std::vector<std::string> results,
                                  const ReturnCode rc) {
  cb(results, rc);
}

LocalStoreManager::LocalStoreManager(
    std::shared_ptr<ChunkStore> client_chunkstore,
    const boost::uint8_t &k,
    const fs3::path &db_directory)
        : K_(k),
          kUpperThreshold_(
              static_cast<boost::uint16_t>(K_ * kMinSuccessfulPecentageStore)),
          db_(), /*vbph_(), */mutex_(),
          local_sm_dir_(db_directory.string()),
          client_chunkstore_(client_chunkstore),
          ss_(SessionSingleton::getInstance()),
          chunks_pending_() {}

LocalStoreManager::LocalStoreManager(const fs3::path &db_directory)
    : K_(0),
      kUpperThreshold_(0),
      db_(),
      mutex_(),
      local_sm_dir_(db_directory.string()),
      client_chunkstore_(),
      ss_(SessionSingleton::getInstance()),
      chunks_pending_() {}

LocalStoreManager::~LocalStoreManager() {
  bool t(false);
  while (!t) {
    {
//      boost::mutex::scoped_lock loch_etive(signal_mutex_);
      t = chunks_pending_.empty();
    }
    if (!t)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
}

void LocalStoreManager::Init(VoidFuncOneInt callback, const boost::uint16_t&) {
#ifdef LOCAL_LifeStuffVAULT
  // Simulate knode join
//  boost::this_thread::sleep(boost::posix_time::seconds(3));
#endif
  if (local_sm_dir_.empty())
    local_sm_dir_ = file_system::LocalStoreManagerDir().string();
  try {
    if (!fs3::exists(local_sm_dir_ + "/StoreChunks")) {
      fs3::create_directories(local_sm_dir_ + "/StoreChunks");
    }
    if (fs3::exists(local_sm_dir_ + "/KademilaDb.db")) {
      db_.open(std::string(local_sm_dir_ + "/KademilaDb.db").c_str());
    } else {
      boost::mutex::scoped_lock loch(mutex_);
      db_.open(std::string(local_sm_dir_ + "/KademilaDb.db").c_str());
      db_.execDML("create table network(key text,"
                                       "value text,"
                                       "primary key(key,value));");
    }
    ExecReturnCodeCallback(callback, kSuccess);
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    ExecReturnCodeCallback(callback, kStoreManagerInitError);
  }
}

void LocalStoreManager::Close(VoidFuncOneInt callback, bool) {
  bool t(false);
  while (!t) {
    {
//      boost::mutex::scoped_lock loch_etive(signal_mutex_);
      t = chunks_pending_.empty();
    }
    if (!t)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
#ifdef LOCAL_LifeStuffVAULT
  // Simulate chunk threadpool join and knode leave
//  boost::this_thread::sleep(boost::posix_time::seconds(3));
#endif
  try {
    boost::mutex::scoped_lock loch(mutex_);
    db_.close();
    ExecReturnCodeCallback(callback, kSuccess);
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    ExecReturnCodeCallback(callback, kStoreManagerError);
  }
}

int LocalStoreManager::LoadChunk(const std::string &chunk_name,
                                 std::string *data) {
//  if (client_chunkstore_->Load(chunk_name, data) == kSuccess) {
//    return kSuccess;
//  }
  return FindAndLoadChunk(chunk_name, data);
}

int LocalStoreManager::StoreChunk(const std::string &chunk_name,
                                  const DirType,
                                  const std::string&) {
//  #ifdef LOCAL_LifeStuffVAULT
//  // Simulate knode lookup in AddToWatchList
//  boost::this_thread::sleep(boost::posix_time::seconds(2));
//  #endif
  std::string hex_chunk_name(EncodeToHex(chunk_name));
  fs3::path file_path(local_sm_dir_ + "/StoreChunks");
  file_path = file_path / hex_chunk_name;

/*
//  client_chunkstore_->Store(chunk_name, file_path);

//  ChunkType type = client_chunkstore_->chunk_type(chunk_name);
//  fs3::path current = client_chunkstore_->GetChunkPath(chunk_name,type,false);
//  try {
//    if (fs3::exists(current)) {
//      if (!fs3::exists(file_path)) {
//        fs3::copy_file(current, file_path);
//      }
//    } else {
//      signal_mutex_.lock();
//      chunks_pending_.insert(chunk_name);
//      signal_mutex_.unlock();
//      boost::thread thr(boost::bind(&LocalStoreManager::ExecuteReturnSignal,
//                                    this, chunk_name, kSendChunkFailure));
//      return kChunkStorePending;
//    }
//  }
//  catch(const std::exception &e) {
//    signal_mutex_.lock();
//    chunks_pending_.insert(chunk_name);
//    signal_mutex_.unlock();
//    boost::thread thr(boost::bind(&LocalStoreManager::ExecuteReturnSignal, this,
//                                  chunk_name, kSendChunkFailure));
//    return kChunkStorePending;
//  }
//
  // Move chunk from Outgoing to Normal.
//  ChunkType chunk_type = client_chunkstore_->chunk_type(chunk_name);
//  ChunkType new_type = chunk_type ^ (kOutgoing | kNormal);
//  if (client_chunkstore_->ChangeChunkType(chunk_name, new_type) != 0) {
//  }
//  signal_mutex_.lock();
//  chunks_pending_.insert(chunk_name);
//  signal_mutex_.unlock();
//  boost::thread thr(boost::bind(&LocalStoreManager::ExecuteReturnSignal, this,
//                                chunk_name, kSuccess));
*/
  return kChunkStorePending;
}

int LocalStoreManager::DeleteChunk(const std::string &chunk_name,
                                   const boost::uint64_t &chunk_size,
                                   DirType, const std::string&) {
#ifdef LOCAL_LifeStuffVAULT
  // Simulate knode lookup in RemoveFromWatchList
//  boost::this_thread::sleep(boost::posix_time::seconds(2));
#endif
/*
//  ChunkType chunk_type = client_chunkstore_->chunk_type(chunk_name);
//    fs3::path chunk_path(client_chunkstore_->GetChunkPath(chunk_name,
//                                                          chunk_type, false));
//  boost::uint64_t size(chunk_size);
//  if (size < 2) {
//    if (chunk_type < 0 || chunk_path.empty()) {
//      return kDeleteSizeError;
//    }
//    try {
//      size = fs3::file_size(chunk_path);
//    }
//    catch(const std::exception &e) {
//      return kDeleteSizeError;
//    }
//  }
//  ChunkType new_type(chunk_type);
//  if (chunk_type >= 0) {
//    // Move chunk to TempCache.
//    if (chunk_type & kNormal)
//      new_type = chunk_type ^ (kNormal | kTempCache);
//    else if (chunk_type & kOutgoing)
//      new_type = chunk_type ^ (kOutgoing | kTempCache);
//    else if (chunk_type & kCache)
//      new_type = chunk_type ^ (kCache | kTempCache);
//    if (!(new_type < 0) &&
//        client_chunkstore_->ChangeChunkType(chunk_name,
//                                            new_type) != kSuccess) {
//    }
//  }
*/
  return kSuccess;
}

bool LocalStoreManager::KeyUnique(const std::string &key, bool) {
#ifdef LOCAL_LifeStuffVAULT
  // Simulate knode findvalue in AddToWatchList
//  boost::this_thread::sleep(boost::posix_time::seconds(2));
#endif
  bool result = false;
  std::string hex_key(EncodeToHex(key));
  try {
    boost::mutex::scoped_lock loch(mutex_);
    std::string s = "select * from network where key='" + hex_key;
    s += "';";
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (q.eof())
      result = true;
    else
      while (!q.eof()) {
        q.nextRow();
      }
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    result = false;
  }
  if (result) {
    fs3::path file_path(local_sm_dir_ + "/StoreChunks");
    file_path = file_path / hex_key;
    try {
      result = (!fs3::exists(file_path));
    }
    catch(const std::exception &e) {
      DLOG(WARNING) << "LSM::KeyUnique - Failed check path existance: "
                    << e.what() << std::endl;
      return false;
    }
  }
  return result;
}

void LocalStoreManager::KeyUnique(const std::string &key, bool check_local,
                                  const VoidFuncOneInt &cb) {
  if (KeyUnique(key, check_local))
    ExecReturnCodeCallback(cb, kKeyUnique);
  else
    ExecReturnCodeCallback(cb, kKeyNotUnique);
}

int LocalStoreManager::LoadPacket(const std::string &packet_name,
                                  std::vector<std::string> *results) {
  return GetValue_FromDB(packet_name, results);
}

void LocalStoreManager::LoadPacket(const std::string &packetname,
                                   const LoadPacketFunctor &lpf) {
  std::vector<std::string> results;
  ReturnCode rc(static_cast<ReturnCode>(GetValue_FromDB(packetname, &results)));
  ExecReturnLoadPacketCallback(lpf, results, rc);
}

void LocalStoreManager::DeletePacket(const std::string &packet_name,
                                     const std::vector<std::string> values,
                                     passport::PacketType system_packet_type,
                                     DirType dir_type, const std::string &msid,
                                     const VoidFuncOneInt &cb) {
  PrintDebugInfo(packet_name, values.at(0), "", "DeletePacket",
                 system_packet_type);
  std::string key_id, public_key, public_key_signature, private_key;
  ClientUtils client_utils;
  client_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid,
      &key_id, &public_key, &public_key_signature, &private_key);
//  pki::MaidsafeValidator msv;
//  if (!msv.ValidateSignerId(key_id, public_key, public_key_signature)) {
//    ExecReturnCodeCallback(cb, kDeletePacketFailure);
//    return;
//  }

  std::vector<std::string> vals(values);
  bool empty(true);
  for (size_t i = 0; i < vals.size(); ++i) {
    if (!vals.at(i).empty()) {
      empty = false;
      break;
    }
  }
  if (empty) {
    ReturnCode res =
        static_cast<ReturnCode>(GetValue_FromDB(packet_name, &vals));
    if (res == kFindValueFailure) {  // packet doesn't exist on net
      ExecReturnCodeCallback(cb, kSuccess);
      return;
    } else if (res != kSuccess || vals.empty()) {
      ExecReturnCodeCallback(cb, kDeletePacketFindValueFailure);
      return;
    }
  }

  std::vector<std::string> ser_gps;
  for (size_t a = 0; a < values.size(); ++a) {
    std::string ser_gp;
    CreateSerialisedSignedValue(values[a], private_key, &ser_gp);
    ser_gps.push_back(ser_gp);
  }

//  for (size_t n = 0; n < ser_gps.size(); ++n) {
//    kad::SignedValue sv;
//    if (sv.ParseFromString(ser_gps[n])) {
//      if (!RSACheckSignedData(sv.value(), sv.value_signature(), public_key)) {
//        ExecReturnCodeCallback(cb, kDeletePacketFailure);
//        return;
//      }
//    }
//  }
  ReturnCode rc = DeletePacket_DeleteFromDb(packet_name, ser_gps, public_key);
  ExecReturnCodeCallback(cb, rc);
}

ReturnCode LocalStoreManager::DeletePacket_DeleteFromDb(
    const std::string &key,
    const std::vector<std::string> &values,
    const std::string &public_key) {
#ifdef LOCAL_LifeStuffVAULT
  // Simulate knode lookup
//  boost::this_thread::sleep(boost::posix_time::seconds(2));
#endif
  std::string hex_key(EncodeToHex(key));
  boost::mutex::scoped_lock loch(mutex_);
  try {
    std::string s("select value from network where key='" + hex_key + "';");
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (q.eof()) {
      DLOG(WARNING) << "LSM::DeletePacket_DeleteFromDb - value not there"
                    << std::endl;
      return kSuccess;
    } else {
      SignedValue ksv;
      if (ksv.ParseFromString(DecodeFromHex(q.getStringField(0)))) {
        if (!crypto::AsymCheckSig(ksv.value(), ksv.value_signature(),
                                  public_key)) {
          DLOG(WARNING) << "LSM::DeletePacket_DeleteFromDb - "
                           "current value failed validation." << std::endl;
          return kDeletePacketFailure;
        }
      }
    }
  }
  catch(CppSQLite3Exception &e1) {  // NOLINT (Fraser)
    DLOG(WARNING) << "LSM::DeletePacket_DeleteFromDb - " << e1.errorCode()
                  << ": " << e1.errorMessage() << std::endl;
    return kStoreManagerError;
  }

  int deleted(values.size()), a(0);
  if (0 == values.size()) {
    try {
      std::string s("delete from network where key='" + hex_key + "';");
      a = db_.execDML(s.c_str());
    } catch(CppSQLite3Exception &e2) {  // NOLINT (Fraser)
      DLOG(WARNING) << "LSM::DeletePacket_DeleteFromDb - " << e2.errorCode()
                    << ": " << e2.errorMessage() << std::endl;
      return kStoreManagerError;
    }
  } else {
    for (size_t n = 0; n < values.size(); ++n) {
      try {
        std::string hex_value(EncodeToHex(values[n]));
        std::string s("delete from network where key='" + hex_key + "' "
                      "and value='" + hex_value + "';");
        a = db_.execDML(s.c_str());
        if (a == 1) {
          --deleted;
        } else {
          DLOG(WARNING) << "LSM::DeletePacket_DeleteFromDb - failure to delete("
                        << a << ") <key, value>(" << hex_key.substr(0, 10)
                        << ", " << HexSubstr(values[n]) << ")" << std::endl;
          return kDeletePacketFailure;
        }
      }
      catch(CppSQLite3Exception &e2) {  // NOLINT (Fraser)
        DLOG(WARNING) << "LSM::DeletePacket_DeleteFromDb - " << e2.errorCode()
                      << ": " << e2.errorMessage() << std::endl;
        return kStoreManagerError;
      }
    }
  }

  return kSuccess;
}

void LocalStoreManager::StorePacket(const std::string &packet_name,
                                    const std::string &value,
                                    passport::PacketType system_packet_type,
                                    DirType dir_type, const std::string& msid,
                                    const VoidFuncOneInt &cb) {

  PrintDebugInfo(packet_name, value, "", "StorePacket", system_packet_type);

//  std::cout << "AAAAAA: " << value.size() << std::endl;
  std::string key_id, public_key, public_key_signature, private_key;
  ClientUtils client_utils;
  client_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid,
                                      &key_id, &public_key,
                                      &public_key_signature, &private_key);
//  pki::MaidsafeValidator msv;
//  if (!msv.ValidateSignerId(key_id, public_key, public_key_signature)) {
//    ExecReturnCodeCallback(cb, kSendPacketFailure);
//    return;
//  }

  std::string ser_gp;
  CreateSerialisedSignedValue(value, private_key, &ser_gp);
  if (ser_gp.empty()) {
    ExecReturnCodeCallback(cb, kSendPacketFailure);
    return;
  }

  SignedValue sv;
  if (sv.ParseFromString(ser_gp)) {
    if (!crypto::AsymCheckSig(sv.value(), sv.value_signature(), public_key)) {
      ExecReturnCodeCallback(cb, kSendPacketFailure);
      DLOG(WARNING) << "LSM::StorePacket - " << sv.value() << std::endl;
      return;
    }
  }

  std::vector<std::string> values;
  int n = GetValue_FromDB(packet_name, &values);
  if (n == kFindValueError) {
    ExecReturnCodeCallback(cb, kStoreManagerError);
    return;
  }

  ReturnCode rc = StorePacket_InsertToDb(packet_name, ser_gp, public_key, true);
  ExecReturnCodeCallback(cb, rc);
}

ReturnCode LocalStoreManager::StorePacket_InsertToDb(const std::string &key,
                                                     const std::string &value,
                                                     const std::string &pub_key,
                                                     const bool &append) {
#ifdef LOCAL_LifeStuffVAULT
  // Simulate knode lookup
//  boost::this_thread::sleep(boost::posix_time::seconds(2));
#endif
  try {
    if (key.length() != kKeySize) {
      return kIncorrectKeySize;
    }
    std::string hex_key(EncodeToHex(key));
    std::string s = "select value from network where key='" + hex_key + "';";
    boost::mutex::scoped_lock loch(mutex_);
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (!q.eof()) {
      std::string dec_value = DecodeFromHex(q.getStringField(0));
      SignedValue sv;
      if (sv.ParseFromString(dec_value)) {
        if (!crypto::AsymCheckSig(sv.value(), sv.value_signature(), pub_key)) {
          DLOG(WARNING) << "LSM::StorePacket_InsertToDb - "
                           "Signature didn't validate" << std::endl;
          return kStoreManagerError;
        }
      }
    }

    if (!append) {
      s = "delete from network where key='" + hex_key + "';";
      db_.execDML(s.c_str());
    }

    CppSQLite3Buffer bufSQL;
    std::string hex_value = EncodeToHex(value);
    s = "insert into network values ('" + hex_key + "', '" + hex_value + "');";
    int a = db_.execDML(s.c_str());
    if (a != 1) {
      DLOG(WARNING) << "LSM::StorePacket_InsertToDb - Insert fail" << std::endl;
      return kStoreManagerError;
    }
    return kSuccess;
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    DLOG(WARNING) << "LSM::StorePacket_InsertToDb - " << e.errorCode()
                  << ": " << e.errorMessage() << std::endl;
    return kStoreManagerError;
  }
}

void LocalStoreManager::UpdatePacket(const std::string &packet_name,
                                     const std::string &old_value,
                                     const std::string &new_value,
                                     passport::PacketType system_packet_type,
                                     DirType dir_type, const std::string &msid,
                                     const VoidFuncOneInt &cb) {
  PrintDebugInfo(packet_name, old_value, new_value, "UpdatePacket",
                 system_packet_type);
  std::string key_id, public_key, public_key_signature, private_key;
  ClientUtils client_utils;
  client_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid,
                                      &key_id, &public_key,
                                      &public_key_signature, &private_key);
//  pki::MaidsafeValidator msv;
//  if (!msv.ValidateSignerId(key_id, public_key, public_key_signature)) {
//    ExecReturnCodeCallback(cb, kUpdatePacketFailure);
//    return;
//  }

  std::string old_ser_gp;
  CreateSerialisedSignedValue(old_value, private_key, &old_ser_gp);
  std::string new_ser_gp;
  CreateSerialisedSignedValue(new_value, private_key, &new_ser_gp);
  if (old_ser_gp.empty() || new_ser_gp.empty()) {
    ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
    DLOG(WARNING) << "LSM::UpdatePacket - Empty old or new" << std::endl;
    return;
  }

  SignedValue old_sv, new_sv;
  if (!old_sv.ParseFromString(old_ser_gp) ||
      !new_sv.ParseFromString(new_ser_gp)) {
    DLOG(WARNING) << "LSM::UpdatePacket - Old/new doesn't parse" << std::endl;
  }

  if (!crypto::AsymCheckSig(old_sv.value(), old_sv.value_signature(),
                            public_key)) {
    ExecReturnCodeCallback(cb, kUpdatePacketFailure);
    DLOG(WARNING) << "LSM::UpdatePacket - Old fails validation" << std::endl;
    return;
  }
  if (!crypto::AsymCheckSig(new_sv.value(), new_sv.value_signature(),
                            public_key)) {
    DLOG(WARNING) << "LSM::UpdatePacket - New fails validation" << std::endl;
    ExecReturnCodeCallback(cb, kUpdatePacketFailure);
    return;
  }

  std::vector<std::string> values;
  int n = GetValue_FromDB(packet_name, &values);
  if (n == kFindValueError || values.empty()) {
    ExecReturnCodeCallback(cb, kStoreManagerError);
    DLOG(WARNING) << "LSM::UpdatePacket - Key not there" << std::endl;
    return;
  }

  std::set<std::string> the_values(values.begin(), values.end());
  std::set<std::string>::iterator it = the_values.find(old_ser_gp);
  std::string s(values.at(0));
  if (it == the_values.end()) {
    ExecReturnCodeCallback(cb, kStoreManagerError);
    DLOG(WARNING) << "LSM::UpdatePacket - Old value not there: "
                  << s.size() /*<< std::endl << std::endl*/  <<  " - "
                  << old_ser_gp.size() << std::endl;
    return;
  }
  it = the_values.find(new_ser_gp);
  if (it != the_values.end()) {
    ExecReturnCodeCallback(cb, kStoreManagerError);
    DLOG(WARNING) << "LSM::UpdatePacket - New value already there" << std::endl;
    return;
  }

  ReturnCode rc = UpdatePacketInDb(packet_name, old_ser_gp, new_ser_gp);
  ExecReturnCodeCallback(cb, rc);
}

ReturnCode LocalStoreManager::UpdatePacketInDb(const std::string &key,
                                               const std::string &old_value,
                                               const std::string &new_value) {
  try {
    if (key.length() != kKeySize) {
      DLOG(WARNING) << "LSM::UpdatePacketInDb: Incorrect key size" << std::endl;
      return kIncorrectKeySize;
    }

    std::string hex_key(EncodeToHex(key));
    std::string hex_old_value(EncodeToHex(old_value));
    std::string hex_new_value(EncodeToHex(new_value));
    std::string statement("update network set value='");
    statement += hex_new_value + "' where key='" + hex_key + "' and value='" +
                 hex_old_value + "';";
    int n = db_.execDML(statement.c_str());
    if (n != 1) {
      DLOG(ERROR) << "LSM::UpdatePacketInDb - Update failed(" << n << ")"
                  << std::endl;
      return kStoreManagerError;
    }
    return kSuccess;
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    DLOG(WARNING) << "LSM::UpdatePacketInDb - " << e.errorCode() << ": "
                  << e.errorMessage() << std::endl;
    return kStoreManagerError;
  }
}

bool LocalStoreManager::ValidateGenericPacket(std::string ser_gp,
                                              std::string public_key) {
  GenericPacket gp;
  if (!gp.ParseFromString(ser_gp))
    return false;
  return crypto::AsymCheckSig(gp.data(), gp.signature(), public_key);
}

////////////// BUFFER PACKET //////////////

/*
int LocalStoreManager::CreateBP() {
  std::string mpid_public, mpid_private;
  if (ss_->MPublicID(NULL, &mpid_public, &mpid_private, NULL) != kSuccess)
    return -666;

  std::string bufferpacketname(BufferPacketName()), ser_packet;
  BufferPacket buffer_packet;
  GenericPacket *ser_owner_info = buffer_packet.add_owner_info();
  BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(ss_->PublicUsername());
  buffer_packet_info.set_owner_publickey(mpid_public);
  ser_owner_info->set_data(buffer_packet_info.SerializeAsString());
  ser_owner_info->set_signature(RSASign(ser_owner_info->data(), mpid_private));
  buffer_packet.SerializeToString(&ser_packet);
  return FlushDataIntoChunk(bufferpacketname, ser_packet, false);
}

int LocalStoreManager::ModifyBPInfo(const std::string &info) {
  std::string mpid_public, mpid_private;
  if (ss_->MPublicID(NULL, &mpid_public, &mpid_private, NULL) != kSuccess)
    return -666;

  std::string bp_in_chunk;
  std::string bufferpacketname(BufferPacketName()), ser_gp;
  GenericPacket gp;
  gp.set_data(info);
  gp.set_signature(RSASign(gp.data(), mpid_private));
  gp.SerializeToString(&ser_gp);
  if (FindAndLoadChunk(bufferpacketname, &bp_in_chunk) != 0) {
    return -1;
  }
  std::string new_bp;
  if (!vbph_.ChangeOwnerInfo(ser_gp, mpid_public, &bp_in_chunk)) {
    return -2;
  }
  if (FlushDataIntoChunk(bufferpacketname, bp_in_chunk, true) != 0) {
    return -3;
  }
  return 0;
}

int LocalStoreManager::LoadBPMessages(
    std::list<ValidatedBufferPacketMessage> *messages) {
  std::string mpid_private;
  if (ss_->MPublicID(NULL, NULL, &mpid_private, NULL) != kSuccess) {
    return 0;
  }

  std::string bp_in_chunk;
  std::string bufferpacketname(BufferPacketName());
  if (FindAndLoadChunk(bufferpacketname, &bp_in_chunk) != 0) {
    return 0;
  }
  std::vector<std::string> msgs;
  if (!vbph_.GetMessages(&bp_in_chunk, &msgs)) {
    return 0;
  }
  messages->clear();
  for (size_t n = 0; n < msgs.size(); ++n) {
    ValidatedBufferPacketMessage valid_message;
    if (valid_message.ParseFromString(msgs[n])) {
      std::string aes_key(AESDecrypt(valid_message.index(), mpid_private));
      valid_message.set_message(AESDecrypt(valid_message.message(), aes_key));
      valid_message.set_index("");
      messages->push_back(valid_message);
    }
  }
  if (FlushDataIntoChunk(bufferpacketname, bp_in_chunk, true) != 0) {
    return 0;
  }
  return kUpperThreshold_;
}

int LocalStoreManager::SendAMessage(
    const std::vector<std::string> &receivers, const std::string &message,
    const MessageType &m_type, std::map<std::string, ReturnCode> *add_results) {
  if (!add_results)
    return -660;
  if (ss_->MPublicID(NULL, NULL, NULL, NULL) != kSuccess)
    return -666;

  std::set<std::string> sss(receivers.begin(), receivers.end());
  std::vector<std::string> recs;
  std::set<std::string>::iterator it;
  if (sss.size() != receivers.size()) {
    for (it = sss.begin(); it != sss.end(); ++it)
      recs.push_back(*it);
  } else {
    recs = receivers;
  }
  for (size_t n = 0; n < recs.size(); ++n)
    add_results->insert(std::pair<std::string, ReturnCode>
                                 (recs[n], kBPAwaitingCallback));

  std::string bp_in_chunk, ser_gp;
  int successes = 0;
  boost::uint32_t timestamp = 0;  //GetDurationSinceEpoch();
  for (size_t n = 0; n < recs.size(); ++n) {
    std::string rec_pub_key(ss_->GetContactPublicKey(recs[n]));
    std::string bufferpacketname(BufferPacketName(recs[n], rec_pub_key));
    if (FindAndLoadChunk(bufferpacketname, &bp_in_chunk) != 0) {
      (*add_results)[recs[n]] = kBPAddMessageError;
      continue;
    }

    std::string updated_bp;
    if (!vbph_.AddMessage(bp_in_chunk,
        CreateMessage(message, rec_pub_key, m_type, timestamp), "",
        &updated_bp)) {
      (*add_results)[recs[n]] = kBPAddMessageError;
      continue;
    }

    if (FlushDataIntoChunk(bufferpacketname, updated_bp, true) != 0) {
      (*add_results)[recs[n]] = kBPAddMessageError;
      continue;
    }
    (*add_results)[recs[n]] = kSuccess;
    ++successes;
  }
  return successes;
}

int LocalStoreManager::LoadBPPresence(std::list<LivePresence>*) {
  return kUpperThreshold_;
}

int LocalStoreManager::AddBPPresence(const std::vector<std::string> &receivers,
                                     std::map<std::string, ReturnCode>*) {
  return receivers.size();
}
*/

////////////// END BUFFER PACKET //////////////

int LocalStoreManager::FindAndLoadChunk(const std::string &chunkname,
                                        std::string *data) {
#ifdef LOCAL_LifeStuffVAULT
  // Simulate knode lookup
//  boost::this_thread::sleep(boost::posix_time::seconds(2));
#endif

//  if (client_chunkstore_->Load(chunkname, data) == kSuccess)
//    return kSuccess;
//
  std::string hex_chunkname(EncodeToHex(chunkname));
  fs3::path file_path(local_sm_dir_ + "/StoreChunks");
  file_path = file_path / hex_chunkname;
  try {
    if (!fs3::exists(file_path)) {
      DLOG(ERROR) << "LocalStoreManager::FindAndLoadChunk - didn't find  BP"
                  << std::endl;
      return -1;
    }
    boost::uintmax_t size = fs3::file_size(file_path);
    boost::scoped_ptr<char> temp(new char[size]);
    fs3::ifstream fstr;
    fstr.open(file_path, std::ios_base::binary);
    fstr.read(temp.get(), size);
    fstr.close();
    *data = std::string((const char*)temp.get(), size);
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "LocalStoreManager::FindAndLoadChunk - " << e.what()
                << std::endl;
    return -1;
  }
  client_chunkstore_->Store(chunkname, *data);
  return 0;
}

int LocalStoreManager::FlushDataIntoChunk(const std::string &chunkname,
                                          const std::string &data,
                                          const bool &overwrite) {
  std::string hex_chunkname(EncodeToHex(chunkname));
  fs3::path file_path(local_sm_dir_ + "/StoreChunks");
  file_path = file_path / hex_chunkname;
  try {
    if (boost::filesystem::exists(file_path) && !overwrite) {
      DLOG(INFO) << "LocalStoreManager::FlushDataIntoChunk - "
                    "This BP (" << hex_chunkname.substr(0, 10)
                 << ") already exists" << std::endl;
      return -1;
    }
    boost::filesystem::ofstream bp_file(file_path.string().c_str(),
                                        boost::filesystem::ofstream::binary);
    bp_file << data;
    bp_file.close();
  }
  catch(const std::exception &e) {
    DLOG(INFO) << "LocalStoreManager::FlushDataIntoChunk - " << e.what()
               << std::endl;
    return -1;
  }
  client_chunkstore_->Store(chunkname, data);
  return 0;
}

std::string LocalStoreManager::BufferPacketName() {
  std::string mpid_public;
  if (ss_->MPublicID(NULL, &mpid_public, NULL, NULL) != kSuccess)
    return "";
  return BufferPacketName(ss_->PublicUsername(), mpid_public);
}

std::string LocalStoreManager::BufferPacketName(const std::string &pub_username,
                                                const std::string &public_key) {
  return crypto::Hash<crypto::SHA512>(pub_username + public_key);
}

/*
std::string LocalStoreManager::CreateMessage(const std::string &message,
                                             const std::string &rec_public_key,
                                             const MessageType &m_type,
                                             const boost::uint32_t &timestamp) {
  std::string mpid_public, mpid_private;
  if (ss_->MPublicID(NULL, &mpid_public, &mpid_private, NULL) != kSuccess)
    return "";
  BufferPacketMessage bpm;
  GenericPacket gp;

  bpm.set_sender_id(ss_->PublicUsername());
  bpm.set_sender_public_key(mpid_public);
  bpm.set_type(m_type);
  std::string aes_key(RandomString(crypto::AES256_KeySize +
                                   crypto::AES256_IVSize));
  bpm.set_rsaenc_key(RSAEncrypt(aes_key, rec_public_key));
  bpm.set_aesenc_message(AESEncrypt(message, aes_key));
  bpm.set_timestamp(timestamp);
  std::string ser_bpm;
  bpm.SerializeToString(&ser_bpm);
  gp.set_data(ser_bpm);
  gp.set_signature(RSASign(gp.data(), mpid_private));
  std::string ser_gp;
  gp.SerializeToString(&ser_gp);
  return ser_gp;
}
*/

int LocalStoreManager::GetValue_FromDB(const std::string &key,
                                       std::vector<std::string> *results) {
#ifdef LOCAL_LifeStuffVAULT
  // Simulate knode lookup
//  boost::this_thread::sleep(boost::posix_time::seconds(2));
#endif
  results->clear();
  std::string hex_key = EncodeToHex(key);
  try {
    boost::mutex::scoped_lock loch(mutex_);
    std::string s = "select value from network where key='" + hex_key + "';";
    CppSQLite3Query q = db_.execQuery(s.c_str());
    while (!q.eof()) {
      results->push_back(DecodeFromHex(q.getStringField(0)));
      q.nextRow();
    }
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    DLOG(WARNING) << "LSM::GetValue_FromDB - " << e.errorCode() << ": "
                  << e.errorMessage() << std::endl;
    return kFindValueError;
  }
  return (results->size() > 0) ? kSuccess : kFindValueFailure;
}

/*
bool LocalStoreManager::VaultStoreInfo(boost::uint64_t *offered_space,
                                       boost::uint64_t *free_space) {
  *offered_space = RandomUint32();
  *free_space = RandomUint32() % *offered_space;
  return true;
}

bool LocalStoreManager::VaultContactInfo(dht::kademlia::Contact *contact) {
  dht::kademlia::Contact ctc;
  *contact = ctc;
  return true;
}

void LocalStoreManager::SetLocalVaultOwned(const std::string&,
                                           const std::string &pub_key,
                                           const std::string &signed_pub_key,
                                           const boost::uint32_t&,
                                           const std::string&,
                                           const boost::uint64_t&,
                                           const SetLocalVaultOwnedFunctor &f) {
  std::string pmid_name = SHA512String(pub_key + signed_pub_key);
  boost::thread thr(f, OWNED_SUCCESS, pmid_name);
}

void LocalStoreManager::LocalVaultOwned(const LocalVaultOwnedFunctor &functor) {
  boost::thread thr(functor, NOT_OWNED);
}
*/

bool LocalStoreManager::NotDoneWithUploading() { return false; }

void LocalStoreManager::CreateSerialisedSignedValue(
    const std::string &value,
    const std::string &private_key,
    std::string *ser_gp) {
  ser_gp->clear();
  GenericPacket gp;
  gp.set_data(value);
  gp.set_signature(crypto::AsymSign(value, private_key));
  gp.SerializeToString(ser_gp);
}

void LocalStoreManager::ExecuteReturnSignal(const std::string &chunkname,
                                            ReturnCode rc) {
  int sleep_seconds((RandomInt32() % 5) + 1);
  boost::this_thread::sleep(boost::posix_time::seconds(sleep_seconds));
//  sig_chunk_uploaded_(chunkname, rc);
//  boost::mutex::scoped_lock loch_laggan(signal_mutex_);
  chunks_pending_.erase(chunkname);
}

void LocalStoreManager::ExecStringCallback(VoidFunctorOneString cb,
                                           MaidsafeRpcResult result) {
  std::string ser_result;
//  GenericResponse response;
//  response.set_result(result);
//  response.SerializeToString(&ser_result);
  boost::thread t(cb, ser_result);
}

void LocalStoreManager::ExecReturnCodeCallback(VoidFuncOneInt cb,
                                               ReturnCode rc) {
  boost::thread t(cb, rc);
}

void LocalStoreManager::ExecReturnLoadPacketCallback(
    LoadPacketFunctor cb,
    std::vector<std::string> results,
    ReturnCode rc) {
  boost::thread t(cb, results, rc);
}

}  // namespace lifestuff

}  // namespace maidsafe
