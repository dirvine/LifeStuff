/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Creates, stores and accesses user details
* Version:      1.0
* Created:      2009-01-28-22.18.47
* Revision:     none
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

#ifndef MAIDSAFE_LIFESTUFF_AUTHENTICATION_H_
#define MAIDSAFE_LIFESTUFF_AUTHENTICATION_H_

#include <list>
#include <memory>
#include <string>
#include <vector>

#include "boost/thread/mutex.hpp"
#include "boost/thread/condition_variable.hpp"

#include "maidsafe/common/rsa.h"

#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#include "maidsafe/passport/passport_config.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"

namespace pcs = maidsafe::priv::chunk_store;

namespace maidsafe {

namespace pki {
class Packet;
class SignaturePacket;
}  // namespace pki
namespace passport { class Passport; }

namespace lifestuff {

class Session;
class YeOldeSignalToCallbackConverter;
namespace test { class UserCredentialsTest; }

class Authentication {
 public:
  explicit Authentication(std::shared_ptr<Session> session);
  ~Authentication();
  // Used to intialise passport_ in all cases.
  void Init(std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
            std::shared_ptr<YeOldeSignalToCallbackConverter> converter);
  // Used to intialise passport_ in all cases.
  int GetUserInfo(const std::string &username, const std::string &pin);
  // Used when creating a new user.
  int CreateUserSysPackets(const std::string &username,
                           const std::string &pin);
  // Used when creating a new user.
  int CreateTmidPacket(const std::string &password,
                       const std::string &serialised_data_atlas,
                       const std::string &surrogate_serialised_data_atlas);

  void SaveSession(const std::string &serialised_data_atlas,
                   const VoidFunctionOneInt &functor);
  int SaveSession(const std::string &serialised_data_atlas);
  // Used when logging in.
  void GetMasterDataMap(const std::string &password,
                        std::string *serialised_data_atlas,
                        std::string *surrogate_serialised_data_atlas);
  int SetLoggedInData(const std::string &ser_da,
                      const std::string &surrogate_ser_da);
  int RemoveMe();
  int ChangeUsername(const std::string &serialised_data_atlas,
                     const std::string &new_username);
  int ChangePin(const std::string &serialised_data_atlas,
                const std::string &new_pin);
  int ChangePassword(const std::string &serialised_data_atlas,
                     const std::string &new_password);
  friend class test::UserCredentialsTest;

 private:
  enum OpStatus {
    kSucceeded,
    kFailed,
    kNotUnique,
    kPending,
    kPendingMid,
    kPendingTmid,
    kNoUser
  };

  enum SaveSessionOpType { kRegular, kSaveNew, kDeleteOld, kUpdate, kIsUnique };

  struct PacketData {
    PacketData();
    PacketData(const passport::PacketType &packet_type,
               std::shared_ptr<passport::Passport> passport,
               bool confirmed);
    passport::PacketType type;
    std::string name, value, signature;
    asymm::PublicKey public_key;
  };

  struct SaveSessionData {
    SaveSessionData(VoidFunctionOneInt func,
                    SaveSessionOpType op_t,
                    const std::string &serialised_data_atlas_in)
        : process_mid(kPending),
          process_smid(kPending),
          process_tmid(kPending),
          process_stmid(kPending),
          functor(func),
          op_type(op_t),
          serialised_data_atlas(serialised_data_atlas_in) {}
    OpStatus process_mid, process_smid, process_tmid, process_stmid;
    VoidFunctionOneInt functor;
    SaveSessionOpType op_type;
    std::string serialised_data_atlas;
  };

  typedef std::shared_ptr<SaveSessionData> SaveSessionDataPtr;

  Authentication &operator=(const Authentication&);
  Authentication(const Authentication&);

  void GetMidCallback(const std::string &value, int return_code);
  void GetSmidCallback(const std::string &value, int return_code);
  void GetTmidCallback(const std::string &value, int return_code);
  void GetStmidCallback(const std::string &value, int return_code);
  void GetMidTmidCallback(const std::string &value,
                          int return_code,
                          bool surrogate);
  // Function waits until dependent_op_status != kPending or timeout before
  // starting
  void StoreSignaturePacket(const passport::PacketType &packet_type,
                            OpStatus *op_status,
                            OpStatus *dependent_op_status);
  void SignaturePacketStoreCallback(int return_code,
                                    passport::PacketType packet_type,
                                    OpStatus *op_status);
  void SaveSessionCallback(int return_code,
                           passport::PacketType packet_type,
                           SaveSessionDataPtr save_session_data);
  void DeletePacket(const passport::PacketType &packet_type,
                    OpStatus *op_status,
                    OpStatus *dependent_op_status);
  void DeletePacketCallback(int return_code,
                            const passport::PacketType &packet_type,
                            OpStatus *op_status);
  int ChangeUserData(const std::string &serialised_data_atlas,
                     const std::string &new_username,
                     const std::string &new_pin);

  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool TmidOpDone() {
    return (tmid_op_status_ == kSucceeded ||
            tmid_op_status_ == kNoUser ||
            tmid_op_status_ == kFailed);
  }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool StmidOpDone() {
    return (stmid_op_status_ == kSucceeded ||
            stmid_op_status_ == kNoUser ||
            stmid_op_status_ == kFailed);
  }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool SignerDone(OpStatus *op_status) { return *op_status != kPending; }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool TwoSystemPacketsOpDone(OpStatus *op_status1, OpStatus *op_status2) {
    return (*op_status1 != kPending) && (*op_status2 != kPending);
  }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool ThreeSystemPacketsOpDone(OpStatus *op_status1,
                                OpStatus *op_status2,
                                OpStatus *op_status3) {
    return TwoSystemPacketsOpDone(op_status1, op_status2) &&
           (*op_status3 != kPending);
  }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool FourSystemPacketsOpDone(OpStatus *op_status1,
                               OpStatus *op_status2,
                               OpStatus *op_status3,
                               OpStatus *op_status4) {
    return TwoSystemPacketsOpDone(op_status1, op_status2) &&
           TwoSystemPacketsOpDone(op_status3, op_status4);
  }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool PacketOpDone(int *return_code) { return *return_code != kPendingResult; }
  int StorePacket(const PacketData &packet,
                  const pcs::RemoteChunkStore::ValidationData &validation_data);
  int DeletePacket(const PacketData &packet);
  void PacketOpCallback(int return_code, int *op_result);
  void CreateSignedData(const PacketData &packet,
                        bool signing_packet_confirmed,
                        std::string *signed_data_name,
                        std::string *serialised_signed_data,
                        asymm::Identity *signing_key_id);
  void GetPacketNameAndKeyId(const std::string &packet_name_raw,
                             const passport::PacketType &type,
                             bool signing_packet_confirmed,
                             std::string *packet_name,
                             std::string *signing_id);
  std::string DebugStr(const passport::PacketType &packet_type);

  void KeysAndProof(passport::PacketType pt,
                    pcs::RemoteChunkStore::ValidationData *validation_data,
                    bool confirmed);

  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store_;
  std::shared_ptr<Session> session_;
  boost::mutex mutex_, mid_mutex_, smid_mutex_;
  boost::condition_variable cond_var_;
  OpStatus tmid_op_status_, stmid_op_status_;
  std::string encrypted_tmid_, encrypted_stmid_, serialised_data_atlas_;
  const boost::posix_time::milliseconds kSingleOpTimeout_;
  std::shared_ptr<YeOldeSignalToCallbackConverter> converter_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_AUTHENTICATION_H_
