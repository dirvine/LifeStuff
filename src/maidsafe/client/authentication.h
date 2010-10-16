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

#ifndef MAIDSAFE_CLIENT_AUTHENTICATION_H_
#define MAIDSAFE_CLIENT_AUTHENTICATION_H_

#include <boost/cstdint.hpp>
//#include <boost/function.hpp>
//#include <boost/shared_ptr.hpp>
//#include <boost/thread/condition_variable.hpp>
//#include <boost/thread/mutex.hpp>
//#include <maidsafe/base/crypto.h>
//
//#include <list>
#include <string>
//#include <vector>

#include "maidsafe/common/maidsafe.h"
#include "maidsafe/passport/passport.h"

//#include "maidsafe/common/packet.pb.h"
#include "maidsafe/common/returncodes.h"

namespace maidsafe {

class StoreManagerInterface;
class SessionSingleton;

struct SystemPacketCreationData {
  SystemPacketCreationData()
      : functor(), packet_count(0), username(), pin(), rid(0) {}
  VoidFuncOneInt functor;
  int packet_count;
  std::string username, pin;
  boost::uint32_t rid;
};

struct FindSystemPacketData {
  FindSystemPacketData() : system_packet_creation_data(), packet_type() {}
  boost::shared_ptr<SystemPacketCreationData> system_packet_creation_data;
  passport::PacketType packet_type;
};

struct SaveSessionData {
  SaveSessionData() : serialised_data_atlas(), current_encrypted_mid(),
                      mid_tmid_data(), new_mid(0), functor(),
                      same_mid_smid(false) {}
  std::string serialised_data_atlas;
  std::string current_encrypted_mid;
  std::string mid_tmid_data;
  boost::uint32_t new_mid;
  VoidFuncOneInt functor;
  bool same_mid_smid;
};

class Authentication {
 public:
  Authentication() : crypto_(),
                     store_manager_(),
                     session_singleton_(),
                     passport_(),
                     mutex_(),
                     cond_var_(),
                     tmid_op_status_(kPendingMid),
                     stmid_op_status(kPendingMid),
                     serialised_tmid_packet_(),
                     serialised_stmid_packet_(),
                     system_packets_result_(kPendingResult) {}
  ~Authentication() {}
  void Init(const boost::uint16_t &crypto_key_buffer_count,
            boost::shared_ptr<StoreManagerInterface> storemanager,
            boost::shared_ptr<passport::Passport> passport);
  int GetUserInfo(const std::string &username, const std::string &pin);
  int GetUserData(const std::string &password,
                  std::string *serialised_data_atlas);





  int CreateUserSysPackets(const std::string &username,
                           const std::string &pin);
  void CreateUserSysPackets(const ReturnCode &return_code,
                            const std::string &username,
                            const std::string &pin,
                            VoidFuncOneInt vfoi,
                            boost::uint16_t *count,
                            bool *calledback);
  int CreateTmidPacket(const std::string &username,
                       const std::string &pin,
                       const std::string &password,
                       const std::string &ser_dm);
  int SaveSession(const std::string &serialised_data_atlas);
  void SaveSession(const std::string &serialised_data_atlas, const VoidFuncOneInt &cb);
  int RemoveMe(std::list<KeyAtlasRow> sig_keys);
  int CreatePublicName(const std::string &public_username);
  int ChangeUsername(const std::string &serialised_data_atlas,
                     const std::string &new_username);
  int ChangePin(const std::string &serialised_data_atlas,
                const std::string &new_pin);
  int ChangePassword(const std::string &serialised_data_atlas,
                     const std::string &new_password);
  int PublicUsernamePublicKey(const std::string &public_username,
                              std::string *public_key);
  void CreateMSIDPacket(kad::VoidFunctorOneString cb);
  ReturnCode get_smidtmid_result() const {
    return get_smidtmid_result_;
  }
 private:
  enum OpStatus { kPendingMid, kPendingTmid, kFailed, kNoUser, kSucceeded };
  Authentication &operator=(const Authentication&);
  Authentication(const Authentication&);
  void GetMidTmidCallback(const std::vector<std::string> &values,
                          const ReturnCode &return_code,
                          bool surrogate);



  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool TmidOpDone() {
    return (tmid_op_status_ == kSucceeded || tmid_op_status_ == kNoUser ||
            tmid_op_status_ == kFailed);
  }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool StmidOpDone() {
    return (stmid_op_status_ == kSucceeded || stmid_op_status_ == kNoUser ||
            stmid_op_status_ == kFailed);
  }





  std::string CreateSignaturePackets(const PacketType &type_da,
                                     std::string *public_key);
  void CreateSignaturePacket(
      boost::shared_ptr<SystemPacketCreationData> system_packet_creation_data,
      const PacketType &type_da);
  bool CheckUsername(const std::string &username);
  bool CheckPin(const std::string &pin);
  bool CheckPassword(const std::string &password);
  int StorePacket(const std::string &packet_name,
                  const std::string &value,
                  const PacketType &type,
                  const std::string &msid);
  // Unneccessary, but more efficient/faster to pass packet's value here
  int DeletePacket(const std::string &packet_name,
                   const std::string &value,
                   const PacketType &type);
  void PacketOpCallback(const int &store_manager_result,
                        boost::mutex *mutex,
                        boost::condition_variable *cond_var,
                        int *op_result);
  void CreateSignaturePacketKeyUnique(
      const ReturnCode &return_code,
      boost::shared_ptr<FindSystemPacketData> find_system_packet_data);
  void CreateSignaturePacketStore(
      const ReturnCode &return_code,
      boost::shared_ptr<FindSystemPacketData> find_system_packet_data);
  void CreateSystemPacketsCallback(const ReturnCode &return_code);
  void CreateMidPacket(
      boost::shared_ptr<FindSystemPacketData> find_system_packet_data);
  void CreateSmidPacket(
      boost::shared_ptr<FindSystemPacketData> find_system_packet_data);
  void CreateMaidPmidPacket(
      boost::shared_ptr<FindSystemPacketData> find_system_packet_data);
  std::string EncryptedDataMidSmid(boost::uint32_t rid);

  void UpdateSmidCallback(const ReturnCode &return_code,
                          boost::shared_ptr<SaveSessionData> ssd);
  void DeleteSmidTmidCallback(const ReturnCode &return_code,
                              boost::shared_ptr<SaveSessionData> ssd);
  void UpdateMidCallback(const ReturnCode &return_code,
                         boost::shared_ptr<SaveSessionData> ssd);
  void StoreMidTmidCallback(const ReturnCode &return_code,
                            boost::shared_ptr<SaveSessionData> ssd);
  void SaveSessionCallback(const ReturnCode &return_code,
                           ReturnCode *return_code_out,
                           boost::condition_variable *cond_var,
                           boost::mutex *mutex);
  char *UtilsTrimRight(char *szSource);
  char *UtilsTrimLeft(char *szSource);
  char *UtilsTrim(char *szSource);

  crypto::Crypto crypto_;
  boost::shared_ptr<StoreManagerInterface> store_manager_;
  SessionSingleton *session_singleton_;
  boost::shared_ptr<passport::Passport> passport_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  OpStatus tmid_op_status_, stmid_op_status_;
  std::string serialised_tmid_packet_, serialised_stmid_packet_;
  ReturnCode system_packets_result_, user_info_result_, stmid_result_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_AUTHENTICATION_H_
