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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_USER_CREDENTIALS_IMPL_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_USER_CREDENTIALS_IMPL_H_

#include <memory>
#include <mutex>
#include <string>

#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/signals2/signal.hpp"

#include "maidsafe/common/rsa.h"


#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"
#include "maidsafe/lifestuff/detail/data_atlas_pb.h"

namespace maidsafe {

namespace priv {
namespace chunk_store {
class RemoteChunkStore;
}  // namespace chunk_store
}  // namespace priv
namespace bs2 = boost::signals2;
namespace pcs = maidsafe::priv::chunk_store;

namespace passport { class Passport; }

namespace lifestuff {

class Session;
struct OperationResults;

/**
 * ATTENTION! This class handles session saves to the network. Running several
 * attempts at the same time can result in lost of credentials. Therefore,
 * operations inside this class have been mutexed to ensure one at a time.
 */

class UserCredentialsImpl {
 public:
  typedef bs2::signal<void()> ImmediateQuitRequiredSignal;
  typedef std::shared_ptr<ImmediateQuitRequiredSignal> ImmediateQuitRequiredSignalPtr;

  UserCredentialsImpl(pcs::RemoteChunkStore& remote_chunk_store,
                      Session& session,
                      boost::asio::io_service& service);
  ~UserCredentialsImpl();

  int LogIn(const std::string& keyword, const std::string& pin, const std::string& password);

  int LogOut();

  int CreateUser(const std::string& keyword, const std::string& pin, const std::string& password);

  int SaveSession(bool log_out);

  int AssessAndUpdateLid(bool log_out);

  int ChangePin(const std::string& new_pin);
  int ChangeKeyword(const std::string new_keyword);
  int ChangeKeywordPin(const std::string& new_keyword, const std::string& new_pin);
  int ChangePassword(const std::string& new_password);

  int DeleteUserCredentials();

  bs2::connection ConnectToImmediateQuitRequiredSignal(
      const ImmediateQuitRequiredFunction& immediate_quit_required_slot);

 private:
  pcs::RemoteChunkStore& remote_chunk_store_;
  Session& session_;
  passport::Passport& passport_;
  std::mutex single_threaded_class_mutex_;
  boost::asio::io_service& asio_service_;
  boost::asio::deadline_timer session_saver_timer_;
  bool session_saver_timer_active_, session_saved_once_;
  const boost::posix_time::seconds session_saver_interval_;

  int AttemptLogInProcess(const std::string& keyword,
                          const std::string& pin,
                          const std::string& password);

  int GetUserInfo(const std::string& keyword,
                  const std::string& pin,
                  const std::string& password,
                  const bool& compare_names,
                  std::string& mid_packet,
                  std::string& smid_packet);

  void StartSessionSaver();

  int GetAndLockLid(const std::string& keyword,
                    const std::string& pin,
                    const std::string& password,
                    std::string& lid_packet,
                    LockingPacket& locking_packet);
  void GetIdAndTemporaryId(const std::string& keyword,
                           const std::string& pin,
                           const std::string& password,
                           bool surrogate,
                           int* result,
                           std::string* id_contents,
                           std::string* temporary_packet);
  int HandleSerialisedDataMaps(const std::string& keyword,
                               const std::string& pin,
                               const std::string& password,
                               const std::string& tmid_serialised_data_atlas,
                               const std::string& stmid_serialised_data_atlas);

  int ProcessSigningPackets();
  int StoreAnonymousPackets();
  void StoreAnmid(OperationResults& results);
  void StoreAnsmid(OperationResults& results);
  void StoreAntmid(OperationResults& results);
  void StoreAnmaid(OperationResults& results);
  void StoreMaid(bool result, OperationResults& results);
  void StorePmid(bool result, OperationResults& results);
  void StoreSignaturePacket(asymm::Keys packet,
                            OperationResults& results,
                            int index);

  int ProcessIdentityPackets(const std::string& keyword,
                             const std::string& pin,
                             const std::string& password);
  int StoreIdentityPackets();
  void StoreMid(OperationResults& results);
  void StoreSmid(OperationResults& results);
  void StoreTmid(OperationResults& results);
  void StoreStmid(OperationResults& results);
  void StoreIdentity(OperationResults& results,
                     int identity_type,
                     int signer_type,
                     int index);
  int StoreLid(const std::string keyword,
               const std::string pin,
               const std::string password,
               const LockingPacket& locking_packet);

  void ModifyMid(OperationResults& results);
  void ModifySmid(OperationResults& results);
  void ModifyIdentity(OperationResults& results,
                      int identity_type,
                      int signer_type,
                      int index);
  int ModifyLid(const std::string keyword,
                const std::string pin,
                const std::string password,
                const LockingPacket& locking_packet);

  int DeleteOldIdentityPackets();
  void DeleteMid(OperationResults& results);
  void DeleteSmid(OperationResults& results);
  void DeleteTmid(OperationResults& results);
  void DeleteStmid(OperationResults& results);
  void DeleteIdentity(OperationResults& results,
                      int packet_type,
                      int signer_type,
                      int index);
  int DeleteLid(const std::string& keyword,
                const std::string& pin);

  int DeleteSignaturePackets();
  void DeleteAnmid(OperationResults& results);
  void DeleteAnsmid(OperationResults& results);
  void DeleteAntmid(OperationResults& results);
  void DeletePmid(OperationResults& results);
  void DeleteMaid(bool result, OperationResults& results, asymm::Keys maid);
  void DeleteAnmaid(bool result, OperationResults& results, asymm::Keys anmaid);
  void DeleteSignaturePacket(asymm::Keys packet,
                             OperationResults& results,
                             int index);

  int DoChangePasswordAdditions();
  int DoChangePasswordRemovals();

  int SerialiseAndSetIdentity(const std::string& keyword,
                              const std::string& pin,
                              const std::string& password,
                              std::string* new_data_atlas);

  void SessionSaver(const boost::posix_time::seconds& interval,
                    const boost::system::error_code& error_code);

  ImmediateQuitRequiredSignal immediate_quit_required_signal_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_USER_CREDENTIALS_IMPL_H_
