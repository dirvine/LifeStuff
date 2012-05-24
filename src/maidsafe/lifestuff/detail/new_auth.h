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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_NEW_AUTH_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_NEW_AUTH_H_

#include <memory>
#include <string>

#include "boost/thread/mutex.hpp"

#include "maidsafe/common/rsa.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"

namespace pcs = maidsafe::priv::chunk_store;

namespace maidsafe {

namespace priv {
namespace chunk_store {
class RemoteChunkStore;
}  // namespace chunk_store
}  // namespace priv
namespace pcs = maidsafe::priv::chunk_store;

namespace pki {
class Packet;
class SignaturePacket;
}  // namespace pki
namespace passport { class Passport; }

namespace lifestuff {

class Session;
namespace { struct OperationResults; }

/**
 * ATTENTION! This class handles session saves to the network. Running several
 * attempts at the same time can result in lost of credentials. Therefore,
 * operations inside this class have been mutexed to ensure one at a time.
 */

class NewAuthentication {
 public:
  NewAuthentication(std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
                    std::shared_ptr<Session> session);
  ~NewAuthentication();
  int GetUserInfo(const std::string &username,
                  const std::string &pin,
                  const std::string &password);
  int CreateUser(const std::string &username,
                 const std::string &pin,
                 const std::string &password);

  int SaveSession();

  int ChangeUsernamePin(const std::string &new_username,
                        const std::string &new_pin);
  int ChangePassword(const std::string &new_password);

 private:
  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store_;
  std::shared_ptr<Session> session_;
  passport::Passport &passport_;
  boost::mutex single_threaded_class_mutex_;

  void GetIdAndTemporaryId(const std::string &username,
                           const std::string &pin,
                           const std::string &password,
                           bool surrogate,
                           int *result,
                           std::string *temporary_packet);
  int HandleSerialisedDataMaps(const std::string &tmid_serialised_data_atlas,
                               const std::string &stmid_serialised_data_atlas);

  int ProcessSigningPackets();
  int StoreAnonymousPackets();
  void StoreAnmid(OperationResults &results);
  void StoreAnsmid(OperationResults &results);
  void StoreAntmid(OperationResults &results);
  void StoreSignaturePacket(std::shared_ptr<asymm::Keys> packet,
                            OperationResults &results,
                            int index);
  void StoreAnmaid(OperationResults &results);
  void StoreMaid(bool result, OperationResults &results);
  void StorePmid(bool result, OperationResults &results);

  int ProcessIdentityPackets(const std::string &username,
                             const std::string &pin,
                             const std::string &password);
  int StoreIdentityPackets();
  void StoreMid(OperationResults &results);
  void StoreSmid(OperationResults &results);
  void StoreTmid(OperationResults &results);
  void StoreStmid(OperationResults &results);
  void StoreIdentity(OperationResults &results,
                     int identity_type,
                     int signer_type,
                     int index);

  void ModifyMid(OperationResults &results);
  void ModifySmid(OperationResults &results);
  void ModifyIdentity(OperationResults &results,
                      int identity_type,
                      int signer_type,
                      int index);

  int DeleteOldIdentityPackets();
  void DeleteMid(OperationResults &results);
  void DeleteSmid(OperationResults &results);
  void DeleteTmid(OperationResults &results);
  void DeleteStmid(OperationResults &results);
  void DeleteIdentity(OperationResults &results,
                      int packet_type,
                      int signer_type,
                      int index);

  int DoChangePasswordAdditions();
  int DoChangePasswordRemovals();

  int SerialiseAndSetIdentity(const std::string &username,
                              const std::string &pin,
                              const std::string &password);
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_NEW_AUTH_H_
