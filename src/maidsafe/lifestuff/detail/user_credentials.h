/***************************************************************************************************
 *  Copyright 2013 MaidSafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use.  The use of this code is governed by the licence file licence.txt found in the root of    *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit         *
 *  written permission of the board of directors of MaidSafe.net.                                  *
 **************************************************************************************************/

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_USER_CREDENTIALS_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_USER_CREDENTIALS_H_

#include "maidsafe/passport/passport.h"

#include "maidsafe/nfs/nfs.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/return_codes.h"

namespace maidsafe {
namespace lifestuff {

struct OperationResults;

/*
 * ATTENTION! This class handles session saves to the network. Running several
 * attempts at the same time can result in loss of credentials. Therefore,
 * operations inside this class have been mutexed to ensure one at a time.
 */

class UserCredentials {
 public:
  typedef maidsafe::nfs::ClientMaidNfs ClientNfs;

  UserCredentials(ClientNfs& client_nfs_);
  ~UserCredentials();

  void CreateUser(const Keyword& keyword, const Pin& pin, const Password& password);

  void LogIn(const Keyword& keyword, const Pin& pin, const Password& password);
  void LogOut();

  int SaveSession(bool log_out);

  int ChangePin(const NonEmptyString& new_pin);
  int ChangeKeyword(const NonEmptyString& new_keyword);
  int ChangeKeywordPin(const NonEmptyString& new_keyword, const NonEmptyString& new_pin);
  int ChangePassword(const NonEmptyString& new_password);

  int DeleteUserCredentials();

  void LogoutCompletedArrived(const std::string& session_marker);
  bool IsOwnSessionTerminationMessage(const std::string& session_marker);

 private:
  UserCredentials &operator=(const UserCredentials&);
  UserCredentials(const UserCredentials&);

  void CheckInputs(const Keyword& keyword, const Pin& pin, const Password& password);
  void CheckKeywordValidity(const Keyword& keyword);
  void CheckPinValidity(const Pin& pin);
  void CheckPasswordValidity(const Password& password);
  bool AcceptableWordSize(const Identity& word);
  bool AcceptableWordPattern(const Identity& word);

  void GetUserInfo(const Keyword& keyword,
                   const Pin& pin,
                   const Password& password,
                   const bool& compare_names,
                   std::string& mid_packet,
                   std::string& smid_packet);

  int CheckForOtherRunningInstances(const NonEmptyString& keyword,
                                    const NonEmptyString& pin,
                                    const NonEmptyString& password,
                                    std::string& mid_packet,
                                    std::string& smid_packet);

  void StartSessionSaver();

  void GetIdAndTemporaryId(const NonEmptyString& keyword,
                           const NonEmptyString& pin,
                           const NonEmptyString& password,
                           bool surrogate,
                           int* result,
                           std::string* id_contents,
                           std::string* temporary_packet);
  int HandleSerialisedDataMaps(const NonEmptyString& keyword,
                               const NonEmptyString& pin,
                               const NonEmptyString& password,
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
  //void StoreSignaturePacket(const Fob& packet, OperationResults& results, int index);

  int ProcessIdentityPackets(const NonEmptyString& keyword,
                             const NonEmptyString& pin,
                             const NonEmptyString& password);
  int StoreIdentityPackets();
  void StoreMid(OperationResults& results);
  void StoreSmid(OperationResults& results);
  void StoreTmid(OperationResults& results);
  void StoreStmid(OperationResults& results);
  void StoreIdentity(OperationResults& results, int identity_type, int signer_type, int index);

  void ModifyMid(OperationResults& results);
  void ModifySmid(OperationResults& results);
  void ModifyIdentity(OperationResults& results, int identity_type, int signer_type, int index);

  int DeleteOldIdentityPackets();
  void DeleteMid(OperationResults& results);
  void DeleteSmid(OperationResults& results);
  void DeleteTmid(OperationResults& results);
  void DeleteStmid(OperationResults& results);
  void DeleteIdentity(OperationResults& results, int packet_type, int signer_type, int index);

  int DeleteSignaturePackets();
  void DeleteAnmid(OperationResults& results);
  void DeleteAnsmid(OperationResults& results);
  void DeleteAntmid(OperationResults& results);
  void DeletePmid(OperationResults& results);
  //void DeleteMaid(bool result, OperationResults& results, const Fob& maid);
  //void DeleteAnmaid(bool result, OperationResults& results, const Fob& anmaid);
  //void DeleteSignaturePacket(const Fob& packet, OperationResults& results, int index);

  int DoChangePasswordAdditions();
  int DoChangePasswordRemovals();

  int SerialiseAndSetIdentity(const std::string& keyword,
                              const std::string& pin,
                              const std::string& password,
                              NonEmptyString& new_data_atlas);
 private:
  passport::Passport passport_;
  ClientNfs& client_nfs_;
};

}  // namespace lifestuff
}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_USER_CREDENTIALS_H_
