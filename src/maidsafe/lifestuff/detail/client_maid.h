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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MAID_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MAID_H_

#include <string>
#include <vector>
#include <utility>

#include "maidsafe/routing/routing_api.h"

#include "maidsafe/nfs/nfs.h"
#include "maidsafe/nfs/pmid_registration.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff_manager/client_controller.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/user_storage.h"
#include "maidsafe/lifestuff/detail/routing_handler.h"

namespace maidsafe {
namespace lifestuff {

class ClientMaid {
 public:
  typedef std::unique_ptr<RoutingHandler> RoutingHandlerPtr;
  typedef RoutingHandler::EndPointVector EndPointVector;
  typedef nfs::PmidRegistration PmidRegistration;
  typedef nfs::ClientMaidNfs ClientNfs;
  typedef std::unique_ptr<ClientNfs> ClientNfsPtr;
  typedef lifestuff_manager::ClientController ClientController;
  typedef passport::Passport Passport;
  typedef passport::Anmid Anmid;
  typedef passport::Ansmid Ansmid;
  typedef passport::Antmid Antmid;
  typedef passport::Anmaid Anmaid;
  typedef passport::Maid Maid;
  typedef passport::Pmid Pmid;
  typedef passport::Mid Mid;
  typedef passport::Tmid Tmid;

  ClientMaid(Session& session, UpdateAvailableFunction update_available_function);
  ~ClientMaid() {}

  void CreateUser(const Keyword& keyword, const Pin& pin, const Password& password);

  void LogIn(const Keyword& keyword, const Pin& pin, const Password& password);
  void LogOut();
  void MountDrive();
  void UnMountDrive();

  void GetBootStrapNodes(EndPointVector& endpoints) {
    client_controller_.GetBootstrapNodes(endpoints);
  }
  template<typename Fob> void PutFob(const Fob& fob);

 private:
  void CheckInputs(const Keyword& keyword, const Pin& pin, const Password& password);
  void CheckKeywordValidity(const Keyword& keyword);
  void CheckPinValidity(const Pin& pin);
  void CheckPasswordValidity(const Password& password);
  bool AcceptableWordSize(const Identity& word);
  bool AcceptableWordPattern(const Identity& word);

  void GetSession(const Keyword& keyword, const Pin& pin, const Password& password);
  void PutSession(const Keyword& keyword, const Pin& pin, const Password& password);

  void JoinNetwork(const Maid& maid);

  void PutFreeFobs();
  void HandlePutFreeFobsFailure();
  void PutPaidFobs();
  void HandlePutPaidFobsFailure();

  void HandlePutFobFailure();
  template<typename Fob> void DeleteFob(const typename Fob::name_type& fob);
  void HandleDeleteFobFailure();
  template<typename Fob> Fob GetFob(const typename Fob::name_type& fob);

  void RegisterPmid(const Maid& maid, const Pmid& pmid);
  void UnregisterPmid(const Maid& maid, const Pmid& pmid);

  void PublicKeyRequest(const NodeId& node_id, const GivePublicKeyFunctor& give_key);

  Session& session_;
  ClientController client_controller_;
  UserStorage user_storage_;
  RoutingHandlerPtr routing_handler_;
  ClientNfsPtr client_nfs_;
};
}  // lifestuff
}  // maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MAID_H_
