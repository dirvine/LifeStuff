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

  ClientMaid(Session& session, const Slots& slots);
  ~ClientMaid() {}

  void CreateUser(const Keyword& keyword,
                  const Pin& pin,
                  const Password& password,
                  const boost::filesystem::path& vault_path,
                  ReportProgressFunction& report_progress);

  void LogIn(const Keyword& keyword,
             const Pin& pin,
             const Password& password,
             ReportProgressFunction& report_progress);
  void LogOut();
  void MountDrive();
  void UnMountDrive();

  void ChangeKeyword(const Keyword& old_keyword,
                     const Keyword& new_keyword,
                     const Pin& pin,
                     const Password& password);
  void ChangePin(const Keyword& keyword,
                 const Pin& old_pin,
                 const Pin& new_pin,
                 const Password& password);
  void ChangePassword(const Keyword& keyword,
                      const Pin& pin,
                      const Password& new_password);

  boost::filesystem::path mount_path();
  boost::filesystem::path owner_path();

 private:
  const Slots& CheckSlots(const Slots& slots);
  void PutSession(const Keyword& keyword, const Pin& pin, const Password& password);
  void DeleteSession(const Keyword& keyword, const Pin& pin);
  void GetSession(const Keyword& keyword, const Pin& pin, const Password& password);
  void JoinNetwork(const Maid& maid);
  void RegisterPmid(const Maid& maid, const Pmid& pmid);
  void UnregisterPmid(const Maid& maid, const Pmid& pmid);
  void UnCreateUser(bool fobs_confirmed, bool drive_mounted);

  template<typename Fob> void PutFob(const Fob& fob);
  template<typename Fob> void DeleteFob(const typename Fob::name_type& fob);
  template<typename Fob> Fob GetFob(const typename Fob::name_type& fob);

  void PutFreeFobs();
  void PutPaidFobs();

  void PublicKeyRequest(const NodeId& node_id, const GivePublicKeyFunctor& give_key);

  Slots slots_;
  Session& session_;
  ClientController client_controller_;
  UserStorage user_storage_;
  RoutingHandlerPtr routing_handler_;
  ClientNfsPtr client_nfs_;
};

}  // lifestuff
}  // maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_CLIENT_MAID_H_
