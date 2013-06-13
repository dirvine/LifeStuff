/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
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

#include "maidsafe/lifestuff/detail/utils.h"

namespace maidsafe {
namespace lifestuff {

namespace detail {
  template <>
  struct PutFobs<Free> {
    typedef maidsafe::nfs::ClientMaidNfs ClientNfs;
    typedef passport::Passport Passport;
    typedef passport::Anmaid Anmaid;
    typedef passport::PublicAnmaid PublicAnmaid;
    typedef passport::Maid Maid;
    typedef passport::PublicMaid PublicMaid;
    typedef passport::Pmid Pmid;
    typedef passport::PublicPmid PublicPmid;

    void operator()(ClientNfs& client_nfs, Passport& passport, ReplyFunction& reply) {
      Pmid::name_type pmid_name(passport.Get<Pmid>(false).name());
      PublicAnmaid public_anmaid(passport.Get<Anmaid>(false));
      PublicMaid public_maid(passport.Get<Maid>(false));
      PublicPmid public_pmid(passport.Get<Pmid>(false));

      maidsafe::nfs::Put<PublicAnmaid>(client_nfs, public_anmaid, pmid_name, 3, reply);
      maidsafe::nfs::Put<PublicMaid>(client_nfs, public_maid, pmid_name, 3, reply);
      maidsafe::nfs::Put<PublicPmid>(client_nfs, public_pmid, pmid_name, 3, reply);
    }
  };

  template <>
  struct PutFobs<Paid> {
    typedef maidsafe::nfs::ClientMaidNfs ClientNfs;
    typedef passport::Passport Passport;
    typedef passport::Anmid Anmid;
    typedef passport::PublicAnmid PublicAnmid;
    typedef passport::Ansmid Ansmid;
    typedef passport::PublicAnsmid PublicAnsmid;
    typedef passport::Antmid Antmid;
    typedef passport::PublicAntmid PublicAntmid;
    typedef passport::Pmid Pmid;

    void operator()(ClientNfs& client_nfs, Passport& passport, ReplyFunction& reply) {
      Pmid::name_type pmid_name(passport.Get<Pmid>(true).name());
      PublicAnmid public_anmid(passport.Get<Anmid>(true));
      PublicAnsmid public_ansmid(passport.Get<Ansmid>(true));
      PublicAntmid public_antmid(passport.Get<Antmid>(true));

      maidsafe::nfs::Put<PublicAnmid>(client_nfs, public_anmid, pmid_name, 3, reply);
      maidsafe::nfs::Put<PublicAnsmid>(client_nfs, public_ansmid, pmid_name, 3, reply);
      maidsafe::nfs::Put<PublicAntmid>(client_nfs, public_antmid, pmid_name, 3, reply);
    }
  };
}  // namespace detail

}  // namespace lifestuff
}  // namespace maidsafe
