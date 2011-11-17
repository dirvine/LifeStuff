/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Utility Functions
* Version:      1.0
* Created:      2010-04-29-13.26.25
* Revision:     none
* Compiler:     gcc
* Author:       Team, dev@maidsafe.net
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

#include "maidsafe/lifestuff/client_utils.h"

#include <algorithm>
#include <cctype>
#include <functional>

#include "maidsafe/common/crypto.h"

#include "maidsafe/lifestuff/session.h"

namespace maidsafe {

namespace lifestuff {

void ClientUtils::GetChunkSignatureKeys(DirType dir_type,
                                        const std::string &msid,
                                        std::string *key_id,
                                        std::string *public_key,
                                        std::string *public_key_sig,
                                        std::string *private_key) {
  key_id->clear();
  public_key->clear();
  public_key_sig->clear();
  private_key->clear();
  switch (dir_type) {
    case PRIVATE_SHARE:
      if (kSuccess == ss_->GetShareKeys(msid, public_key, private_key)) {
        *key_id = msid;
        *public_key_sig = crypto::AsymSign(*public_key, *private_key);
      } else {
        key_id->clear();
        public_key->clear();
        public_key_sig->clear();
        private_key->clear();
      }
      break;
    case PUBLIC_SHARE:
      *key_id = ss_->Id(passport::MPID, true);
      *public_key = ss_->PublicKey(passport::MPID, true);
      *public_key_sig = ss_->PublicKeySignature(passport::MPID, true);
      *private_key = ss_->PrivateKey(passport::MPID, true);
      break;
    case ANONYMOUS:
      *key_id = " ";
      *public_key = " ";
      *public_key_sig = " ";
      *private_key = "";
      break;
    case PRIVATE:
    default:
      *key_id = ss_->Id(passport::kPmid, true);
      *public_key = ss_->PublicKey(passport::kPmid, true);
      *public_key_sig = ss_->PublicKeySignature(passport::kPmid, true);
      *private_key = ss_->PrivateKey(passport::kPmid, true);
      break;
  }
}

void ClientUtils::GetPacketSignatureKeys(passport::PacketType packet_type,
                                         DirType dir_type,
                                         const std::string &msid,
                                         std::string *key_id,
                                         std::string *public_key,
                                         std::string *public_key_sig,
                                         std::string *private_key,
                                         bool *hashable) {
  // For self-signers, signing packet will not be confirmed as stored.  For all
  // others, it must be.
  key_id->clear();
  public_key->clear();
  public_key_sig->clear();
  private_key->clear();
  bool confirmed_as_stored(true);
  *hashable = false;
  switch (packet_type) {
    case passport::kAnmid:
      confirmed_as_stored = false;
    case passport::MID:
      *key_id = ss_->Id(passport::kAnmid, confirmed_as_stored);
      *public_key = ss_->PublicKey(passport::kAnmid, confirmed_as_stored);
      *public_key_sig = ss_->PublicKeySignature(passport::kAnmid,
                                                confirmed_as_stored);
      *private_key = ss_->PrivateKey(passport::kAnmid, confirmed_as_stored);
      *hashable = false;
      break;
    case passport::kAnsmid:
      confirmed_as_stored = false;
    case passport::SMID:
      *key_id = ss_->Id(passport::kAnsmid, confirmed_as_stored);
      *public_key = ss_->PublicKey(passport::kAnsmid, confirmed_as_stored);
      *public_key_sig = ss_->PublicKeySignature(passport::kAnsmid,
                                                confirmed_as_stored);
      *private_key = ss_->PrivateKey(passport::kAnsmid, confirmed_as_stored);
      *hashable = false;
      break;
    case passport::kAntmid:
      confirmed_as_stored = false;
    case passport::TMID:
    case passport::STMID:
      *key_id = ss_->Id(passport::kAntmid, confirmed_as_stored);
      *public_key = ss_->PublicKey(passport::kAntmid, confirmed_as_stored);
      *public_key_sig = ss_->PublicKeySignature(passport::kAntmid,
                                                confirmed_as_stored);
      *private_key = ss_->PrivateKey(passport::kAntmid, confirmed_as_stored);
      *hashable = false;
      break;
    case passport::ANMPID:
      confirmed_as_stored = false;
    case passport::MPID:
      *key_id = ss_->Id(passport::ANMPID, confirmed_as_stored);
      *public_key = ss_->PublicKey(passport::ANMPID, confirmed_as_stored);
      *public_key_sig = ss_->PublicKeySignature(passport::ANMPID,
                                                confirmed_as_stored);
      *private_key = ss_->PrivateKey(passport::ANMPID, confirmed_as_stored);
      break;
    case passport::kAnmaid:
      confirmed_as_stored = false;
    case passport::kMaid:
      *key_id = ss_->Id(passport::kAnmaid, confirmed_as_stored);
      *public_key = ss_->PublicKey(passport::kAnmaid, confirmed_as_stored);
      *public_key_sig = ss_->PublicKeySignature(passport::kAnmaid,
                                                confirmed_as_stored);
      *private_key = ss_->PrivateKey(passport::kAnmaid, confirmed_as_stored);
      break;
    case passport::kPmid:
      *key_id = ss_->Id(passport::kMaid, true);
      *public_key = ss_->PublicKey(passport::kMaid, true);
      *public_key_sig = ss_->PublicKeySignature(passport::kMaid, true);
      *private_key = ss_->PrivateKey(passport::kMaid, true);
      break;
    case passport::PD_DIR:
    case passport::MSID:
      GetChunkSignatureKeys(dir_type, msid, key_id, public_key, public_key_sig,
                            private_key);
      *hashable = false;
      break;
    default:
      break;
  }
}

}  // namespace lifestuff

}  // namespace maidsafe
