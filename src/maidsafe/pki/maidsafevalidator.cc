/*
 * ============================================================================
 *
 * Copyright [2009] maidsafe.net limited
 *
 * Description:  Implementation of signature and signer id validation
 * Version:      1.0
 * Created:      2010-01-06
 * Revision:     none
 * Compiler:     gcc
 * Author:       Jose Cisneros
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

#ifndef MAIDSAFE_VALIDATIONIMPL_H_
#define MAIDSAFE_VALIDATIONIMPL_H_

#include "maidsafe/pki/maidsafevalidator.h"

#include <cstdio>

#include "boost/bind.hpp"
#include "boost/function.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/returncodes.h"

namespace maidsafe {

namespace pki {

boost::function<std::string(const std::string&)> Hash512 =
    boost::bind(&crypto::Hash<crypto::SHA512>, _1);

bool MaidsafeValidator::ValidateSignerId(const std::string &signer_id,
                                         const std::string &public_key,
                                         const std::string &signed_public_key) {
  if (signer_id.empty() || public_key.empty() || signed_public_key.empty()) {
#ifdef DEBUG
    if (signer_id.empty())
      printf("MaidsafeValidator::ValidateSignerId: signer_id empty.\n");
    if (public_key.empty())
      printf("MaidsafeValidator::ValidateSignerId: public_key empty.\n");
    if (signed_public_key.empty())
      printf("MaidsafeValidator::ValidateSignerId: signed_public_key empty.\n");
#endif
    return false;
  }
  if (signer_id != Hash512(public_key + signed_public_key)) {
#ifdef DEBUG
    printf("MaidsafeValidator::ValidateSignerId - Id doesn't validate.\n");
#endif
    return false;
  }
  return true;
}

bool MaidsafeValidator::ValidateRequest(const std::string &signed_request,
                                        const std::string &public_key,
                                        const std::string &signed_public_key,
                                        const std::string &key) {
  if (crypto::AsymCheckSig(Hash512(signed_public_key + key +  kSigningKeyId_),
                           signed_request,
                           public_key))
    return true;
  if (crypto::AsymCheckSig(Hash512(public_key + signed_public_key + key),
                           signed_request,
                           public_key))
    return true;
#ifdef DEBUG
  printf("MaidsafeValidator::ValidateRequest - Failed to validate request.\n");
#endif
  return false;
}


int MaidsafeValidator::SignMessage(
    const std::string &private_key,
    const std::list<std::string> &parameters,
    std::string *signature) {
  if (private_key.empty())
    return kValidatorNoPrivateKey;
  if (parameters.size() > 2)
    return CreateRequestSignature(private_key, parameters, signature);
  else
    return kValidatorNoParameters;
}

int MaidsafeValidator::CreateRequestSignature(
    const std::string &private_key,
    const std::list<std::string> &parameters,
    std::string *request_signature) {
  if (private_key.empty())
    return kValidatorNoPrivateKey;
  if (parameters.size() == 0)
    return kValidatorNoParameters;

  std::string concatenation;
  std::list<std::string>::const_iterator it;
  for (it = parameters.begin(); it != parameters.end(); ++it)
    concatenation += *it;

  *request_signature = crypto::AsymSign(Hash512(concatenation), private_key);
  return 0;
}

}  // namespace pki

}  // namespace maidsafe

#endif  // MAIDSAFE_VALIDATIONIMPL_H_
