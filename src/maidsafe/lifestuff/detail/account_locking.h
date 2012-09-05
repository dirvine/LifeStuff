/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of maidsafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the license file LICENSE.TXT found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of maidsafe.net.                                          *
 **************************************************************************************************/
/**
 * @file  account_locking.h
 * @brief Functionality to handle account packet.
 * @date  2012-09-04
 */

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_ACCOUNT_LOCKING_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_ACCOUNT_LOCKING_H_

#include <string>
#include <vector>

#include "maidsafe/lifestuff/detail/data_atlas_pb.h"

namespace maidsafe {

namespace lifestuff {

namespace account_locking {

std::string LidName(const std::string& keyword, const std::string& pin);

std::string EncryptAccountStatus(const std::string& keyword,
                                 const std::string& pin,
                                 const std::string& password,
                                 const std::string& account_status);

std::string DecryptAccountStatus(const std::string& keyword,
                                 const std::string& pin,
                                 const std::string& password,
                                 const std::string& encrypted_account_status);

LockingPacket CreateLockingPacket(const std::string& identifier);

int CheckLockingPacketForIdentifier(LockingPacket& locking_packet, const std::string& identifier);

int AddItemToLockingPacket(LockingPacket& locking_packet,
                           const std::string& identifier,
                           bool full_access);

int RemoveItemFromLockingPacket(LockingPacket& locking_packet, const std::string& identifier);

int RemoveItemsFromLockingPacket(LockingPacket& locking_packet,
                                 std::vector<std::string>& identifiers);

void OverthrowInstancesUsingLockingPacket(LockingPacket& locking_packet,
                                          const std::string& identifier);

int UpdateTimestampInLockingPacket(LockingPacket& locking_packet, const std::string& identifier);

int CheckLockingPacketForFullAccess(const LockingPacket& locking_packet);

int CheckLockingPacketForOthersLoggedIn(const LockingPacket& locking_packet,
                                        const std::string& identifier);

int ProcessAccountStatus(const std::string& keyword,
                         const std::string& pin,
                         const std::string& password,
                         const std::string& lid_packet,
                         LockingPacket& locking_packet);

}  // namespace account_locking

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_ACCOUNT_LOCKING_H_
