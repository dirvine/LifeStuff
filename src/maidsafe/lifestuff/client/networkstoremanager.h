/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Interface allowing storage of data to network or local database
* Version:      1.0
* Created:      2011-05-16-00.49.17
* Revision:     none
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

#ifndef MAIDSAFE_LIFESTUFF_CLIENT_NETWORKSTOREMANAGER_H_
#define MAIDSAFE_LIFESTUFF_CLIENT_NETWORKSTOREMANAGER_H_

#include "maidsafe/lifestuff/client/packet_manager.h"

#include <functional>
#include <memory>
#include "boost/asio/ip/address.hpp"
#include "boost/asio/io_service.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/node_id.h"
#include "maidsafe/dht/kademlia/node-api.h"
#include "maidsafe/dht/kademlia/securifier.h"

namespace maidsafe {

namespace lifestuff {

typedef std::function<void(std::vector<bool>)> DeleteFunctor;

class NetworkStoreManager : public PacketManager {
 public:
  NetworkStoreManager(const boost::uint16_t &k,
                      const boost::uint16_t &alpha,
                      const boost::uint16_t beta,
                      const bptime::seconds &mean_refresh_interval);
  virtual void Init(
      const std::vector<dht::kademlia::Contact> &bootstrap_contacts,
      const dht::kademlia::JoinFunctor callback,
      const boost::uint16_t &port);

  void Close(VoidFuncOneInt callback,
             std::vector<dht::kademlia::Contact> *bootstrap_contacts);

  virtual void KeyUnique(const std::string &key,
                         bool check_local,
                         const dht::kademlia::FindValueFunctor &cb);

  virtual void GetPacket(const std::string &packet_name,
                         const dht::kademlia::FindValueFunctor &lpf);

  virtual void StorePacket(const std::string &packet_name,
                           const std::string &value,
                           passport::PacketType system_packet_type,
                           DirType dir_type,
                           const std::string &msid,
                           const dht::kademlia::StoreFunctor &cb);

  virtual void DeletePacket(const std::string &packet_name,
                            const std::vector<std::string> values,
                            passport::PacketType system_packet_type,
                            DirType dir_type,
                            const std::string &msid,
                            const DeleteFunctor &cb);
  virtual void UpdatePacket(const std::string &packet_name,
                            const std::string &old_value,
                            const std::string &new_value,
                            passport::PacketType system_packet_type,
                            DirType dir_type,
                            const std::string &msid,
                            const dht::kademlia::UpdateFunctor &cb);

 private:
  void DeletePacketImpl(const dht::kademlia::Key &key,
                        const std::vector<std::string> values,
                        dht::kademlia::SecurifierPtr securifier,
                        const DeleteFunctor &cb);
  void DeletePacketCallback(int result);

  void FindValueCallback(int results,
                         std::vector<std::string> values,
                         std::vector<dht::kademlia::Contact> contacts,
                         dht::kademlia::Contact node,
                         dht::kademlia::Contact cache,
                         const dht::kademlia::Key& key,
                         const dht::kademlia::SecurifierPtr securifier,
                         const DeleteFunctor &cb);

  void PopulateValues(const dht::kademlia::Key &key,
                      const dht::kademlia::SecurifierPtr securifier,
                      const DeleteFunctor &cb);

  boost::uint16_t k_;
  boost::uint16_t alpha_;
  boost::uint16_t beta_;
  std::shared_ptr<boost::asio::io_service> asio_service_;
  std::shared_ptr<boost::asio::io_service::work> work_;
  std::shared_ptr<dht::Securifier> securifier_;
  std::shared_ptr<dht::kademlia::Node> node_;
  dht::kademlia::NodeId node_id_;
  bptime::seconds mean_refresh_interval_;
	std::vector<bool> delete_results_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_CLIENT_NETWORKSTOREMANAGER_H_
