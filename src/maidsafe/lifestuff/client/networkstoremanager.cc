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

#include "maidsafe/lifestuff/client/networkstoremanager.h"

#include <functional>
#include <memory>

#include "maidsafe/dht/transport/transport.h"
#include "maidsafe/lifestuff/client/clientutils.h"

namespace arg = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace lifestuff {

NetworkStoreManager::NetworkStoreManager(const boost::uint16_t &k,
    const boost::uint16_t &alpha, const boost::uint16_t beta,
      const bptime::seconds &mean_refresh_interval)
  : k_(k),
    alpha_(alpha),
    beta_(beta),
    asio_service_(),
    work_(),
    securifier_(),
//    node_(),
    node_id_(dht::kademlia::NodeId::kRandomId),
    mean_refresh_interval_(mean_refresh_interval) {
}

void NetworkStoreManager::Init(const std::vector<dht::kademlia::Contact> &bootstrap_contacts, //NOLINT
                               const dht::kademlia::JoinFunctor callback,
                               const boost::uint16_t &port) {
  dht::kademlia::TransportPtr transport;
	dht::kademlia::MessageHandlerPtr message_handler;
	dht::kademlia::AlternativeStorePtr alternative_store;

  node_.reset(new dht::kademlia::Node(asio_service_, transport, message_handler,
              securifier_, alternative_store, true, k_, alpha_, beta_,
              mean_refresh_interval_));
  node_->Join(node_id_, bootstrap_contacts, callback);

}

void NetworkStoreManager::Close(VoidFuncOneInt callback,
    std::vector<dht::kademlia::Contact> *bootstrap_contacts) {
  node_->Leave(bootstrap_contacts);
}

bool NetworkStoreManager::KeyUnique(const std::string &key, bool check_local) {
  return true;
}

void NetworkStoreManager::KeyUnique(const std::string &key, bool check_local,
                                    const dht::kademlia::FindValueFunctor &cb){
	dht::kademlia::Key node_id(key);	
	node_->FindValue(node_id, securifier_, cb);
}

int NetworkStoreManager::GetPacket(const std::string &packet_name,
                                    std::vector<std::string> *results) {
  return 0;
}

void NetworkStoreManager::GetPacket(const std::string &packet_name,
                                     const dht::kademlia::FindValueFunctor &lpf) {
  dht::kademlia::Key key(packet_name);  
  node_->FindValue(key, securifier_, lpf);
}

void NetworkStoreManager::StorePacket(const std::string &packet_name,
                           const std::string &value,
                           passport::PacketType system_packet_type,
                           DirType dir_type,
                           const std::string &msid,
                           const dht::kademlia::StoreFunctor &cb) {
	dht::kademlia::Key key(packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  maidsafe::lifestuff::ClientUtils client_utils;
  client_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid,
                                      &key_id, &public_key,
                                      &public_key_signature, &private_key);
	boost::posix_time::seconds ttl(boost::posix_time::neg_infin);
	dht::kademlia::SecurifierPtr securifier;
	std::string singature;
	securifier.reset(new dht::Securifier(key_id, public_key, private_key));	
	node_->Store(key, value, singature, ttl, securifier, cb);
}

void NetworkStoreManager::DeletePacket(const std::string &packet_name,
                            const std::vector<std::string> values,
                            passport::PacketType system_packet_type,
                            DirType dir_type,
                            const std::string &msid,
                            const VoidFuncOneInt &cb) {
	dht::kademlia::Key key(packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  maidsafe::lifestuff::ClientUtils client_utils;
  client_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid,
                                      &key_id, &public_key,
                                      &public_key_signature, &private_key);
  dht::kademlia::SecurifierPtr securifier;	
	securifier.reset(new dht::Securifier(key_id, public_key, private_key));
//	node_->Delete(key, values, )
}

void NetworkStoreManager::UpdatePacket(const std::string &packet_name,
                            const std::string &old_value,
                            const std::string &new_value,
                            passport::PacketType system_packet_type,
                            DirType dir_type,
                            const std::string &msid,
                            const dht::kademlia::UpdateFunctor &cb) {
	dht::kademlia::Key key(packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  maidsafe::lifestuff::ClientUtils client_utils;
  client_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid,
                                      &key_id, &public_key,
                                      &public_key_signature, &private_key);
	boost::posix_time::seconds ttl(boost::posix_time::neg_infin);
  dht::kademlia::SecurifierPtr securifier;
	securifier.reset(new dht::Securifier(key_id, public_key, private_key));
	node_->Update(key, new_value, "", old_value, "", securifier, ttl, cb);
}

}  // namespace lifestuff

}  // namespace maidsafe