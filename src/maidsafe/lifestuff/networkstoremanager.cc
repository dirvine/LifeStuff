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

#include "maidsafe/lifestuff/networkstoremanager.h"

#include <functional>
#include <memory>

#include "maidsafe/dht/transport/transport.h"
#include "maidsafe/lifestuff/clientutils.h"

namespace arg = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace lifestuff {

NetworkStoreManager::NetworkStoreManager(
    const boost::uint16_t &k,
    const boost::uint16_t &alpha,
    const boost::uint16_t beta,
    const bptime::seconds &mean_refresh_interval,
    std::shared_ptr<SessionSingleton> ss)
    : k_(k),
      alpha_(alpha),
      beta_(beta),
      asio_service_(),
      work_(),
      securifier_(),
      node_(),
      node_id_(dht::kademlia::NodeId::kRandomId),
      mean_refresh_interval_(mean_refresh_interval),
      delete_results_(),
      session_singleton_(ss) {}

void NetworkStoreManager::Init(
     const std::vector<dht::kademlia::Contact> &bootstrap_contacts,
     const dht::kademlia::JoinFunctor callback,
     const boost::uint16_t &/*port*/) {
  dht::kademlia::TransportPtr transport;
  dht::kademlia::MessageHandlerPtr message_handler;
  dht::kademlia::AlternativeStorePtr alternative_store;
  node_.reset(new dht::kademlia::Node(asio_service_, transport, message_handler,
                                      securifier_, alternative_store, true, k_,
                                      alpha_, beta_, mean_refresh_interval_));
  node_->Join(node_id_, bootstrap_contacts, callback);
}

void NetworkStoreManager::Close(
    VoidFuncOneInt,
    std::vector<dht::kademlia::Contact> *bootstrap_contacts) {
  node_->Leave(bootstrap_contacts);
}

void NetworkStoreManager::KeyUnique(const std::string &key,
                                    bool /*check_local*/,
                                    const dht::kademlia::FindValueFunctor &cb) {
  dht::kademlia::Key node_id(key);
  node_->FindValue(node_id, securifier_, cb);
}

void NetworkStoreManager::GetPacket(
    const std::string &packet_name,
    const dht::kademlia::FindValueFunctor &lpf) {
  dht::kademlia::Key key(packet_name);
  node_->FindValue(key, securifier_, lpf);
}

void NetworkStoreManager::StorePacket(
    const std::string &packet_name,
    const std::string &value,
    passport::PacketType system_packet_type,
    DirType dir_type,
    const std::string &msid,
    const dht::kademlia::StoreFunctor &cb) {
  boost::posix_time::seconds ttl(boost::posix_time::pos_infin);
  dht::kademlia::SecurifierPtr securifier;
  dht::kademlia::Key key(packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  maidsafe::lifestuff::ClientUtils client_utils(session_singleton_);
  client_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid,
                                      &key_id, &public_key,
                                      &public_key_signature, &private_key);
  securifier.reset(new dht::Securifier(key_id, public_key, private_key));
  node_->Store(key, value, "", ttl, securifier, cb);
}

void NetworkStoreManager::DeletePacket(
    const std::string &packet_name,
    std::vector<std::string> values,
    passport::PacketType system_packet_type,
    DirType dir_type,
    const std::string &msid,
    const DeleteFunctor &cb) {
  dht::kademlia::Key key(packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  maidsafe::lifestuff::ClientUtils client_utils(session_singleton_);
  client_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid,
                                      &key_id, &public_key,
                                      &public_key_signature, &private_key);
  dht::kademlia::SecurifierPtr securifier;
  securifier.reset(new dht::Securifier(key_id, public_key, private_key));
  if (values.empty())
    PopulateValues(key, securifier, cb);
  else
    DeletePacketImpl(key, values, securifier, cb);
}

void NetworkStoreManager::DeletePacketImpl(
    const dht::kademlia::Key &key,
    const std::vector<std::string> values,
    const dht::kademlia::SecurifierPtr securifier,
    const DeleteFunctor &cb) {
  std::shared_ptr<std::vector<int>> delete_results;
  delete_results->resize(values.size());
  std::shared_ptr<boost::mutex> mutex;
  mutex.reset(new boost::mutex);
  dht::kademlia::DeleteFunctor delete_functor;
  for (int index = 0; index != static_cast<int>(values.size()); ++index) {
    delete_functor = std::bind(&NetworkStoreManager::DeletePacketCallback, this,
                               arg::_1, index, delete_results, mutex);
    node_->Delete(key, values[index], "", securifier, delete_functor);
  }
  cb(delete_results);
}

void NetworkStoreManager::PopulateValues(const dht::kademlia::Key &key,
    const dht::kademlia::SecurifierPtr securifier,
    const DeleteFunctor &cb) {
  node_->FindValue(key,
                   securifier,
                   std::bind(&NetworkStoreManager::FindValueCallback, this,
                             arg::_1, key, securifier, cb));
}

void NetworkStoreManager::FindValueCallback(
    dht::kademlia::FindValueReturns fvr,
    const dht::kademlia::Key& key,
    const dht::kademlia::SecurifierPtr securifier,
    const DeleteFunctor &cb) {
  if (fvr.return_code == 0)
    DeletePacketImpl(key, fvr.values, securifier, cb);
}

void NetworkStoreManager::DeletePacketCallback(
  int result,
  int index,
  std::shared_ptr<std::vector<int>> delete_results,
  std::shared_ptr<boost::mutex> mutex) {
  boost::mutex::scoped_lock lock(*mutex.get());
  delete_results->at(index) = (result == dht::transport::kSuccess);
}

void NetworkStoreManager::UpdatePacket(
    const std::string &packet_name,
    const std::string &old_value,
    const std::string &new_value,
    passport::PacketType system_packet_type,
    DirType dir_type,
    const std::string &msid,
    const dht::kademlia::UpdateFunctor &cb) {
  dht::kademlia::Key key(packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  maidsafe::lifestuff::ClientUtils client_utils(session_singleton_);
  client_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid,
                                      &key_id, &public_key,
                                      &public_key_signature, &private_key);
  boost::posix_time::seconds ttl(boost::posix_time::pos_infin);
  dht::kademlia::SecurifierPtr securifier;
  securifier.reset(new dht::Securifier(key_id, public_key, private_key));
  node_->Update(key, new_value, "", old_value, "", ttl, securifier, cb);
}

}  // namespace lifestuff

}  // namespace maidsafe
