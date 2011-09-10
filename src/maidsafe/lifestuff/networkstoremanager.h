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

#ifndef MAIDSAFE_LIFESTUFF_NETWORKSTOREMANAGER_H_
#define MAIDSAFE_LIFESTUFF_NETWORKSTOREMANAGER_H_

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "boost/asio/ip/address.hpp"
#include "boost/asio/io_service.hpp"

#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/kademlia/node_id.h"

#include "maidsafe/lifestuff/packet_manager.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace dht {

class Securifier;

namespace kademlia {
class Contact;
class Node;
}  // namespace kademlia

}  // namespace dht

namespace lifestuff {

typedef std::function<void(std::shared_ptr<std::vector<int>>)> DeleteFunctor;  // NOLINT (Dan)
class SessionSingleton;
struct FindValueParameters;

class NetworkStoreManager : public PacketManager {
 public:
  NetworkStoreManager(
      const std::vector<dht::kademlia::Contact> &bootstrap_contacts,
      const boost::uint16_t &k,
      const boost::uint16_t &alpha,
      const boost::uint16_t beta,
      const bptime::seconds &mean_refresh_interval,
      std::shared_ptr<SessionSingleton> ss);

  virtual void Init(const dht::kademlia::JoinFunctor callback,
                    const boost::uint16_t &port);

  int Close(bool cancel_pending_ops);

  virtual bool KeyUnique(const std::string &key, bool check_local);
  virtual void KeyUnique(const std::string &key,
                         bool check_local,
                         const VoidFuncOneInt &cb);

  virtual int GetPacket(const std::string &packet_name,
                        std::vector<std::string> *results);
  virtual void GetPacket(const std::string &packet_name,
                         const GetPacketFunctor &cb);

  virtual void StorePacket(const std::string &packet_name,
                           const std::string &value,
                           passport::PacketType system_packet_type,
                           DirType dir_type,
                           const std::string &msid,
                           const VoidFuncOneInt &cb);

  virtual void DeletePacket(const std::string &packet_name,
                            const std::vector<std::string> values,
                            passport::PacketType system_packet_type,
                            DirType dir_type,
                            const std::string &msid,
                            const VoidFuncOneInt &cb);

  virtual void UpdatePacket(const std::string &packet_name,
                            const std::string &old_value,
                            const std::string &new_value,
                            passport::PacketType system_packet_type,
                            DirType dir_type,
                            const std::string &msid,
                            const VoidFuncOneInt &cb);

 private:
  void DeletePacketImpl(const dht::kademlia::Key &key,
                        const std::vector<std::string> values,
                        dht::kademlia::SecurifierPtr securifier,
                        const VoidFuncOneInt &cb);

  void DeletePacketCallback(int result,
                            int index,
                            std::shared_ptr<std::vector<int>> delete_results,
                            std::shared_ptr<boost::mutex> mutex);

  void FindValueCallback(dht::kademlia::FindValueReturns fvr,
                         FindValueParameters parameters);

  void PopulateValues(const dht::kademlia::Key &key,
                      const dht::kademlia::SecurifierPtr securifier,
                      const VoidFuncOneInt &cb);

  void KeyUniqueBlockCallback(int result,
                              boost::mutex *mutex,
                              boost::condition_variable *cv,
                              int *expected_result);

  void GetPacketBlockCallback(const std::vector<std::string> &values,
                              int result,
                              boost::mutex *mutex,
                              boost::condition_variable *cv,
                              int *expected_result,
                              std::vector<std::string> *expected_values);

  std::vector<dht::kademlia::Contact> bootstrap_contacts_;
  boost::uint16_t k_;
  boost::uint16_t alpha_;
  boost::uint16_t beta_;
  boost::asio::io_service &asio_service_;
  std::shared_ptr<boost::asio::io_service::work> work_;
  std::shared_ptr<dht::Securifier> securifier_;
  std::shared_ptr<dht::kademlia::Node> node_;
  dht::kademlia::NodeId node_id_;
  bptime::seconds mean_refresh_interval_;
  std::vector<bool> delete_results_;
  std::shared_ptr<SessionSingleton> session_singleton_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_NETWORKSTOREMANAGER_H_
