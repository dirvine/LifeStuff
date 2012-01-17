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

#ifndef MAIDSAFE_LIFESTUFF_PUBLIC_ID_H_
#define MAIDSAFE_LIFESTUFF_PUBLIC_ID_H_


#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/signals2.hpp"

#include "maidsafe/passport/passport_config.h"

#include "maidsafe/lifestuff/version.h"

#if MAIDSAFE_LIFESTUFF_VERSION != 111
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-lifestuff library.
#endif

namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;

namespace maidsafe {

namespace lifestuff {

class PacketManager;
class Session;

class PublicId {
 public:
  typedef bs2::signal<void(const std::string&,  // NOLINT (Fraser)
                           const std::string&)> NewContactSignal;
  typedef std::shared_ptr<NewContactSignal> NewContactSignalPtr;
  typedef bs2::signal<void(const std::string&)> ContactConfirmedSignal;  // NOLINT (Dan)
  typedef std::shared_ptr<ContactConfirmedSignal> ContactConfirmedSignalPtr;
  PublicId(std::shared_ptr<PacketManager> packet_manager,
           std::shared_ptr<Session> session,
           ba::io_service &asio_service);  // NOLINT (Fraser)
  ~PublicId();

  // Periodically retrieves saved MCIDs from MPID and fires new_contact_signal_
  // for each valid MCID retrieved.  After the signal is fired, the MCID(s) are
  // deleted from the network.  Checking will only succeed if at least one
  // public username has been successfully created.
  int StartCheckingForNewContacts(boost::posix_time::seconds interval);
  void StopCheckingForNewContacts();

  // Creates and stores to the network a new MSID, MPID, ANMPID and MMID.
  int CreatePublicId(const std::string &public_username,
                     bool accepts_new_contacts);
  // Appends our info as an MCID to the recipient's MPID packet.
  int SendContactInfo(const std::string &public_username,
                      const std::string &recipient_public_username,
                      bool add_contact = true);
  // Disallow others add contact or send msg.
  int DisablePublicId(const std::string &public_username);
  // Allow others add contact or send msg.
  int EnablePublicId(const std::string &public_username);
  // To confirm a contact once user has decided on the introduction
  int ConfirmContact(const std::string &public_username,
                     const std::string &recipient_public_username);
  // Remove a contact from current contact list, and inform other contacts the
  // new MMID
  int RemoveContact(const std::string &public_username,
                    const std::string &contact_name);

  NewContactSignalPtr new_contact_signal() const;
  ContactConfirmedSignalPtr contact_confirmed_signal() const;

  std::vector<std::string> ContactList(
      const std::string &public_username) const;
  std::vector<std::string> PublicIdsList() const;

 private:
  PublicId(const PublicId&);
  PublicId& operator=(const PublicId&);
  void GetNewContacts(const bptime::seconds &interval,
                      const boost::system::error_code &error_code);
  void ProcessRequests(const passport::SelectableIdData &data,
                       const std::vector<std::string> &mpid_values);
  // Modify the Appendability of MCID and MMID associated with the public_name
  // i.e. enable/disable others add new contact and send msg
  int ModifyAppendability(const std::string &public_username,
                          const char appendability);
  // Notify each contact in the list about the contact_info
  int InformContactInfo(const std::string &public_username,
                        const std::vector<std::string> &contacts);
  // Universal blocking function for waiting response
  int WaitingResponse(boost::mutex &mutex,
                      boost::condition_variable &cond_var,
                      std::vector<int> &results);

  std::shared_ptr<PacketManager> packet_manager_;
  std::shared_ptr<Session> session_;
  ba::io_service &asio_service_;
  ba::deadline_timer get_new_contacts_timer_;
  NewContactSignalPtr new_contact_signal_;
  ContactConfirmedSignalPtr contact_confirmed_signal_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_PUBLIC_ID_H_
