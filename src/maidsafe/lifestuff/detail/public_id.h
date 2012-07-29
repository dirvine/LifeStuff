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

#ifndef MAIDSAFE_LIFESTUFF_DETAIL_PUBLIC_ID_H_
#define MAIDSAFE_LIFESTUFF_DETAIL_PUBLIC_ID_H_


#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/signals2.hpp"

#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#include "maidsafe/passport/passport_config.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/session.h"

namespace ba = boost::asio;
namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace pcs = maidsafe::priv::chunk_store;

namespace maidsafe {

namespace passport {
class Passport;
}  // namespace passport

namespace lifestuff {

class Session;
class Introduction;

class PublicId {
 public:
  typedef bs2::signal<void(const std::string&,  // NOLINT (Fraser)
                           const std::string&,
                           const std::string&,
                           const std::string&)> NewContactSignal;
  typedef std::shared_ptr<NewContactSignal> NewContactSignalPtr;
  typedef bs2::signal<void(const std::string&,  // NOLINT (Fraser)
                           const std::string&,
                           const std::string&)> ContactConfirmedSignal;  // NOLINT (Dan)
  typedef std::shared_ptr<ContactConfirmedSignal> ContactConfirmedSignalPtr;

  PublicId(std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store,
           Session& session,
           ba::io_service &asio_service);
  ~PublicId();

  // Periodically retrieves saved MCIDs from MPID and fires new_contact_signal_
  // for each valid MCID retrieved.  After the signal is fired, the MCID(s) are
  // deleted from the network.  Checking will only succeed if at least one
  // public username has been successfully created.
  void StartUp(const bptime::seconds &interval);
  void ShutDown();
  int StartCheckingForNewContacts(const bptime::seconds &interval);
  void StopCheckingForNewContacts();

  // Creates and stores to the network a new MSID, MPID, ANMPID and MMID.
  int CreatePublicId(const std::string &public_id, bool accepts_new_contacts);

  // Appends our info as an MCID to the recipient's MPID packet.
  int AddContact(const std::string& own_public_id, const std::string& recipient_public_id,
                 const std::string& message);

  // Disallow/allow others add contact or send messages
  int DisablePublicId(const std::string &public_id);
  int EnablePublicId(const std::string &public_id);
  int DeletePublicId(const std::string &public_id);

  // To confirm/reject a contact once user has decided on the introduction
  int ConfirmContact(const std::string &own_public_id, const std::string &recipient_public_id);
  int RejectContact(const std::string &own_public_id, const std::string &recipient_public_id);

  // Remove a contact from current contact list, and inform other contacts the new MMID
  void RemoveContactHandle(const std::string &public_id, const std::string &contact_name);
  int RemoveContact(const std::string &public_id, const std::string &contact_name);


  // Signals
  bs2::connection ConnectToNewContactSignal(const NewContactFunction &new_contact_slot);
  bs2::connection ConnectToContactConfirmedSignal(
      const ContactConfirmationFunction &contact_confirmation_slot);

  // Lists
  std::map<std::string, ContactStatus> ContactList(const std::string &public_id,
                                                   ContactOrder type = kLastContacted,
                                                   uint16_t bitwise_status = kConfirmed) const;

 private:
  PublicId(const PublicId&);
  PublicId& operator=(const PublicId&);

  void GetNewContacts(const bptime::seconds &interval, const boost::system::error_code &error_code);
  void GetContactsHandle();
  void ProcessRequests(const std::string &mpid_name,
                       const std::string &retrieved_mpid_packet,
                       std::shared_ptr<asymm::Keys> mpid);
  void ProcessContactConfirmation(Contact& contact,
                                  const ContactsHandlerPtr contacts_handler,
                                  const std::string& own_public_id,
                                  const Introduction& introduction,
                                  Session& session);
  void ProcessContactMoveInbox(Contact& contact,
                               const ContactsHandlerPtr contacts_handler,
                               const std::string& inbox_name,
                               Session& session);
  void ProcessNewContact(Contact& contact,
                         const ContactsHandlerPtr contacts_handler,
                         const std::string& own_public_id,
                         const Introduction& introduction,
                         Session& session);
  void ProcessMisplacedContactRequest(Contact& contact, const std::string& own_public_id);
  // Modify the Appendability of MCID and MMID associated with the public_id
  // i.e. enable/disable others add new contact and send msg
  int ModifyAppendability(const std::string &public_id, const char appendability);
  // Notify each contact in the list about the contact_info
  int InformContactInfo(const std::string& public_id, const std::vector<Contact>& contacts,
                        const std::string& message);
  int GetPublicKey(const std::string& packet_name, Contact& contact, int type);

  std::shared_ptr<pcs::RemoteChunkStore> remote_chunk_store_;
  Session& session_;
  passport::Passport& passport_;
  ba::deadline_timer get_new_contacts_timer_;
  bool get_new_contacts_timer_active_;
  NewContactSignalPtr new_contact_signal_;
  ContactConfirmedSignalPtr contact_confirmed_signal_;
  boost::asio::io_service &asio_service_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_PUBLIC_ID_H_
