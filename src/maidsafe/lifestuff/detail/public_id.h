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
#include "boost/signals2/signal.hpp"

#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#include "maidsafe/passport/passport_config.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/detail/contacts.h"
#include "maidsafe/lifestuff/detail/session.h"
#include "maidsafe/lifestuff/detail/utils.h"

namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;

namespace maidsafe {

namespace priv {
namespace chunk_actions { class SignedData; }
}  // namespace priv

namespace passport { class Passport; }

namespace lifestuff {

enum IntroductionType {
  kFriendRequest,
  kFriendResponse,
  kDefriend,
  kMovedInbox,
  kFixAsync,
  kLifestuffCardChanged
};

namespace test { class PublicIdTest; }

class Session;
class Introduction;

class PublicId {
 public:
  typedef bs2::signal<void(const NonEmptyString&,  // NOLINT (Fraser)
                           const NonEmptyString&,
                           const std::string&,
                           const NonEmptyString&)> NewContactSignal;

  typedef bs2::signal<void(const NonEmptyString&,  // NOLINT (Fraser)
                           const NonEmptyString&,
                           const NonEmptyString&)> ContactConfirmedSignal;

  typedef bs2::signal<void(const NonEmptyString&,  // NOLINT (Alison)
                           const NonEmptyString&,
                           const std::string&,
                           const NonEmptyString&)> ContactDeletionReceivedSignal;

  typedef bs2::signal<void(const NonEmptyString&,  // NOLINT (Alison)
                           const NonEmptyString&,
                           const std::string&,
                           const NonEmptyString&)> ContactDeletionProcessedSignal;

  typedef bs2::signal<void(const NonEmptyString&,  // NOLINT (Dan)
                           const NonEmptyString&,
                           const NonEmptyString&)> LifestuffCardUpdatedSignal;

  PublicId(priv::chunk_store::RemoteChunkStore& remote_chunk_store,
           Session& session,
           boost::asio::io_service& asio_service);
  ~PublicId();

  // Periodically retrieves saved MCIDs from MPID and fires new_contact_signal_
  // for each valid MCID retrieved.  After the signal is fired, the MCID(s) are
  // deleted from the network.  Checking will only succeed if at least one
  // public username has been successfully created.
  void StartUp(const bptime::seconds& interval);
  void ShutDown();
  int StartCheckingForNewContacts(const bptime::seconds& interval);
  void StopCheckingForNewContacts();

  // Creates and stores to the network a new MSID, MPID, ANMPID and MMID.
  int CreatePublicId(const NonEmptyString& own_public_id, bool accepts_new_contacts);

  // Appends our info as an MCID to the recipient's MPID packet.
  int AddContact(const NonEmptyString& own_public_id,
                 const NonEmptyString& recipient_public_id,
                 const std::string& message);

  // Disallow/allow others add contact or send messages
  int DisablePublicId(const NonEmptyString& own_public_id);
  int EnablePublicId(const NonEmptyString& own_public_id);
  int DeletePublicId(const NonEmptyString& own_public_id);

  // To confirm/reject a contact once user has decided on the introduction
  int ConfirmContact(const NonEmptyString& own_public_id,
                     const NonEmptyString& recipient_public_id);
  int RejectContact(const NonEmptyString& own_public_id, const NonEmptyString& recipient_public_id);

  // Remove a contact from current contact list, and inform other contacts the new MMID
  int RemoveContact(const NonEmptyString& own_public_id,
                    const NonEmptyString& recipient_public_id,
                    const std::string& message,
                    const NonEmptyString& timestamp,
                    const bool& instigator);

  // Lifestuff Card
  int GetLifestuffCard(const NonEmptyString& my_public_id,
                       const std::string& contact_public_id,
                       SocialInfoMap& social_info);
  int SetLifestuffCard(const NonEmptyString& my_public_id, const SocialInfoMap& social_info);

  // Signals
  bs2::connection ConnectToNewContactSignal(const NewContactFunction& new_contact_slot);
  bs2::connection ConnectToContactConfirmedSignal(
      const ContactConfirmationFunction& contact_confirmation_slot);
  bs2::connection ConnectToContactDeletionReceivedSignal(
      const ContactDeletionReceivedFunction& contact_deletion_received_slot);
  bs2::connection ConnectToContactDeletionProcessedSignal(
      const ContactDeletionFunction& contact_deletion_slot);
  bs2::connection ConnectToLifestuffCardUpdatedSignal(
      const LifestuffCardUpdateFunction& lifestuff_card_update_slot);

 private:
  PublicId(const PublicId&);
  PublicId& operator=(const PublicId&);

  friend class test::PublicIdTest;

  int ProcessPublicIdPacketsStore(const NonEmptyString& public_id, bool accepts_new_contacts);
  void StoreInbox(const NonEmptyString& public_id, OperationResults& results);
  void StoreMpidPath(const NonEmptyString& public_id,
                     OperationResults& results,
                     bool accepts_new_contacts);
  void StoreMpid(bool result,
                 OperationResults& results,
                 const NonEmptyString& public_id,
                 bool accepts_new_contacts);
  void StoreMcid(bool result,
                 OperationResults& results,
                 const NonEmptyString& public_id,
                 bool accepts_new_contacts);

  void DeleteLifestuffCard(const NonEmptyString& public_id);
  int ProcessPublicIdPacketsDelete(const NonEmptyString& public_id);
  void DeleteInbox(const NonEmptyString& public_id, OperationResults& results);
  void DeleteMpidPath(const NonEmptyString& public_id, OperationResults& results);
  void DeleteMpid(bool response, OperationResults& results, const NonEmptyString& public_id);
  void DeleteAnmpid(bool response, OperationResults& results, const NonEmptyString& public_id);

  int CheckContactAndMoveInbox(const NonEmptyString& own_public_id,
                               const NonEmptyString& contact_public_id,
                               ContactsHandlerPtr& contacts_handler);
  int StoreNewInbox(const NonEmptyString& own_public_id);
  int BlockOldInbox(const NonEmptyString& own_public_id);
  int SendInformationMessages(const ContactsHandlerPtr& contacts_handler,
                              const Contact& deleted_contact,
                              const Identity& old_inbox_identity,
                              const NonEmptyString& own_public_id,
                              const NonEmptyString& contact_public_id,
                              const std::string& removal_message,
                              const NonEmptyString& timestamp,
                              const bool& instigator);

  void GetNewContacts(const bptime::seconds& interval, const boost::system::error_code& error_code);
  void GetContactsHandle();
  void ProcessRequests(const NonEmptyString& own_public_id,
                       const NonEmptyString& retrieved_mpid_packet,
                       const Fob& mpid);
  void HandleAppendix(const priv::chunk_actions::SignedData& signed_data,
                      const NonEmptyString& own_public_id,
                      const Fob& mpid);
  void ProcessIntroduction(Contact& contact,
                           const ContactsHandlerPtr& contacts_handler,
                           const NonEmptyString& own_public_id,
                           const Introduction& introduction,
                           const priv::chunk_actions::SignedData& signed_data,
                           int have_contact);
  void ProccessFriendRequest(Contact& contact,
                             const ContactsHandlerPtr& contacts_handler,
                             const NonEmptyString& own_public_id,
                             const Introduction& introduction,
                             const priv::chunk_actions::SignedData& signed_data,
                             int have_contact);
  void ProccessFriendResponse(Contact& contact,
                              const ContactsHandlerPtr& contacts_handler,
                              const NonEmptyString& own_public_id,
                              const Introduction& introduction,
                              int have_contact);
  void ProcessDefriending(const NonEmptyString& own_public_id,
                          const Introduction& introduction);
  void ProcessContactConfirmation(Contact& contact,
                                  const ContactsHandlerPtr contacts_handler,
                                  const NonEmptyString& own_public_id,
                                  const Introduction& introduction);
  void ProcessContactMoveInbox(Contact& contact,
                               const ContactsHandlerPtr contacts_handler,
                               const Identity& inbox_name,
                               const Identity& pointer_to_info,
                               const Introduction& introduction,
                               int have_contact);
  void ProcessFixAsync(Contact& contact,
                       const ContactsHandlerPtr& contacts_handler,
                       const NonEmptyString& own_public_id,
                       const Introduction& introduction,
                       int have_contact);
  void ProcessLifestuffCardChanged(Contact& contact,
                                   const NonEmptyString& own_public_id,
                                   const Introduction& introduction,
                                   int have_contact);
  void ProcessNewContact(Contact& contact,
                         const ContactsHandlerPtr contacts_handler,
                         const NonEmptyString& own_public_id,
                         const Introduction& introduction,
                         const priv::chunk_actions::SignedData& singed_introduction);
  int ProcessRequestWhenExpectingResponse(Contact& contact,
                                          const ContactsHandlerPtr contacts_handler,
                                          const NonEmptyString& own_public_id,
                                          const Introduction& introduction);
  void ProcessMisplacedContactRequest(Contact& contact, const NonEmptyString& own_public_id);
  void ProcessNewLifestuffCardInformation(const Identity& card_address,
                                          const NonEmptyString& own_public_id,
                                          const NonEmptyString& contact_public_id,
                                          const NonEmptyString& timestamp);

  // Modify the Appendability of MCID and MMID associated with the public_id
  // i.e. enable/disable others add new contact and send msg
  int ModifyAppendability(const NonEmptyString& own_public_id, const bool appendability);
  // Notify each contact in the list about the contact_info
  int InformContactInfo(const NonEmptyString& own_public_id,
                        const std::vector<Contact>& contacts,
                        const std::string& message,
                        const IntroductionType& type,
                        const std::string& inbox_name = "");
  int GetPublicKey(const Identity& packet_name, Contact& contact, int type);

  int StoreLifestuffCard(const NonEmptyString& public_id, Identity& lifestuff_card_address);
  int RemoveLifestuffCard(const Identity& lifestuff_card_address, const Fob& mmid);
  Identity GetOwnCardAddress(const NonEmptyString& my_public_id);
  Identity GetContactCardAddress(const NonEmptyString& my_public_id,
                                 const NonEmptyString& contact_public_id);
  int RetrieveLifestuffCard(const Identity& lifestuff_card_address, SocialInfoMap& social_info);

  priv::chunk_store::RemoteChunkStore& remote_chunk_store_;
  Session& session_;
  passport::Passport& passport_;
  boost::asio::deadline_timer get_new_contacts_timer_;
  bool get_new_contacts_timer_active_;
  NewContactSignal new_contact_signal_;
  ContactConfirmedSignal contact_confirmed_signal_;
  ContactDeletionReceivedSignal contact_deletion_received_signal_;
  ContactDeletionProcessedSignal contact_deletion_processed_signal_;
  LifestuffCardUpdatedSignal lifestuff_card_updated_signal_;
  boost::asio::io_service& asio_service_;
};

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DETAIL_PUBLIC_ID_H_
