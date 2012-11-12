/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#include <iostream>  // NOLINT (Dan)
#include <cstdio>

#include "boost/regex.hpp"

#include "maidsafe/common/log.h"

#include "maidsafe/lifestuff/lifestuff.h"
#include "maidsafe/lifestuff/lifestuff_api.h"
#include "maidsafe/lifestuff/return_codes.h"

namespace maidsafe {

namespace lifestuff {

struct ChatMessage {
  ChatMessage() : own_id(), other_id(), message(), timestamp() {}
  ChatMessage(const NonEmptyString& own,
              const NonEmptyString& other,
              const NonEmptyString& msg,
              const NonEmptyString& stamp)
    : own_id(own), other_id(other), message(msg), timestamp(stamp) {}
  NonEmptyString own_id;
  NonEmptyString other_id;
  NonEmptyString message;
  NonEmptyString timestamp;
};

std::mutex g_messages_mutex;
std::vector<ChatMessage> g_messages;

void ConnectSignals(Slots& slot_functions) {
  slot_functions.chat_slot = [] (const NonEmptyString& own_id,
                                 const NonEmptyString& other_id,
                                 const NonEmptyString& message,
                                 const NonEmptyString& timestamp) {
                               std::lock_guard<std::mutex> lock(g_messages_mutex);
                               g_messages.push_back(ChatMessage(own_id, other_id, message,
                                                                timestamp));
                             };
  slot_functions.file_success_slot = [] (const NonEmptyString&,
                                         const NonEmptyString&,
                                         const NonEmptyString&,
                                         const NonEmptyString&,
                                         const NonEmptyString&) {
                                     };
  slot_functions.file_failure_slot = [] (const NonEmptyString&,
                                         const NonEmptyString&,
                                         const NonEmptyString&) {
                                     };
  slot_functions.new_contact_slot = [&/*lifestuff*/] (const NonEmptyString&,
                                                      const NonEmptyString&,
                                                      const std::string&,
                                                      const NonEmptyString&) {
//                                      int result(lifestuff.ConfirmContact(own_id, other_id));
//                                      printf("%s confirming %s result: %d\n",
//                                             own_id.string().c_str(),
//                                             other_id.string().c_str(),
//                                             result);
                                    };
  slot_functions.confirmed_contact_slot = [&] (const NonEmptyString& own_id,
                                               const NonEmptyString& other_id,
                                               const NonEmptyString&) {
                                            printf("%s confirmed %s\n",
                                                   own_id.string().c_str(),
                                                   other_id.string().c_str());
                                          };
  slot_functions.profile_picture_slot = [] (const NonEmptyString&,
                                            const NonEmptyString&,
                                            const NonEmptyString&) {
                                        };
  slot_functions.contact_presence_slot = [] (const NonEmptyString&,
                                             const NonEmptyString&,
                                             const NonEmptyString&,
                                             ContactPresence) {
                                         };
  slot_functions.contact_deletion_slot =  [] (const NonEmptyString&,
                                              const NonEmptyString&,
                                              const std::string&,
                                              const NonEmptyString&) {
                                          };
  slot_functions.lifestuff_card_update_slot = [] (const NonEmptyString&,
                                                  const NonEmptyString&,
                                                  const NonEmptyString&) {
                                              };
  slot_functions.network_health_slot = [] (const int&) {};  // NOLINT (Dan)
  slot_functions.immediate_quit_required_slot = [] () {};  // NOLINT (Dan)
  slot_functions.update_available_slot = [] (NonEmptyString) {};  // NOLINT (Dan)
  slot_functions.operation_progress_slot = [] (Operation, SubTask) {};  // NOLINT (Dan)
}

void PrintMenu() {
  printf("\n");
  printf("Options: \n");
  printf("1. Quit\n");
  printf("2. Create user\n");
  printf("3. Log in\n");
  printf("4. Mount drive\n");
  printf("5. Unmount drive\n");
  printf("6. Create public id\n");
  printf("7. Add contact\n");
  printf("8. Get messages\n");
  printf("Choice: ");
}

bool ReadAndValidateInput(int& option) {
  option = -1;
  std::cin >> option;
  if (option > 7 || option  < 1)
    return false;
  return true;
}

void ReadAndParseCredentials(std::vector<NonEmptyString>& creds) {
  printf("Please give keyword, pin & password (keyword,pin,password): ");
  std::string input;
  std::cin >> input;
  boost::regex re(",");
  boost::sregex_token_iterator it(input.begin(), input.end(), re, -1), end;
  while (it != end)
    creds.push_back(NonEmptyString(*it++));

#ifndef NDEBUG
  for (auto& s : creds)
    printf("%s\n", s.string().c_str());
#endif
}

int DoCreateUser(LifeStuff& lifestuff) {
  std::vector<NonEmptyString> creds;
  ReadAndParseCredentials(creds);
  if (creds.size() != 3U) {
    printf("Credentials size inadequate: %d", creds.size());
    return -1;
  }

  return lifestuff.CreateUser(creds[0], creds[1], creds[2]);
}

int DoLogin(LifeStuff& lifestuff) {
  std::vector<NonEmptyString> creds;
  ReadAndParseCredentials(creds);
  if (creds.size() != 3U) {
    printf("Credentials size inadequate: %d", creds.size());
    return -1;
  }

  return lifestuff.LogIn(creds[0], creds[1], creds[2]);
}

int DoLogout(LifeStuff& lifestuff) {
  if (lifestuff.state() == kLoggedIn) {
    int result(lifestuff.LogOut());
    return result == kSuccess ? 1 : result;
  } else {
    return 1;
  }
}

int DoMount(LifeStuff& lifestuff) {
  return lifestuff.MountDrive();
}

int DoUnmont(LifeStuff& lifestuff) {
  return lifestuff.UnMountDrive();
}

int DoCreatePublicId(LifeStuff& lifestuff) {
  printf("Please give a public id: ");
  std::string public_id;
  std::cin >> public_id;
  return lifestuff.CreatePublicId(NonEmptyString(public_id));
}

int DoAddContact(LifeStuff& lifestuff) {
  printf("Please give your public id, contact public id, and message(own_id,other_id): ");
  std::string input;
  std::cin >> input;
  boost::regex re(",");
  boost::sregex_token_iterator it(input.begin(), input.end(), re, -1), end;
  std::vector<NonEmptyString> ids;
  while (it != end)
    ids.push_back(NonEmptyString(*it++));
  if (ids.size() != 2U) {
    printf("Id size inadequate: %d", ids.size());
    return -1;
  }
  return lifestuff.AddContact(ids.at(0), ids.at(1), "Let's be friends.");
}

int DoGetMessages() {
  std::lock_guard<std::mutex> lock(g_messages_mutex);
  for (auto& message : g_messages) {
    printf("%s says(%s): %s\n",
           message.other_id.string().c_str(),
           message.timestamp.string().c_str(),
           message.message.string().c_str());
  }
  g_messages.clear();
  return kSuccess;
}

int HandleChoice(const int& option, LifeStuff& lifestuff) {
  switch (option) {
    case 1: return DoLogout(lifestuff);  // quit
    case 2: return DoCreateUser(lifestuff);
    case 3: return DoLogin(lifestuff);
    case 4: return DoMount(lifestuff);
    case 5: return DoUnmont(lifestuff);
    case 6: return DoCreatePublicId(lifestuff);
    case 7: return DoAddContact(lifestuff);
    case 8: return DoGetMessages();
    default: return -1;
  }
}

}  // namespace lifestuff

}  // namespace maidsafe

int main(int argc, char* argv[]) {
  maidsafe::log::Logging::Instance().Initialise(argc, argv);

  printf("---------------------------------\n");
  printf("-- Lifestuff command line tool --\n");
  printf("---------------------------------\n");
  printf("Initilising, please wait...\n");

  maidsafe::lifestuff::Slots slot_functions;
  maidsafe::lifestuff::ConnectSignals(slot_functions);
  maidsafe::lifestuff::LifeStuff lifestuff(slot_functions, fs::path());

  int option(-1), operation_result;
  do {
    // Print menu
    maidsafe::lifestuff::PrintMenu();
    // Read input
    if (maidsafe::lifestuff::ReadAndValidateInput(option)) {
      // Handle choice
      operation_result = maidsafe::lifestuff::HandleChoice(option, lifestuff);
      printf("Operation result: %d\n", operation_result);
    }
  } while (option != 1);

//  lifestuff.Finalise();

  return 0;
}

