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

int ConnectSignals(maidsafe::lifestuff::LifeStuff& lifestuff) {
  return lifestuff.ConnectToSignals(ChatFunction(),
                                    FileTransferSuccessFunction(),
                                    FileTransferFailureFunction(),
                                    NewContactFunction(),
                                    ContactConfirmationFunction(),
                                    ContactProfilePictureFunction(),
                                    [&] (const NonEmptyString& /*own_public_id*/,
                                         const NonEmptyString& /*contact_public_id*/,
                                         const NonEmptyString& /*timestamp*/,
                                         ContactPresence /*cp*/) {},
                                    ContactDeletionFunction(),
                                    LifestuffCardUpdateFunction(),
                                    NetworkHealthFunction(),
                                    ImmediateQuitRequiredFunction());
}

void PrintMenu() {
  printf("\n");
  printf("Options: \n");
  printf("1. Quit\n");
  printf("2. Create user\n");
  printf("3. Log in\n");
  printf("4. Mount drive\n");
  printf("5. Unmount drive\n");
  printf("6. Log out\n");
  printf("Choice: ");
}

bool ReadAndValidateInput(int& option) {
  option = -1;
  std::cin >> option;
  if (option > 6 || option  < 0)
    return false;
  return true;
}

void ReadAndParseCredentials(std::vector<maidsafe::NonEmptyString>& creds) {
  printf("Please give keyword, pin & password (keyword,pin,password): ");
  std::string input;
  std::cin >> input;
  boost::regex re(",");
  boost::sregex_token_iterator it(input.begin(), input.end(), re, -1), end;
  while (it != end)
    creds.push_back(maidsafe::NonEmptyString(*it++));

#ifndef NDEBUG
  for (auto& s : creds)
    printf("%s\n", s.string().c_str());
#endif
}

int DoCreateUser(maidsafe::lifestuff::LifeStuff& lifestuff) {
  std::vector<maidsafe::NonEmptyString> creds;
  ReadAndParseCredentials(creds);
  if (creds.size() != 3U) {
    printf("Credentials size inadequate: %d", creds.size());
    return -1;
  }

  return lifestuff.CreateUser(creds[0], creds[1], creds[2]);
}

int DoLogin(maidsafe::lifestuff::LifeStuff& lifestuff) {
  std::vector<maidsafe::NonEmptyString> creds;
  ReadAndParseCredentials(creds);
  if (creds.size() != 3U) {
    printf("Credentials size inadequate: %d", creds.size());
    return -1;
  }

  return lifestuff.LogIn(creds[0], creds[1], creds[2]);
}

int DoLogout(maidsafe::lifestuff::LifeStuff& lifestuff) {
  return lifestuff.LogOut();
}

int DoMount(maidsafe::lifestuff::LifeStuff& lifestuff) {
  return lifestuff.MountDrive();
}

int DoUnmont(maidsafe::lifestuff::LifeStuff& lifestuff) {
  return lifestuff.UnMountDrive();
}

int HandleChoice(const int& option, maidsafe::lifestuff::LifeStuff& lifestuff) {
  switch (option) {
    case 1: return 1;  // quit
    case 2: return DoCreateUser(lifestuff);
    case 3: return DoLogin(lifestuff);
    case 4: return DoMount(lifestuff);
    case 5: return DoUnmont(lifestuff);
    case 6: return DoLogout(lifestuff);
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

  maidsafe::lifestuff::LifeStuff lifestuff;
  int result(lifestuff.Initialise([] (maidsafe::NonEmptyString) {}, fs::path(), false));
  if (result != maidsafe::lifestuff::kSuccess) {
    printf("Lifestuff failed to initialise: %d\n", result);
    return -1;
  }

  result = maidsafe::lifestuff::ConnectSignals(lifestuff);
  if (result != maidsafe::lifestuff::kSuccess) {
    printf("Lifestuff failed to connect signals: %d\n", result);
    return -1;
  }

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

  return 0;
}

