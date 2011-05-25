/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Version:      1.0
* Created:      2011-04-22
* Author:       Team
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

#include "maidsafe/lifestuff/client/tests/demo/commands.h"

#include <string>
#include <iostream>  //NOLINT
#include <stdio.h>
#include <termios.h>
#include <unistd.h>

#include "boost/format.hpp"
#include "boost/thread.hpp"
#include "boost/tokenizer.hpp"

#include "maidsafe/common/utils.h"
#include "maidsafe/lifestuff/shared/returncodes.h"

namespace maidsafe {

namespace lifestuff {

namespace commandline_demo {

Commands::Commands(UserCredentialPtr user_credential)
    : result_arrived_(false),
      finish_(false),
      user_credential_(user_credential),
      username_(),
      pin_(),
      logged_in_(false) {}

void Commands::Run() {
  if (!LoginUser())
    return;
  bool wait = false;
  while (!finish_) {
    std::cout << "lifestuff > ";
    std::string cmdline;
    std::getline(std::cin, cmdline);
    ProcessCommand(cmdline, &wait);
    if (wait) {
      while (!result_arrived_)
        boost::this_thread::sleep(boost::posix_time::milliseconds(500));
      result_arrived_ = false;
    }
  }
}

int mygetch() {
  struct termios oldt, newt;
  int ch;
  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~(ICANON | ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  ch = getchar();
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  return ch;
}

std::string GetLineWithAsterisks() {
  std::vector<char> pword;
  char a;
  while ((a = mygetch()) != '\n' && a != '\r') {
    pword.push_back(a);
    std::string s(1, a);
    std::cout << '*';  // << "(" << EncodeToHex(s) << ")";
  }
  std::cout << std::endl;
  return std::string(pword.begin(), pword.end());
}

bool VerifyPinness(const std::string &pin) {
  try {
    boost::uint32_t numerical_pin = boost::lexical_cast<boost::uint32_t>(pin);
  }
  catch (const boost::bad_lexical_cast&) {
    return false;
  }
  return true;
}

bool Commands::LoginUser() {
  std::string username, pin, password;
  bool success(false);
  int no_of_attempts(0);
  std::string create_new("n");

  while (!success && (no_of_attempts < 5)) {
    std::cout << "Enter User Name: ";
    std::getline(std::cin, username);

    while (!VerifyPinness(pin)) {
      std::cout << "Enter PIN: ";
      pin = GetLineWithAsterisks();
    }

    int return_value = user_credential_->CheckUserExists(username, pin);

    // ValidateUser
    if (return_value == kUserExists) {
      std::cout << "Enter Password: ";
      password = GetLineWithAsterisks();
      success = user_credential_->ValidateUser(password);
      if (success)
        std::cout << " Logged in successfully." << std::endl;
      else
        std::cout << " Login failed!" << std::endl;

    // CreateUser
    } else if (return_value == kUserDoesntExist) {
      std::cout << "User doesn't exist! Do u want to create new (y/n): ";
      std::getline(std::cin, create_new);

      if (create_new == "y") {
        std::cout << std::endl << "Chose a password: ";
        password = GetLineWithAsterisks();

        success = user_credential_->CreateUser(username, pin, password);
        if (success) {
          std::cout << std::endl
                    << "Successfully created user and logged in" << std::endl;
        } else {
          std::cout << std::endl  << "Failed to create user" << std::endl;
        }
      } else if (create_new == "n") {
        std::cout << "Retry again .." << std::endl;
      } else {
        std::cout << "Behave !!!" << std::endl;
        // return false;
      }
    } else {
      std::cout << boost::format("User lookup failed with return value: <%1%>.")
                   % return_value << std::endl;
    }
    ++no_of_attempts;
  }
  if (success) {
    username_ = username;
    pin_ = pin;
    logged_in_ = true;
    PrintUsage();
  }
  return success;
}

void Commands::PrintUsage() {
  if (!logged_in_) {
    printf("\thelp                         Print help.\n");
    printf("\tlogin                        Login.\n");
    printf("\texit or 'q'                  Exit the application.\n");
  } else {
    printf("\thelp                         Print help.\n");
    printf("\tsavesession                  Save Session.\n");
    printf("\tchangeuname newname          Change username.\n");
    printf("\tchangepin newpin             Change pin.\n");
    printf("\tchangepwd newpasswd          Change password.\n");
    printf("\tlogout                       Logout.\n");
    printf("\tleave                        Leave Maidsafe Network.\n");
    printf("\texit  or 'q'                 Exit the application.\n");
  }
}

void Commands::ProcessCommand(const std::string &cmdline, bool *wait_for_cb) {
  std::string cmd;
  std::vector<std::string> args;
  try {
    boost::char_separator<char> sep(" ");
    boost::tokenizer< boost::char_separator<char> > tok(cmdline, sep);
    for (boost::tokenizer< boost::char_separator<char> >::iterator
         it = tok.begin(); it != tok.end(); ++it) {
      if (it == tok.begin())
        cmd = *it;
      else
        args.push_back(*it);
    }
  }
  catch(const std::exception &ex) {
    printf("Error processing command: %s\n", ex.what());
    return;
  }
  int return_value(-1);

  // Common Command options
  if (cmd == "help") {
    PrintUsage();
    return;

  } else if ((cmd == "exit") || (cmd == "q")) {
    return_value = user_credential_->SaveSession();
    if (return_value == kSuccess) {
      std::cout << "Saved Session successfully" << std::endl;
    } else {
      std::cout << boost::format("savesession returned <%1%>")
                 % return_value << std::endl;
    }
    printf("Exiting application...\n");
    finish_ = true;
    return;
  }

  // Before Login Command options
  if (!logged_in_) {
    if (cmd == "login") {
      LoginUser();
      return;

    } else {
      printf("Invalid command %s\n", cmd.c_str());
    }

  } else {  // After Login Command options
    if (cmd == "savesession") {
      return_value = user_credential_->SaveSession();
      if (return_value == kSuccess) {
        std::cout << "Saved Session successfully" << std::endl;
      } else {
        std::cout << boost::format("savesession returned <%1%>")
                   % return_value << std::endl;
      }

    } else if (cmd == "changeuname") {
      if (args.empty() || args.size() > 1) {
        std::cout << "Change username correct usage: changeuname new_uname"
                  << std::endl;
      } else {
        bool ret = user_credential_->ChangeUsername(args[0]);
        if (ret) {
          std::cout << "Changed user name successfully" << std::endl;
        } else {
          std::cout << "Change user name Failed" << std::endl;
        }
      }
    } else if (cmd == "changepin") {
      if (args.empty() || args.size() > 1) {
        std::cout << "Change pin correct usage: changepin new_pin" << std::endl;
      } else {
        bool ret = user_credential_->ChangePin(args[0]);
        if (ret) {
          std::cout << "Changed pin successfully" << std::endl;
        } else {
          std::cout << "Change pin Failed" << std::endl;
        }
      }
    } else if (cmd == "changepwd") {
      if (args.empty() || args.size() > 1) {
        std::cout << "Change password correct usage: changepwd new_password"
                  << std::endl;
      } else {
        bool ret = user_credential_->ChangePassword(args[0]);
        if (ret) {
          std::cout << "Changed password successfully" << std::endl;
        } else {
          std::cout << "Change password Failed" << std::endl;
        }
      }
    } else if (cmd == "logout") {
      bool ret = user_credential_->Logout();
      if (ret) {
        logged_in_ = false;
        std::cout << "Logged out Successfully" << std::endl;
        PrintUsage();
      } else {
        std::cout << "Log out Failed" << std::endl;
      }

    } else if (cmd == "leave") {
      bool ret = user_credential_->LeaveMaidsafeNetwork();
      if (ret) {
        std::cout << "Leave Maidsafe Network Successfull" << std::endl;
      } else {
        std::cout << "Leave Maidsafe Network failed" << std::endl;
      }
    } else {
      printf("Invalid command %s\n", cmd.c_str());
    }
  }
}

}  // namespace commandline_demo

}  // namespace lifestuff

}  // namespace maidsafe
