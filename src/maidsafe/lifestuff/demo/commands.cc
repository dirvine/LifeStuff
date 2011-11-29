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

#include "maidsafe/lifestuff/demo/commands.h"

#ifndef MAIDSAFE_WIN32
#include <termios.h>
#include <unistd.h>
#else
#include <conio.h>
#endif
#include <stdio.h>
#include <cstdlib>

#include <iostream>  // NOLINT (Dan)
#include <string>
#include <vector>

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif

#include "boost/format.hpp"
#include "boost/thread.hpp"
#include "boost/tokenizer.hpp"

#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff/return_codes.h"

namespace maidsafe {

namespace lifestuff {

namespace commandline_demo {

const int _MAX_TRY = 3;

Commands::Commands(SessionPtr session,
                   UserCredentialPtr user_credential)
    : result_arrived_(false),
      finish_(false),
      session_(session),
      user_credential_(user_credential),
      user_storage_(user_credential->client_chunk_store()),
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
        Sleep(boost::posix_time::milliseconds(500));
      result_arrived_ = false;
    }
  }
}

int mygetch() {
  int ch;
#ifdef MAIDSAFE_WIN32
  ch = _getch();
#else
  struct termios oldt, newt;
  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~(ICANON | ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  ch = getchar();
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
  return ch;
}

std::string GetLineWithAsterisks() {
  std::vector<char> pword;
  char a;
  while ((a = static_cast<char>(mygetch())) != '\n' && a != '\r') {
    pword.push_back(a);
    std::string s(1, a);
    std::cout << '*';  // << "(" << EncodeToHex(s) << ")";
  }
  std::cout << std::endl;
  return std::string(pword.begin(), pword.end());
}

bool VerifyPinness(const std::string &pin) {
  try {
    boost::lexical_cast<boost::uint32_t>(pin);
  }
  catch(const boost::bad_lexical_cast&) {
    return false;
  }
  return true;
}

bool Commands::LoginUser() {
  std::string username, pin, password, confirm;
  bool success(false);
  int no_of_attempts(0), count(0);
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
      if (success) {
        user_storage_.MountDrive(fs::initial_path() / "LifeStuff",
                                 user_credential_->SessionName(),
                                 session_,
                                 false);
        std::cout << " Logged in successfully." << std::endl;
      } else {
        std::cout << " Login failed!" << std::endl;
      }

    // CreateUser
    } else if (return_value == kUserDoesntExist) {
      std::cout << "User doesn't exist! Do u want to create new (y/n): ";
      std::getline(std::cin, create_new);

      if (create_new == "y") {
        do {
          std::cout << "Confirm pin: ";
          confirm = GetLineWithAsterisks();
          success = (pin.compare(confirm) == 0);
          if (!success)
            std::cout << "Pin confirmation mismatch" << std::endl;
        } while (!success &&  (++count < _MAX_TRY));

        count = 0;

        if (success) {
          do {
            std::cout << std::endl << "Choose a password: ";
            password = GetLineWithAsterisks();
            std::cout << "Confirm password: ";
            confirm = GetLineWithAsterisks();
            success = (password.compare(confirm) == 0);
            if (!success)
              std::cout << "Password confirmation mismatch." << std::endl;
          } while (!success &&  (++count < _MAX_TRY));
        }
        if (success) {
          success = user_credential_->CreateUser(username, pin, password);
        }
        if (success) {
          user_storage_.MountDrive(fs::initial_path() / "LifeStuff",
                                   user_credential_->SessionName(),
                                   session_,
                                   true);
          std::cout << std::endl << "Successfully created user and logged in"
                    << std::endl;
        } else {
          std::cout << std::endl  << "Failed to create user" << std::endl;
        }
      } else if (create_new == "n") {
        std::cout << "Retry again ..." << std::endl;
        username.clear();
        pin.clear();
        confirm.clear();
        password.clear();
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
    printf("\tchangeuname                  Change username.\n");
    printf("\tchangepin                    Change pin.\n");
    printf("\tchangepwd                    Change password.\n");
    printf("\tlogout                       Logout.\n");
    printf("\tleave                        Leave Maidsafe Network.\n");
    printf("\texit  or 'q'                 Exit the application.\n");
  }
}

void Commands::ProcessCommand(const std::string &cmdline,
                              bool * /*wait_for_cb*/) {
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
    user_storage_.UnMountDrive();
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
        bool success(false);
        std::string pword, confirm;
        int count = 0;
        do {
          std::cout << "Enter password: ";
          pword = GetLineWithAsterisks();
          if (pword.compare(user_credential_->Password()) == 0) {
            success = user_credential_->ChangeUsername(args[0]);
              if (success) {
                std::cout << "Changed user name successfully" << std::endl;
              } else {
                 std::cout << "Changing user name failed" << std::endl;
                 count = _MAX_TRY;
                 break;
              }
          } else {
            std::cout << "Invalid password." << std::endl;
          }
        } while (!success && (++count < _MAX_TRY));
      }
    } else if (cmd == "changepin") {
      if (!args.empty()) {
        std::cout << "Change pin correct usage: changepin" << std::endl;
      } else {
        bool success(false);
        std::string string, confirm;
        int count = 0;
        do {
          std::cout << "Enter password: ";
          string = GetLineWithAsterisks();
          if (string.compare(user_credential_->Password()) == 0) {
            while (string.compare(confirm) != 0) {
              std::cout << "New pin: ";
              string = GetLineWithAsterisks();
              std::cout << "Confirm pin: ";
              confirm = GetLineWithAsterisks();
              success = false;
              if (string.compare(confirm) == 0) {
                success = user_credential_->ChangePin(string);
                if (success) {
                  std::cout << "Changed pin successfully" << std::endl;
                } else {
                  std::cout << "Changing pin failed" << std::endl;
                  count = _MAX_TRY;
                  break;
                }
              } else {
                std::cout << "Pin confirmation mismatch" << std::endl;
              }
            }
          } else {
            std::cout << "Invalid password" << std::endl;
          }
        } while (!success && (++count < _MAX_TRY));
      }
    } else if (cmd == "changepwd") {
      if (!args.empty()) {
        std::cout << "Change password correct usage: changepwd"
                  << std::endl;
      } else {
        bool success(false);
        std::string password, confirm_password;
        int count = 0;
        do {
          std::cout << "Current password: ";
          password = GetLineWithAsterisks();
          if (password.compare(user_credential_->Password()) == 0) {
            while (password.compare(confirm_password) != 0) {
              std::cout << "New password: ";
              password = GetLineWithAsterisks();
              std::cout << "Confirm new password: ";
              confirm_password = GetLineWithAsterisks();
              success = false;
              if (password.compare(confirm_password) == 0) {
                success = user_credential_->ChangePassword(password);
                if (success) {
                  std::cout << "Changed password successfully" << std::endl;
                } else {
                   std::cout << "Change password Failed" << std::endl;
                   count = _MAX_TRY;
                    break;
                }
              } else {
                std::cout << "Password confirmation mismatch"<< std::endl;
              }
            }
          } else {
            std::cout << "Invalid password" << std::endl;
          }
        } while (!success && (count++ < _MAX_TRY));
      }
    } else if (cmd == "logout") {
      bool ret = user_credential_->Logout();
      if (ret) {
        logged_in_ = false;
        user_storage_.UnMountDrive();
        std::cout << "Logged out Successfully" << std::endl;
        PrintUsage();
      } else {
        std::cout << "Log out Failed" << std::endl;
      }

    } else if (cmd == "leave") {
      bool ret = user_credential_->LeaveMaidsafeNetwork();
      if (ret) {
        user_storage_.UnMountDrive();
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
