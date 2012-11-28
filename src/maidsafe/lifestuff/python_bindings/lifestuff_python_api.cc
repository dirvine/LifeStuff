/*
* ============================================================================
*
* Copyright [2012] maidsafe.net limited
*
* Description:  Exposing the LifeStuff API as a module to Python.
* Version:      1.0
* Created:      2012-11-28
* Revision:     none
* Compiler:     gcc
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

#include "boost/filesystem/path.hpp"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4100 4127 4244)
#endif
#include "boost/python.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "maidsafe/lifestuff/lifestuff_api.h"

// NOTE set PYTHONPATH to your build directory

// NOTE in Python, do "from lifestuff_python_api import *"

namespace bpy = boost::python;
namespace ls = maidsafe::lifestuff;

namespace {

struct PathConverter {
  static PyObject* convert(const boost::filesystem::path& path) {
    return bpy::incref(bpy::str(path.c_str()).ptr());
  }
};

struct NonEmptyStringConverter {
  static PyObject* convert(const maidsafe::NonEmptyString& nes) {
    return bpy::incref(bpy::str(nes.string().c_str()).ptr());
  }
};

// struct PathExtractor {
//   extract(const boost::filesystem::path& path) ...
// };

boost::filesystem::path ExtractPath(const bpy::str& s) {
  return boost::filesystem::path(std::string(bpy::extract<const char*>(s)));
}

maidsafe::NonEmptyString ExtractNonEmptyString(const bpy::str& s) {
  return maidsafe::NonEmptyString(std::string(bpy::extract<const char*>(s)));
}

// TODO(Steve) get this to work...
std::string TestConversion(const maidsafe::NonEmptyString& nes) {
  return nes.string();
}

}  // namespace

BOOST_PYTHON_MODULE(lifestuff_python_api) {
  bpy::def("TestConversion", TestConversion);

  bpy::to_python_converter<boost::filesystem::path, PathConverter>();
  bpy::to_python_converter<maidsafe::NonEmptyString, NonEmptyStringConverter>();
//   boost::lvalue_from_pytype<PathExtractor, bpy::str>();
//   bpy::converter::registry::insert(&ExtractPath, bpy::type_id<boost::filesystem::path>);
//   bpy::converter::registry::insert(&ExtractNonEmptyString,
//                                    bpy::type_id<maidsafe::NonEmptyString>);

  bpy::class_<ls::LifeStuff>(
      "LifeStuff", bpy::init<ls::Slots, boost::filesystem::path>())

      // Credential operations
      .def("CreateUser", &ls::LifeStuff::CreateUser)
      .def("CreatePublicId", &ls::LifeStuff::CreatePublicId)
      .def("LogIn", &ls::LifeStuff::LogIn)
      .def("LogOut", &ls::LifeStuff::LogOut)
      .def("MountDrive", &ls::LifeStuff::MountDrive)
      .def("UnMountDrive", &ls::LifeStuff::UnMountDrive)
      .def("StartMessagesAndIntros", &ls::LifeStuff::StartMessagesAndIntros)
      .def("StopMessagesAndIntros", &ls::LifeStuff::StopMessagesAndIntros)
      .def("CheckPassword", &ls::LifeStuff::CheckPassword)
      .def("ChangeKeyword", &ls::LifeStuff::ChangeKeyword)
      .def("ChangePin", &ls::LifeStuff::ChangePin)
      .def("ChangePassword", &ls::LifeStuff::ChangePassword)
//       .def("ChangePublicId", &ls::LifeStuff::ChangePublicId)
      .def("LeaveLifeStuff", &ls::LifeStuff::LeaveLifeStuff)

      // Contact operations
      .def("AddContact", &ls::LifeStuff::AddContact)
      .def("ConfirmContact", &ls::LifeStuff::ConfirmContact)
      .def("DeclineContact", &ls::LifeStuff::DeclineContact)
      .def("RemoveContact", &ls::LifeStuff::RemoveContact)
      .def("ChangeProfilePicture", &ls::LifeStuff::ChangeProfilePicture)
      .def("GetOwnProfilePicture", &ls::LifeStuff::GetOwnProfilePicture)
      .def("GetContactProfilePicture", &ls::LifeStuff::GetContactProfilePicture)
      .def("GetLifestuffCard", &ls::LifeStuff::GetLifestuffCard)
      .def("SetLifestuffCard", &ls::LifeStuff::SetLifestuffCard)
      .def("GetContacts", &ls::LifeStuff::GetContacts)
      .def("PublicIdsList", &ls::LifeStuff::PublicIdsList)

      // Messaging
      .def("SendChatMessage", &ls::LifeStuff::SendChatMessage)
      .def("SendFile", &ls::LifeStuff::SendFile)
      .def("AcceptSentFile", &ls::LifeStuff::AcceptSentFile)
      .def("RejectSentFile", &ls::LifeStuff::RejectSentFile)

      // Filesystem
      .def("ReadHiddenFile", &ls::LifeStuff::ReadHiddenFile)
      .def("WriteHiddenFile", &ls::LifeStuff::WriteHiddenFile)
      .def("DeleteHiddenFile", &ls::LifeStuff::DeleteHiddenFile)
      .def("SearchHiddenFiles", &ls::LifeStuff::SearchHiddenFiles)

      // getters
      .def("state", &ls::LifeStuff::state)
      .def("logged_in_state", &ls::LifeStuff::logged_in_state)
      .def("mount_path", &ls::LifeStuff::mount_path);
}
