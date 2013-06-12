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

#include "maidsafe/common/log.h"

#include "maidsafe/lifestuff/lifestuff_api.h"

/**
 * NOTE
 * - set PYTHONPATH to your build directory, or move the module to where Python finds it
 * - create /tmp/maidsafe_log.ini to enable logging, if desired
 * - in Python, call "from lifestuff_python_api import *"
 * - slots in the LifeStuff constructor are passed via dictionary, e.g. simply {}
 * - paths and NonEmptyStrings are passed via strings
 *
 * TODO
 * - extend slots to actually call Python functions passed via dictionary
 * - implement converter for ContactPresence to Python object (as in ContactPresenceFunction)
 * - implement converter for Operation to Python object (as in OperationProgressFunction)
 * - implement converter for SubTask to Python object (as in OperationProgressFunction)
 * - implement converter for ContactMap to Python object (as in GetContacts)
 * - implement converter for std::vector<NonEmptyString> to Python object (as in PublicIdsList)
 * - implement converter for Python object to SocialInfoMap (as in Get/SetLifestuffCard)
 * - handle API functions that take arguments as pointers/references
 */

namespace bpy = boost::python;
namespace ls = maidsafe::lifestuff;

namespace {

void SetEmptySlots(maidsafe::lifestuff::Slots* pslots) {
  assert(pslots);
  auto three_strings_func = [](const maidsafe::NonEmptyString&,
                               const maidsafe::NonEmptyString&,
                               const maidsafe::NonEmptyString&) {};  // NOLINT
  auto three_plus_one_strings_func = [](const maidsafe::NonEmptyString&,
                                        const maidsafe::NonEmptyString&,
                                        const std::string&,
                                        const maidsafe::NonEmptyString&) {};  // NOLINT
  auto four_strings_func = [](const maidsafe::NonEmptyString&,
                              const maidsafe::NonEmptyString&,
                              const maidsafe::NonEmptyString&,
                              const maidsafe::NonEmptyString&) {};  // NOLINT
  auto five_strings_func = [](const maidsafe::NonEmptyString&,
                              const maidsafe::NonEmptyString&,
                              const maidsafe::NonEmptyString&,
                              const maidsafe::NonEmptyString&,
                              const maidsafe::NonEmptyString&) {};  // NOLINT
  pslots->chat_slot = four_strings_func;
  pslots->file_success_slot = five_strings_func;
  pslots->file_failure_slot = three_strings_func;
  pslots->new_contact_slot = three_plus_one_strings_func;
  pslots->confirmed_contact_slot = three_strings_func;
  pslots->profile_picture_slot = three_strings_func;
  pslots->contact_presence_slot = [](const maidsafe::NonEmptyString&,
                                     const maidsafe::NonEmptyString&,
                                     const maidsafe::NonEmptyString&,
                                     maidsafe::lifestuff::ContactPresence) {};  // NOLINT
  pslots->contact_deletion_slot = three_plus_one_strings_func;
  pslots->lifestuff_card_update_slot = three_strings_func;
  pslots->network_health_slot = [](const int&) {};  // NOLINT
  pslots->immediate_quit_required_slot = [] {};  // NOLINT
  pslots->update_available_slot = [](const maidsafe::NonEmptyString&) {};  // NOLINT
  pslots->operation_progress_slot = [](maidsafe::lifestuff::Operation,
                                       maidsafe::lifestuff::SubTask) {};  // NOLINT
}

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

struct PathExtractor {
  static void* convertible(PyObject* obj_ptr) {
    return PyString_Check(obj_ptr) ? obj_ptr : nullptr;
  }
  static void construct(PyObject* obj_ptr, bpy::converter::rvalue_from_python_stage1_data* data) {
    const char* value = PyString_AsString(obj_ptr);
    assert(value);
    typedef bpy::converter::rvalue_from_python_storage<boost::filesystem::path> storage_type;
    void* storage = reinterpret_cast<storage_type*>(data)->storage.bytes;
    new(storage) boost::filesystem::path(value);
    data->convertible = storage;
  }
};

struct NonEmptyStringExtractor {
  static void* convertible(PyObject* obj_ptr) {
    return PyString_Check(obj_ptr) ? obj_ptr : nullptr;
  }
  static void construct(PyObject* obj_ptr, bpy::converter::rvalue_from_python_stage1_data* data) {
    const char* value = PyString_AsString(obj_ptr);
    assert(value);
    typedef bpy::converter::rvalue_from_python_storage<maidsafe::NonEmptyString> storage_type;
    void* storage = reinterpret_cast<storage_type*>(data)->storage.bytes;
    new(storage) maidsafe::NonEmptyString(value);
    data->convertible = storage;
  }
};

struct SlotsExtractor {
  static void* convertible(PyObject* obj_ptr) {
    return PyDict_Check(obj_ptr) ? obj_ptr : nullptr;
  }
  static void construct(PyObject*, bpy::converter::rvalue_from_python_stage1_data* data) {
    typedef bpy::converter::rvalue_from_python_storage<maidsafe::lifestuff::Slots> storage_type;
    void* storage = reinterpret_cast<storage_type*>(data)->storage.bytes;
    auto pslots = new(storage) maidsafe::lifestuff::Slots();
    SetEmptySlots(pslots);
    // TODO(Steve) connect slots as per passed in dictionary
    data->convertible = storage;
  }
};

#ifdef __GNUC__
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Weffc++"
#endif
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(create_user_overloads, CreateUser, 3, 4)
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(get_contacts_overloads, GetContacts, 1, 2)
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(accept_sent_file_overloads, AcceptSentFile, 1, 3)
#ifdef __GNUC__
#  pragma GCC diagnostic pop
#endif

}  // namespace

BOOST_PYTHON_MODULE(lifestuff_python_api) {
  maidsafe::log::Logging::Instance().Initialise(0, nullptr);
  LOG(kInfo) << "Initialising LifeStuff Python API";
//   bpy::register_exception_translator<std::exception>([](const std::exception& ex) {
//     PyErr_SetString(PyExc_RuntimeError, ex.what());
//   });
  bpy::to_python_converter<boost::filesystem::path, PathConverter>();
  bpy::to_python_converter<maidsafe::NonEmptyString, NonEmptyStringConverter>();
  bpy::converter::registry::push_back(&PathExtractor::convertible,
                                      &PathExtractor::construct,
                                      bpy::type_id<boost::filesystem::path>());
  bpy::converter::registry::push_back(&NonEmptyStringExtractor::convertible,
                                      &NonEmptyStringExtractor::construct,
                                      bpy::type_id<maidsafe::NonEmptyString>());
  bpy::converter::registry::push_back(&SlotsExtractor::convertible,
                                      &SlotsExtractor::construct,
                                      bpy::type_id<maidsafe::lifestuff::Slots>());

  bpy::class_<ls::LifeStuff>(
      "LifeStuff", bpy::init<ls::Slots, boost::filesystem::path>())

      // Credential operations
      .def("CreateUser", &ls::LifeStuff::CreateUser, create_user_overloads())
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
      .def("GetContacts", &ls::LifeStuff::GetContacts, get_contacts_overloads())
      .def("PublicIdsList", &ls::LifeStuff::PublicIdsList)

      // Messaging
      .def("SendChatMessage", &ls::LifeStuff::SendChatMessage)
      .def("SendFile", &ls::LifeStuff::SendFile)
      .def("AcceptSentFile", &ls::LifeStuff::AcceptSentFile, accept_sent_file_overloads())
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
