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
#include "boost/python/call.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "maidsafe/common/log.h"
#include "maidsafe/common/types.h"

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

class LifeStuffPython {
 public:
  LifeStuffPython(const ls::Slots& slots)
   : lifestuff_(slots) {}
  ~LifeStuffPython() {}

  void InsertUserInput(uint32_t position,
                       const std::string& character,
                       ls::InputField input_field) {
    lifestuff_.InsertUserInput(position, character, input_field);
  }
  void RemoveUserInput(uint32_t position, uint32_t length, ls::InputField input_field) {
    lifestuff_.RemoveUserInput(position, length, input_field);
  }
  void ClearUserInput(ls::InputField input_field) { lifestuff_.ClearUserInput(input_field); }
  bool ConfirmUserInput(ls::InputField input_field) {
    return lifestuff_.ConfirmUserInput(input_field);
  }

  void CreateUser(const std::string& vault_path, PyObject *py_callback) {
    ls::ReportProgressFunction cb([this, py_callback](ls::Action action,
                                                      ls::ProgessCode progesscode) {
                                    this->ProgressCB(action, progesscode, py_callback);
                                  });
    lifestuff_.CreateUser(vault_path, cb);
  }
  void LogIn(PyObject *py_callback) {
    ls::ReportProgressFunction cb([this, py_callback](ls::Action action,
                                                      ls::ProgessCode progesscode) {
                                    this->ProgressCB(action, progesscode, py_callback);
                                  });
    lifestuff_.LogIn(cb);
  }
  void LogOut() { lifestuff_.LogOut(); }

  void MountDrive() { lifestuff_.MountDrive(); }
  void UnMountDrive() { lifestuff_.UnMountDrive(); }

  void ChangeKeyword() { lifestuff_.ChangeKeyword(); }
  void ChangePin() { lifestuff_.ChangePin(); }
  void ChangePassword() { lifestuff_.ChangePassword(); }

  bool logged_in() { return lifestuff_.logged_in(); }

  std::string mount_path() { return lifestuff_.mount_path(); }
  std::string owner_path() { return lifestuff_.owner_path(); }

 private:
  void ProgressCB(ls::Action action, ls::ProgessCode progesscode, PyObject *py_callback) {
    std::cout << "action : " << action << " , progesscode : " << progesscode << std::endl;
    boost::python::call<void>(py_callback, action, progesscode);
  }

  ls::LifeStuff lifestuff_;
};

void SetEmptySlots(maidsafe::lifestuff::Slots* pslots) {
  assert(pslots);
  auto string_callback = [](const std::string&) {};  // NOLINT
  auto int32_callback = [](int32_t) {};  // NOLINT
  auto bool_callback = [](bool) {};  // NOLINT

  pslots->update_available = string_callback;
  pslots->network_health = int32_callback;
  pslots->operations_pending = bool_callback;
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

  bpy::class_<LifeStuffPython, boost::noncopyable>(
      "LifeStuff", bpy::init<ls::Slots>())

       // Credential Operations
      .def("InsertUserInput", &LifeStuffPython::InsertUserInput)
      .def("RemoveUserInput", &LifeStuffPython::RemoveUserInput)
      .def("ClearUserInput", &LifeStuffPython::ClearUserInput)
      .def("ConfirmUserInput", &LifeStuffPython::ConfirmUserInput)
      .def("ChangeKeyword", &LifeStuffPython::ChangeKeyword)
      .def("ChangePin", &LifeStuffPython::ChangePin)
      .def("ChangePassword", &LifeStuffPython::ChangePassword)

      // User Behaviour
      .def("CreateUser", &LifeStuffPython::CreateUser)
      .def("LogIn", &LifeStuffPython::LogIn)
      .def("LogOut", &LifeStuffPython::LogOut)

      // Virtual Drive
      .def("MountDrive", &LifeStuffPython::MountDrive)
      .def("UnMountDrive", &LifeStuffPython::UnMountDrive)

      // Getter
      .def("logged_in", &LifeStuffPython::logged_in)
      .def("mount_path", &LifeStuffPython::mount_path)
      .def("owner_path", &LifeStuffPython::owner_path);
}
