/*
 * copyright maidsafe.net limited 2009
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: May 19, 2009
 *      Author: Team
 */

#include "maidsafe/lifestuff/qt_ui/client/user_space_filesystem.h"

// qt
#include <QObject>
#include <QDebug>
#include <QProcess>

// dht
//  #include <maidsafe/maidsafe-dht_config.h>

// os
#ifdef LifeStuff_WIN32
  #include <windows.h>
  #include <shellapi.h>
#endif

#include <string>

#include"boost/thread.hpp"

// core
#include "maidsafe/lifestuff/shared/filesystem.h"

// 3rd party
#if defined(LifeStuff_WIN32)
#ifndef LifeStuff_LIGHT
#include "maidsafe/lifestuff/fuse/windows/fswin.h"
#endif
#elif defined(LifeStuff_POSIX)
#include "maidsafe/lifestuff/fuse/linux/fslinux.h"
#endif

// local
#include "maidsafe/lifestuff/qt_ui/client/client_controller.h"

namespace maidsafe {

namespace lifestuff {

namespace qt_ui {

class UserSpaceFileSystem::UserSpaceFileSystemImpl {
 public:
  UserSpaceFileSystemImpl() { }

#ifdef LifeStuff_WIN32
  // none needed
#elif defined(LifeStuff_POSIX)
  #ifndef LifeStuff_LIGHT
    fs_l_fuse::FSLinux fsl_;
  #endif
#endif
};

UserSpaceFileSystem* UserSpaceFileSystem::instance() {
  static UserSpaceFileSystem usfp;
  return &usfp;
}

UserSpaceFileSystem::UserSpaceFileSystem(QObject* parent)
    : QObject(parent),
      impl_(new UserSpaceFileSystemImpl) { }

UserSpaceFileSystem::~UserSpaceFileSystem() {
  delete impl_;
  impl_ = NULL;
}

bool UserSpaceFileSystem::mount() {
//  #ifdef DEBUG
  qDebug() << "UserSpaceFileSystem::mount";
//    boost::this_thread::sleep(boost::posix_time::seconds(2));
//    qDebug() << "UserSpaceFileSystem::mount after 2 sec sleep";
//  #endif

  ClientController::instance()->SetMounted(0);

  std::string debug_mode("-d");
#ifdef LifeStuff_WIN32
  char drive = ClientController::instance()->DriveLetter();
  #ifndef LifeStuff_LIGHT
    fs_w_fuse::Mount(drive);
  #endif
  ClientController::instance()->SetWinDrive(drive);
#elif defined(LifeStuff_POSIX)
  #ifndef LifeStuff_LIGHT
    std::string mount_point(file_system::MaidsafeFuseDir(
                                ClientController::instance()->SessionName())
                                    .string());
    if (!impl_->fsl_.Mount(mount_point, debug_mode))
      return false;
  #endif
#endif
  boost::this_thread::sleep(boost::posix_time::seconds(1));

  if (ClientController::instance()->Mounted() != 0) {
    return false;
  }
  return true;
}

bool UserSpaceFileSystem::unmount() {
  // unmount drive
  bool success = false;
#ifdef LifeStuff_WIN32
  #ifndef LifeStuff_LIGHT
    std::locale loc;
    wchar_t drive_letter = std::use_facet< std::ctype<wchar_t> >
        (loc).widen(ClientController::instance()->WinDrive());
    success = fs_w_fuse::UnMount(drive_letter);
    if (!success)
      qWarning() << "UserSpaceFileSystem::unmount: failed to unmount dokan"
                 << success;
  #endif
#elif defined(LifeStuff_POSIX)
  #ifndef LifeStuff_LIGHT
    // un-mount fuse
    impl_->fsl_.UnMount();
  #endif
  success = true;
#endif

  // logout from client controller
  const bool n = ClientController::instance()->Logout();
  if (!n) {
    // TODO(Team#5#): 2009-06-25 - do stuff
    success = false;
  }
#ifdef LifeStuff_LIGHT
  return n;
#endif
  return success;
}

void UserSpaceFileSystem::explore(Location l, QString subDir) {
  QDir dir;
  if (l == MY_FILES) {
    dir = ClientController::instance()->myFilesDirRoot(subDir);
  } else {  // PRIVATE_SHARES
    dir = ClientController::instance()->shareDirRoot(subDir);
  }

#ifdef LifeStuff_WIN32
  // %SystemRoot%\explorer.exe /e /root,M:\Shares\Private\Share 1
  // invoking using QProcess doesn't work if the path has spaces in the name
  // so we need to go old skool...
  QString operation("explore");
  quintptr returnValue;
  QT_WA({
        returnValue = (quintptr)ShellExecute(0,
                          (TCHAR *)(operation.utf16()),  //NOLINT
                          (TCHAR *)(dir.absolutePath().utf16()),  //NOLINT
                          0,
                          0,
                          SW_SHOWNORMAL);
      } , {
        returnValue = (quintptr)ShellExecuteA(0,
                                  operation.toLocal8Bit().constData(),
                                  dir.absolutePath().toLocal8Bit().constData(),
                                  0,
                                  0,
                                  SW_SHOWNORMAL);
      });

  if (returnValue <= 32) {
    qWarning() << "UserSpaceFileSystem::explore: failed to open"
               << dir.absolutePath();
  }
#else
  // nautilus FuseHomeDir()/Shares/Private/"name"
  QString app("nautilus");
  QStringList args;
  args <<  QString("%1").arg(dir.absolutePath());

  qDebug() << "explore:" << app << args;

  if (!QProcess::startDetached(app, args)) {
    qWarning() << "UserSpaceFileSystem::explore: failed to start"
               << app
               << "with args"
               << args;
  }
#endif
}

}  // namespace qt_ui

}  // namespace lifestuff

}  // namespace maidsafe
