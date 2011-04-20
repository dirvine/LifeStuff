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
 *  Created on: May 20, 2009
 *      Author: Team
 */

#ifndef MAIDSAFE_LIFESTUFF_CLIENT_WORKER_THREAD_H_
#define MAIDSAFE_LIFESTUFF_CLIENT_WORKER_THREAD_H_

#include <QThread>

namespace maidsafe {

namespace lifestuff {

namespace qt_ui {

// Worker thread for mounting
/*!
    Base class for worker threads that perform operations that
    can take a significant amount of time.

    On complettion the thread notifies results and deletes itself.
*/
class WorkerThread : public QThread {
  Q_OBJECT
 public:
  explicit WorkerThread(QObject* parent = 0);
  virtual ~WorkerThread();

  signals:
    void completed(bool success);
};
}  // namespace qt_ui

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_CLIENT_WORKER_THREAD_H_

