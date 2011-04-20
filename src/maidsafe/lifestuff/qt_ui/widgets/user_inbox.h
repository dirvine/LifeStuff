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
 *  Created on: May 19, 2010
 *      Author: Stephen Alexander
 */


#ifndef MAIDSAFE_LIFESTUFF_WIDGETS_USER_INBOX_H_
#define MAIDSAFE_LIFESTUFF_WIDGETS_USER_INBOX_H_

#include <QWidget>
#include <QString>

// local
#include "maidsafe/lifestuff/qt_ui/client/client_controller.h"
#include "maidsafe/lifestuff/qt_ui/client/read_file_thread.h"
#include "maidsafe/lifestuff/qt_ui/client/send_email_thread.h"
#include "maidsafe/lifestuff/qt_ui/client/remove_dir_thread.h"
#include "maidsafe/lifestuff/qt_ui/client/save_file_thread.h"
#include "maidsafe/lifestuff/qt_ui/widgets/user_send_mail.h"
#include "maidsafe/lifestuff/qt_ui/widgets/file_browser.h"

#include "ui_user_inbox.h"

namespace maidsafe {

namespace lifestuff {

namespace qt_ui {

class UserInbox : public QDialog {
  Q_OBJECT

 public:
  explicit UserInbox(QWidget* parent = 0);
  virtual ~UserInbox();

  virtual void setActive(bool active);

 private:
  Ui::UserInbox ui_;
  FileBrowser* browser_;
  UserSendMail* sendMail_;
  QString folder_;
  QString rootPath_;

  int populateEmails();
  void onDeleteItemClicked();

  private slots:
    void onReplyClicked();
    void onEmailClicked(QListWidgetItem*);
    void onItemClicked(QListWidgetItem*);
    void onEmailFileCompleted(int, const QString&);
    void onSendEmailCompleted(int, const QString&);
    void onSaveFileCompleted(int, const QString&);
    void onRemoveDirCompleted(int, const QString&);
    void onEmailCompleted(int, const QString&);
    void onEmailReceived(const QString &subject, const QString &conversation,
                         const QString &message, const QString &sender,
                         const QString &date);

 protected:
  void changeEvent(QEvent *event);
};

}  // namespace qt_ui

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_WIDGETS_USER_INBOX_H_
