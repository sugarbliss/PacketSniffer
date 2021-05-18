#ifndef NEW_WINDOW_H
#define NEW_WINDOW_H

#include <QMainWindow>

namespace Ui {
class new_window;
}

class new_window : public QMainWindow {
    Q_OBJECT

public:
    explicit new_window(QWidget* parent = nullptr);
    ~new_window();

private:
    Ui::new_window* ui;
};

#endif // NEW_WINDOW_H
