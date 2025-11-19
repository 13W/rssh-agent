Экран поделен на 3 фрейма:
* Основной - где выводятся все ключи
* Статус - снизу, 1 строка, где выводится статус выполненного действия
* Информационная панель справа - где выводится детальная информация по ключу, при выборе ключа

При запуске, независимо от того разблокирован агент или нет - необходимо произвести авторизацию пользователя - спросить его мастер-пароль.
Для этого, после запуска - отображаем чистый экран с модалкой, в которой только один инпут: Password, и кнопки: ok, exit.

Ключи отображаются в следующем виде:
<icond-loaded> <icon-protected> <icon-confirmation-or-notification> <icon-ttl> <short-key-fingerprint> <key-description>

icon-loaded: ● - loaded | ○ unloaded | ↗ external
icon-protected: 🛡 - green if protected, gray if not
icon-confirmation-or-notification:
* if confirmation is enabled: ⚠
* if notification is enabled: ✉
icon-expiration: ⏳:
* gray - если не активно
* green - если активно
short-key-fingerprint: <N-символов спереди>...<N-символов сзади>
key-description: он же key comment

Статус:
Исключительно текст, однострочный:
* key <name> loaded/unloaded
* constraint <constraint-name> set
* description changed
* expiration changed
* key imported
* agent locked
* etc...

Информационная панель справа:
* Содержит HELP/Key bindings
* Информацию о ключе:
Description: String
Password: Protected | Not protected
Created/Imported: Date
Updated: Date
Confirmation: Radio: None | Notify | Confirm, в случае если задано дефолтное значение для этого ключа - в скобках это значение, серым цветом
Expiration: время до экспирации, в случае если задано дефолтное значение для этого ключа - в скобках это значение, серым цветом

При отображении информации о ключе - стрелками можно выбрать description, Password, Confirmation, Expiration.
При селекте:
* description - отобразить модалку с инпутом, в котором отображено текущее значение, которое можно изменить. Кнопки: save, cancel.
* Password - модалка:
* * Input: Old password - отобразить если ключь запаролен
* * Input: New Password
* * Input: Confirm Password
* * кнопки: change, cancel
* Confirmation - модалка, разделенная на 2 половины(если ключ загружен, иначе одна - для дефолтного значения) - активное значение для загруженного ключа и дефолтное значение, в каждой radio buttons: None, Notify, Confirm. Кнопки: save, cancel
* Expiration - модалка с инпутом, для задания дефолтного значения. В случае если ключ загружен и таймер тикает - отобразить его над инпутом. Кнопки: reset timer, save, cancel. reset timer - сбрасывает таймер на значение прописанное в дефолте. если значение не задано - убираем дефолт, а ресет - убирает таймер.
