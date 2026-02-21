pub mod auth;
pub mod confirmation;
pub mod create_key;
pub mod delete_confirm;
pub mod description;
pub mod expiration;
pub mod import_key;
pub mod key_password;
pub mod password;
pub mod remove_pwd;
pub mod set_password;

pub use auth::AuthenticationState;
pub use confirmation::ConfirmationState;
pub use create_key::CreateKeyState;
pub use delete_confirm::DeleteConfirmState;
pub use description::DescriptionState;
pub use expiration::ExpirationState;
pub use import_key::ImportKeyState;
pub use key_password::KeyPasswordState;
pub use password::PasswordChangeState;
pub use remove_pwd::RemovePasswordState;
pub use set_password::SetKeyPasswordState;

/// The result of processing a key event inside a modal.
#[derive(Debug, PartialEq)]
pub enum ModalEvent {
    /// No action needed (input consumed, state updated internally)
    None,
    /// User confirmed / submitted the modal
    Confirm,
    /// User cancelled the modal
    Cancel,
    /// Special action: reset timer (ExpirationState only)
    ResetTimer,
}

/// All possible modal dialogs, each carrying its own self-contained state.
pub enum ActiveModal {
    Authentication(AuthenticationState),
    Description(DescriptionState),
    PasswordChange(PasswordChangeState),
    Confirmation(ConfirmationState),
    Expiration(ExpirationState),
    RemovePassword(RemovePasswordState),
    KeyPassword(KeyPasswordState),
    SetKeyPassword(SetKeyPasswordState),
    CreateKey(CreateKeyState),
    ImportKey(ImportKeyState),
    DeleteConfirm(DeleteConfirmState),
}

/// Dispatch a key event to the currently active modal and return the result.
pub fn handle_modal_key(
    modal: &mut ActiveModal,
    key: crossterm::event::KeyCode,
) -> ModalEvent {
    match modal {
        ActiveModal::Authentication(s) => auth::handle(s, key),
        ActiveModal::Description(s) => description::handle(s, key),
        ActiveModal::PasswordChange(s) => password::handle(s, key),
        ActiveModal::Confirmation(s) => confirmation::handle(s, key),
        ActiveModal::Expiration(s) => expiration::handle(s, key),
        ActiveModal::RemovePassword(s) => remove_pwd::handle(s, key),
        ActiveModal::KeyPassword(s) => key_password::handle(s, key),
        ActiveModal::SetKeyPassword(s) => set_password::handle(s, key),
        ActiveModal::CreateKey(s) => create_key::handle(s, key),
        ActiveModal::ImportKey(s) => import_key::handle(s, key),
        ActiveModal::DeleteConfirm(s) => delete_confirm::handle(s, key),
    }
}

/// Render the currently active modal on top of the screen.
pub fn render_modal(modal: &ActiveModal, f: &mut ratatui::Frame, screen: ratatui::layout::Rect) {
    match modal {
        ActiveModal::Authentication(s) => auth::render(s, f, screen),
        ActiveModal::Description(s) => description::render(s, f, screen),
        ActiveModal::PasswordChange(s) => password::render(s, f, screen),
        ActiveModal::Confirmation(s) => confirmation::render(s, f, screen),
        ActiveModal::Expiration(s) => expiration::render(s, f, screen),
        ActiveModal::RemovePassword(s) => remove_pwd::render(s, f, screen),
        ActiveModal::KeyPassword(s) => key_password::render(s, f, screen),
        ActiveModal::SetKeyPassword(s) => set_password::render(s, f, screen),
        ActiveModal::CreateKey(s) => create_key::render(s, f, screen),
        ActiveModal::ImportKey(s) => import_key::render(s, f, screen),
        ActiveModal::DeleteConfirm(s) => delete_confirm::render(s, f, screen),
    }
}
