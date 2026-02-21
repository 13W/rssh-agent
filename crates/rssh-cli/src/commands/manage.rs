use rssh_core::Result;

pub struct ManageCommand;

impl ManageCommand {
    pub fn execute(socket: Option<String>) -> Result<()> {
        // Run the TUI
        crate::tui::run_tui(socket).map_err(|e| rssh_core::Error::Internal(e.to_string()))?;
        Ok(())
    }
}
