use rssh_core::{Error, Result};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wrapper for password that zeroizes on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureString(String);

impl SecureString {
    pub fn new(s: String) -> Self {
        SecureString(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Trait for password prompting and confirmations
pub trait Prompter: Send + Sync {
    fn prompt(&self, prompt_text: &str) -> Result<SecureString>;
    fn confirm(&self, prompt_text: &str) -> Result<bool>;
}

/// TTY prompter using rpassword
pub struct TtyPrompter;

impl Prompter for TtyPrompter {
    fn prompt(&self, prompt_text: &str) -> Result<SecureString> {
        print!("{}: ", prompt_text);
        std::io::stdout().flush()?;

        let password = rpassword::read_password().map_err(Error::Io)?;

        if password.is_empty() {
            return Err(Error::BadArgs);
        }

        Ok(SecureString::new(password))
    }

    fn confirm(&self, prompt_text: &str) -> Result<bool> {
        loop {
            print!("{} (y/n): ", prompt_text);
            std::io::stdout().flush()?;

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            match input.trim().to_lowercase().as_str() {
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => {
                    println!("Please enter 'y' or 'n'");
                    continue;
                }
            }
        }
    }
}

/// ASKPASS prompter using SSH_ASKPASS program
pub struct AskpassPrompter {
    program: String,
}

impl AskpassPrompter {
    pub fn new(program: String) -> Self {
        AskpassPrompter { program }
    }
}

impl Prompter for AskpassPrompter {
    fn prompt(&self, prompt_text: &str) -> Result<SecureString> {
        let mut child = Command::new(&self.program)
            .arg(prompt_text)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Internal("Failed to capture stdout".into()))?;

        let mut reader = BufReader::new(stdout);
        let mut password = String::new();
        reader.read_line(&mut password)?;

        let status = child.wait()?;
        if !status.success() {
            return Err(Error::BadArgs);
        }

        // Trim trailing newline
        if password.ends_with('\n') {
            password.pop();
        }
        if password.ends_with('\r') {
            password.pop();
        }

        if password.is_empty() {
            return Err(Error::BadArgs);
        }

        Ok(SecureString::new(password))
    }

    fn confirm(&self, prompt_text: &str) -> Result<bool> {
        // For ASKPASS programs, we'll prompt with instructions and expect y/n response
        let confirmation_prompt = format!("{} (Enter 'y' for yes, 'n' for no)", prompt_text);

        let mut child = Command::new(&self.program)
            .arg(&confirmation_prompt)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Internal("Failed to capture stdout".into()))?;

        let mut reader = BufReader::new(stdout);
        let mut response = String::new();
        reader.read_line(&mut response)?;

        let status = child.wait()?;
        if !status.success() {
            // Treat program failure as denial
            return Ok(false);
        }

        // Trim trailing newline
        if response.ends_with('\n') {
            response.pop();
        }
        if response.ends_with('\r') {
            response.pop();
        }

        // Accept y/yes as confirmation, everything else as denial
        match response.trim().to_lowercase().as_str() {
            "y" | "yes" => Ok(true),
            _ => Ok(false),
        }
    }
}

/// Decision logic for choosing prompter based on environment
pub struct PrompterDecision;

impl PrompterDecision {
    /// Determine which prompter to use based on environment
    pub fn choose() -> Option<Box<dyn Prompter>> {
        // Check SSH_ASKPASS_REQUIRE
        let askpass_require = env::var("SSH_ASKPASS_REQUIRE")
            .unwrap_or_default()
            .to_lowercase();

        if askpass_require == "never" {
            // Only use TTY
            if atty::is(atty::Stream::Stdin) {
                return Some(Box::new(TtyPrompter));
            }
            return None;
        }

        // Check if we have SSH_ASKPASS
        if let Ok(askpass_prog) = env::var("SSH_ASKPASS")
            && !askpass_prog.is_empty()
        {
            // Check conditions for using ASKPASS
            let has_tty = atty::is(atty::Stream::Stdin);
            let has_display = env::var("DISPLAY").is_ok();

            if askpass_require == "force" {
                return Some(Box::new(AskpassPrompter::new(askpass_prog)));
            }

            if askpass_require == "prefer" {
                return Some(Box::new(AskpassPrompter::new(askpass_prog)));
            }

            // Default behavior: use ASKPASS if no TTY and DISPLAY is set
            if !has_tty && has_display {
                return Some(Box::new(AskpassPrompter::new(askpass_prog)));
            }
        }

        // Fall back to TTY if available
        if atty::is(atty::Stream::Stdin) {
            Some(Box::new(TtyPrompter))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    // Mock environment for testing
    struct MockEnv {
        vars: HashMap<String, String>,
        has_tty: bool,
    }

    impl MockEnv {
        fn new() -> Self {
            MockEnv {
                vars: HashMap::new(),
                has_tty: true,
            }
        }

        fn set_var(&mut self, key: &str, value: &str) {
            self.vars.insert(key.to_string(), value.to_string());
        }

        fn set_tty(&mut self, has_tty: bool) {
            self.has_tty = has_tty;
        }

        fn choose_prompter(&self) -> Option<String> {
            // Simulate the decision logic
            let askpass_require = self
                .vars
                .get("SSH_ASKPASS_REQUIRE")
                .map(|s| s.to_lowercase())
                .unwrap_or_default();

            if askpass_require == "never" {
                return if self.has_tty {
                    Some("TTY".to_string())
                } else {
                    None
                };
            }

            if let Some(askpass) = self.vars.get("SSH_ASKPASS") {
                if !askpass.is_empty() {
                    let has_display = self.vars.contains_key("DISPLAY");

                    if askpass_require == "force" || askpass_require == "prefer" {
                        return Some("ASKPASS".to_string());
                    }

                    if !self.has_tty && has_display {
                        return Some("ASKPASS".to_string());
                    }
                }
            }

            if self.has_tty {
                Some("TTY".to_string())
            } else {
                None
            }
        }
    }

    #[test]
    fn test_decision_matrix_tty_available() {
        let mut env = MockEnv::new();
        env.set_tty(true);

        // TTY available, no ASKPASS
        assert_eq!(env.choose_prompter(), Some("TTY".to_string()));

        // TTY available, ASKPASS set but no DISPLAY
        env.set_var("SSH_ASKPASS", "/usr/bin/askpass");
        assert_eq!(env.choose_prompter(), Some("TTY".to_string()));

        // TTY available, ASKPASS and DISPLAY set
        env.set_var("DISPLAY", ":0");
        assert_eq!(env.choose_prompter(), Some("TTY".to_string()));

        // TTY available, ASKPASS_REQUIRE=prefer
        env.set_var("SSH_ASKPASS_REQUIRE", "prefer");
        assert_eq!(env.choose_prompter(), Some("ASKPASS".to_string()));

        // TTY available, ASKPASS_REQUIRE=force
        env.set_var("SSH_ASKPASS_REQUIRE", "force");
        assert_eq!(env.choose_prompter(), Some("ASKPASS".to_string()));

        // TTY available, ASKPASS_REQUIRE=never
        env.set_var("SSH_ASKPASS_REQUIRE", "never");
        assert_eq!(env.choose_prompter(), Some("TTY".to_string()));
    }

    #[test]
    fn test_decision_matrix_no_tty() {
        let mut env = MockEnv::new();
        env.set_tty(false);

        // No TTY, no ASKPASS
        assert_eq!(env.choose_prompter(), None);

        // No TTY, ASKPASS but no DISPLAY
        env.set_var("SSH_ASKPASS", "/usr/bin/askpass");
        assert_eq!(env.choose_prompter(), None);

        // No TTY, ASKPASS and DISPLAY
        env.set_var("DISPLAY", ":0");
        assert_eq!(env.choose_prompter(), Some("ASKPASS".to_string()));

        // No TTY, ASKPASS_REQUIRE=force
        env.set_var("SSH_ASKPASS_REQUIRE", "force");
        assert_eq!(env.choose_prompter(), Some("ASKPASS".to_string()));

        // No TTY, ASKPASS_REQUIRE=never
        env.set_var("SSH_ASKPASS_REQUIRE", "never");
        assert_eq!(env.choose_prompter(), None);
    }
}
