//! D-Bus notification system for SSH key approval
//!
//! This module provides a D-Bus-based notification system that prompts users
//! for approval when SSH keys with confirmation constraints are used.

use rssh_core::{Error, Result};
use std::time::Duration;
use tokio::time::timeout;
use zbus::{Connection, Result as ZBusResult};

/// D-Bus notification service for SSH key approval
pub struct DbusNotificationService {
    connection: Option<Connection>,
}

impl DbusNotificationService {
    /// Create a new D-Bus notification service
    pub async fn new() -> Self {
        let connection = match Connection::session().await {
            Ok(conn) => {
                tracing::info!("Connected to D-Bus session bus for notifications");
                Some(conn)
            }
            Err(e) => {
                tracing::warn!("Failed to connect to D-Bus session bus: {}", e);
                tracing::warn!("Key approval notifications will be disabled");
                None
            }
        };

        Self { connection }
    }

    /// Show a notification asking for SSH key usage approval
    /// Returns true if approved, false if denied, or an error if the notification system failed
    pub async fn request_key_approval(
        &self,
        fingerprint: &str,
        description: &str,
        key_type: &str,
        timeout_secs: u64,
    ) -> Result<bool> {
        let connection = match &self.connection {
            Some(conn) => conn,
            None => {
                tracing::warn!("D-Bus connection not available, denying key usage");
                return Ok(false);
            }
        };

        let summary = "SSH Key Usage Request";
        let body = format!(
            "Allow use of {} key '{}'?\n\nFingerprint: {}...",
            key_type,
            description,
            &fingerprint[..12]
        );

        // Show notification with action buttons
        let notification_result = timeout(
            Duration::from_secs(timeout_secs),
            self.show_approval_notification(connection, summary, &body),
        )
        .await;

        match notification_result {
            Ok(Ok(approved)) => {
                tracing::info!(
                    "User {} SSH key usage for {}",
                    if approved { "approved" } else { "denied" },
                    &fingerprint[..12]
                );
                Ok(approved)
            }
            Ok(Err(e)) => {
                tracing::error!("D-Bus notification failed: {}", e);
                Err(Error::Internal(format!(
                    "Failed to show notification: {}",
                    e
                )))
            }
            Err(_) => {
                tracing::warn!(
                    "SSH key approval notification timed out after {} seconds, denying access",
                    timeout_secs
                );
                Ok(false) // Timeout means denial
            }
        }
    }

    /// Show the actual notification with approval/denial buttons using the freedesktop notifications spec
    async fn show_approval_notification(
        &self,
        connection: &Connection,
        summary: &str,
        body: &str,
    ) -> ZBusResult<bool> {
        use zbus::proxy;

        // Use the org.freedesktop.Notifications D-Bus interface
        #[proxy(
            interface = "org.freedesktop.Notifications",
            default_service = "org.freedesktop.Notifications",
            default_path = "/org/freedesktop/Notifications"
        )]
        trait Notifications {
            async fn notify(
                &self,
                app_name: &str,
                replaces_id: u32,
                app_icon: &str,
                summary: &str,
                body: &str,
                actions: Vec<&str>,
                hints: std::collections::HashMap<&str, zbus::zvariant::Value<'_>>,
                expire_timeout: i32,
            ) -> zbus::Result<u32>;

            #[zbus(signal)]
            async fn action_invoked(&self, id: u32, action_key: &str) -> zbus::Result<()>;

            #[zbus(signal)]
            async fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;
        }

        let proxy = NotificationsProxy::new(connection).await?;

        // Create notification with Approve/Deny buttons
        let actions = vec!["approve", "Approve", "deny", "Deny"];
        let mut hints = std::collections::HashMap::new();

        // Set urgency to critical for security notifications
        hints.insert("urgency", zbus::zvariant::Value::U8(2));
        hints.insert("category", zbus::zvariant::Value::Str("security".into()));

        // Make notification persistent until user responds
        let expire_timeout = 0; // 0 means no timeout

        let notification_id = proxy
            .notify(
                "rssh-agent",
                0,
                "security-high", // Icon name
                summary,
                body,
                actions,
                hints,
                expire_timeout,
            )
            .await?;

        tracing::debug!("Showed notification with ID: {}", notification_id);

        // Listen for the user's response
        use tokio_stream::StreamExt;

        let mut action_stream = proxy.receive_action_invoked().await?;
        let mut closed_stream = proxy.receive_notification_closed().await?;

        tokio::select! {
            Some(signal) = action_stream.next() => {
                let args = signal.args()?;
                if args.id == notification_id {
                    match args.action_key {
                        "approve" => {
                            tracing::debug!("User approved SSH key usage");
                            Ok(true)
                        }
                        "deny" => {
                            tracing::debug!("User denied SSH key usage");
                            Ok(false)
                        }
                        _ => {
                            tracing::warn!("Unknown action: {}", args.action_key);
                            Ok(false)
                        }
                    }
                } else {
                    tracing::debug!("Received action for different notification ID: {}", args.id);
                    Ok(false)
                }
            }
            Some(signal) = closed_stream.next() => {
                let args = signal.args()?;
                if args.id == notification_id {
                    tracing::debug!("Notification closed without action (reason: {})", args.reason);
                    Ok(false) // Closed without explicit approval means denial
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Check if D-Bus notifications are available
    pub fn is_available(&self) -> bool {
        self.connection.is_some()
    }
}