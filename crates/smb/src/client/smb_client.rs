use std::{collections::HashMap, net::IpAddr, sync::Arc};

use smb_transport::utils::TransportUtils;
use tokio::sync::RwLock;

use crate::connection::{Connection, ConnectionConfig};

use super::config::ClientConfig;

/// Connection owner used by the domain runtime.
///
/// Session, Share, and Resource lifecycles live above this type. This module
/// only deduplicates physical server connections and closes those it owns.
pub struct Client {
    config: ClientConfig,
    connections: RwLock<HashMap<IpAddr, Arc<Connection>>>,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            connections: RwLock::new(HashMap::new()),
        }
    }

    pub async fn connect(&self, server: &str) -> crate::Result<Arc<Connection>> {
        let server_address = TransportUtils::parse_socket_address(server)?;
        let address = server_address.ip();
        if let Some(connection) = self.connections.read().await.get(&address).cloned() {
            return Ok(connection);
        }

        let connection = Arc::new(Connection::build(
            server,
            server_address,
            self.config.client_guid,
            ConnectionConfig {
                ..self.config.connection.clone()
            },
        )?);
        connection.connect().await?;

        let mut connections = self.connections.write().await;
        if let Some(existing) = connections.get(&address).cloned() {
            drop(connections);
            connection.close().await.ok();
            return Ok(existing);
        }
        connections.insert(address, connection.clone());
        Ok(connection)
    }

    pub async fn close(&self) -> crate::Result<()> {
        let connections = {
            let mut owned = self.connections.write().await;
            owned
                .drain()
                .map(|(_, connection)| connection)
                .collect::<Vec<_>>()
        };
        let mut first_error = None;
        for connection in connections {
            if let Err(error) = connection.close().await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new(ClientConfig::default())
    }
}
