use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RemotePath {
    server: String,
    share: Option<String>,
    path: Option<String>,
}

impl RemotePath {
    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn share(&self) -> Option<&str> {
        self.share.as_deref()
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

impl FromStr for RemotePath {
    type Err = smb::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let normalized = input.replace('/', "\\");
        let Some(relative) = normalized.strip_prefix("\\\\") else {
            return Err(smb::Error::InvalidArgument(
                "remote path must begin with two separators".into(),
            ));
        };
        let mut parts = relative.split('\\');
        let server = parts.next().unwrap_or_default();
        if server.is_empty() {
            return Err(smb::Error::InvalidArgument(
                "remote path requires a server".into(),
            ));
        }
        let share = parts.next().filter(|value| !value.is_empty());
        let remaining = parts.collect::<Vec<_>>();
        if remaining
            .iter()
            .any(|part| part.is_empty() || *part == "..")
        {
            return Err(smb::Error::InvalidArgument(
                "remote path must remain within its Share".into(),
            ));
        }
        let path = (!remaining.is_empty()).then(|| remaining.join("\\"));
        if let Some(share) = share {
            smb::ShareTarget::new(server, share)?;
        }
        Ok(Self {
            server: server.to_owned(),
            share: share.map(str::to_owned),
            path,
        })
    }
}

impl fmt::Display for RemotePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "\\\\{}", self.server)?;
        if let Some(share) = &self.share {
            write!(formatter, "\\{share}")?;
        }
        if let Some(path) = &self.path {
            write!(formatter, "\\{path}")?;
        }
        Ok(())
    }
}

/// Remote UNC or local filesystem path used by copy.
#[derive(Debug, Clone)]
pub enum Path {
    Local(std::path::PathBuf),
    Remote(RemotePath),
}

impl Path {
    pub fn as_local(&self) -> Option<&std::path::Path> {
        if let Self::Local(path) = self {
            Some(path)
        } else {
            None
        }
    }

    pub fn as_remote(&self) -> Option<&RemotePath> {
        if let Self::Remote(path) = self {
            Some(path)
        } else {
            None
        }
    }
}

impl FromStr for Path {
    type Err = smb::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.starts_with("\\\\") || input.starts_with("//") {
            Ok(Self::Remote(input.parse()?))
        } else {
            Ok(Self::Local(std::path::PathBuf::from(input)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_remote_identity_without_legacy_path_model() {
        let path: RemotePath = "//server/share/dir/file".parse().unwrap();
        assert_eq!(path.server(), "server");
        assert_eq!(path.share(), Some("share"));
        assert_eq!(path.path(), Some("dir\\file"));
        assert_eq!(path.to_string(), "\\\\server\\share\\dir\\file");
        assert!(
            "\\\\server\\share\\..\\escape"
                .parse::<RemotePath>()
                .is_err()
        );
    }
}
