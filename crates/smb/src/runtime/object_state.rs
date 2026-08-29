//! Generation-aware domain object authority.
//!
//! Tokens are opaque outside the runtime. The registry commits hierarchy
//! changes synchronously, so callers can never observe a partially revoked or
//! partially replaced dependency chain.

use super::GenerationId;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ObjectToken {
    generation: GenerationId,
    id: u64,
    epoch: u64,
}

impl ObjectToken {
    pub(crate) const fn generation(self) -> GenerationId {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectKind {
    Connection,
    Session,
    Share,
    Resource,
}

impl ObjectKind {
    const fn accepts_parent(self, parent: Self) -> bool {
        matches!(
            (parent, self),
            (Self::Connection, Self::Session)
                | (Self::Session, Self::Share)
                | (Self::Share, Self::Resource)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectPhase {
    Active,
    Recovering,
    Revoked,
    Closing,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectError {
    ForeignGeneration,
    Unknown,
    Stale,
    ParentNotActive,
    InvalidParent,
    IdExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CloseDecision {
    OwnProtocolClose,
    AwaitExistingClose,
    AlreadyClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectEffect {
    Revoked(ObjectToken),
    ReplacementPublished {
        previous: ObjectToken,
        replacement: ObjectToken,
    },
}

#[derive(Clone, Copy, Debug)]
struct ObjectRecord {
    token: ObjectToken,
    kind: ObjectKind,
    parent: Option<ObjectToken>,
    phase: ObjectPhase,
}

pub(crate) struct ObjectRegistry {
    generation: GenerationId,
    next_id: Option<u64>,
    records: HashMap<u64, ObjectRecord>,
    connection: ObjectToken,
}

impl ObjectRegistry {
    pub(crate) fn new(generation: GenerationId) -> Self {
        let connection = ObjectToken {
            generation,
            id: 0,
            epoch: 0,
        };
        Self {
            generation,
            next_id: Some(1),
            records: HashMap::from([(
                0,
                ObjectRecord {
                    token: connection,
                    kind: ObjectKind::Connection,
                    parent: None,
                    phase: ObjectPhase::Active,
                },
            )]),
            connection,
        }
    }

    pub(crate) const fn connection(&self) -> ObjectToken {
        self.connection
    }

    pub(crate) fn create_child(
        &mut self,
        parent: ObjectToken,
        kind: ObjectKind,
    ) -> Result<ObjectToken, ObjectError> {
        let parent_record = self.record(parent)?;
        if !kind.accepts_parent(parent_record.kind) {
            return Err(ObjectError::InvalidParent);
        }
        if parent_record.phase != ObjectPhase::Active {
            return Err(ObjectError::ParentNotActive);
        }
        let id = self.next_id.ok_or(ObjectError::IdExhausted)?;
        self.next_id = id.checked_add(1);
        let token = ObjectToken {
            generation: self.generation,
            id,
            epoch: 0,
        };
        self.records.insert(
            id,
            ObjectRecord {
                token,
                kind,
                parent: Some(parent),
                phase: ObjectPhase::Active,
            },
        );
        Ok(token)
    }

    pub(crate) fn validate_active(&self, token: ObjectToken) -> Result<(), ObjectError> {
        let mut current = Some(token);
        while let Some(token) = current {
            let record = self.record(token)?;
            if record.phase != ObjectPhase::Active {
                return Err(ObjectError::ParentNotActive);
            }
            current = record.parent;
        }
        Ok(())
    }

    pub(crate) fn begin_recovery(&mut self, token: ObjectToken) -> Result<(), ObjectError> {
        self.validate_active(token)?;
        self.record_mut(token)?.phase = ObjectPhase::Recovering;
        Ok(())
    }

    pub(crate) fn publish_replacement(
        &mut self,
        token: ObjectToken,
    ) -> Result<ObjectEffect, ObjectError> {
        let record = self.record_mut(token)?;
        if record.phase != ObjectPhase::Recovering {
            return Err(ObjectError::ParentNotActive);
        }
        let epoch = record.token.epoch.checked_add(1).ok_or(ObjectError::IdExhausted)?;
        let replacement = ObjectToken { epoch, ..record.token };
        let previous = record.token;
        record.token = replacement;
        record.phase = ObjectPhase::Active;
        for child in self.records.values_mut() {
            if child.parent == Some(previous) {
                child.parent = Some(replacement);
            }
        }
        Ok(ObjectEffect::ReplacementPublished {
            previous,
            replacement,
        })
    }

    pub(crate) fn begin_close(
        &mut self,
        token: ObjectToken,
    ) -> Result<CloseDecision, ObjectError> {
        let record = self.record_mut(token)?;
        match record.phase {
            ObjectPhase::Active | ObjectPhase::Recovering => {
                record.phase = ObjectPhase::Closing;
                Ok(CloseDecision::OwnProtocolClose)
            }
            ObjectPhase::Closing => Ok(CloseDecision::AwaitExistingClose),
            ObjectPhase::Revoked | ObjectPhase::Closed => Ok(CloseDecision::AlreadyClosed),
        }
    }

    pub(crate) fn complete_close(
        &mut self,
        token: ObjectToken,
    ) -> Result<Vec<ObjectEffect>, ObjectError> {
        self.record(token)?;
        let mut effects = self.revoke_descendants(token);
        self.record_mut(token)?.phase = ObjectPhase::Closed;
        effects.sort_by_key(|effect| match effect {
            ObjectEffect::Revoked(token) => token.id,
            ObjectEffect::ReplacementPublished { replacement, .. } => replacement.id,
        });
        Ok(effects)
    }

    pub(crate) fn lose_generation(&mut self) -> Vec<ObjectEffect> {
        let mut effects = self
            .records
            .values_mut()
            .filter_map(|record| {
                if matches!(record.phase, ObjectPhase::Revoked | ObjectPhase::Closed) {
                    None
                } else {
                    record.phase = ObjectPhase::Revoked;
                    Some(ObjectEffect::Revoked(record.token))
                }
            })
            .collect::<Vec<_>>();
        effects.sort_by_key(|effect| match effect {
            ObjectEffect::Revoked(token) => token.id,
            ObjectEffect::ReplacementPublished { replacement, .. } => replacement.id,
        });
        effects
    }

    fn revoke_descendants(&mut self, ancestor: ObjectToken) -> Vec<ObjectEffect> {
        let ids = self
            .records
            .values()
            .filter(|record| self.is_descendant(record.token, ancestor))
            .map(|record| record.token.id)
            .collect::<Vec<_>>();
        ids.into_iter()
            .filter_map(|id| {
                let record = self.records.get_mut(&id)?;
                if matches!(record.phase, ObjectPhase::Revoked | ObjectPhase::Closed) {
                    None
                } else {
                    record.phase = ObjectPhase::Revoked;
                    Some(ObjectEffect::Revoked(record.token))
                }
            })
            .collect()
    }

    fn is_descendant(&self, candidate: ObjectToken, ancestor: ObjectToken) -> bool {
        let mut parent = self.records.get(&candidate.id).and_then(|record| record.parent);
        while let Some(token) = parent {
            if token == ancestor {
                return true;
            }
            parent = self.records.get(&token.id).and_then(|record| record.parent);
        }
        false
    }

    fn record(&self, token: ObjectToken) -> Result<&ObjectRecord, ObjectError> {
        if token.generation != self.generation {
            return Err(ObjectError::ForeignGeneration);
        }
        let record = self.records.get(&token.id).ok_or(ObjectError::Unknown)?;
        if record.token != token {
            return Err(ObjectError::Stale);
        }
        Ok(record)
    }

    fn record_mut(&mut self, token: ObjectToken) -> Result<&mut ObjectRecord, ObjectError> {
        if token.generation != self.generation {
            return Err(ObjectError::ForeignGeneration);
        }
        let record = self.records.get_mut(&token.id).ok_or(ObjectError::Unknown)?;
        if record.token != token {
            return Err(ObjectError::Stale);
        }
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hierarchy() -> (ObjectRegistry, [ObjectToken; 4]) {
        let mut registry = ObjectRegistry::new(GenerationId::new(7));
        let connection = registry.connection();
        let session = registry.create_child(connection, ObjectKind::Session).unwrap();
        let share = registry.create_child(session, ObjectKind::Share).unwrap();
        let resource = registry.create_child(share, ObjectKind::Resource).unwrap();
        (registry, [connection, session, share, resource])
    }

    #[test]
    fn hierarchy_rejects_skipped_parent_kinds() {
        let mut registry = ObjectRegistry::new(GenerationId::new(7));
        assert_eq!(
            registry.create_child(registry.connection(), ObjectKind::Resource),
            Err(ObjectError::InvalidParent)
        );
    }

    #[test]
    fn parent_close_revokes_every_descendant_once() {
        let (mut registry, [_, session, share, resource]) = hierarchy();
        assert_eq!(
            registry.begin_close(session),
            Ok(CloseDecision::OwnProtocolClose)
        );
        assert_eq!(
            registry.begin_close(session),
            Ok(CloseDecision::AwaitExistingClose)
        );
        assert_eq!(
            registry.complete_close(session).unwrap(),
            vec![ObjectEffect::Revoked(share), ObjectEffect::Revoked(resource)]
        );
        assert!(registry.complete_close(session).unwrap().is_empty());
    }

    #[test]
    fn generation_loss_is_atomic_idempotent_and_rejects_all_old_tokens() {
        let (mut registry, tokens) = hierarchy();
        assert_eq!(registry.lose_generation().len(), tokens.len());
        assert!(registry.lose_generation().is_empty());
        for token in tokens {
            assert_eq!(
                registry.validate_active(token),
                Err(ObjectError::ParentNotActive)
            );
        }
    }

    #[test]
    fn replacement_publication_makes_previous_token_stale() {
        let (mut registry, [_, session, _, _]) = hierarchy();
        registry.begin_recovery(session).unwrap();
        let ObjectEffect::ReplacementPublished {
            previous,
            replacement,
        } = registry.publish_replacement(session).unwrap()
        else {
            panic!("expected replacement effect")
        };
        assert_eq!(previous, session);
        assert_eq!(registry.validate_active(previous), Err(ObjectError::Stale));
        assert_eq!(registry.validate_active(replacement), Ok(()));
    }

    #[test]
    fn foreign_generation_is_rejected_before_registry_lookup() {
        let (registry, [_, session, _, _]) = hierarchy();
        let foreign = ObjectToken {
            generation: GenerationId::new(8),
            ..session
        };
        assert_eq!(
            registry.validate_active(foreign),
            Err(ObjectError::ForeignGeneration)
        );
    }
}
