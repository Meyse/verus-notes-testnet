use crate::local_store::SyncState;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IncomingRecordSource {
    ImportedLocal,
    RemoteSynced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MergeRecord<'a> {
    pub content_version: u64,
    pub deleted: bool,
    pub revision_hash: &'a str,
    pub sync_state: SyncState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MergeDecision {
    InsertIncoming,
    Unchanged { mark_synced: bool },
    ReplaceWithIncoming,
    KeepLocalAsPending { sync_state: SyncState },
    ReplaceWithIncomingAndStoreLocalConflict,
    StoreIncomingConflict,
}

pub(crate) fn decide_merge(
    existing: Option<MergeRecord<'_>>,
    incoming: MergeRecord<'_>,
    source: IncomingRecordSource,
) -> MergeDecision {
    let Some(existing) = existing else {
        return MergeDecision::InsertIncoming;
    };

    if existing.revision_hash == incoming.revision_hash {
        return MergeDecision::Unchanged {
            mark_synced: source == IncomingRecordSource::RemoteSynced,
        };
    }

    if incoming.content_version > existing.content_version && !is_pending(existing.sync_state) {
        return MergeDecision::ReplaceWithIncoming;
    }

    if existing.content_version > incoming.content_version {
        return MergeDecision::KeepLocalAsPending {
            sync_state: pending_sync_state_for_deleted(existing.deleted),
        };
    }

    if source == IncomingRecordSource::RemoteSynced && is_pending(existing.sync_state) {
        return MergeDecision::ReplaceWithIncomingAndStoreLocalConflict;
    }

    MergeDecision::StoreIncomingConflict
}

pub(crate) fn pending_sync_state_for_deleted(deleted: bool) -> SyncState {
    if deleted {
        SyncState::PendingDelete
    } else {
        SyncState::PendingUpsert
    }
}

pub(crate) fn conflict_record_id(kind: &str, record_id: &str, revision_hash: &str) -> String {
    let suffix = revision_hash.chars().take(16).collect::<String>();
    format!("{kind}-conflict-{record_id}-{suffix}")
}

fn is_pending(sync_state: SyncState) -> bool {
    matches!(
        sync_state,
        SyncState::PendingUpsert | SyncState::PendingDelete
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(
        content_version: u64,
        revision_hash: &'static str,
        sync_state: SyncState,
    ) -> MergeRecord<'static> {
        MergeRecord {
            content_version,
            deleted: false,
            revision_hash,
            sync_state,
        }
    }

    #[test]
    fn inserts_missing_incoming_record() {
        assert_eq!(
            decide_merge(
                None,
                record(1, "incoming", SyncState::Synced),
                IncomingRecordSource::RemoteSynced
            ),
            MergeDecision::InsertIncoming
        );
    }

    #[test]
    fn marks_matching_remote_record_synced() {
        assert_eq!(
            decide_merge(
                Some(record(1, "same", SyncState::PendingUpsert)),
                record(1, "same", SyncState::Synced),
                IncomingRecordSource::RemoteSynced
            ),
            MergeDecision::Unchanged { mark_synced: true }
        );
    }

    #[test]
    fn replaces_clean_older_local_record() {
        assert_eq!(
            decide_merge(
                Some(record(1, "local", SyncState::Synced)),
                record(2, "remote", SyncState::Synced),
                IncomingRecordSource::RemoteSynced
            ),
            MergeDecision::ReplaceWithIncoming
        );
    }

    #[test]
    fn keeps_newer_local_record_pending() {
        assert_eq!(
            decide_merge(
                Some(record(3, "local", SyncState::Synced)),
                record(2, "remote", SyncState::Synced),
                IncomingRecordSource::RemoteSynced
            ),
            MergeDecision::KeepLocalAsPending {
                sync_state: SyncState::PendingUpsert,
            }
        );
    }

    #[test]
    fn remote_replaces_pending_local_record_and_stores_local_conflict() {
        assert_eq!(
            decide_merge(
                Some(record(2, "local", SyncState::PendingUpsert)),
                record(2, "remote", SyncState::Synced),
                IncomingRecordSource::RemoteSynced
            ),
            MergeDecision::ReplaceWithIncomingAndStoreLocalConflict
        );
    }

    #[test]
    fn import_conflicts_with_pending_local_record_without_replacing_it() {
        assert_eq!(
            decide_merge(
                Some(record(2, "local", SyncState::PendingUpsert)),
                record(2, "import", SyncState::PendingUpsert),
                IncomingRecordSource::ImportedLocal
            ),
            MergeDecision::StoreIncomingConflict
        );
    }
}
