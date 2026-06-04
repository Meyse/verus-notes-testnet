import type { StorageMode } from "./types";
import type { CloudReplicaSummary } from "./vaultWorkspaceRuntime";

export function shouldSeedInitialNoteAfterOpen(input: {
  cloudReplica?: CloudReplicaSummary;
  noteCount: number;
  storageMode: StorageMode | null | undefined;
}) {
  if (input.noteCount !== 0) return false;
  if (input.storageMode !== "sync_enabled") return true;
  return input.cloudReplica?.checked === true && input.cloudReplica.liveNoteCount === 0;
}
