import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

import {
  encryptedRecordCiphertextFields,
  encryptedRecordHeaderFields,
} from "./lib/encryptedRecords";

const ciphertextHeader = v.object({
  ...encryptedRecordHeaderFields,
  noteId: v.string(),
});

const folderCiphertextHeader = v.object({
  ...encryptedRecordHeaderFields,
  folderId: v.string(),
});

export default defineSchema({
	vaults: defineTable({
		vaultId: v.string(),
		backendAuthAlgorithm: v.string(),
		backendAuthKeyId: v.string(),
		backendAuthPublicKey: v.string(),
		backendAuthKeyVersion: v.number(),
		authStrength: v.optional(v.union(v.literal("backend_key"), v.literal("signer_attested"))),
		attestationProtocol: v.optional(v.string()),
		walletSignerIdentityHash: v.optional(v.string()),
		appIdentityHash: v.optional(v.string()),
		chain: v.optional(v.string()),
		derivationNumber: v.optional(v.number()),
		createdAtMs: v.number(),
		deletingAtMs: v.optional(v.number()),
		updatedAtMs: v.number(),
	}).index("by_vault_id", ["vaultId"]),

  challenges: defineTable({
    sessionId: v.string(),
    vaultId: v.string(),
    backendAuthAlgorithm: v.string(),
    backendAuthKeyId: v.string(),
    backendAuthPublicKey: v.string(),
    backendAuthKeyVersion: v.number(),
    appEncryptionRequestId: v.string(),
    appIdentityIAddress: v.string(),
    chain: v.optional(v.string()),
    challenge: v.string(),
    derivationNumber: v.number(),
    expiresAtMs: v.number(),
    walletSignerIdentityIAddress: v.string(),
    authStrength: v.optional(v.union(v.literal("backend_key"), v.literal("signer_attested"))),
    attestationProtocol: v.optional(v.string()),
    attestationIdHash: v.optional(v.string()),
    signerSessionIdHash: v.optional(v.string()),
    attestedAtMs: v.optional(v.number()),
    walletUnlockFreshUntilMs: v.optional(v.number()),
    createdAtMs: v.number(),
    usedAtMs: v.optional(v.number()),
  })
    .index("by_session_id", ["sessionId"])
    .index("by_vault_id", ["vaultId"])
    .index("by_expires_at", ["expiresAtMs"])
    .index("by_vault_created", ["vaultId", "createdAtMs"])
    .index("by_backend_key_created", ["backendAuthKeyId", "createdAtMs"]),

  sessions: defineTable({
    sessionTokenHash: v.string(),
    vaultId: v.string(),
    backendAuthAlgorithm: v.string(),
    backendAuthKeyId: v.string(),
    backendAuthPublicKey: v.string(),
    backendAuthKeyVersion: v.number(),
    authStrength: v.optional(v.union(v.literal("backend_key"), v.literal("signer_attested"))),
    attestationProtocol: v.optional(v.string()),
    attestedAtMs: v.optional(v.number()),
    walletUnlockFreshUntilMs: v.optional(v.number()),
    requiresFreshAttestationForCloudDelete: v.optional(v.boolean()),
    signerSessionIdHash: v.optional(v.string()),
    attestationIdHash: v.optional(v.string()),
    createdAtMs: v.number(),
    expiresAtMs: v.number(),
    lastSeenAtMs: v.number(),
  })
    .index("by_token_hash", ["sessionTokenHash"])
    .index("by_vault_id", ["vaultId"])
    .index("by_expires_at", ["expiresAtMs"]),

  rateLimits: defineTable({
    key: v.string(),
    count: v.number(),
    windowStartedAtMs: v.number(),
    updatedAtMs: v.number(),
  }).index("by_key", ["key"]),

  vaultUsage: defineTable({
    vaultId: v.string(),
    planKind: v.literal("free"),
    maxSyncedNotes: v.number(),
    maxStorageBytes: v.number(),
    liveSyncedNoteCount: v.number(),
    liveSyncedFolderCount: v.number(),
    liveStorageBytes: v.number(),
    updatedAtMs: v.number(),
  }).index("by_vault_id", ["vaultId"]),

	notes: defineTable({
		vaultId: v.string(),
		noteId: v.string(),
		header: ciphertextHeader,
		...encryptedRecordCiphertextFields,
		contentVersion: v.number(),
		accountedStorageBytes: v.optional(v.number()),
		cloudState: v.optional(v.union(v.literal("live"), v.literal("deleted"), v.literal("removed_from_sync"))),
		serverCreatedAtBucketMs: v.number(),
		serverUpdatedAtBucketMs: v.number(),
		serverDeletedAtBucketMs: v.optional(v.number()),
		serverRemovedFromSyncAtBucketMs: v.optional(v.number()),
		retentionExpiresAtBucketMs: v.optional(v.number()),
	})
	.index("by_vault_note", ["vaultId", "noteId"])
	.index("by_vault_updated", ["vaultId", "serverUpdatedAtBucketMs"])
	.index("by_retention_expiry", ["retentionExpiresAtBucketMs"]),

	folders: defineTable({
		vaultId: v.string(),
		folderId: v.string(),
		header: folderCiphertextHeader,
		...encryptedRecordCiphertextFields,
		contentVersion: v.number(),
		accountedStorageBytes: v.optional(v.number()),
		cloudState: v.optional(v.union(v.literal("live"), v.literal("deleted"), v.literal("removed_from_sync"))),
		serverCreatedAtBucketMs: v.number(),
		serverUpdatedAtBucketMs: v.number(),
		serverDeletedAtBucketMs: v.optional(v.number()),
		serverRemovedFromSyncAtBucketMs: v.optional(v.number()),
		retentionExpiresAtBucketMs: v.optional(v.number()),
	})
	.index("by_vault_folder", ["vaultId", "folderId"])
	.index("by_vault_updated", ["vaultId", "serverUpdatedAtBucketMs"])
	.index("by_retention_expiry", ["retentionExpiresAtBucketMs"]),
});
