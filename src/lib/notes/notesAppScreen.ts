export type NotesAppScreen = "locked" | "storage" | "workspace";

export function deriveNotesAppScreen(input: {
  isLockedAccessBlocking: boolean;
  isStorageOnboardingOpen: boolean;
  isUnlocked: boolean;
}): NotesAppScreen {
  if (input.isUnlocked) return "workspace";
  if (input.isLockedAccessBlocking) return "locked";
  if (input.isStorageOnboardingOpen) return "storage";
  return "locked";
}
