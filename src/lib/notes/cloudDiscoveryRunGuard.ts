export type CloudDiscoveryRunSnapshot<TVault, TUnlockInput> = {
  runId: number;
  storageOnboardingOpen: boolean;
  unlockInput: TUnlockInput | null;
  vault: TVault | null;
};

export type CloudDiscoveryRunExpectation<TVault, TUnlockInput> = {
  runId: number;
  unlockInput: TUnlockInput;
  vault: TVault;
};

export function isCloudDiscoveryRunCurrent<TVault, TUnlockInput>(
  expected: CloudDiscoveryRunExpectation<TVault, TUnlockInput>,
  current: CloudDiscoveryRunSnapshot<TVault, TUnlockInput>
) {
  return (
    current.storageOnboardingOpen &&
    current.runId === expected.runId &&
    current.vault === expected.vault &&
    current.unlockInput === expected.unlockInput
  );
}
