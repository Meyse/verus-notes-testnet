import { cronJobs } from "convex/server";

import { internal } from "./_generated/api";

const internalApi = internal as any;

const crons = cronJobs();

crons.interval(
  "cleanup expired privacy metadata",
  { minutes: 15 },
  internalApi.auth.cleanupExpiredMetadataRows,
  {},
);

export default crons;
