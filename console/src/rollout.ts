import type { Rollout } from "./api/client";

// Kademeli dağıtım hazır ayarları: pilot halka, ardından genel dağıtım.
export const ROLLOUT_PRESETS = {
  none: null,
  pilot: {
    stages: [
      { percent: 10, delay_hours: 0 },
      { percent: 90, delay_hours: 24 },
    ],
    min_success_percent: 90,
  },
  rings: {
    stages: [
      { percent: 5, delay_hours: 0 },
      { percent: 25, delay_hours: 24 },
      { percent: 70, delay_hours: 72 },
    ],
    min_success_percent: 95,
  },
} satisfies Record<string, Rollout | null>;
export type RolloutPreset = keyof typeof ROLLOUT_PRESETS;
