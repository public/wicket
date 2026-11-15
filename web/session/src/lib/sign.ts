// Every signed action from the session view goes through one sheet, as on the console's page (#124):
// a tap asks the server for the action, the sheet states the server's reading of it, pinned to the
// top of the screen (above where a phone's passkey sheet opens), with its own sign button that can't
// be tapped for a moment. One at a time.
import { shallowRef } from 'vue';
import { begin, finish, type Begun } from './wicket';

export interface Sheet {
  begun: Begun;
  waiting: boolean;
  error: string;
  go: () => void;
  cancel: () => void;
}

export const sheet = shallowRef<Sheet | null>(null);
/** How long the sign button stays disabled after the sheet opens (the console's SETTLE_MS). */
export const SETTLE_MS = 800;

/** Begins `body`, shows it, and on the sign tap has the passkey sign it: the server's answer, or
 * null if the operator cancelled. Throws what begin or finish refused. */
export async function signed(body: Record<string, unknown>): Promise<any | null> {
  if (sheet.value) return null;
  const b = await begin(body);
  return new Promise((resolve, reject) => {
    const s: Sheet = {
      begun: b,
      waiting: false,
      error: '',
      go: async () => {
        sheet.value = { ...s, waiting: true };
        try {
          resolve(await finish(b));
        } catch (e) {
          reject(e);
        } finally {
          sheet.value = null;
        }
      },
      cancel: () => {
        sheet.value = null;
        resolve(null);
      },
    };
    sheet.value = s;
  });
}
