/**
 * Smoke test — Group messaging (Sender Keys).
 *
 * Simulates a group of 4 members (Alice, Bob, Carol, Dave). Alice creates the
 * group, distributes her sender key, and everyone exchanges messages. Carol
 * leaves: Alice rotates her key. Carol returns — she cannot read new messages
 * until she receives the rotated key.
 *
 * Usage:  node smoke-group.mjs
 *         or: pnpm install && pnpm run test:smoke
 */

import {
  InMemorySignalProtocolStore,
  SignalProtocolManager,
} from './src/signal/index.js';

// ---------------------------------------------------------------------------
// Fake key server — stores prekey bundles in a local Map (same origin PoC).
// Matches the KeyServerClient contract from the signal-protocol module.
// ---------------------------------------------------------------------------
class SmokeKeyServer {
  /** @type {Map<string, import("./src/signal").SerializedPreKeyBundle>} */
  bundles = new Map();

  async publishKeys(userId, keys) {
    // Build a SerializedPreKeyBundle from the PublishedKeys payload.
    const bundle = {
      registrationId: keys.registrationId,
      identityKey: keys.identityKey,
      signedPreKey: {
        id: keys.signedPreKey.id,
        publicKey: keys.signedPreKey.publicKey,
        signature: keys.signedPreKey.signature,
      },
      oneTimePreKey: keys.oneTimePreKeys[0]
        ? { id: keys.oneTimePreKeys[0].id, publicKey: keys.oneTimePreKeys[0].publicKey }
        : undefined,
    };
    this.bundles.set(userId, bundle);
  }

  async fetchPreKeyBundle(userId) {
    const bundle = this.bundles.get(userId);
    if (!bundle) throw new Error(`NO_BUNDLE: ${userId}`);
    return bundle;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
let failures = 0;
function ok(label, fn) {
  try {
    fn();
    console.log(`  ${PASS} ${label}`);
  } catch (e) {
    console.log(`  ${FAIL} ${label} — ${e.message}`);
    failures++;
  }
}

async function createMember(name, server) {
  const store = new InMemorySignalProtocolStore();
  const manager = new SignalProtocolManager(name, store, server);
  await manager.initialize();
  return { name, store, manager };
}

// ---------------------------------------------------------------------------
// Scenario
// ---------------------------------------------------------------------------
console.log("\n=== Sender Keys group smoke test ===\n");

const server = new SmokeKeyServer();

// 1. Create members
console.log("1. Creating 4 members...");
const alice = await createMember("alice", server);
const bob = await createMember("bob", server);
const carol = await createMember("carol", server);
const dave = await createMember("dave", server);
console.log(`  ${PASS} Alice, Bob, Carol, Dave initialized\n`);

// 2. Alice sets up her sender key for the group
console.log("2. Alice sets up sender key for group 'test-group'...");
const GROUP = "test-group";
await alice.manager.setupSenderKey(GROUP);
const aliceSKDM = await alice.manager.getSenderKeyDistribution(GROUP);
ok("Alice SKDM created", () => { if (!aliceSKDM) throw new Error("no SKDM"); });

// 3. Distribute Alice's SKDM to all members
console.log("\n3. Distributing Alice's SKDM to Bob, Carol, Dave...");
for (const member of [bob, carol, dave]) {
  await member.manager.processSenderKeyDistribution(GROUP, "alice", aliceSKDM);
  console.log(`  ${PASS} ${member.name} received Alice's SKDM`);
}

// 4. Alice sends a group message — everyone decrypts
console.log("\n4. Alice sends group message: 'Hello everyone!'");
const msg1 = await alice.manager.encryptGroupMessage(GROUP, "Hello everyone!");
for (const member of [bob, carol, dave]) {
  const plain = await member.manager.decryptGroupMessage(GROUP, msg1);
  ok(`${member.name} decrypts: "${plain}"`, () => {
    if (plain !== "Hello everyone!") throw new Error(`got "${plain}"`);
  });
}

// 5. Bob and Carol reply
console.log("\n5. Bob and Carol set up their own sender keys and reply...");

await bob.manager.setupSenderKey(GROUP);
const bobSKDM = await bob.manager.getSenderKeyDistribution(GROUP);
await alice.manager.processSenderKeyDistribution(GROUP, "bob", bobSKDM);
await carol.manager.processSenderKeyDistribution(GROUP, "bob", bobSKDM);
await dave.manager.processSenderKeyDistribution(GROUP, "bob", bobSKDM);

const bobMsg = await bob.manager.encryptGroupMessage(GROUP, "Hey from Bob!");
const bobPlain = await alice.manager.decryptGroupMessage(GROUP, bobMsg);
ok("Alice decrypts Bob: " + bobPlain, () => { if (bobPlain !== "Hey from Bob!") throw new Error(); });

await carol.manager.setupSenderKey(GROUP);
const carolSKDM = await carol.manager.getSenderKeyDistribution(GROUP);
await alice.manager.processSenderKeyDistribution(GROUP, "carol", carolSKDM);
const carolMsg = await carol.manager.encryptGroupMessage(GROUP, "Carol here!");
const carolPlain = await alice.manager.decryptGroupMessage(GROUP, carolMsg);
ok("Alice decrypts Carol: " + carolPlain, () => { if (carolPlain !== "Carol here!") throw new Error(); });

// 6. Dave without sender key — can he send?
console.log("\n6. Dave (no sender key yet) tries to encrypt...");
let daveErr = null;
try {
  await dave.manager.encryptGroupMessage(GROUP, "Should fail");
} catch (e) {
  daveErr = e.message;
}
ok("Dave encrypt rejected (no sender key)", () => {
  if (!daveErr || !daveErr.includes("No sender key")) throw new Error(daveErr || "no error");
});

// Setup Dave too
await dave.manager.setupSenderKey(GROUP);
const daveSKDM = await dave.manager.getSenderKeyDistribution(GROUP);
await alice.manager.processSenderKeyDistribution(GROUP, "dave", daveSKDM);
const daveMsg2 = await dave.manager.encryptGroupMessage(GROUP, "Dave finally!");
const davePlain = await alice.manager.decryptGroupMessage(GROUP, daveMsg2);
ok("Alice decrypts Dave: " + davePlain, () => { if (davePlain !== "Dave finally!") throw new Error(); });

// 7. Carol leaves — Alice rotates her sender key
console.log("\n7. Carol leaves the group. Alice rotates her sender key...");
const newAliceSKDM = await alice.manager.rotateSenderKey(GROUP);

// Distribute to Bob and Dave only (NOT Carol)
await bob.manager.processSenderKeyDistribution(GROUP, "alice", newAliceSKDM);
await dave.manager.processSenderKeyDistribution(GROUP, "alice", newAliceSKDM);
console.log(`  ${PASS} New key distributed to Bob and Dave (Carol excluded)`);

// Alice sends new message after rotation
const msgAfterRotate = await alice.manager.encryptGroupMessage(GROUP, "Post-rotation message");
const bobDecrypted = await bob.manager.decryptGroupMessage(GROUP, msgAfterRotate);
ok("Bob decrypts post-rotation: " + bobDecrypted,
  () => { if (bobDecrypted !== "Post-rotation message") throw new Error(); });

const daveDecrypted = await dave.manager.decryptGroupMessage(GROUP, msgAfterRotate);
ok("Dave decrypts post-rotation: " + daveDecrypted,
  () => { if (daveDecrypted !== "Post-rotation message") throw new Error(); });

// Carol should NOT be able to decrypt (she didn't get the new SKDM)
let carolRotateErr = null;
try {
  await carol.manager.decryptGroupMessage(GROUP, msgAfterRotate);
} catch (e) {
  carolRotateErr = e.message;
}
ok("Carol rejected (no rotated key)", () => {
  if (!carolRotateErr) throw new Error("Carol should not be able to decrypt");
});

// 8. Carol returns — gets the rotated key and can read new messages
console.log("\n8. Carol returns, receives rotated SKDM...");
await carol.manager.processSenderKeyDistribution(GROUP, "alice", newAliceSKDM);
const nextMsg = await alice.manager.encryptGroupMessage(GROUP, "Welcome back Carol!");
const carolBack = await carol.manager.decryptGroupMessage(GROUP, nextMsg);
ok("Carol decrypts after receiving rotated key: " + carolBack,
  () => { if (carolBack !== "Welcome back Carol!") throw new Error(); });

// 9. After receiving the rotated key, Carol CAN read the post-rotation
// message she missed (SenderKeyRecord keeps old states for transition).
// The security property is: Carol could NOT read it BEFORE step 8.
console.log("\n9. After receiving rotated key, Carol reads the message she missed...");
const carolMissed = await carol.manager.decryptGroupMessage(GROUP, msgAfterRotate);
ok("Carol CAN read missed message after rotation key: " + carolMissed,
  () => { if (carolMissed !== "Post-rotation message") throw new Error(); });

// ---------------------------------------------------------------------------
console.log(`\n${failures === 0 ? PASS : FAIL} ${failures} failure(s) total\n`);
process.exitCode = failures > 0 ? 1 : 0;
