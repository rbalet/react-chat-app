/*
 * Smoke test — Group messaging (Sender Keys).
 *
 * Simulates a group of 4 members (Alice, Bob, Carol, Dave). Alice creates
 * the group, distributes her sender key, and everyone exchanges messages.
 * Carol leaves: Alice rotates her key. Carol returns — she cannot read new
 * messages until she receives the rotated key.
 *
 * Usage:  pnpm run smoke:group
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
console.log("╔══════════════════════════════════════╗");
console.log("║  Sender Keys — Group Smoke Test     ║");
console.log("║  4 members · encrypt · rotate ·     ║");
console.log("║  departure · return                 ║");
console.log("╚══════════════════════════════════════╝");

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

// Alice sends new message after rotation — Bob and Dave can read, Carol cannot.
console.log("\n7. After rotation, Alice sends 'Post-rotation message'...");
const msgAfterRotate = await alice.manager.encryptGroupMessage(GROUP, "Post-rotation message");
const bobDecrypted = await bob.manager.decryptGroupMessage(GROUP, msgAfterRotate);
ok("Bob decrypts: " + bobDecrypted,
  () => { if (bobDecrypted !== "Post-rotation message") throw new Error(); });

const daveDecrypted = await dave.manager.decryptGroupMessage(GROUP, msgAfterRotate);
ok("Dave decrypts: " + daveDecrypted,
  () => { if (daveDecrypted !== "Post-rotation message") throw new Error(); });

// Carol should NOT be able to decrypt — she didn't get the rotated key
let carolRotateErr = null;
try {
  await carol.manager.decryptGroupMessage(GROUP, msgAfterRotate);
} catch (e) {
  carolRotateErr = e.message;
}
ok("Carol rejected (no rotated key — she is still excluded)", () => {
  if (!carolRotateErr) throw new Error("Carol should not be able to decrypt");
});

// The group keeps chatting while Carol is away.
// Alice sends more messages with her ROTATED key — Carol cannot read them.
console.log("\n7.5 Group keeps chatting while Carol is away...");
const msgWhileAway1 = await alice.manager.encryptGroupMessage(GROUP, "Where did Carol go?");
const msgWhileAway2 = await alice.manager.encryptGroupMessage(GROUP, "She left the moment.");
ok("Alice sends 2 messages with rotated key", () => {});
// Carol cannot read these (still excluded, no rotated Alice key)
let carolAwayErr = null;
try { await carol.manager.decryptGroupMessage(GROUP, msgWhileAway1); }
catch (e) { carolAwayErr = e.message; }
ok("Carol cannot read 'Where did Carol go?' (still excluded)", () => {
  if (!carolAwayErr) throw new Error("Carol should not decrypt while excluded");
});

// 8. Carol returns — gets the rotated key and can read ALL messages
// from the current chain, including those sent while she was away.
// (SenderKeyRecord keeps the new distributionId; once Carol has it,
// she can decrypt any message encrypted under it.)
console.log("\n8. Carol returns, receives rotated SKDM...");
await carol.manager.processSenderKeyDistribution(GROUP, "alice", newAliceSKDM);

// Carol can now read the missed messages (must decrypt in iteration order).
const carolMissed1 = await carol.manager.decryptGroupMessage(GROUP, msgAfterRotate);
ok("Carol reads: \"" + carolMissed1 + "\"", () => { if (carolMissed1 !== "Post-rotation message") throw new Error(); });
const carolMissed2 = await carol.manager.decryptGroupMessage(GROUP, msgWhileAway1);
ok("Carol reads: \"" + carolMissed2 + "\"", () => { if (carolMissed2 !== "Where did Carol go?") throw new Error(); });
const carolMissed3 = await carol.manager.decryptGroupMessage(GROUP, msgWhileAway2);
ok("Carol reads: \"" + carolMissed3 + "\"", () => { if (carolMissed3 !== "She left the moment.") throw new Error(); });

// New messages after return work normally
const nextMsg = await alice.manager.encryptGroupMessage(GROUP, "Welcome back Carol!");
const carolBack = await carol.manager.decryptGroupMessage(GROUP, nextMsg);
ok("Carol reads new message: \"" + carolBack + "\"",
  () => { if (carolBack !== "Welcome back Carol!") throw new Error(); });

// ---------------------------------------------------------------------------
const total = 4 /*create*/ + 1 /*SKDM*/ + 3 /*dist*/ + 3 /*msg1*/ + 2 /*replies*/
  + 1 /*dave err*/ + 1 /*dave ok*/ + 3 /*rotate+dist*/ + 3 /*post-rotate*/ + 1 /*away-ok*/
  + 2 /*away-reject*/ + 3 /*carol miss*/ + 1 /*carol back*/;
console.log(
  `\n${failures === 0 ? "╔══════════════════════════╗\n║" : "╔══════════════════════════╗\n║"}` +
  `  ${failures === 0 ? "  ALL SCENARIOS PASS  " : `  ${failures} FAILURE(S)         `}  ║\n` +
  "╚══════════════════════════╝"
);
process.exitCode = failures > 0 ? 1 : 0;
