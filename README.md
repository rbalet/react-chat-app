# A Secure Chat Application using React and the Signal Protocol

> **⚠️ 2026 — Repurposed as a Signal Protocol PoC.** This repo now hosts a
> **from-scratch, clean-room TypeScript implementation** of the Signal
> Protocol (X3DH + Double Ratchet) in [`src/signal/`](src/signal/README.md),
> built on `@noble` crypto and licensed Apache-2.0. The old vendored
> `libsignal-protocol.js` (GPL) is gone, and the build moved from
> Create React App to **Vite** (`npm run dev`, tests with `npm test`).
> Read **[BRIEF.md](BRIEF.md)** for the plan; the sections below describe
> the original 2021 demo app and are partially outdated.

## Technology Stack
1. ReactJS library for UI
2. Signal Protocol Implementation for E2EE — from-scratch module in `src/signal/`
3. Axios for AJAX calls
4. LocalStorage to store/fetch Pre-key bundle and Chats/Conversations
5. Web Sockets Implementation for Instant Messaging

## To Initialize the Frontend of this Project use the command -
` npm run dev `

## Components
1. Login
2. Chat Window
    1. Contact List
    2. Message Box

## Axios Calls
1. GET - api/users/login/userName - Returns User Object of the given User
2. GET - api/users/users/userId/role - Returns Users Array other than the given User with given role

## Web Sockets
1. Establishing WS Connection: `let webSocket = new WebSocket("ws://localhost:3000/chat")`
2. Event Listeners of the webSocket Object:
```
    webSocket.onopen = () => {
        console.log(‘WebSocket Client Connected’);
        webSocket.send('Hi this is web client.');
    };
    webSocket.onmessage = (e) => {
        console.log(‘Received: ’ + e.data);
    };
    webSocket.close = () => {
        console.log('WebSocket Client Closed.’);
    };
```

## Signal Protocol Implementation
1. InMemorySignalProtocolStore.js (and helpers.js) are taken for storage purpose from Signal Github (link mentioned in resources)
2. libsignal-protocol.js (also from Signal Github) implements the protocol
3. Signal Gateway - Created by me to integrate React with Signal. It performs the Initialization, Encryption and Decryption functionality when required on Frontend. Check the file in src/signal/SignalGateway.js for detailed code.

**Note:** If you do not clear local storage, then you can recover your old conversations post re-login since these are saved in their respective decrypted form. No data is stored on the server. Kindly view the tutorial for more details.

## Resources
1. [Complete YouTube Tutorial for this project](https://www.youtube.com/watch?v=gNbdgIznjhU&ab_channel=QED42)
2. [Complete Blog for this project](https://www.qed42.com/blog/developing-real-time-secure-chat-application-like-whatsapp-or-signal-with-end-end-encryption)
3. [Backend - NodeJS](https://github.com/VertikaJain/node-express-ts-chat-app)
4. [Signal Protocol in JavaScript Github](https://github.com/signalapp/libsignal-protocol-javascript)
5. [Why Axios](https://medium.com/@MinimalGhost/what-is-axios-js-and-why-should-i-care-7eb72b111dc0)
6. [ReactJS](https://reactjs.org/)
7. [Web Sockets API](https://developer.mozilla.org/en-US/docs/Web/API/Websockets_API)
