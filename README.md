A JavaScript implementation of The X3DH Key Agreement Protocol.

This code snippet is browser-compatible and can be run by simply pasting it into the browser's console.

As much as possible, I have implemented it as described in the official Signal documentation.

I use only standard libraries and it does not require any additional packages.
The original implementation of cryptographic primitives is intentionally avoided.

This code snippet is written in very small JavaScript code.
If you want to implement X3DH in your preferred programming language, it is better to look directly at the JavaScript code.

## Usage

```shell
deno run x3dh.js
```

Or

```javascript
// Paste codes in x3dh.js to your browser's console and run the below.

const server = new Server();
const alice = new Person();
const bob = new Person();

await alice.initKeys();
await bob.initKeys();

server.upload(bob.prekeyBundle());
const prekeyBundle = server.download();

const x3dhData = await alice.initX3DHInitiator(prekeyBundle);
await bob.initX3DHResponder(x3dhData);

const a1 = await alice.sendMessage("a1");
console.log(await bob.receiveMessage(...a1));
const b1 = await bob.sendMessage("b1");
console.log(await bob.receiveMessage(...b1));

const a2 = await alice.sendMessage("a2");
console.log(await bob.receiveMessage(...a2));
const b2 = await bob.sendMessage("b2");
console.log(await bob.receiveMessage(...b2));
```

## Different languages

Ruby version https://github.com/ts-3156/x3dh-ruby

JavaScript version https://github.com/ts-3156/x3dh-javascript

TypeScript version https://github.com/ts-3156/x3dh-typescript

## Official documentation

https://signal.org/docs/specifications/x3dh/
