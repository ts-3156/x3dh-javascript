const { subtle, getRandomValues } = globalThis.crypto;

class PrivateKey {
  #key;

  constructor(key) {
    this.#key = key;
  }

  async exchange(key) {
    return await subtle.deriveBits(
      {
        name: "ECDH",
        public: key,
      },
      this.#key,
      256,
    );
  }

  static async generate() {
    const pair = await subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-384",
      },
      true,
      ["deriveBits"],
    );
    return [new PrivateKey(pair.privateKey), pair.publicKey];
  }
}

class SigningKey {
  #key;

  constructor(key) {
    this.#key = key;
  }

  async sign(data) {
    return await subtle.sign(
      "Ed25519",
      this.#key,
      data,
    );
  }

  static async generate() {
    const pair = await subtle.generateKey(
      "Ed25519",
      false,
      ["sign", "verify"],
    );
    return [new SigningKey(pair.privateKey), new VerifyKey(pair.publicKey)];
  }
}

class VerifyKey {
  #key;

  constructor(key) {
    this.#key = key;
  }

  async verify(signature, data) {
    await subtle.verify(
      "Ed25519",
      this.#key,
      signature,
      data,
    );
  }
}

class AES256GCM {
  async encrypt(key, plaintext, ad) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    return [
      await subtle.encrypt(
        { name: "AES-GCM", iv: iv, additionalData: ad },
        await this.keyFromBytes(key),
        plaintext,
      ),
      iv,
    ];
  }

  async decrypt(key, ciphertext, ad, iv) {
    return await subtle.decrypt(
      { name: "AES-GCM", iv: iv, additionalData: ad },
      await this.keyFromBytes(key),
      ciphertext,
    );
  }

  async keyFromBytes(bytes) {
    return await subtle.importKey(
      "raw",
      bytes,
      {
        name: "AES-GCM",
        length: 256,
      },
      false,
      ["encrypt", "decrypt"],
    );
  }
}

async function generateKeyPair() {
  return await PrivateKey.generate();
}

async function dh(privateKey, publicKey) {
  return await privateKey.exchange(publicKey);
}

async function encodeKey(key) {
  return await subtle.exportKey("raw", key);
}
function concat(...args) {
  let len = 0;
  for (const a of args) {
    len += a.byteLength;
  }

  let buf = new Uint8Array(len);
  let offset = 0;
  for (const a of args) {
    const out = new Uint8Array(a);
    buf.set(out, offset);
    offset += out.byteLength;
  }

  return buf;
}

async function hkdfSha256(km, n) {
  const raw = concat(new ArrayBuffer(32), km);
  const ikm = await subtle.importKey("raw", raw, "HKDF", false, ["deriveBits"]);

  return await subtle.deriveBits(
    {
      name: "HKDF",
      salt: new ArrayBuffer(32),
      info: new TextEncoder().encode(`MyProtocol key${n + 1}`),
      hash: "SHA-256",
    },
    ikm,
    256,
  );
}

async function encrypt(key, plaintext, ad) {
  const cipher = new AES256GCM();
  return await cipher.encrypt(key, new TextEncoder().encode(plaintext), ad);
}

async function decrypt(key, ciphertext, ad, iv) {
  const cipher = new AES256GCM();
  return new TextDecoder().decode(
    await cipher.decrypt(key, ciphertext, ad, iv),
  );
}

class Person {
  #ik;
  #ik_pub;
  #spk;
  #spk_pub;
  #sk;
  #ad;
  #sk_pub;
  #spk_signature;
  #opk_set;
  #opk_pub_set;

  constructor() {
  }

  async initKeys() {
    [this.#ik, this.#ik_pub] = await generateKeyPair();
    [this.#spk, this.#spk_pub] = await generateKeyPair();

    [this.#sk, this.#sk_pub] = await SigningKey.generate();
    this.#spk_signature = await this.#sk.sign(await encodeKey(this.#spk_pub));

    const [opk, opk_pub] = await generateKeyPair();
    this.#opk_set = [opk];
    this.#opk_pub_set = [opk_pub];
  }

  prekeyBundle() {
    return {
      ik_pub: this.#ik_pub,
      sk_pub: this.#sk_pub,
      spk_pub: this.#spk_pub,
      spk_signature: this.#spk_signature,
      opk_pub_set: this.#opk_pub_set,
    };
  }

  async initX3DHInitiator(prekeyBundle) {
    const bundle = {
      ik_pub: prekeyBundle.ik_pub,
      sk_pub: prekeyBundle.sk_pub,
      spk_pub: prekeyBundle.spk_pub,
      spk_signature: prekeyBundle.spk_signature,
      opk_id: prekeyBundle.opk_id,
      opk_pub: prekeyBundle.opk_pub,
    };

    // This value will be used for sending and receiving messages after X3DH.
    this.#spk_pub = bundle.spk_pub;

    await bundle.sk_pub.verify(
      bundle.spk_signature,
      await encodeKey(bundle.spk_pub),
    );

    const [ek, ek_pub] = await generateKeyPair();

    const dh1 = await dh(this.#ik, this.#spk_pub);
    const dh2 = await dh(ek, bundle.ik_pub);
    const dh3 = await dh(ek, this.#spk_pub);
    const dh4 = await dh(ek, bundle.opk_pub);
    this.#sk = await hkdfSha256(concat(dh1, dh2, dh3, dh4), 0);
    this.#ad = concat(
      await encodeKey(this.#ik_pub),
      await encodeKey(bundle.ik_pub),
    );

    const [ciphertext, nonce] = await encrypt(
      this.#sk,
      "Initial message",
      this.#ad,
    );

    return {
      ik_pub: this.#ik_pub,
      ek_pub: ek_pub,
      opk_id: bundle.opk_id,
      message: ciphertext,
      nonce: nonce,
    };
  }

  async initX3DHResponder(data) {
    data.ik_pub = data.ik_pub; // TODO
    data.ek_pub = data.ek_pub; // TODO
    const opk = this.#opk_set[data.opk_id];

    const dh1 = await dh(this.#spk, data.ik_pub);
    const dh2 = await dh(this.#ik, data.ek_pub);
    const dh3 = await dh(this.#spk, data.ek_pub);
    const dh4 = await dh(opk, data.ek_pub);
    this.#sk = await hkdfSha256(concat(dh1, dh2, dh3, dh4), 0);
    this.#ad = concat(
      await encodeKey(data.ik_pub),
      await encodeKey(this.#ik_pub),
    );

    return {
      message: await decrypt(this.#sk, data.message, this.#ad, data.nonce),
    };
  }

  async sendMessage(msg) {
    const [ciphertext, nonce] = await encrypt(this.#sk, msg, this.#ad);
    return [{ nonce: nonce }, ciphertext];
  }

  async receiveMessage(header, ciphertext) {
    return await decrypt(this.#sk, ciphertext, this.#ad, header.nonce);
  }
}

class Server {
  #bundle;

  upload(bundle) {
    this.#bundle = bundle;
  }

  download() {
    return {
      ik_pub: this.#bundle.ik_pub,
      sk_pub: this.#bundle.sk_pub,
      spk_pub: this.#bundle.spk_pub,
      spk_signature: this.#bundle.spk_signature,
      opk_id: 0,
      opk_pub: this.#bundle.opk_pub_set[0],
    };
  }
}

if (import.meta.main) {
  const server = new Server();
  const alice = new Person();
  const bob = new Person();

  await alice.initKeys();
  await bob.initKeys();

  server.upload(bob.prekeyBundle());
  const prekeyBundle = server.download();

  const x3dh_data = await alice.initX3DHInitiator(prekeyBundle);
  await bob.initX3DHResponder(x3dh_data);

  const a1 = await alice.sendMessage("a1");
  console.log(await bob.receiveMessage(...a1));
  const b1 = await bob.sendMessage("b1");
  console.log(await bob.receiveMessage(...b1));

  const a2 = await alice.sendMessage("a2");
  console.log(await bob.receiveMessage(...a2));
  const b2 = await bob.sendMessage("b2");
  console.log(await bob.receiveMessage(...b2));
}
