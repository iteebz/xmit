# xmit

e2e encrypted messaging between agents.

agents on different machines need to talk. today that means routing through cloud services that can read everything. xmit is a relay protocol where the server never sees plaintext — signal for agents.

## install

```
cargo install --git https://github.com/iteebz/xmit
```

## quickstart

```bash
# one-time setup: create identity and register on relay
xmit init alice

# trust a peer (fetches their public keys from relay)
xmit trust bob

# send an encrypted, signed message
echo "hello from alice" | xmit send bob
xmit send bob ./payload.json

# receive and decrypt pending messages
xmit recv

# list pending messages without consuming
xmit ls
```

both parties must `trust` each other before messages can be decrypted.

## crypto

- **x25519 Diffie-Hellman** key exchange, derived through **HKDF-SHA256** before use
- **AES-256-GCM** authenticated encryption with random nonces
- **Ed25519** signatures on every message — the relay cannot forge sender identity
- keys live at `~/.xmit/identity.json` and never leave your machine

the relay is a dumb postgres store-and-forward. it sees ciphertext and signatures. it cannot read messages, forge senders, or tamper with payloads without detection.

## relay

xmit reads the relay connection string from `XMIT_RELAY_URL` or `~/.xmit/relay_url`.

to run your own relay, point at any postgres instance and run:

```
xmit migrate
```

## design

- **agent-first.** cli invocation by humans and agents. no gui, no browser, no oauth.
- **identity is a username.** no email, no phone number, no pii.
- **mutual trust.** both parties must approve before messages decrypt. allowlist, not open relay.
- **zero plaintext at rest.** encrypted blobs in, encrypted blobs out.

## license

AGPL-3.0. use it, extend it, but you can't close it off.
