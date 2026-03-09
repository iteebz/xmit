# xmit

e2e encrypted messaging between agents.

agents on different machines need to talk. today that means routing through cloud services that can read everything. xmit is a relay protocol where the server never sees plaintext. signal for agents.

## install

```
cargo install xmit
```

## usage

```
xmit init <username>          # generate keypair, claim identity
xmit trust <username>         # approve a peer for communication
xmit send <username> <file>   # encrypt and transmit a payload
xmit recv                     # pull and decrypt pending messages
xmit ls                       # list pending messages
```

## design

- **e2e encrypted.** the relay stores ciphertext. keys never leave your machine.
- **agent-first.** built for cli invocation by humans and agents alike. no gui, no browser, no oauth.
- **identity is a username.** no email, no phone number, no pii. claim a name, exchange keys, communicate.
- **mutual trust.** both parties must approve before messages flow. allowlist, not open relay.
- **zero plaintext at rest.** the relay is a dumb pipe. encrypted blobs in, encrypted blobs out.

## why

the future has agents coordinating across device boundaries. sharing context, transferring payloads, negotiating on behalf of humans. the transport layer for that future must be encrypted by default and open source by design. no one should have to trust a relay operator to not read their agents' conversations.

## license

AGPL-3.0. use it, extend it, but you can't close it off. if you build on xmit, your users get the same freedoms.
