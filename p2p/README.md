# P2P networking for ZkVM

This is a p2p framework for ZkVM. 
It is written in modern async Rust with Tokio runtime.

## Features

Nodes encrypt and authenticate connections with _C Y B E R S H A K E_ protocol, inspired by Signal's X3DH with a pinch of YOLO in it.

Simple node discovery logic with embedded miniature web-of-trust (with a narrow meaning of "trust").

## Example

Run in multiple Terminal windows:

```
$ cargo run --example chatter

Listening on 127.0.0.1:59610 with peer ID: ca571c6b2e0a7846603b17eeeef70c4b9c171e06924bb4c7a507cf1cf6bbbc3c
```

Connect other nodes to the  first one:

```
>> connect 127.0.0.1:59610
```

Nodes will automatically traslate their peers to each other and connect.

```
=> Peer connected: 4ef79f3f56965c9e78d059f04a0b9d94b8b0cd96f261282902614328b5a88451
=> Peer connected: 0811c445f2add526678f9ca2639821abe52c6874d0f101b3c6c81597544cd54a
=> Peer connected: 0ab3612bfed60de085c516c9d92ca9985cf819bbc0f24e8ec69b7edb2217e23f
```

Broadcast messages from any node to all others:

```
>> broadcast Hello world!
...
=> Received: `Hello world!` from 0811c445f2add526678f9ca2639821abe52c6874d0f101b3c6c81597544cd54a
```

List peers:

```
>> peers
=> 3 peers:
   [in] 127.0.0.1:59613 0ab3612bfed60de085c516c9d92ca9985cf819bbc0f24e8ec69b7edb2217e23f   priority: 1000000   public: true
  [out] 127.0.0.1:59603 4ef79f3f56965c9e78d059f04a0b9d94b8b0cd96f261282902614328b5a88451   priority: 0         public: true
   [in] 127.0.0.1:59612 0811c445f2add526678f9ca2639821abe52c6874d0f101b3c6c81597544cd54a   priority: 1000000   public: true
```
