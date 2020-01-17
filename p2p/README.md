# P2P networking for ZkVM

This is a p2p framework for ZkVM. 
It is written in modern async Rust with Tokio runtime.

## Features

Nodes encrypt and authenticate connections with _C Y B E R S H A K E_ protocol, inspired by Signal's X3DH with a pinch of YOLO in it.

Simple node discovery logic with embedded miniature web-of-trust (with a narrow meaning of "trust").

