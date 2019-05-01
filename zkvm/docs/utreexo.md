# Utreexo specification

Based on [Utreexo proposal by Tadge Dryja](https://www.youtube.com/watch?v=edRun-6ubCc).

## Introduction

This is a specification of a dynamic accumulator for _unspent transaction outputs_
that supports inserts and deletions, costs `O(log(n))` in storage and proof bandwidth,
with efficient update of the accumulator and the membership proofs.



