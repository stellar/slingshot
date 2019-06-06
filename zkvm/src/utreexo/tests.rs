use merlin::Transcript;

use super::*;
use crate::merkle::*;

impl MerkleItem for u64 {
    fn commit(&self, t: &mut Transcript) {
        t.commit_u64(b"test_item", *self);
    }
}

#[test]
fn empty_utreexo() {
    let forest0 = Forest::<u64>::new();
    let metrics0 = forest0.metrics();
    assert_eq!(metrics0.generation, 0);
    assert_eq!(metrics0.capacity, 0);
    assert_eq!(metrics0.insertions, 0);
    assert_eq!(metrics0.deletions, 0);

    let (root0, forest1, _catchup1) = forest0.normalize();
    let metrics1 = forest1.metrics();
    assert_eq!(root0, MerkleTree::root::<u64>(b"ZkVM.utreexo", &[]));
    assert_eq!(metrics1.generation, 1);
    assert_eq!(metrics1.capacity, 0);
    assert_eq!(metrics1.insertions, 0);
    assert_eq!(metrics1.deletions, 0);
}

#[test]
fn transient_items_utreexo() {
    let mut forest0 = Forest::new();

    let proof0 = forest0.insert(&0);
    let proof1 = forest0.insert(&1);

    assert_eq!(
        forest0.metrics(),
        Metrics {
            generation: 0,
            capacity: 0,
            insertions: 2,
            deletions: 0,
            memory: forest0.metrics().memory,
        }
    );

    forest0.delete(&1, &proof1).unwrap();
    forest0.delete(&0, &proof0).unwrap();

    // double spends are not allowed
    assert_eq!(forest0.delete(&1, &proof1), Err(UtreexoError::InvalidProof));
    assert_eq!(forest0.delete(&0, &proof0), Err(UtreexoError::InvalidProof));

    assert_eq!(
        forest0.metrics(),
        Metrics {
            generation: 0,
            capacity: 0,
            insertions: 0,
            deletions: 0,
            memory: forest0.metrics().memory,
        }
    );
}

#[test]
fn insert_to_utreexo() {
    let mut forest0 = Forest::new();

    let proofs0 = (0..6).map(|i| forest0.insert(&i)).collect::<Vec<_>>();

    let (root, mut forest1, catchup1) = forest0.normalize();

    assert_eq!(
        forest1.metrics(),
        Metrics {
            generation: 1,
            capacity: 6,
            insertions: 0,
            deletions: 0,
            memory: forest1.metrics().memory,
        }
    );

    assert_eq!(
        root,
        MerkleTree::root::<u64>(b"ZkVM.utreexo", &(0..6).collect::<Vec<_>>())
    );

    for i in 0..6u64 {
        let deletion = forest1.delete(&i, &proofs0[i as usize]);
        assert_eq!(deletion, Err(UtreexoError::OutdatedProof));
    }

    // update the proofs
    let proofs1 = proofs0
        .into_iter()
        .enumerate()
        .map(|(i, p)| catchup1.update_proof(&(i as u64), p).unwrap())
        .collect::<Vec<_>>();

    // after the proofs were updated, deletions should succeed
    for i in 0..6u64 {
        forest1.delete(&i, &proofs1[i as usize]).unwrap();
    }

    assert_eq!(
        forest1.metrics(),
        Metrics {
            generation: 1,
            capacity: 6,
            insertions: 0,
            deletions: 6,
            memory: forest1.metrics().memory,
        }
    );
}

#[test]
fn insert_and_delete_utreexo() {
    let mut forest0 = Forest::new();
    let n = 6u64;
    let proofs0 = (0..n).map(|i| forest0.insert(&i)).collect::<Vec<_>>();

    let (_, forest1, catchup1) = forest0.normalize();

    assert_eq!(
        forest1.metrics(),
        Metrics {
            generation: 1,
            capacity: n as usize,
            insertions: 0,
            deletions: 0,
            memory: forest1.metrics().memory,
        }
    );

    // update the proofs
    let proofs1 = proofs0
        .into_iter()
        .enumerate()
        .map(|(i, p)| catchup1.update_proof(&(i as u64), p).unwrap())
        .collect::<Vec<_>>();

    // after the proofs were updated, deletions should succeed

    {
        /* delete 0:
            d                                       e
            |\                                      | \
            a   b   c      ->        b   c      ->  b   c
            |\  |\  |\               |\  |\         |\  |\
            0 1 2 3 4 5          x 1 2 3 4 5        2 3 4 5 1
        */
        let mut forest = forest1.clone();
        forest.verify(&0u64, &proofs1[0]).unwrap();
        forest.delete(&0u64, &proofs1[0]).unwrap();

        // double spends are not allowed
        assert_eq!(
            forest.delete(&0, &proofs1[0]),
            Err(UtreexoError::InvalidProof)
        );

        let (root, _, _) = forest.normalize();
        assert_eq!(
            root,
            MerkleTree::root::<u64>(b"ZkVM.utreexo", &[2, 3, 4, 5, 1])
        )
    }

    {
        /* delete 1:
            d                                       e
            |\                                      | \
            a   b   c      ->        b   c      ->  b   c
            |\  |\  |\               |\  |\         |\  |\
            0 1 2 3 4 5          0 x 2 3 4 5        2 3 4 5 0
        */
        let mut forest = forest1.clone();
        forest.verify(&1u64, &proofs1[1]).unwrap();
        forest.delete(&1u64, &proofs1[1]).unwrap();

        // double spends are not allowed
        assert_eq!(
            forest.delete(&1, &proofs1[1]),
            Err(UtreexoError::InvalidProof)
        );

        let (root, _, _) = forest.normalize();
        assert_eq!(
            root,
            MerkleTree::root::<u64>(b"ZkVM.utreexo", &[2, 3, 4, 5, 0])
        )
    }

    {
        /* delete 2:
            d                                       e
            |\                                      | \
            a   b   c      ->    a       c      ->  a   c
            |\  |\  |\           |\      |\         |\  |\
            0 1 2 3 4 5          0 1 x 3 4 5        0 1 4 5 3
        */
        let mut forest = forest1.clone();
        forest.delete(&2u64, &proofs1[2]).unwrap();

        let (root, _, _) = forest.normalize();
        assert_eq!(
            root,
            MerkleTree::root::<u64>(b"ZkVM.utreexo", &[0, 1, 4, 5, 3])
        )
    }

    {
        /* delete 5:
            d                                       e
            |\                                      | \
            a   b   c      ->    a   b          ->  a   b
            |\  |\  |\           |\  |\             |\  |\
            0 1 2 3 4 5          0 1 2 3 4 x        0 1 2 3 4
        */
        let mut forest = forest1.clone();
        forest.delete(&5u64, &proofs1[5]).unwrap();

        let (root, _, _) = forest.normalize();
        assert_eq!(
            root,
            MerkleTree::root::<u64>(b"ZkVM.utreexo", &[0, 1, 2, 3, 4])
        )
    }

    {
        /* delete 2,3:
            d                                       e
            |\                                      | \
            a   b   c      ->    a       c      ->  a   c
            |\  |\  |\           |\      |\         |\  |\
            0 1 2 3 4 5          0 1 x x 4 5        0 1 4 5
        */
        let mut forest = forest1.clone();
        forest.delete(&2u64, &proofs1[2]).unwrap();
        forest.delete(&3u64, &proofs1[3]).unwrap();

        let (root, _, _) = forest.normalize();
        assert_eq!(
            root,
            MerkleTree::root::<u64>(b"ZkVM.utreexo", &[0, 1, 4, 5])
        );

        let mut forest_b = forest1.clone(); // try deletion in another order
        forest_b.delete(&3u64, &proofs1[3]).unwrap();
        forest_b.delete(&2u64, &proofs1[2]).unwrap();

        let (root, _, _) = forest_b.normalize();
        assert_eq!(
            root,
            MerkleTree::root::<u64>(b"ZkVM.utreexo", &[0, 1, 4, 5])
        );
    }

    {
        /* delete 0,3:
            d                                       f
            |\                                      | \
            a   b   c      ->            c      ->  e   c
            |\  |\  |\                   |\         |\  |\
            0 1 2 3 4 5          x 1 2 x 4 5        1 2 4 5
        */
        let mut forest = forest1.clone();
        forest.verify(&0u64, &proofs1[0]).unwrap();
        forest.verify(&3u64, &proofs1[3]).unwrap();
        forest.delete(&0u64, &proofs1[0]).unwrap();
        forest.delete(&3u64, &proofs1[3]).unwrap();

        assert_eq!(
            forest.delete(&3, &proofs1[3]),
            Err(UtreexoError::InvalidProof)
        );
        assert_eq!(
            forest.delete(&0, &proofs1[0]),
            Err(UtreexoError::InvalidProof)
        );

        let (root, _, _) = forest.normalize();
        assert_eq!(
            root,
            MerkleTree::root::<u64>(b"ZkVM.utreexo", &[1, 2, 4, 5])
        );
    }

    {
        /* delete 0, insert 6, 7:
            d                                          f
            |\                                         | \
            a   b   c      ->        b   c       ->    b   c   h
            |\  |\  |\               |\  |\            |\  |\  |\
            0 1 2 3 4 5          x 1 2 3 4 5 6 7       2 3 4 5 1 6 7
        */
        let mut forest = forest1.clone();
        forest.verify(&0u64, &proofs1[0]).unwrap();
        forest.delete(&0u64, &proofs1[0]).unwrap();
        let proof6 = forest.insert(&6u64);
        let proof7 = forest.insert(&7u64);

        let (root, mut forest2, catchup) = forest.normalize();

        assert_eq!(
            root,
            //MerkleTree::root::<u64>(b"ZkVM.utreexo", &[1, 6, 2, 3, 4, 5, 7])
            MerkleTree::root::<u64>(b"ZkVM.utreexo", &[2, 3, 4, 5, 1, 6, 7])
        );

        let proof6 = catchup.update_proof(&6u64, proof6).unwrap();
        let proof7 = catchup.update_proof(&7u64, proof7).unwrap();
        let proof1 = catchup.update_proof(&1u64, proofs1[1].clone()).unwrap();

        /* delete 1, 7, insert :
             f                                        g
             | \                                      | \
             e   b   c        ->      b   c     ->    b   c
             |\  |\  |\               |\  |\          |\  |\
             1 6 2 3 4 5 7        x 6 2 3 4 5 x       2 3 4 5 6
        */

        forest2.verify(&1u64, &proof1).unwrap();
        forest2.verify(&7u64, &proof7).unwrap();
        forest2.delete(&1u64, &proof1).unwrap();
        forest2.delete(&7u64, &proof7).unwrap();

        let (root, mut forest3, catchup) = forest2.normalize();

        assert_eq!(
            root,
            MerkleTree::root::<u64>(b"ZkVM.utreexo", &[2, 3, 4, 5, 6])
        );

        let proof6 = catchup.update_proof(&6u64, proof6).unwrap();
        forest3.delete(&6u64, &proof6).unwrap();
        let (root, _, _) = forest3.normalize();
        assert_eq!(
            root,
            MerkleTree::root::<u64>(b"ZkVM.utreexo", &[2, 3, 4, 5])
        );
    }
}

#[test]
fn large_utreexo() {
    let mut forest0 = Forest::new();
    let n = 10_000u64;
    let proofs0 = (0..n).map(|i| forest0.insert(&i)).collect::<Vec<_>>();

    let (_, forest1, catchup1) = forest0.normalize();

    let _proofs1 = proofs0
        .into_iter()
        .enumerate()
        .map(|(i, p)| catchup1.update_proof(&(i as u64), p).unwrap())
        .collect::<Vec<_>>();

    assert!(forest1.metrics().memory < 1600);

    // TODO: perform 1000 changes, normalize again and measure the memory footprint of the Catchup struct.
}