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
    assert_eq!(forest0.root(), MerkleTree::root::<u64>(b"ZkVM.utreexo", &[]));
}

#[test]
fn transient_items_utreexo() {
    let forest0 = Forest::new();

    let (_, _forest1, _catchup) = forest0.update(|forest| {

        let proof0 = forest.insert(&0);
        let proof1 = forest.insert(&1);

        forest.delete(&1, &proof1).expect("just received proof should not fail");
        forest.delete(&0, &proof0).expect("just received proof should not fail");

        // double spends are not allowed
        assert_eq!(forest.delete(&1, &proof1), Err(UtreexoError::InvalidProof));
        assert_eq!(forest.delete(&0, &proof0), Err(UtreexoError::InvalidProof));

        Ok(())
    }).unwrap();
}

#[test]
fn insert_to_utreexo() {
    let forest0 = Forest::new();
    let (proofs0, forest1, catchup1) = forest0.update(|forest|{
        Ok((0..6).map(|i| {
            forest.insert(&i)
        }).collect::<Vec<_>>())
    }).expect("cannot fail");

    assert_eq!(
        forest1.root(),
        MerkleTree::root::<u64>(b"ZkVM.utreexo", &(0..6).collect::<Vec<_>>())
    );


    for i in 0..6u64 {
        let result = forest1.update(|forest| {
            forest.delete(&i, &proofs0[i as usize])
        }).map(|_| ()).unwrap_err();
        assert_eq!(result, UtreexoError::OutdatedProof);
    }

    // update the proofs
    let proofs1 = proofs0
        .into_iter()
        .enumerate()
        .map(|(i, p)| catchup1.update_proof(&(i as u64), p).unwrap())
        .collect::<Vec<_>>();

    // after the proofs were updated, deletions should succeed
    let _ = forest1.update(|forest| {
        for i in 0..6u64 {
            forest.delete(&i, &proofs1[i as usize])?;
        }
        Ok(())
    }).expect("all proofs must be valid");
}

#[test]
fn insert_and_delete_utreexo() {
    let n = 6u64;

    let forest0 = Forest::new();
    let (proofs0, forest1, catchup1) = forest0.update(|forest|{
        Ok((0..n).map(|i| {
            forest.insert(&i)
        }).collect::<Vec<_>>())
    }).expect("cannot fail");

    forest1.verify(&0u64, &proofs0[0]).expect_err("proof should not be valid");
    forest1.verify(&5u64, &proofs0[5]).expect_err("proof should not be valid");
    
    // update the proofs
    let proofs1 = proofs0
        .into_iter()
        .enumerate()
        .map(|(i, p)| catchup1.update_proof(&(i as u64), p).unwrap())
        .collect::<Vec<_>>();

    // after the proofs were updated, deletions should succeed

    forest1.verify(&0u64, &proofs1[0]).expect("proof should be valid");
    forest1.verify(&5u64, &proofs1[5]).expect("proof should be valid");

    fn verify_update<M:MerkleItem>(forest: &Forest<M>, new_set: &[M], upd: impl FnOnce(&mut WorkForest<M>)) -> (Forest<M>, Catchup<M>) {
        let (_, forest2, catchup2) = forest.update(|forest| {
            upd(forest);
            Ok(())
        }).unwrap();

        assert_eq!(
            forest2.root(),
            MerkleTree::root(b"ZkVM.utreexo", new_set)
        );

        (forest2, catchup2)
    }

    // delete 0:
    //  d                                       e
    //  |\                                      | \
    //  a   b   c      ->        b   c      ->  b   c
    //  |\  |\  |\               |\  |\         |\  |\
    //  0 1 2 3 4 5          x 1 2 3 4 5        2 3 4 5 1
    forest1.verify(&0u64, &proofs1[0]).unwrap();
    let (_,_) = verify_update(&forest1, &[2, 3, 4, 5, 1], |forest| {
        forest.delete(&0u64, &proofs1[0]).unwrap();
    });

    // delete 1:
    //  d                                       e
    //  |\                                      | \
    //  a   b   c      ->        b   c      ->  b   c
    //  |\  |\  |\               |\  |\         |\  |\
    //  0 1 2 3 4 5          0 x 2 3 4 5        2 3 4 5 0
    forest1.verify(&1u64, &proofs1[1]).unwrap();
    let (_,_) = verify_update(&forest1, &[2, 3, 4, 5, 0], |forest| {
        forest.delete(&1u64, &proofs1[1]).unwrap();
    });

    // delete 2:
    //  d                                       e
    //  |\                                      | \
    //  a   b   c      ->    a       c      ->  a   c
    //  |\  |\  |\           |\      |\         |\  |\
    //  0 1 2 3 4 5          0 1 x 3 4 5        0 1 4 5 3
    let (_,_) = verify_update(&forest1, &[0, 1, 4, 5, 3], |forest| {
        forest.delete(&2u64, &proofs1[2]).unwrap();
    });

    // delete 5:
    //  d                                       e
    //  |\                                      | \
    //  a   b   c      ->    a   b          ->  a   b
    //  |\  |\  |\           |\  |\             |\  |\
    //  0 1 2 3 4 5          0 1 2 3 4 x        0 1 2 3 4
    let (_,_) = verify_update(&forest1, &[0, 1, 2, 3, 4], |forest| {
        forest.delete(&5u64, &proofs1[5]).unwrap();
    });

    // delete 2,3:
    //  d                                       e
    //  |\                                      | \
    //  a   b   c      ->    a       c      ->  a   c
    //  |\  |\  |\           |\      |\         |\  |\
    //  0 1 2 3 4 5          0 1 x x 4 5        0 1 4 5
    let (_,_) = verify_update(&forest1, &[0, 1, 4, 5], |forest| {
        forest.delete(&2u64, &proofs1[2]).unwrap();
        forest.delete(&3u64, &proofs1[3]).unwrap();
    });

    // delete in another order
    let (_,_) = verify_update(&forest1, &[0, 1, 4, 5], |forest| {
        forest.delete(&3u64, &proofs1[3]).unwrap();
        forest.delete(&2u64, &proofs1[2]).unwrap();
    });
    
    // delete 0,3:
    //  d                                       f
    //  |\                                      | \
    //  a   b   c      ->            c      ->  e   c
    //  |\  |\  |\                   |\         |\  |\
    //  0 1 2 3 4 5          x 1 2 x 4 5        1 2 4 5
    let (_,_) = verify_update(&forest1, &[1, 2, 4, 5], |forest| {
        forest.delete(&0u64, &proofs1[0]).unwrap();
        forest.delete(&3u64, &proofs1[3]).unwrap();
    });


    // delete 0, insert 6, 7:
    //  d                                          f
    //  |\                                         | \
    //  a   b   c      ->        b   c       ->    b   c   h
    //  |\  |\  |\               |\  |\            |\  |\  |\
    //  0 1 2 3 4 5          x 1 2 3 4 5 6 7       2 3 4 5 1 6 7
    let mut proof6 = Proof {generation: 0, path: None};
    let mut proof7 = Proof {generation: 0, path: None};
    let (forest2,catchup) = verify_update(&forest1, &[2, 3, 4, 5, 1, 6, 7], |forest| {
        forest.delete(&0u64, &proofs1[0]).unwrap();
        proof6 = forest.insert(&6u64);
        proof7 = forest.insert(&7u64);
    });

    proof7 = catchup.update_proof(&7u64, proof7).unwrap();
    let proof2 = catchup.update_proof(&2u64, proofs1[2].clone()).unwrap();

    // delete 2, 7:
    //   f                    f                   g
    //   | \                  | \                 | \
    //   b   c   h     ->     b   c   h     ->    c   h
    //   |\  |\  |\           |\  |\  |\          |\  |\
    //   2 3 4 5 1 6 7        x 3 4 5 1 6 x       4 5 1 6 3
    // 
    let (_forest2,_catchup) = verify_update(&forest2, &[4, 5, 1, 6, 3], |forest| {
        forest.delete(&2u64, &proof2).unwrap();
        forest.delete(&7u64, &proof7).unwrap();
    });
}


#[test]
fn large_utreexo() {
    
    // TBD: try random changes
}