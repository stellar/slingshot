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
    let utreexo0 = Utreexo::<u64>::new();
    assert_eq!(utreexo0.root(), MerkleTree::root::<u64>(b"ZkVM.utreexo", &[]));
}

#[test]
fn transient_items_utreexo() {
    let utreexo0 = Utreexo::new();

    let (_, _utreexo1, _catchup) = utreexo0.update::<_,_,()>(|forest| {

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
    let utreexo0 = Utreexo::new();
    let (proofs0, utreexo1, catchup1) = utreexo0.update::<_,_,()>(|forest|{
        Ok((0..6).map(|i| {
            forest.insert(&i)
        }).collect::<Vec<_>>())
    }).expect("cannot fail");

    assert_eq!(
        utreexo1.root(),
        MerkleTree::root::<u64>(b"ZkVM.utreexo", &(0..6).collect::<Vec<_>>())
    );


    for i in 0..6u64 {
        let result = utreexo1.update(|forest| {
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
    let _ = utreexo1.update::<_,_,UtreexoError>(|forest| {
        for i in 0..6u64 {
            forest.delete(&i, &proofs1[i as usize])?;
        }
        Ok(())
    }).expect("all proofs must be valid");
}

#[test]
fn insert_and_delete_utreexo() {
    let n = 6u64;

    let utreexo0 = Utreexo::new();
    let (proofs0, utreexo1, catchup1) = utreexo0.update::<_,_,()>(|forest|{
        Ok((0..n).map(|i| {
            forest.insert(&i)
        }).collect::<Vec<_>>())
    }).expect("cannot fail");

    utreexo1.verify(&0u64, &proofs0[0]).expect_err("proof should not be valid");
    utreexo1.verify(&5u64, &proofs0[5]).expect_err("proof should not be valid");
    
    // update the proofs
    let proofs1 = proofs0
        .into_iter()
        .enumerate()
        .map(|(i, p)| catchup1.update_proof(&(i as u64), p).unwrap())
        .collect::<Vec<_>>();

    // after the proofs were updated, deletions should succeed

    utreexo1.verify(&0u64, &proofs1[0]).expect("proof should be valid");
    utreexo1.verify(&5u64, &proofs1[5]).expect("proof should be valid");

    {
        /* delete 0:
            d                                       e
            |\                                      | \
            a   b   c      ->        b   c      ->  b   c
            |\  |\  |\               |\  |\         |\  |\
            0 1 2 3 4 5          x 1 2 3 4 5        2 3 4 5 1
        */
        let (_, utreexo2, _catchup2) = utreexo1.update::<_,_,UtreexoError>(|forest| {
    
            forest.delete(&0u64, &proofs1[0]).unwrap();

            // double spends are not allowed
            assert_eq!(
                forest.delete(&0, &proofs1[0]),
                Err(UtreexoError::InvalidProof)
            );

            Ok(())
        }).expect("all proofs must be valid");

        assert_eq!(
            utreexo2.root(),
            MerkleTree::root::<u64>(b"ZkVM.utreexo", &[2, 3, 4, 5, 1])
        )
    }

    // {
    //     /* delete 1:
    //         d                                       e
    //         |\                                      | \
    //         a   b   c      ->        b   c      ->  b   c
    //         |\  |\  |\               |\  |\         |\  |\
    //         0 1 2 3 4 5          0 x 2 3 4 5        2 3 4 5 0
    //     */
    //     let mut forest = forest1.clone();
    //     forest.verify(&1u64, &proofs1[1]).unwrap();
    //     forest.delete(&1u64, &proofs1[1]).unwrap();

    //     // double spends are not allowed
    //     assert_eq!(
    //         forest.delete(&1, &proofs1[1]),
    //         Err(UtreexoError::InvalidProof)
    //     );

    //     let (root, _, _) = forest.normalize();
    //     assert_eq!(
    //         root,
    //         MerkleTree::root::<u64>(b"ZkVM.utreexo", &[2, 3, 4, 5, 0])
    //     )
    // }

    // {
    //     /* delete 2:
    //         d                                       e
    //         |\                                      | \
    //         a   b   c      ->    a       c      ->  a   c
    //         |\  |\  |\           |\      |\         |\  |\
    //         0 1 2 3 4 5          0 1 x 3 4 5        0 1 4 5 3
    //     */
    //     let mut forest = forest1.clone();
    //     forest.delete(&2u64, &proofs1[2]).unwrap();

    //     let (root, _, _) = forest.normalize();
    //     assert_eq!(
    //         root,
    //         MerkleTree::root::<u64>(b"ZkVM.utreexo", &[0, 1, 4, 5, 3])
    //     )
    // }

    // {
    //     /* delete 5:
    //         d                                       e
    //         |\                                      | \
    //         a   b   c      ->    a   b          ->  a   b
    //         |\  |\  |\           |\  |\             |\  |\
    //         0 1 2 3 4 5          0 1 2 3 4 x        0 1 2 3 4
    //     */
    //     let mut forest = forest1.clone();
    //     forest.delete(&5u64, &proofs1[5]).unwrap();

    //     let (root, _, _) = forest.normalize();
    //     assert_eq!(
    //         root,
    //         MerkleTree::root::<u64>(b"ZkVM.utreexo", &[0, 1, 2, 3, 4])
    //     )
    // }

    // {
    //     /* delete 2,3:
    //         d                                       e
    //         |\                                      | \
    //         a   b   c      ->    a       c      ->  a   c
    //         |\  |\  |\           |\      |\         |\  |\
    //         0 1 2 3 4 5          0 1 x x 4 5        0 1 4 5
    //     */
    //     let mut forest = forest1.clone();
    //     forest.delete(&2u64, &proofs1[2]).unwrap();
    //     forest.delete(&3u64, &proofs1[3]).unwrap();

    //     let (root, _, _) = forest.normalize();
    //     assert_eq!(
    //         root,
    //         MerkleTree::root::<u64>(b"ZkVM.utreexo", &[0, 1, 4, 5])
    //     );

    //     let mut forest_b = forest1.clone(); // try deletion in another order
    //     forest_b.delete(&3u64, &proofs1[3]).unwrap();
    //     forest_b.delete(&2u64, &proofs1[2]).unwrap();

    //     let (root, _, _) = forest_b.normalize();
    //     assert_eq!(
    //         root,
    //         MerkleTree::root::<u64>(b"ZkVM.utreexo", &[0, 1, 4, 5])
    //     );
    // }

    // {
    //     /* delete 0,3:
    //         d                                       f
    //         |\                                      | \
    //         a   b   c      ->            c      ->  e   c
    //         |\  |\  |\                   |\         |\  |\
    //         0 1 2 3 4 5          x 1 2 x 4 5        1 2 4 5
    //     */
    //     let mut forest = forest1.clone();
    //     forest.verify(&0u64, &proofs1[0]).unwrap();
    //     forest.verify(&3u64, &proofs1[3]).unwrap();
    //     forest.delete(&0u64, &proofs1[0]).unwrap();
    //     forest.delete(&3u64, &proofs1[3]).unwrap();

    //     assert_eq!(
    //         forest.delete(&3, &proofs1[3]),
    //         Err(UtreexoError::InvalidProof)
    //     );
    //     assert_eq!(
    //         forest.delete(&0, &proofs1[0]),
    //         Err(UtreexoError::InvalidProof)
    //     );

    //     let (root, _, _) = forest.normalize();
    //     assert_eq!(
    //         root,
    //         MerkleTree::root::<u64>(b"ZkVM.utreexo", &[1, 2, 4, 5])
    //     );
    // }

    // {
    //     /* delete 0, insert 6, 7:
    //         d                                          f
    //         |\                                         | \
    //         a   b   c      ->        b   c       ->    b   c   h
    //         |\  |\  |\               |\  |\            |\  |\  |\
    //         0 1 2 3 4 5          x 1 2 3 4 5 6 7       2 3 4 5 1 6 7
    //     */
    //     let mut forest = forest1.clone();
    //     forest.verify(&0u64, &proofs1[0]).unwrap();
    //     forest.delete(&0u64, &proofs1[0]).unwrap();
    //     let proof6 = forest.insert(&6u64);
    //     let proof7 = forest.insert(&7u64);

    //     let (root, mut forest2, catchup) = forest.normalize();

    //     assert_eq!(
    //         root,
    //         //MerkleTree::root::<u64>(b"ZkVM.utreexo", &[1, 6, 2, 3, 4, 5, 7])
    //         MerkleTree::root::<u64>(b"ZkVM.utreexo", &[2, 3, 4, 5, 1, 6, 7])
    //     );

    //     let proof6 = catchup.update_proof(&6u64, proof6).unwrap();
    //     let proof7 = catchup.update_proof(&7u64, proof7).unwrap();
    //     let proof1 = catchup.update_proof(&1u64, proofs1[1].clone()).unwrap();

    //     /* delete 1, 7, insert :
    //          f                                        g
    //          | \                                      | \
    //          e   b   c        ->      b   c     ->    b   c
    //          |\  |\  |\               |\  |\          |\  |\
    //          1 6 2 3 4 5 7        x 6 2 3 4 5 x       2 3 4 5 6
    //     */

    //     forest2.verify(&1u64, &proof1).unwrap();
    //     forest2.verify(&7u64, &proof7).unwrap();
    //     forest2.delete(&1u64, &proof1).unwrap();
    //     forest2.delete(&7u64, &proof7).unwrap();

    //     let (root, mut forest3, catchup) = forest2.normalize();

    //     assert_eq!(
    //         root,
    //         MerkleTree::root::<u64>(b"ZkVM.utreexo", &[2, 3, 4, 5, 6])
    //     );

    //     let proof6 = catchup.update_proof(&6u64, proof6).unwrap();
    //     forest3.delete(&6u64, &proof6).unwrap();
    //     let (root, _, _) = forest3.normalize();
    //     assert_eq!(
    //         root,
    //         MerkleTree::root::<u64>(b"ZkVM.utreexo", &[2, 3, 4, 5])
    //     );
    // }
}


#[test]
fn large_utreexo() {
    
    // TBD: try random changes
}