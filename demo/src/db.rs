use std::env;
use dotenv::dotenv;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

use zkvm::{Anchor, BlockchainState};

use crate::user::{User,UserRecord};
use crate::asset;
use crate::blockchain::BlockRecord;
use crate::account::{AccountRecord,Wallet};
use crate::util;

#[database("demodb")]
pub struct DBConnection(SqliteConnection);


//
// Initial setup helpers
//

pub fn establish_db_connection() -> SqliteConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url))
}

pub fn prepare_db_if_needed() {
    use crate::schema::block_records::dsl::*;
    use crate::schema::user_records::dsl::*;
    use crate::schema::asset_records::dsl::*;
    use crate::schema::account_records::dsl::*;

    let db_connection = establish_db_connection();

    let results = block_records
        .limit(1)
        .load::<BlockRecord>(&db_connection)
        .expect("Error loading a block");

    if results.len() > 0 {
        return;
    }

    // Initialize the blockchain

    println!("No blocks found in the database. Initializing blockchain...");
    db_connection
        .transaction::<(), diesel::result::Error, _>(|| {

            // Create a treasury account
            let treasury_owner = User::random();
            let xlm_record = asset::AssetRecord::new(&treasury_owner, "XLM");

            diesel::insert_into(asset_records)
                .values(vec![&xlm_record])
                .execute(&db_connection)
                .expect("Inserting an asset record should work");

            // Create a treasury account that will issue various tokens to anyone.
            let mut treasury = Wallet::new(&treasury_owner, "Issuer");

            let initial_utxos = {
                let mut utxos = Vec::new();
                let anchor = Anchor::from_raw_bytes([0; 32]);
                let (mut list, _anchor) =
                        treasury.mint_utxos(anchor, xlm_record.flavor(), vec![1_000_000_000u64]);
                utxos.append(&mut list);
                utxos
            };

            let timestamp_ms = util::current_timestamp_ms();
            let (network_state, proofs) = BlockchainState::make_initial(
                timestamp_ms,
                initial_utxos.iter().map(|utxo| utxo.contract_id()),
            );

            treasury.utxos = initial_utxos
                .into_iter()
                .zip(proofs.into_iter())
                .map(|(mut utxo, proof)| {
                    utxo.proof = proof;
                    utxo.received()
                })
                .collect();

            
            diesel::insert_into(user_records)
                .values(vec![&UserRecord::new(&treasury_owner)])
                .execute(&db_connection)
                .expect("Inserting new user record should work");
            
            diesel::insert_into(account_records)
                .values(vec![&AccountRecord::new(&treasury)])
                .execute(&db_connection)
                .expect("Inserting new account record should work");

            let initial_block_record = BlockRecord::initial(&network_state);

            diesel::insert_into(block_records)
                .values(&initial_block_record)
                .execute(&db_connection)
                .expect("Inserting a block record should work");

            Ok(())
        })
        .expect("Initial DB transaction should succeed.");
}

