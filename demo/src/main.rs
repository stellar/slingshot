#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate diesel;
#[macro_use] extern crate rocket;
#[macro_use] extern crate rocket_contrib;

mod schema;
mod records;
mod nodes;
mod util;

use std::env;
use std::collections::HashMap;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use dotenv::dotenv;

use rocket::Request;
use rocket_contrib::templates::Template;
use rocket_contrib::serve::StaticFiles;
use rocket_contrib::databases::diesel as rocket_diesel;

#[database("demodb")]
struct DBConnection(rocket_diesel::SqliteConnection);

#[get("/")]
fn network_status(dbconn: DBConnection) -> Template {
    let mut context = HashMap::<&str, String>::new();
    context.insert("test", "here is test".into());
    Template::render("network/status", &context)
}

#[get("/network/mempool")]
fn network_mempool() -> Template {
    let mut context = HashMap::<&str, String>::new();
    context.insert("test", "here is test".into());
    Template::render("network/mempool", &context)
}

#[get("/network/blocks")]
fn network_blocks() -> Template {
    let mut context = HashMap::<&str, String>::new();
    context.insert("test", "here is test".into());
    Template::render("network/blocks", &context)
}

#[get("/accounts/<id>")]
fn accounts_show(id: String) -> Template {
    let mut context = HashMap::<&str, String>::new();
    context.insert("id", id);
    Template::render("accounts/show", &context)
}

#[get("/assets/<id>")]
fn assets_show(id: String) -> Template {
    let mut context = HashMap::<&str, String>::new();
    context.insert("id", id);
    Template::render("assets/show", &context)
}


#[catch(404)]
fn not_found(req: &Request<'_>) -> Template {
    let mut map = HashMap::new();
    map.insert("path", req.uri().path());
    Template::render("404", &map)
}

fn prepare_db_if_needed() {
    use schema::block_records::dsl::*;
    use schema::asset_records::dsl::*;
    use schema::node_records::dsl::*;

    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_connection = SqliteConnection::establish(&database_url).expect(&format!("Error connecting to {}", database_url));

    let results = block_records.limit(1).load::<records::BlockRecord>(&db_connection).expect("Error loading a block");

    if results.len() > 0 {
        return;
    }

    // Initialize the blockchain

    println!("No blocks found in the database. Initializing blockchain...");
    db_connection.transaction::<(), diesel::result::Error, _>(|| {
        
        use nodes::{Wallet,Node};
        use zkvm::{Anchor, Block, BlockchainState};

        let token_record = records::AssetRecord::new("Token");
        let usd_record = records::AssetRecord::new("USD");
        let eur_record = records::AssetRecord::new("EUR");

        diesel::insert_into(asset_records)
            .values(vec![&token_record,&usd_record,&eur_record])
            .execute(&db_connection).expect("Inserting an asset record should work");

        // Create a treasury node that will issue various tokens to anyone.
        let mut treasury_wallet = Wallet::new("Issuer");

        let pending_utxos = {
            let mut utxos = Vec::new();
            let anchor = Anchor::from_raw_bytes([0;32]);

            let (mut list, anchor) = treasury_wallet.mint_utxos(anchor, token_record.flavor(), vec![1,2,4,8]);
            utxos.append(&mut list);
            let (mut list, anchor) = treasury_wallet.mint_utxos(anchor, usd_record.flavor(), vec![1000, 5000]);
            utxos.append(&mut list);
            let (mut list, _) = treasury_wallet.mint_utxos(anchor, eur_record.flavor(), vec![80, 99, 7000]);
            utxos.append(&mut list);

            utxos
        };

        let (network_state, proofs) =
            BlockchainState::make_initial(0u64, pending_utxos.iter().map(|utxo| utxo.contract().id()));

        treasury_wallet.utxos = pending_utxos
            .into_iter()
            .zip(proofs.into_iter())
            .map(|(pending_utxo, proof)| pending_utxo.to_confirmed(proof))
            .collect();

        let initial_block_record = records::BlockRecord {
            height: 1,
            block_json: serde_json::to_string_pretty(&Block{
                header: network_state.tip.clone(),
                txs: Vec::new(),
                all_utxo_proofs: Vec::new(),
            }).expect("JSON encoding should work for initial block"),
            state_json: serde_json::to_string_pretty(&network_state).expect("JSON encoding should work for chain state")
        };

        diesel::insert_into(block_records)
            .values(&initial_block_record)
            .execute(&db_connection).expect("Inserting a block record should work");

        let treasury = Node {
            blockchain: network_state.clone(),
            wallet: treasury_wallet,
        };

        let treasury_record = records::NodeRecord::new(treasury);
        diesel::insert_into(node_records)
            .values(&treasury_record)
            .execute(&db_connection).expect("Inserting a node record should work");

        // TBD: add more accounts


        Ok(())
        //Err(diesel::result::Error::RollbackTransaction)
    }).expect("Initial DB transaction should succeed.");


    // let mut alice_wallet = Wallet::new([0; 32]);
    // let bob_wallet = Wallet::new([1; 32]);

    // // 1. Instantiate a blockchain with some utxos allocated to Alice.
    // let utxos = alice_wallet.generate_pending_utxos([0; 32]);

    // let (network_state, proofs) =
    //     BlockchainState::make_initial(0u64, utxos.iter().map(|utxo| utxo.contract().id()));

    // alice_wallet.utxos = utxos
    //     .into_iter()
    //     .zip(proofs.into_iter())
    //     .map(|(pending_utxo, proof)| pending_utxo.to_confirmed(proof))
    //     .collect();

    // let mut alice = Node {
    //     blockchain: network_state.clone(),
    //     wallet: alice_wallet,
    // };

    // // 2. Bob is instantiated with no utxos.
    // let mut bob = Node {
    //     blockchain: network_state.clone(),
    //     wallet: bob_wallet,
    // };

}

fn launch_rocket_app() {
    rocket::ignite()
    .attach(DBConnection::fairing())
    .attach(Template::fairing())
    .mount("/static", StaticFiles::from("static"))
    .mount("/", routes![
        network_status,
        network_mempool,
        network_blocks,
        accounts_show,
        assets_show
    ])
    .launch();
}

fn main() {
    prepare_db_if_needed();
    launch_rocket_app();
}
