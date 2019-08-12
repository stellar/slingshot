#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate diesel;
#[macro_use] extern crate rocket;
#[macro_use] extern crate rocket_contrib;

mod schema;
mod models;

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
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let conn = SqliteConnection::establish(&database_url).expect(&format!("Error connecting to {}", database_url));

    use schema::block_records::dsl::*;

    let results = block_records.limit(1).load::<models::BlockRecord>(&conn).expect("Error loading a block");

    if results.len() > 0 {
        return;
    }

    // Initialize the blockchain

    println!("No blocks found in the database. Initializing blockchain...");

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
