#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
#[macro_use]
extern crate serde_json;

mod nodes;
mod records;
mod schema;
mod util;

use std::collections::HashMap;
use std::env;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use dotenv::dotenv;

use rocket::request::{Form, FromForm, FlashMessage};
use rocket::response::{Flash, Redirect, status::NotFound};
use rocket::Request;
use rocket_contrib::serve::StaticFiles;
use rocket_contrib::templates::Template;

#[database("demodb")]
struct DBConnection(SqliteConnection);

#[get("/")]
fn network_status(dbconn: DBConnection) -> Result<Template, NotFound<String>> {
    use schema::block_records::dsl::*;

    let blk_record = block_records
        .order(height.desc())
        .first::<records::BlockRecord>(&dbconn.0)
        .map_err(|_| NotFound("Block not found".into()))?;

    let context = json!({
        "sidebar": sidebar_context(&dbconn.0),
        "network_status": blk_record.network_status_summary()
    });

    Ok(Template::render("network/status", &context))
}

#[get("/network/mempool")]
fn network_mempool(dbconn: DBConnection) -> Template {
    let context = json!({
        "sidebar": sidebar_context(&dbconn.0)
    });
    Template::render("network/mempool", &context)
}

#[get("/network/blocks")]
fn network_blocks(dbconn: DBConnection) -> Result<Template, NotFound<String>> {
    use schema::block_records::dsl::*;

    let blk_records = block_records
        .order(height.desc())
        .load::<records::BlockRecord>(&dbconn.0)
        .map_err(|_| NotFound("Blocks can't be loaded".into()))?;

    let context = json!({
        "sidebar": sidebar_context(&dbconn.0),
        "blocks": blk_records.into_iter().map(|b|b.to_table_item()).collect::<Vec<_>>()
    });

    Ok(Template::render("network/blocks", &context))
}

#[get("/nodes/<alias_param>")]
fn nodes_show(alias_param: String, flash: Option<FlashMessage>, dbconn: DBConnection) -> Result<Template, NotFound<String>> {
    let (node,others_aliases) = {
        use schema::node_records::dsl::*;
        let node = node_records
            .filter(alias.eq(&alias_param))
            .first::<records::NodeRecord>(&dbconn.0)
            .map_err(|_| NotFound("Node not found".into()))?;

        let others_aliases = node_records
            .filter(alias.ne(&alias_param))
            .load::<records::NodeRecord>(&dbconn.0)
            .map_err(|_| NotFound("Cannot load nodes".into()))?
            .into_iter()
            .map(|rec| rec.alias)
            .collect::<Vec<_>>();

        (node, others_aliases)
    };

    let assets = {
        use schema::asset_records::dsl::*;
        asset_records
            .load::<records::AssetRecord>(&dbconn.0)
            .map_err(|_| NotFound("Assets can't be loaded".into()))?
    };

    let balances = node.balances(&assets);

    let context = json!({
        "sidebar": sidebar_context(&dbconn.0),
        "node": node.to_json(),
        "balances": balances,
        "others": others_aliases,
        "flash": flash.map(|f| {json!({
            "name": f.name(),
            "msg": f.msg(),
        })})
    });
    Ok(Template::render("nodes/show", &context))
}

#[derive(FromForm)]
struct TransferForm {
    sender_alias: String,
    recipient_alias: String,
    flavor_alias: String,
    qty: String,
}


#[post("/pay", data = "<transfer_form>")]
fn pay(transfer_form: Form<TransferForm>, dbconn: DBConnection) -> Flash<Redirect> {
    
    // TBD: load all records related to sending 

    Flash::error(Redirect::to(uri!(nodes_show: transfer_form.sender_alias.clone())), "Insufficient funds")
}


#[get("/assets/<alias_param>")]
fn assets_show(alias_param: String, dbconn: DBConnection) -> Result<Template, NotFound<String>> {
    use schema::asset_records::dsl::*;

    let asset = asset_records
        .filter(alias.eq(alias_param))
        .first::<records::AssetRecord>(&dbconn.0)
        .map_err(|_| NotFound("Asset not found".into()))?;

    let context = json!({
        "sidebar": sidebar_context(&dbconn.0),
        "asset": asset.to_json()
    });
    Ok(Template::render("assets/show", &context))
}

#[catch(404)]
fn not_found(req: &Request<'_>) -> Template {
    let mut map = HashMap::new();
    map.insert("path", req.uri().path());
    Template::render("404", &map)
}

/// Returns context for the sidebar in all the pages
fn sidebar_context(dbconn: &SqliteConnection) -> serde_json::Value {
    use schema::asset_records::dsl::*;
    use schema::node_records::dsl::*;

    let nodes = node_records
        .load::<records::NodeRecord>(dbconn)
        .expect("Error loading nodes");
    let assets = asset_records
        .load::<records::AssetRecord>(dbconn)
        .expect("Error loading assets");
    json!({
        "nodes": nodes.into_iter().map(|n|n.to_json()).collect::<Vec<_>>(),
        "assets": assets.into_iter().map(|a|a.to_json()).collect::<Vec<_>>(),
    })
}

fn prepare_db_if_needed() {
    use schema::asset_records::dsl::*;
    use schema::block_records::dsl::*;
    use schema::node_records::dsl::*;

    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_connection = SqliteConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url));

    let results = block_records
        .limit(1)
        .load::<records::BlockRecord>(&db_connection)
        .expect("Error loading a block");

    if results.len() > 0 {
        return;
    }

    // Initialize the blockchain

    println!("No blocks found in the database. Initializing blockchain...");
    db_connection
        .transaction::<(), diesel::result::Error, _>(|| {
            use nodes::{Node, Wallet};
            use zkvm::{Anchor, Block, BlockchainState};

            let token_record = records::AssetRecord::new("Token");
            let usd_record = records::AssetRecord::new("USD");
            let eur_record = records::AssetRecord::new("EUR");

            diesel::insert_into(asset_records)
                .values(vec![&token_record, &usd_record, &eur_record])
                .execute(&db_connection)
                .expect("Inserting an asset record should work");

            // Create a treasury node that will issue various tokens to anyone.
            let mut treasury_wallet = Wallet::new("Issuer");

            let pending_utxos = {
                let mut utxos = Vec::new();
                let anchor = Anchor::from_raw_bytes([0; 32]);

                let (mut list, anchor) =
                    treasury_wallet.mint_utxos(anchor, token_record.flavor(), vec![1, 2, 4, 8]);
                utxos.append(&mut list);
                let (mut list, anchor) =
                    treasury_wallet.mint_utxos(anchor, usd_record.flavor(), vec![1000, 5000]);
                utxos.append(&mut list);
                let (mut list, _) =
                    treasury_wallet.mint_utxos(anchor, eur_record.flavor(), vec![80, 99, 7000]);
                utxos.append(&mut list);

                utxos
            };

            let (network_state, proofs) = BlockchainState::make_initial(
                0u64,
                pending_utxos.iter().map(|utxo| utxo.contract().id()),
            );

            treasury_wallet.utxos = pending_utxos
                .into_iter()
                .zip(proofs.into_iter())
                .map(|(pending_utxo, proof)| pending_utxo.to_confirmed(proof))
                .collect();

            let initial_block_record = records::BlockRecord {
                height: 1,
                block_json: util::to_json(&Block {
                    header: network_state.tip.clone(),
                    txs: Vec::new(),
                    all_utxo_proofs: Vec::new(),
                }),
                state_json: util::to_json(&network_state),
            };

            diesel::insert_into(block_records)
                .values(&initial_block_record)
                .execute(&db_connection)
                .expect("Inserting a block record should work");

            let treasury = Node {
                blockchain: network_state.clone(),
                wallet: treasury_wallet,
            };

            let treasury_record = records::NodeRecord::new(treasury);
            let alice_record = records::NodeRecord::new(Node::new("Alice", network_state.clone()));
            let bob_record = records::NodeRecord::new(Node::new("Bob", network_state.clone()));

            diesel::insert_into(node_records)
                .values(vec![&treasury_record, &alice_record, &bob_record])
                .execute(&db_connection)
                .expect("Inserting new node records should work");

            Ok(())
        })
        .expect("Initial DB transaction should succeed.");
}

fn launch_rocket_app() {
    rocket::ignite()
        .attach(DBConnection::fairing())
        .attach(Template::fairing())
        .mount("/static", StaticFiles::from("static"))
        .mount(
            "/",
            routes![
                network_status,
                network_mempool,
                network_blocks,
                nodes_show,
                assets_show,
                pay
            ],
        )
        .launch();
}

fn main() {
    prepare_db_if_needed();
    launch_rocket_app();
}
