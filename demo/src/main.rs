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
mod publication;
mod records;
mod schema;
mod util;

use std::collections::HashMap;
use std::env;
use std::sync::Mutex;
use std::time::SystemTime;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use dotenv::dotenv;

use rocket::request::{FlashMessage, Form, FromForm};
use rocket::response::{status::NotFound, Flash, Redirect};
use rocket::{Request, State};
use rocket_contrib::serve::StaticFiles;
use rocket_contrib::templates::Template;

use bulletproofs::BulletproofGens;
use zkvm::blockchain::Mempool;
use zkvm::utreexo;

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
fn network_mempool(dbconn: DBConnection, mempool: State<Mutex<Mempool>>) -> Template {
    // Add tx to the mempool so we can make blocks of multiple txs in the demo.
    let mempool = mempool
        .lock()
        .expect("Threads haven't crashed holding the mutex lock");

    let context = json!({
        "sidebar": sidebar_context(&dbconn.0),
        "mempool_len": mempool.len(),
        "mempool_size_kb": (mempool.estimated_memory_cost() as f64) / 1024.0,
        "mempool_txs": mempool.txs().map(|tx| {
            records::BlockRecord::tx_details(&tx)
        }).collect::<Vec<_>>()
    });
    Template::render("network/mempool", &context)
}

#[post("/network/mempool/makeblock")]
fn network_mempool_makeblock(
    dbconn: DBConnection,
    mempool: State<Mutex<Mempool>>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let back_url = uri!(network_mempool);

    // let (new_block_record, new_block) = {
    //     use schema::block_records::dsl::*;

    //     let blk_record = block_records
    //         .order(height.desc())
    //         .first::<records::BlockRecord>(&dbconn.0)
    //         .map_err(|_| flash_error("Block not found".to_string()))?;

    //     let state = blk_record.state();

    //     let timestamp = SystemTime::now()
    //         .duration_since(SystemTime::UNIX_EPOCH)
    //         .expect("SystemTime should work")
    //         .as_millis() as u64;
    //     let (new_block, _verified_block, new_state) = state
    //         .make_block(1, timestamp, Vec::new(), vec![tx], proofs, &bp_gens)
    //         .expect("BlockchainState::make_block should succeed");

    //     // Store the new state
    //     (
    //         records::BlockRecord {
    //             height: new_block.header.height as i32,
    //             block_json: util::to_json(&new_block),
    //             state_json: util::to_json(&new_state),
    //         },
    //         new_block,
    //     )
    // };

    // // Save everything in a single DB transaction.
    // dbconn
    //     .0
    //     .transaction::<(), diesel::result::Error, _>(|| {
    //         // Save the new block
    //         {
    //             use schema::block_records::dsl::*;
    //             diesel::insert_into(block_records)
    //                 .values(&new_block_record)
    //                 .execute(&dbconn.0)?;
    //         }

    //         // Catch up ALL the nodes.

    //         use schema::node_records::dsl::*;
    //         let recs = node_records.load::<records::NodeRecord>(&dbconn.0)?;

    //         for rec in recs.into_iter() {
    //             let mut node = rec.node();
    //             node.process_block(&new_block, &bp_gens);
    //             let rec = records::NodeRecord::new(node);
    //             diesel::update(node_records.filter(alias.eq(&rec.alias)))
    //                 .set(&rec)
    //                 .execute(&dbconn.0)?;
    //         }

    //         Ok(())
    //     })
    //     .map_err(|e| flash_error(format!("Database error: {}", e)))?;

    //let msg = format!("Block published: ", hex::encode(&blockid));
    let msg = format!("Block published: TBD");
    Ok(Flash::success(Redirect::to(back_url), msg))
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

#[get("/network/block/<height_param>")]
fn network_block_show(
    height_param: i32,
    dbconn: DBConnection,
) -> Result<Template, NotFound<String>> {
    use schema::block_records::dsl::*;
    let blk_record = block_records
        .filter(height.eq(&height_param))
        .first::<records::BlockRecord>(&dbconn.0)
        .map_err(|_| NotFound("Block not found".into()))?;

    let context = json!({
        "sidebar": sidebar_context(&dbconn.0),
        "block": blk_record.to_details()
    });

    Ok(Template::render("network/block_show", &context))
}

#[get("/nodes/<alias_param>")]
fn nodes_show(
    alias_param: String,
    flash: Option<FlashMessage>,
    dbconn: DBConnection,
) -> Result<Template, NotFound<String>> {
    let (node, others_aliases) = {
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
    qty: u64,
}

#[post("/pay", data = "<transfer_form>")]
fn pay(
    transfer_form: Form<TransferForm>,
    dbconn: DBConnection,
    mempool: State<Mutex<Mempool>>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let back_url = uri!(nodes_show: transfer_form.sender_alias.clone());
    let flash_error = |msg| Flash::error(Redirect::to(back_url.clone()), msg);

    let bp_gens = BulletproofGens::new(256, 1);

    // Load all records that we'll need: sender, recipient, asset.
    let (mut sender, mut recipient) = {
        use schema::node_records::dsl::*;

        let sender_record = node_records
            .filter(alias.eq(&transfer_form.sender_alias))
            .first::<records::NodeRecord>(&dbconn.0)
            .map_err(|_| flash_error("Sender not found".to_string()))?;

        let recipient_record = node_records
            .filter(alias.eq(&transfer_form.recipient_alias))
            .first::<records::NodeRecord>(&dbconn.0)
            .map_err(|_| flash_error("Recipient not found".to_string()))?;

        (sender_record.node(), recipient_record.node())
    };

    let asset_record = {
        use schema::asset_records::dsl::*;

        asset_records
            .filter(alias.eq(&transfer_form.flavor_alias))
            .first::<records::AssetRecord>(&dbconn.0)
            .map_err(|_| flash_error("Asset not found".to_string()))?
    };

    // recipient prepares a receiver
    let payment = zkvm::ClearValue {
        qty: transfer_form.qty,
        flv: asset_record.flavor(),
    };
    let payment_receiver_witness = recipient.wallet.account.generate_receiver(payment);
    let payment_receiver = &payment_receiver_witness.receiver;

    // Note: at this point, recipient saves the increased seq #,
    // but since we are doing the exchange in one call, we'll skip it.

    // Sender prepares a tx
    let (tx, _txid, proofs, reply) = sender
        .prepare_payment_tx(&payment_receiver, &bp_gens)
        .map_err(|msg| flash_error(msg.to_string()))?;
    // Note: at this point, sender reserves the utxos and saves its incremented seq # until sender ACK'd ReceiverReply,
    // but since we are doing the exchange in one call, we'll skip it.

    // Sender gives Recipient info to watch for tx.
    recipient.wallet.pending_utxos.push(nodes::Utxo {
        receiver_witness: payment_receiver_witness,
        anchor: reply.anchor, // store anchor sent by Alice
        proof: utreexo::Proof::Transient,
    });
    // Note: at this point, recipient saves the unconfirmed utxo,
    // but since we are doing the exchange in one call, we'll skip it for now.

    // Add tx to the mempool so we can make blocks of multiple txs in the demo.
    let txid = mempool
        .lock()
        .expect("Threads haven't crashed holding the mutex lock")
        .append(tx, proofs, &bp_gens)
        .map_err(|msg| flash_error(msg.to_string()))?;

    // Save everything in a single DB transaction.
    dbconn
        .0
        .transaction::<(), diesel::result::Error, _>(|| {
            // Save the updated records.
            use schema::node_records::dsl::*;
            let sender_record = records::NodeRecord::new(sender);
            let sender_scope = node_records.filter(alias.eq(&sender_record.alias));
            diesel::update(sender_scope)
                .set(&sender_record)
                .execute(&dbconn.0)?;

            let recipient_record = records::NodeRecord::new(recipient);
            let recipient_scope = node_records.filter(alias.eq(&recipient_record.alias));
            diesel::update(recipient_scope)
                .set(&recipient_record)
                .execute(&dbconn.0)?;

            Ok(())
        })
        .map_err(|e| flash_error(format!("Database error: {}", e)))?;

    let msg = format!("Transaction saved in mempool: {}", hex::encode(&txid));
    Ok(Flash::success(Redirect::to(back_url), msg))
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

//
// Initial setup helpers
//

fn establish_db_connection() -> SqliteConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url))
}

fn prepare_db_if_needed() {
    use schema::asset_records::dsl::*;
    use schema::block_records::dsl::*;
    use schema::node_records::dsl::*;

    let db_connection = establish_db_connection();

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

            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("SystemTime should work")
                .as_millis() as u64;
            let (network_state, proofs) = BlockchainState::make_initial(
                timestamp,
                pending_utxos.iter().map(|utxo| utxo.contract().id()),
            );

            treasury_wallet.utxos = pending_utxos
                .into_iter()
                .zip(proofs.into_iter())
                .map(|(mut pending_utxo, proof)| {
                    pending_utxo.proof = proof;
                    pending_utxo
                })
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

fn prepare_mempool() -> Mempool {
    use schema::block_records::dsl::*;
    let dbconn = establish_db_connection();

    let blk_record = block_records
        .order(height.desc())
        .first::<records::BlockRecord>(&dbconn)
        .expect("Block not found. Make sure prepare_db_if_needed() was called.".into());

    let timestamp_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("SystemTime should work")
        .as_millis() as u64;

    Mempool::new(blk_record.state(), timestamp_ms)
}

fn launch_rocket_app() {
    // TBD: make the gens size big enough
    let bp_gens = BulletproofGens::new(256, 1);
    let mempool = Mutex::new(prepare_mempool());

    rocket::ignite()
        .attach(DBConnection::fairing())
        .attach(Template::fairing())
        .manage(mempool)
        .manage(bp_gens)
        .mount("/static", StaticFiles::from("static"))
        .mount(
            "/",
            routes![
                network_status,
                network_mempool,
                network_mempool_makeblock,
                network_blocks,
                network_block_show,
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
