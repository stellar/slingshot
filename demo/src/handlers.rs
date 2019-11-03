use std::mem;
use std::ops::DerefMut;
use std::sync::Mutex;

use diesel::prelude::*;

use rocket::request::{Form, FromForm};
use rocket::response::{status::NotFound, Flash, Redirect};
use rocket::{Request, State};

use rocket_contrib::serve::StaticFiles;
use rocket_contrib::templates::Template;

use bulletproofs::BulletproofGens;
use zkvm::utreexo;

use crate::account::{AccountRecord, Utxo, Wallet};
use crate::asset::AssetRecord;
use crate::blockchain::BlockRecord;
use crate::db::{self, DBConnection};
use crate::mempool::{self, Mempool, MempoolTx};
use crate::schema;
use crate::sidebar::Sidebar;
use crate::user::User;
use crate::util;

#[get("/")]
fn network_status(dbconn: DBConnection, sidebar: Sidebar) -> Result<Template, NotFound<String>> {
    use schema::block_records::dsl::*;

    let blk_record = block_records
        .order(height.desc())
        .first::<BlockRecord>(&dbconn.0)
        .map_err(|_| NotFound("Block not found".into()))?;

    let context = json!({
        "sidebar": sidebar.json,
        "network_status": blk_record.network_status_summary(),
    });

    Ok(Template::render("network/status", &context))
}

#[get("/network/mempool")]
fn network_mempool(mempool: State<Mutex<Mempool>>, sidebar: Sidebar) -> Template {
    // Add tx to the mempool so we can make blocks of multiple txs in the demo.
    let mempool = mempool
        .lock()
        .expect("Threads haven't crashed holding the mutex lock");

    let context = json!({
        "sidebar": sidebar.json,
        "mempool_timestamp": util::current_timestamp_ms(),
        "mempool_len": mempool.len(),
        "mempool_size_kb": (mempool::estimated_memory_cost(&mempool) as f64) / 1024.0,
        "mempool_txs": mempool.items().map(|item| {
            BlockRecord::tx_details(&item.tx)
        }).collect::<Vec<_>>(),
    });
    Template::render("network/mempool", &context)
}

#[post("/network/mempool/makeblock")]
fn network_mempool_makeblock(
    dbconn: DBConnection,
    mempool: State<Mutex<Mempool>>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let back_url = uri!(network_mempool);
    let flash_error = |msg| Flash::error(Redirect::to(back_url.clone()), msg);

    let mut mempool = mempool
        .lock()
        .expect("Threads haven't crashed holding the mutex lock");

    let timestamp_ms = util::current_timestamp_ms();

    let txs = mempool
        .items()
        .map(|item| item.tx.clone())
        .collect::<Vec<_>>();

    let verified_txs = mempool
        .items()
        .map(|item| item.verified_tx.clone())
        .collect::<Vec<_>>();

    let proofs = mempool
        .items()
        .flat_map(|i| i.proofs.iter().cloned())
        .collect::<Vec<_>>();

    let new_state = mempool
        .make_block()
        .expect("Mempool::make_block should succeed");

    let new_block_record = BlockRecord {
        height: new_state.tip.height as i32,
        header_json: util::to_json(&new_state.tip),
        txs_json: util::to_json(&txs),
        utxo_proofs_json: util::to_json(&proofs),
        state_json: util::to_json(&new_state),
    };

    // Save everything in a single DB transaction.
    dbconn
        .0
        .transaction::<(), diesel::result::Error, _>(|| {
            // Save the new block
            {
                use schema::block_records::dsl::*;
                diesel::insert_into(block_records)
                    .values(&new_block_record)
                    .execute(&dbconn.0)?;
            }

            // Catch up ALL the nodes.

            use schema::account_records::dsl::*;
            let recs = account_records.load::<AccountRecord>(&dbconn.0)?;

            for rec in recs.into_iter() {
                let mut wallet = rec.wallet();
                wallet.process_block(
                    &verified_txs,
                    &txs,
                    new_state.tip.height,
                    &new_state.catchup,
                );
                let rec = AccountRecord::new(&wallet);
                diesel::update(account_records.filter(alias.eq(&rec.alias)))
                    .set(&rec)
                    .execute(&dbconn.0)?;
            }

            Ok(())
        })
        .map_err(|e| flash_error(format!("Database error: {}", e)))?;

    let block_height = new_state.tip.height;
    let block_id = new_state.tip.id();

    // If tx succeeded, reset the mempool to the new state.
    mem::replace(mempool.deref_mut(), Mempool::new(new_state, timestamp_ms));

    let msg = format!("Block published: {}", hex::encode(&block_id));
    Ok(Flash::success(
        Redirect::to(uri!(network_block_show: block_height as i32)),
        msg,
    ))
}

#[get("/network/blocks")]
fn network_blocks(dbconn: DBConnection, sidebar: Sidebar) -> Result<Template, NotFound<String>> {
    use schema::block_records::dsl::*;

    let blk_records = block_records
        .order(height.desc())
        .load::<BlockRecord>(&dbconn.0)
        .map_err(|_| NotFound("Blocks can't be loaded".into()))?;

    let context = json!({
        "sidebar": sidebar.json,
        "blocks": blk_records.into_iter().map(|b|b.to_table_item()).collect::<Vec<_>>()
    });

    Ok(Template::render("network/blocks", &context))
}

#[get("/network/block/<height_param>")]
fn network_block_show(
    height_param: i32,
    dbconn: DBConnection,
    sidebar: Sidebar,
) -> Result<Template, NotFound<String>> {
    use schema::block_records::dsl::*;
    let blk_record = block_records
        .filter(height.eq(&height_param))
        .first::<BlockRecord>(&dbconn.0)
        .map_err(|_| NotFound("Block not found".into()))?;

    let context = json!({
        "sidebar": sidebar.json,
        "block": blk_record.to_details(),
    });

    Ok(Template::render("network/block_show", &context))
}

#[get("/nodes/<alias_param>")]
fn nodes_show(
    alias_param: String,
    mempool: State<Mutex<Mempool>>,
    dbconn: DBConnection,
    sidebar: Sidebar,
) -> Result<Template, Flash<Redirect>> {
    let back_url = uri!(network_status);
    let flash_error = |msg| Flash::error(Redirect::to(back_url.clone()), msg);

    let current_user = sidebar.current_user;
    let (acc_record, others_aliases) = {
        use schema::account_records::dsl::*;
        let acc_record = account_records
            .filter(alias.eq(&alias_param))
            .filter(owner_id.eq(&current_user.id()))
            .first::<AccountRecord>(&dbconn.0)
            .map_err(|_| flash_error(format!("Account record not found: {}", alias_param)))?;

        let others_aliases = account_records
            .filter(owner_id.eq(&current_user.id()))
            .filter(alias.ne(&alias_param))
            .load::<AccountRecord>(&dbconn.0)
            .map_err(|_| flash_error("Cannot load other account records".to_string()))?
            .into_iter()
            .map(|rec| rec.alias)
            .collect::<Vec<_>>();

        (acc_record, others_aliases)
    };

    let others_accs = others_aliases
        .into_iter()
        .map(|alias| {
            json!({
                "wallet_id": Wallet::compute_wallet_id(&current_user.id(), &alias),
                "alias": alias
            })
        })
        .collect::<Vec<_>>();

    // TBD: we actually need all our own assets here + all the assets we know about.
    let assets = {
        use schema::asset_records::dsl::*;
        asset_records
            .load::<AssetRecord>(&dbconn.0)
            .map_err(|_| flash_error("Assets can't be loaded".to_string()))?
    };

    // load mempool txs and annotate them.
    let mempool = mempool
        .lock()
        .expect("Threads haven't crashed holding the mutex lock");

    let mut wallet_pending = acc_record.wallet();
    let pending_txs = mempool
        .items()
        .filter_map(|item| {
            let (_txid, txlog) = item
                .tx
                .precompute()
                .expect("Our mempool should not contain invalid transactions.");

            wallet_pending.process_tx(&item.tx, &txlog, None)
        })
        .collect::<Vec<_>>();

    let balances = wallet_pending.balances(&assets);

    let context = json!({
        "sidebar": sidebar.json,
        "wallet": wallet_pending.to_json(),
        "balances": balances,
        "others": others_accs,
        "pending_txs": pending_txs.into_iter().map(|atx| {
            atx.tx_details(&assets)
        }).collect::<Vec<_>>(),
        "txs": acc_record.wallet().txs.iter().map(|atx| {
            atx.tx_details(&assets)
        }).collect::<Vec<_>>(),
    });
    Ok(Template::render("nodes/show", &context))
}

#[derive(FromForm)]
struct TransferForm {
    sender_alias: String,
    recipient_wallet_id: String,
    ext_recipient_wallet_id: String,
    flavor_hex: String,
    qty: u64,
}

#[post("/pay", data = "<form>")]
fn pay(
    form: Form<TransferForm>,
    dbconn: DBConnection,
    mempool: State<Mutex<Mempool>>,
    bp_gens: State<BulletproofGens>,
    current_user: User,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let back_url = uri!(nodes_show: form.sender_alias.clone());
    let flash_error = |msg| Flash::error(Redirect::to(back_url.clone()), msg);

    if form.qty == 0 {
        return Err(flash_error("Cannot transfer zero".into()));
    }

    let recipient_wallet_id = if form.ext_recipient_wallet_id.is_empty() {
        &form.recipient_wallet_id
    } else {
        // TODO: remember this account
        &form.ext_recipient_wallet_id
    };

    // Load all records that we'll need: sender, recipient, asset.
    let (mut sender, mut recipient) = {
        use schema::account_records::dsl::*;

        let sender_record = account_records
            .filter(owner_id.eq(&current_user.id()))
            .filter(alias.eq(&form.sender_alias))
            .first::<AccountRecord>(&dbconn.0)
            .map_err(|_| flash_error("Sender not found".to_string()))?;

        let recipient_record = account_records
            .filter(wallet_id.eq(&recipient_wallet_id))
            .first::<AccountRecord>(&dbconn.0)
            .map_err(|_| flash_error("Recipient not found".to_string()))?;

        (sender_record.wallet(), recipient_record.wallet())
    };

    let sending_to_yourself = recipient.wallet_id == sender.wallet_id;

    // FIXME: we should actually just decode flavor from hex!
    let asset_record = {
        use schema::asset_records::dsl::*;

        asset_records
            .filter(flavor_hex.eq(&form.flavor_hex))
            .first::<AssetRecord>(&dbconn.0)
            .map_err(|_| flash_error("Asset not found".to_string()))?
    };

    // recipient prepares a receiver
    let payment = zkvm::ClearValue {
        qty: form.qty,
        flv: asset_record.flavor(),
    };
    let payment_receiver_witness = recipient.account.generate_receiver(payment);
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

    // In a real system we'd add pending_utxos here, but since we are not pruning the mempool,
    // we want to show these as contributing to the node's balance immediately.
    recipient.utxos.push(
        Utxo {
            receiver: payment_receiver.clone(),
            sequence: payment_receiver_witness.sequence,
            anchor: reply.anchor, // store anchor sent by Alice
            proof: utreexo::Proof::Transient,
        }
        .received(),
    );
    if sending_to_yourself {
        sender.utxos.push(
            Utxo {
                receiver: payment_receiver.clone(),
                sequence: payment_receiver_witness.sequence,
                anchor: reply.anchor, // store anchor sent by Alice
                proof: utreexo::Proof::Transient,
            }
            .received(),
        );
    }
    // Note: at this point, recipient saves the unconfirmed utxo,
    // but since we are doing the exchange in one call, we'll skip it for now.

    let verified_tx = tx
        .verify(&bp_gens)
        .expect("We just formed a tx and it must be valid");

    let txid = verified_tx.id;

    // Add tx to the mempool so we can make blocks of multiple txs in the demo.
    mempool
        .lock()
        .expect("Thread should have not crashed holding the unlocked mutex.")
        .append(MempoolTx {
            tx,
            verified_tx,
            proofs,
        })
        .map_err(|msg| flash_error(msg.to_string()))?;

    // Save everything in a single DB transaction.
    dbconn
        .0
        .transaction::<(), diesel::result::Error, _>(|| {
            // Save the updated records.
            use schema::account_records::dsl::*;
            let sender_record = AccountRecord::new(&sender);
            let sender_scope = account_records.filter(alias.eq(&sender_record.alias));
            diesel::update(sender_scope)
                .set(&sender_record)
                .execute(&dbconn.0)?;

            if !sending_to_yourself {
                let recipient_record = AccountRecord::new(&recipient);
                let recipient_scope = account_records.filter(alias.eq(&recipient_record.alias));
                diesel::update(recipient_scope)
                    .set(&recipient_record)
                    .execute(&dbconn.0)?;
            }
            Ok(())
        })
        .map_err(|e| flash_error(format!("Database error: {}", e)))?;

    let msg = format!("Transaction added to mempool: {}", hex::encode(&txid));
    Ok(Flash::success(Redirect::to(back_url), msg))
}

#[get("/assets/<flavor_param>")]
fn assets_show(
    flavor_param: String,
    dbconn: DBConnection,
    sidebar: Sidebar,
) -> Result<Template, NotFound<String>> {
    use schema::asset_records::dsl::*;

    let asset = asset_records
        .filter(flavor_hex.eq(flavor_param))
        .first::<AssetRecord>(&dbconn.0)
        .map_err(|_| NotFound("Asset not found".into()))?;

    let context = json!({
        "sidebar": sidebar.json,
        "asset": asset.to_json()
    });
    Ok(Template::render("assets/show", &context))
}

#[derive(FromForm)]
struct NewAccountForm {
    alias: String,
}

#[post("/nodes/create", data = "<form>")]
fn nodes_create(
    form: Form<NewAccountForm>,
    dbconn: DBConnection,
    current_user: User,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let flash_error = |msg| Flash::error(Redirect::to(uri!(network_status)), msg);

    let dbconn = dbconn.0;
    dbconn
        .transaction::<(), diesel::result::Error, _>(|| {
            let new_record = AccountRecord::new(&Wallet::new(&current_user, &form.alias));

            {
                use schema::account_records::dsl::*;
                diesel::insert_into(account_records)
                    .values(&new_record)
                    .execute(&dbconn)?;
            }

            Ok(())
        })
        .map_err(|e| flash_error(e.to_string()))?;

    let msg = format!("Account created: {}", &form.alias);
    Ok(Flash::success(
        Redirect::to(uri!(nodes_show: &form.alias)),
        msg,
    ))
}

#[derive(FromForm)]
struct NewAssetForm {
    asset_alias: String,
    qty: u64,
    recipient_wallet_id: String,
    ext_recipient_wallet_id: String,
}

#[post("/assets/create", data = "<form>")]
fn assets_create(
    form: Form<NewAssetForm>,
    mempool: State<Mutex<Mempool>>,
    bp_gens: State<BulletproofGens>,
    dbconn: DBConnection,
    current_user: User,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let flash_error = |msg| Flash::error(Redirect::to(uri!(network_status)), msg);

    // Determine the recipient.

    let recipient_wallet_id = if form.ext_recipient_wallet_id.is_empty() {
        &form.recipient_wallet_id
    } else {
        // TODO: remember this account
        &form.ext_recipient_wallet_id
    };

    // Uses any issuer's utxo to help create an issuance transaction.

    let dbconn = dbconn.0;

    let asset_record = dbconn
        .transaction::<AssetRecord, diesel::result::Error, _>(|| {
            // Try to find the record by name, if not found - create one.

            use schema::asset_records::dsl::*;

            let rec = asset_records
                .filter(owner_id.eq(&current_user.id()))
                .filter(alias.eq(&form.asset_alias))
                .first::<AssetRecord>(&dbconn)
                .unwrap_or_else(|_| {
                    let rec = AssetRecord::new(&current_user, form.asset_alias.clone());
                    diesel::insert_into(asset_records)
                        .values(&rec)
                        .execute(&dbconn)
                        .expect("Inserting an asset record should work");
                    rec
                });
            Ok(rec)
        })
        .map_err(|e| flash_error(e.to_string()))?;

    // Find some utxo from the Root's account and use it as an anchoring tool.
    let mut issuer = {
        use schema::account_records::dsl::*;
        account_records
            .filter(alias.eq("Root"))
            .first::<AccountRecord>(&dbconn)
            .map_err(|msg| flash_error(msg.to_string()))?
            .wallet()
    };

    let mut recipient = {
        use schema::account_records::dsl::*;
        account_records
            .filter(wallet_id.eq(&recipient_wallet_id))
            .first::<AccountRecord>(&dbconn)
            .map_err(|msg| flash_error(msg.to_string()))?
            .wallet()
    };

    // Root will be receiving the tokens it issues.
    let payment = zkvm::ClearValue {
        qty: form.qty,
        flv: asset_record.flavor(),
    };
    let payment_receiver_witness = recipient.account.generate_receiver(payment);
    let payment_receiver = &payment_receiver_witness.receiver;

    // Note: at this point, recipient saves the increased seq #,
    // but since we are doing the exchange in one call, we'll skip it.

    // Sender prepares a tx
    let (tx, _txid, proofs, reply) = issuer
        .prepare_issuance_tx(
            asset_record.issuance_key(),
            asset_record.metadata(),
            &payment_receiver,
            &bp_gens,
        )
        .map_err(|msg| flash_error(msg.to_string()))?;
    // Note: at this point, sender reserves the utxos and saves its incremented seq # until sender ACK'd ReceiverReply,
    // but since we are doing the exchange in one call, we'll skip it.

    // Recipient receives new tokens, so they can spend them right away.
    recipient.utxos.push(
        Utxo {
            receiver: payment_receiver.clone(),
            sequence: payment_receiver_witness.sequence,
            anchor: reply.anchor, // store anchor sent by Alice
            proof: utreexo::Proof::Transient,
        }
        .received(),
    );

    // Note: at this point, recipient saves the unconfirmed utxo,
    // but since we are doing the exchange in one call, we'll skip it for now.

    let verified_tx = tx
        .verify(&bp_gens)
        .expect("We just formed a tx and it must be valid");

    let txid = verified_tx.id;

    // Add tx to the mempool so we can make blocks of multiple txs in the demo.
    mempool
        .lock()
        .expect("Thread should have not crashed holding the unlocked mutex.")
        .append(MempoolTx {
            tx,
            verified_tx,
            proofs,
        })
        .map_err(|msg| flash_error(msg.to_string()))?;

    // Save everything in a single DB transaction.
    dbconn
        .transaction::<(), diesel::result::Error, _>(|| {
            // Save the updated records.
            use schema::account_records::dsl::*;
            let issuer_record = AccountRecord::new(&issuer);
            let scope = account_records.filter(alias.eq(&issuer_record.alias));
            diesel::update(scope).set(&issuer_record).execute(&dbconn)?;

            let recipient_record = AccountRecord::new(&recipient);
            let scope = account_records.filter(alias.eq(&recipient_record.alias));
            diesel::update(scope)
                .set(&recipient_record)
                .execute(&dbconn)?;

            Ok(())
        })
        .map_err(|e| flash_error(format!("Database error: {}", e)))?;

    let msg = format!(
        "Asset {} issued. Transaction added to mempool: {}",
        form.asset_alias,
        hex::encode(&txid)
    );

    if recipient.owner_id == current_user.id() {
        Ok(Flash::success(
            Redirect::to(uri!(nodes_show: &recipient.alias)),
            msg,
        ))
    } else {
        // If external account - show the mempool
        Ok(Flash::success(Redirect::to(uri!(network_mempool)), msg))
    }
}

#[catch(404)]
fn not_found(req: &Request<'_>) -> Template {
    let sidebar = req.guard::<Sidebar>().expect("Sidebar guard never fails.");
    let context = json!({
        "sidebar": sidebar.json,
        "path": req.uri().path(),
    });

    Template::render("404", &context)
}

fn prepare_mempool() -> Mempool {
    use schema::block_records::dsl::*;
    let dbconn = db::establish_db_connection();

    let blk_record = block_records
        .order(height.desc())
        .first::<BlockRecord>(&dbconn)
        .expect("Block not found. Make sure prepare_db_if_needed() was called.".into());

    let timestamp_ms = util::current_timestamp_ms();

    Mempool::new(blk_record.state(), timestamp_ms)
}

pub fn launch_rocket_app() {
    // TBD: make the gens size big enough
    let bp_gens = BulletproofGens::new(256, 1);
    let mempool = Mutex::new(prepare_mempool());

    rocket::ignite()
        .attach(DBConnection::fairing())
        .attach(Template::fairing())
        .register(catchers![not_found])
        .manage(mempool)
        .manage(bp_gens)
        .mount("/static", StaticFiles::from("static"))
        .mount("/favicon.ico", StaticFiles::from("static"))
        .mount(
            "/",
            routes![
                network_status,
                network_mempool,
                network_mempool_makeblock,
                network_blocks,
                network_block_show,
                nodes_show,
                nodes_create,
                assets_show,
                assets_create,
                pay
            ],
        )
        .launch();
}
