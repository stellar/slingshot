#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
#[macro_use]
extern crate serde_json;

extern crate time;

mod account;
mod asset;
mod blockchain;
mod db;
mod handlers;
mod mempool;
mod names;
mod schema;
mod sidebar;
mod user;
mod util;

fn main() {
    db::prepare_db_if_needed();
    handlers::launch_rocket_app();
}
