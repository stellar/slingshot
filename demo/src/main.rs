#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;
extern crate rocket_contrib;

use rocket::Request;
use rocket_contrib::templates::Template;
use rocket_contrib::serve::StaticFiles;
use std::collections::HashMap;

#[get("/")]
fn network_status() -> Template {
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

fn main() {
    rocket::ignite()
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