use rocket::outcome::IntoOutcome;
use rocket::request::{self, FlashMessage, FromRequest, Request};
use serde_json::Value as JsonValue;

use diesel::prelude::*;

use crate::account::AccountRecord;
use crate::asset::AssetRecord;
use crate::db::DBConnection;
use crate::schema;
use crate::user::User;

pub struct Sidebar {
    pub json: JsonValue,
    pub current_user: User,
}

impl<'a, 'r> FromRequest<'a, 'r> for Sidebar {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Sidebar, ()> {
        let dbconn = request.guard::<DBConnection>()?.0;
        let flash = request
            .guard::<Option<FlashMessage>>()
            .expect("Error type for Option<FlashMessage> is ! anyway");
        let current_user = request.guard::<User>()?;

        // TBD: load User and user-specific accounts and assets

        use schema::account_records::dsl::*;
        use schema::asset_records::dsl::*;

        let accounts = account_records
            .load::<AccountRecord>(&dbconn)
            .expect("Error loading accounts");
        let assets = asset_records
            .load::<AssetRecord>(&dbconn)
            .expect("Error loading assets");

        Some(Sidebar {
            json: json!({
                "flash": flash.map(|f| json!({
                    "name": f.name(),
                    "msg": f.msg(),
                })),
                "accounts": accounts.into_iter().map(|n|n.to_json()).collect::<Vec<_>>(),
                "assets": assets.into_iter().map(|a|a.to_json()).collect::<Vec<_>>(),
                "current_user_id": current_user.id()
            }),
            current_user: current_user,
        })
        .or_forward(())
    }
}
