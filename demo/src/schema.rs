table! {
    account_records (owner_id, alias) {
        owner_id -> Text,
        alias -> Text,
        wallet_id -> Text,
        wallet_json -> Text,
    }
}

table! {
    asset_records (owner_id, alias) {
        owner_id -> Text,
        alias -> Text,
        key_hex -> Text,
        flavor_hex -> Text,
    }
}

table! {
    block_records (height) {
        height -> Integer,
        header_json -> Text,
        txs_json -> Text,
        utxo_proofs_json -> Text,
        state_json -> Text,
    }
}

table! {
    user_records (id) {
        id -> Text,
        seed -> Text,
        info_json -> Text,
    }
}

allow_tables_to_appear_in_same_query!(
    account_records,
    asset_records,
    block_records,
    user_records,
);
