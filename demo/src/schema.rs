table! {
    asset_records (alias) {
        alias -> Text,
        key_json -> Text,
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
    node_records (alias) {
        alias -> Text,
        state_json -> Text,
    }
}

allow_tables_to_appear_in_same_query!(asset_records, block_records, node_records,);
