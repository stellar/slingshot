table! {
    blocks (height) {
        height -> Integer,
        block -> Text,
    }
}

table! {
    nodes (alias) {
        alias -> Text,
        state -> Text,
    }
}

allow_tables_to_appear_in_same_query!(
    blocks,
    nodes,
);
