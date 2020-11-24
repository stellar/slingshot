# Slingshot Node

Blockchain node application.

## Creating a new blockchain

Choose a prefix for the addresses and create a new ledger:

    slingshot new --prefix=test

This generates a random block signing key and places it in `<blockchain.storage_path>/signer.key`.

Also generates a wallet key and places it in `<wallet.storage_path>/wallet.xprv`

(Encryption and external signers will be available later.)

## TBD: Connecting to an existing blockchain

TODO: we need a format for bootstrap data (utreexo commitment, address prefix, signer key)

Choose a prefix for the addresses and create a new ledger:

    slingshot connect ...

This generates a wallet key and places it in `<wallet.storage_path>/wallet.xprv`

(Encryption and external signers will be available later.)

## Starting the node

Launch the initialized node to catchup with the network:

    slingshot run

Then, open http://localhost:3000 in your browser.

## Wallet

Show balances:

    $ slingshot wallet balance
      e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855       100   Alice-USD
      c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a     10000   Bob-USD
      7281234e9f3f150763b220fb65843df1fd5a453db5473be4feb705915bc19319     10000   (unknown asset)

Show assets:

    $ slingshot wallet assets
      
      Issued by this wallet:
      e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 Alice-USD
      26c03b239cef0f2542be385f817aa9f79ba206f4e01aebb311066df775003596 Alice-EUR
      
      Issued by others:
      c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a Bob-USD

Register a known asset alias:

    $ slingshot wallet add-asset c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a Bob-USD
      
Generate an address:

    $ slingshot wallet new-address
      test1uq90n36dnmdca0xpvr8we974x89adc54d71fzc4ca8k6yc8g9epca0ntey5jx9jk3q70cwzzjz6jgwx8zm6ezff4ss0f9a5p2junsnc480zqt

Issue an asset:

    $ slingshot wallet issue \
                --alias=Alice-USD \
                --qty=12351 \
                --address=test1uq90n36dnmdca0xpvr8we974x89adc54d71fzc4ca8k6yc8g9epca0ntey5jx9jk3q70cwzzjz6jgwx8zm6ezff4ss0f9a5p2junsnc480zqt

Send funds to an address:

    $ slingshot wallet send \
                --address=test1uq90n36dnmdca0xpvr8we974x89adc54d71fzc4ca8k6yc8g9epca0ntey5jx9jk3q70cwzzjz6jgwx8zm6ezff4ss0f9a5p2junsnc480zqt \
                --qty=1235 \
                --asset=Alice-USD

## Viewing current configuration

Shows current configuration settings:

    slingshot config

