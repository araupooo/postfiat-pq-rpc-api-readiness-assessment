# Source excerpts

Short verbatim excerpts from the pinned postfiatd tree. Every excerpt
gives the exact commit SHA and repo path. Full excerpts (with header,
line range, file SHA-256, and git blob SHA) are in
`fixtures/source-excerpts/E01.txt`–`E41.txt`; the manifest is
`fixtures/excerpts-manifest.json`.

Commit: `0085a1ff885d6a446369cf73a4430f75af22be55` (postfiatd).

## E02 — handler table: signing methods registered

`src/xrpld/rpc/detail/Handler.cpp:170-176`

```cpp
    {"sign", byRef(&doSign), Role::USER, NO_CONDITION},
```

## E10 — transaction signing with the supplied secret key

`src/xrpld/rpc/detail/TransactionSign.cpp:676-682`

```cpp
        auto multisig = ripple::sign(pk, sk, s.slice());
```

```cpp
        stTx->sign(pk, sk, signatureTarget);
```

## E17 — validation_create generates a secp256k1 key pair

`src/xrpld/rpc/handlers/ValidationCreate.cpp:54-58`

```cpp
    auto const private_key = generateSecretKey(KeyType::secp256k1, *seed);
```

## E22 — sha512Half definition

`include/xrpl/protocol/digest.h:222-231`

```cpp
template <class... Args>
sha512_half_hasher::result_type
sha512Half(Args const&... args)
{
    sha512_half_hasher h;
    using beast::hash_append;
    hash_append(h, args...);
    return static_cast<typename sha512_half_hasher::result_type>(h);
}
```

## E23 — KeyType has exactly two enumerators

`include/xrpl/protocol/KeyType.h:29-30`

```cpp
    secp256k1 = 0,
    ed25519 = 1,
```

## E26 — default TLS cipher list

`src/libxrpl/basics/make_SSLContext.cpp:104`

```cpp
std::string const defaultCipherList = "TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL";
```

## E31 — gRPC handler declarations

`src/xrpld/rpc/GRPCHandlers.h:40-41`

```cpp
std::pair<org::xrpl::rpc::v1::GetLedgerResponse, grpc::Status>
doLedgerGrpc(RPC::GRPCContext<org::xrpl::rpc::v1::GetLedgerRequest>& context);
```

## E38 — signing gate

`src/xrpld/core/Config.h:365-367`

```cpp
    canSign() const
    {
        return signingEnabled_;
    }
```

## Full excerpt index

| ID | File | Lines | Purpose |
|----|------|-------|---------|
| E01 | src/xrpld/rpc/detail/Handler.cpp | 84-87 | handlerArray opens; account_info registered |
| E02 | src/xrpld/rpc/detail/Handler.cpp | 170-176 | sign, sign_for, simulate, submit, submit_multisigned |
| E03 | src/xrpld/rpc/detail/Handler.cpp | 183-187 | validation_create registration (ADMIN) |
| E04 | src/xrpld/rpc/detail/Handler.cpp | 196-199 | wallet_propose (ADMIN); subscribe/unsubscribe |
| E05 | src/xrpld/rpc/detail/Handler.cpp | 133-136 | ledger_header pinned to API v1,1 |
| E06 | src/xrpld/rpc/detail/Handler.cpp | 146-150 | profile handler commented out |
| E07 | src/xrpld/rpc/detail/Handler.cpp | 246-250 | addHandler LedgerHandler/VersionHandler |
| E08 | src/xrpld/rpc/handlers/LedgerHandler.h | 51-75 | LedgerHandler: name ledger, USER, NO_CONDITION |
| E09 | src/xrpld/rpc/handlers/Version.h | 28-64 | VersionHandler: name version, USER, NO_CONDITION |
| E10 | src/xrpld/rpc/detail/TransactionSign.cpp | 670-686 | ripple::sign / stTx->sign call sites |
| E11 | src/xrpld/rpc/detail/TransactionSign.cpp | 998-1010 | transactionSign definition |
| E12 | src/xrpld/rpc/detail/TransactionSign.cpp | 1166-1180 | transactionSignFor definition |
| E13 | src/xrpld/rpc/detail/TransactionSign.cpp | 1282-1295 | transactionSubmitMultiSigned definition |
| E14 | src/libxrpl/protocol/STTx.cpp | 259-295 | STTx::checkSign verification |
| E15 | src/xrpld/rpc/handlers/PayChanClaim.cpp | 85-100 | channel_authorize signs a claim |
| E16 | src/xrpld/rpc/handlers/PayChanClaim.cpp | 155-164 | channel_verify verifies a claim |
| E17 | src/xrpld/rpc/handlers/ValidationCreate.cpp | 44-66 | validation_create key generation |
| E18 | src/xrpld/rpc/handlers/WalletPropose.cpp | 130-145 | wallet_propose key generation |
| E19 | src/xrpld/rpc/handlers/DoManifest.cpp | 30-65 | manifest lookup by node public key |
| E20 | src/xrpld/overlay/detail/Handshake.cpp | 195-210 | handshake session signature (signDigest) |
| E21 | src/xrpld/overlay/detail/Handshake.cpp | 310-322 | handshake signature verification |
| E22 | include/xrpl/protocol/digest.h | 218-245 | sha512Half / sha512Half_s definitions |
| E23 | include/xrpl/protocol/KeyType.h | 25-55 | KeyType enum, secp256k1/ed25519 |
| E24 | src/libxrpl/protocol/PublicKey.cpp | 225-245 | verifyDigest (secp256k1) |
| E25 | src/libxrpl/protocol/PublicKey.cpp | 295-310 | Ed25519 verification + canonical check |
| E26 | src/libxrpl/basics/make_SSLContext.cpp | 90-106 | default TLS cipher list |
| E27 | src/libxrpl/basics/make_SSLContext.cpp | 347-376 | cipher list applied to OpenSSL context |
| E28 | include/xrpl/protocol/STValidation.h | 90-102 | STValidation construct/sign/trust |
| E29 | src/xrpld/rpc/handlers/LedgerData.cpp | 75-85 | ledger_data returns ledger hash |
| E30 | src/xrpld/rpc/handlers/Tx.cpp | 44-56 | tx hash-by-sequence check |
| E31 | src/xrpld/rpc/GRPCHandlers.h | 36-56 | gRPC method declarations |
| E32 | src/libxrpl/protocol/Indexes.cpp | 105-115 | entry indexes are sha512Half |
| E33 | src/xrpld/rpc/handlers/Random.cpp | 36-50 | random: CSPRNG output, no key/signature |
| E34 | src/xrpld/rpc/handlers/Handlers.h | 108-122 | doPause/doResume declared, unregistered |
| E35 | src/xrpld/rpc/handlers/Submit.cpp | 64-72 | submit inline signing deprecated |
| E36 | src/xrpld/rpc/handlers/Simulate.cpp | 225-232 | simulate dry-runs via TxQ::apply |
| E37 | include/xrpl/protocol/ApiVersion.h | 56-63 | API versions: min 1, max 2, beta 3 |
| E38 | src/xrpld/core/Config.h | 362-368 | canSign() gate |
| E39 | src/xrpld/rpc/detail/RPCHandler.cpp | 222-230 | doCommand dispatcher entry |
| E40 | src/xrpld/app/main/GRPCServer.cpp | 488-498 | GetLedger bound to doLedgerGrpc |
| E41 | src/xrpld/rpc/handlers/Simulate.cpp | 124-139 | simulate rejects signed input |
