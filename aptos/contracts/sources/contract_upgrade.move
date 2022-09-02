module wormhole::contract_upgrade {
    use std::aptos_hash;
    use std::vector;
    use aptos_framework::code;
    use wormhole::deserialize;
    use wormhole::cursor;
    use wormhole::vaa;
    use wormhole::state;

    const E_UPGRADE_UNAUTHORIZED: u64 = 0;
    const E_UNEXPECTED_HASH: u64 = 1;
    const E_INVALID_MODULE: u64 = 2;
    const E_INVALID_ACTION: u64 = 3;

    // TODO(csongor): document how this works
    struct UpgradeAuthorized has key {
        hash: vector<u8>
    }

    struct Hash {
        hash: vector<u8>
    }

    // TODO(csongor): maybe a parse and verify...?
    fun parse_payload(payload: vector<u8>): Hash {
        let cur = cursor::init(payload);
        let target_module = deserialize::deserialize_vector(&mut cur, 32);

        // TODO(csongor): refactor this (like deserialize_module_magic or something)
        let expected_module = x"00000000000000000000000000000000000000000000000000000000436f7265"; // Core
        assert!(target_module == expected_module, E_INVALID_MODULE);

        let action = deserialize::deserialize_u8(&mut cur);
        assert!(action == 0x01, E_INVALID_ACTION);

        let _chain = deserialize::deserialize_u16(&mut cur);
        // TODO(csongor): check it's the current chain
        // assert!(chain == u16::from_u64(0x00), E_INVALID_TARGET);

        let hash = deserialize::deserialize_vector(&mut cur, 32);

        cursor::destroy_empty(cur);

        Hash { hash }
    }

    public entry fun submit_vaa(
        vaa: vector<u8>
    ) acquires UpgradeAuthorized {
        let vaa = vaa::parse_and_verify(vaa);
        vaa::assert_governance(&vaa);

        authorize_upgrade(parse_payload(vaa::destroy(vaa)));
    }

    fun authorize_upgrade(hash: Hash) acquires UpgradeAuthorized {
        let Hash { hash } = hash;
        let wormhole = state::wormhole_signer();
        if (exists<UpgradeAuthorized>(@wormhole)) {
            // TODO(csongor): here we're dropping the upgrade hash, in case an
            // upgrade fails for some reason. Should we emit a log or something?
            let UpgradeAuthorized { hash: _ } = move_from<UpgradeAuthorized>(@wormhole);
        };
        move_to(&wormhole, UpgradeAuthorized { hash });
    }

    public entry fun upgrade(
        metadata_serialized: vector<u8>,
        code: vector<vector<u8>>
    ) acquires UpgradeAuthorized {
        assert!(exists<UpgradeAuthorized>(@wormhole), E_UPGRADE_UNAUTHORIZED);
        let UpgradeAuthorized { hash } = move_from<UpgradeAuthorized>(@wormhole);

        let c = copy code;
        vector::reverse(&mut c);
        let a = vector::empty<u8>();
        while (!vector::is_empty(&c)) vector::append(&mut a, vector::pop_back(&mut c));
        assert!(aptos_hash::keccak256(a) == hash, E_UNEXPECTED_HASH);

        let wormhole = state::wormhole_signer();
        code::publish_package_txn(&wormhole, metadata_serialized, code);
    }
}
