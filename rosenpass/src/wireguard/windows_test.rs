#[cfg(test)]
mod wireguard_windows_tests {
    use crate::wireguard::windows::generate_or_load_config;

    use std::fs;
    use std::path::Path;

    #[test]
    fn test_wireguard_config_generation() {
        let dev = "testwg0";
        let peer_pk = "TEST_PEER_PUBLIC_KEY_BASE64";
        let psk = b"test-psk-32-bytes-long----";
        let extra = vec![
            "AllowedIPs = 0.0.0.0/0".to_string(),
            "Endpoint = 1.2.3.4:51820".to_string(),
        ];

        let cfg_path =
            generate_or_load_config(dev, peer_pk, psk, &extra).expect("config generation failed");

        assert!(
            cfg_path.exists(),
            "WireGuard config file was not created"
        );

        // ✅ Private key file must exist
        let key_path = cfg_path.with_extension("key");
        assert!(
            key_path.exists(),
            "WireGuard private key file was not created"
        );

        // ✅ Validate config contents
        let contents = fs::read_to_string(&cfg_path).expect("unable to read config file");

        assert!(contents.contains("[Interface]"));
        assert!(contents.contains("PrivateKey = "));
        assert!(contents.contains("Address = 10.66.0.1/32"));
        assert!(contents.contains("ListenPort = 51820"));

        assert!(contents.contains("[Peer]"));
        assert!(contents.contains("PublicKey = TEST_PEER_PUBLIC_KEY_BASE64"));
        assert!(contents.contains("PresharedKey = "));
        assert!(contents.contains("AllowedIPs = 0.0.0.0/0"));
        assert!(contents.contains("Endpoint = 1.2.3.4:51820"));

        println!("✅ Windows WireGuard config test passed: {:?}", cfg_path);
    }

    #[test]
    fn test_private_key_is_persistent() {
        let dev = "testwg1";
        let peer_pk = "PEER_KEY";
        let psk = b"another-test-psk-32-bytez----";
        let extra = vec![];

        let cfg1 =
            generate_or_load_config(dev, peer_pk, psk, &extra).expect("first config failed");
        let private_key_path = cfg1.with_extension("key");

        let first_key = fs::read_to_string(&private_key_path).unwrap();

        // ✅ Run generation again
        let _ =
            generate_or_load_config(dev, peer_pk, psk, &extra).expect("second config failed");

        let second_key = fs::read_to_string(&private_key_path).unwrap();

        // ✅ Private key must be stable across restarts
        assert_eq!(
            first_key, second_key,
            "Private key was regenerated — this must NEVER happen"
        );

        println!("✅ Windows private key persistence test passed");
    }

    #[test]
    fn test_multiple_interfaces_do_not_conflict() {
        let a = generate_or_load_config("wgA", "PK_A", b"a-psk-----------------------", &[])
            .unwrap();
        let b = generate_or_load_config("wgB", "PK_B", b"b-psk-----------------------", &[])
            .unwrap();

        assert_ne!(a, b, "Multiple interfaces are overwriting each other");

        println!("✅ Multiple interface isolation test passed");
    }
}
