#[cfg(feature = "serde")]
mod serialize {
    extern crate oqs;
    extern crate serde_json;

    use self::oqs::kex::{AliceMsg, OqsKex, OqsKexAlg, OqsRand, OqsRandAlg};

    #[test]
    fn serialize_alice_msg() {
        let rand = OqsRand::new(OqsRandAlg::default()).unwrap();
        let kex_alice = OqsKex::new(&rand, OqsKexAlg::RlweNewhope).unwrap();
        let kex_alice_0 = kex_alice.alice_0().unwrap();
        let alice_msg = kex_alice_0.get_alice_msg();

        let json_value = serde_json::to_value(alice_msg).unwrap();
        let json_object = json_value.as_object().unwrap();

        let algorithm = json_object
            .get("algorithm")
            .expect("Expected field with name \"algorithm\"")
            .as_str()
            .unwrap();
        assert_eq!(algorithm, "RlweNewhope");

        let data = json_object.get("data").unwrap().as_array().unwrap();
        assert!(!data.is_empty());
        assert_eq!(data.len(), alice_msg.data().len());
        for (actual, expected) in data.iter().zip(alice_msg.data()) {
            assert_eq!(actual.as_u64().unwrap(), *expected as u64);
        }
    }

    #[test]
    fn serialize_to_string() {
        let rand = OqsRand::new(OqsRandAlg::default()).unwrap();
        let kex_alice = OqsKex::new(&rand, OqsKexAlg::Default).unwrap();
        let kex_alice_0 = kex_alice.alice_0().unwrap();
        let alice_msg = kex_alice_0.get_alice_msg();

        let json_string = serde_json::to_string(alice_msg).unwrap();
        println!("AliceMsg in json: {}", json_string);

        let deserialized_alice_msg: AliceMsg = serde_json::from_str(&json_string).unwrap();
        println!("AliceMsg deserialized: {:?}", deserialized_alice_msg);
        assert_eq!(&deserialized_alice_msg, alice_msg);
    }
}
