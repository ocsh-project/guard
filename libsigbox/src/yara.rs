use yara_x::Rules;

pub struct YaraSignature {
    serialized: Vec<u8>,
}

impl YaraSignature {
    fn from_serialized(serialized: Vec<u8>) -> Self {
        Self {
            serialized
        }
    }

    fn from_rules(rules: &Rules) -> Self {
        Self {
            serialized: rules.serialize().expect("Unable to serialize YARA rule.")
        }
    }

    fn get_rules(&self) -> Rules {
        Rules::deserialize(self.serialized.clone()).expect("Unable to deserialize YARA rule.")
    }
}