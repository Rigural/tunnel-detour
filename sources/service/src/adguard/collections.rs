//! Bound materialized API collections before their elements can amplify a reply.
//! Ignored future fields remain under serde's normal allocation-free skip path.

use serde::{
    Deserialize, Deserializer,
    de::{Error, IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use std::{collections::BTreeMap, fmt, marker::PhantomData};

pub(super) const UPSTREAMS: usize = 8192;
const DNS_BINDINGS: usize = 256;
const AUXILIARY: usize = 64;
const CLIENTS: usize = 1024;
const CLIENT_IDS: usize = 64;

struct List<T, const LIMIT: usize>(Vec<T>);
impl<'de, T: Deserialize<'de>, const LIMIT: usize> Deserialize<'de> for List<T, LIMIT> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Items<T, const LIMIT: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const LIMIT: usize> Visitor<'de> for Items<T, LIMIT> {
            type Value = List<T, LIMIT>;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an API array containing at most {LIMIT} items")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                for _ in 0..LIMIT {
                    match sequence.next_element()? {
                        Some(value) => values.push(value),
                        None => return Ok(List(values)),
                    }
                }
                // Do not deserialize an excess element into T: it may contain
                // another large collection. Syntax is still checked by serde.
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom(
                        "AdGuard API collection exceeds its supported item limit",
                    ));
                }
                Ok(List(values))
            }
        }
        deserializer.deserialize_seq(Items(PhantomData))
    }
}

pub(super) fn upstreams<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    List::<String, UPSTREAMS>::deserialize(deserializer).map(|value| value.0)
}

pub(super) fn bindings<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    List::<String, DNS_BINDINGS>::deserialize(deserializer).map(|value| value.0)
}

pub(super) fn optional_auxiliary<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    Option::<List<String, AUXILIARY>>::deserialize(deserializer)
        .map(|value| value.map(|list| list.0))
}

pub(super) fn client_ids<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    List::<String, CLIENT_IDS>::deserialize(deserializer).map(|value| value.0)
}

pub(super) fn optional_clients<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<Vec<T>>, D::Error> {
    Option::<List<T, CLIENTS>>::deserialize(deserializer).map(|value| value.map(|list| list.0))
}

pub(super) fn search_results<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    // The production request searches one client; multiple results are not an
    // unrestricted client-list API and cannot be trusted as a matching reply.
    List::<T, 1>::deserialize(deserializer).map(|value| value.0)
}

pub(super) fn search_entry<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, T>, D::Error> {
    struct Entry<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Entry<T> {
        type Value = BTreeMap<String, T>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an API search map for at most one requested client")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            if let Some((key, value)) = map.next_entry()? {
                result.insert(key, value);
            }
            if map.next_key::<IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(
                    "AdGuard API search returned more than one client",
                ));
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Entry(PhantomData))
}
