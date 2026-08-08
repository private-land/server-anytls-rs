use std::collections::HashMap;
use std::sync::Arc;

use md5::{Digest, Md5};
use rand::RngExt;

pub const CHECK_MARK: i32 = -1;

pub const DEFAULT_SCHEME: &str = "stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

#[derive(Debug, Clone)]
pub struct PaddingRange {
    pub min: i32,
    pub max: i32,
}

/// Inner data behind Arc — cloning PaddingFactory is just an Arc refcount bump.
#[derive(Debug)]
struct PaddingFactoryInner {
    stop: u32,
    ranges: HashMap<u32, Vec<PaddingRange>>,
    raw: String,
    md5: String,
}

#[derive(Debug, Clone)]
pub struct PaddingFactory {
    inner: Arc<PaddingFactoryInner>,
}

impl PaddingFactory {
    pub fn new(scheme: &str) -> crate::error::Result<Self> {
        let mut stop: Option<u32> = None;
        let mut ranges: HashMap<u32, Vec<PaddingRange>> = HashMap::new();

        for line in scheme.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Some(val) = line.strip_prefix("stop=") {
                stop = Some(val.parse::<u32>().map_err(|e| {
                    crate::error::Error::PaddingParse(format!("invalid stop value: {e}"))
                })?);
            } else if let Some(eq_pos) = line.find('=') {
                let key_str = &line[..eq_pos];
                let val_str = &line[eq_pos + 1..];

                let key = key_str.parse::<u32>().map_err(|e| {
                    crate::error::Error::PaddingParse(format!(
                        "invalid packet key '{key_str}': {e}"
                    ))
                })?;

                let mut entry: Vec<PaddingRange> = Vec::new();
                for token in val_str.split(',') {
                    let token = token.trim();
                    if token == "c" {
                        // CHECK_MARK sentinel: use min=max=CHECK_MARK
                        entry.push(PaddingRange {
                            min: CHECK_MARK,
                            max: CHECK_MARK,
                        });
                    } else if let Some(dash_pos) = token.find('-') {
                        let min_str = &token[..dash_pos];
                        let max_str = &token[dash_pos + 1..];
                        let min = min_str.parse::<i32>().map_err(|e| {
                            crate::error::Error::PaddingParse(format!(
                                "invalid range min '{min_str}': {e}"
                            ))
                        })?;
                        let max = max_str.parse::<i32>().map_err(|e| {
                            crate::error::Error::PaddingParse(format!(
                                "invalid range max '{max_str}': {e}"
                            ))
                        })?;
                        entry.push(PaddingRange { min, max });
                    } else {
                        return Err(crate::error::Error::PaddingParse(format!(
                            "invalid token '{token}'"
                        )));
                    }
                }
                ranges.insert(key, entry);
            } else {
                return Err(crate::error::Error::PaddingParse(format!(
                    "unrecognized line: '{line}'"
                )));
            }
        }

        let stop = stop.ok_or_else(|| {
            crate::error::Error::PaddingParse("missing 'stop' directive".to_string())
        })?;

        let md5 = {
            let mut hasher = Md5::new();
            hasher.update(scheme.as_bytes());
            format!("{:x}", hasher.finalize())
        };

        Ok(Self {
            inner: Arc::new(PaddingFactoryInner {
                stop,
                ranges,
                raw: scheme.to_string(),
                md5,
            }),
        })
    }

    pub fn generate_record_payload_sizes(&self, pkt: u32) -> Vec<i32> {
        if pkt >= self.inner.stop {
            return Vec::new();
        }

        let Some(entry) = self.inner.ranges.get(&pkt) else {
            return Vec::new();
        };

        let mut rng = rand::rng();
        let mut result = Vec::with_capacity(entry.len());
        for pr in entry {
            if pr.min == CHECK_MARK && pr.max == CHECK_MARK {
                result.push(CHECK_MARK);
            } else if pr.min == pr.max {
                result.push(pr.min);
            } else {
                result.push(rng.random_range(pr.min..=pr.max));
            }
        }
        result
    }

    pub fn md5_hex(&self) -> &str {
        &self.inner.md5
    }

    pub fn raw_scheme(&self) -> &str {
        &self.inner.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_default_scheme() {
        let factory = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
        // stop=8: packets 0..7 have ranges, packet 8 returns empty
        assert!(!factory.generate_record_payload_sizes(7).is_empty());
        assert!(factory.generate_record_payload_sizes(8).is_empty());
    }

    #[test]
    fn test_parse_stop_value() {
        let scheme = "stop=5\n0=100-200";
        let factory = PaddingFactory::new(scheme).unwrap();
        // stop=5: packet 5 and above return empty
        assert!(factory.generate_record_payload_sizes(5).is_empty());
    }

    #[test]
    fn test_generate_sizes_packet_0() {
        let factory = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
        let sizes = factory.generate_record_payload_sizes(0);
        assert_eq!(sizes.len(), 1);
        assert_eq!(sizes[0], 30);
    }

    #[test]
    fn test_generate_sizes_packet_1_range() {
        let factory = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
        for _ in 0..100 {
            let sizes = factory.generate_record_payload_sizes(1);
            assert_eq!(sizes.len(), 1);
            assert!(sizes[0] >= 100 && sizes[0] <= 400, "got {}", sizes[0]);
        }
    }

    #[test]
    fn test_generate_sizes_with_checkmarks() {
        let factory = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
        let sizes = factory.generate_record_payload_sizes(2);
        assert!(sizes.contains(&CHECK_MARK));
    }

    #[test]
    fn test_generate_sizes_beyond_stop() {
        let factory = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
        let sizes = factory.generate_record_payload_sizes(8);
        assert!(sizes.is_empty());
    }

    #[test]
    fn test_generate_sizes_unknown_packet() {
        let scheme = "stop=3\n0=100-100";
        let factory = PaddingFactory::new(scheme).unwrap();
        let sizes = factory.generate_record_payload_sizes(1);
        assert!(sizes.is_empty());
    }

    #[test]
    fn test_md5_hash() {
        let factory = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
        let factory2 = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
        assert_eq!(factory.md5_hex(), factory2.md5_hex());
    }

    #[test]
    fn test_md5_different_schemes() {
        let f1 = PaddingFactory::new("stop=1\n0=10-10").unwrap();
        let f2 = PaddingFactory::new("stop=2\n0=20-20").unwrap();
        assert_ne!(f1.md5_hex(), f2.md5_hex());
    }

    #[test]
    fn test_invalid_scheme_no_stop() {
        let result = PaddingFactory::new("0=100-200");
        assert!(result.is_err());
    }

    #[test]
    fn test_raw_scheme() {
        let scheme = "stop=3\n0=100-100";
        let factory = PaddingFactory::new(scheme).unwrap();
        assert_eq!(factory.raw_scheme(), scheme);
    }

    #[test]
    fn test_parse_real_panel_padding_rules() {
        // Simulates the actual string after JSON deserialization from panel response:
        // "stop=5\r\n0=30-30\r\n1=100-300\r\n2=300-500,c,500-1000,c,500-1000,c,500-1000\r\n3=500-1000\r\n4=500-1000"
        let scheme = "stop=5\r\n0=30-30\r\n1=100-300\r\n2=300-500,c,500-1000,c,500-1000,c,500-1000\r\n3=500-1000\r\n4=500-1000";
        let factory = PaddingFactory::new(scheme).unwrap();

        // packet 0: fixed 30
        let sizes = factory.generate_record_payload_sizes(0);
        assert_eq!(sizes, vec![30]);

        // packet 1: range 100-300
        let sizes = factory.generate_record_payload_sizes(1);
        assert_eq!(sizes.len(), 1);
        assert!(sizes[0] >= 100 && sizes[0] <= 300);

        // packet 2: has checkmarks
        let sizes = factory.generate_record_payload_sizes(2);
        assert!(sizes.contains(&CHECK_MARK));

        // packet 5: beyond stop
        assert!(factory.generate_record_payload_sizes(5).is_empty());
    }
}
