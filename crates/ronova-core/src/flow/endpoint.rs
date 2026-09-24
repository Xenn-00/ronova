use std::{cmp::Ordering, net::Ipv4Addr};

// Represent one transport layer endpoiint in a Ronova flow
// Ein Endpoint beschreibt nur IP Adresse und Port
// Direction und Rolleninformationen gehören nicht hier hinein.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl PartialOrd for Endpoint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Endpoint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // IP address is the primary ordering criterian.
        match self.ip.cmp(&other.ip) {
            Ordering::Equal => self.port.cmp(&other.port),
            ordering => ordering,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_endpoints_by_ip() {
        let first = Endpoint {
            ip: Ipv4Addr::new(10, 0, 0, 5),
            port: 49152,
        };

        let second = Endpoint {
            ip: Ipv4Addr::new(10, 0, 0, 10),
            port: 443,
        };

        assert!(first < second);
        assert!(second > first);
    }

    #[test]
    fn orders_ports_when_ip_is_equal() {
        let first = Endpoint {
            ip: Ipv4Addr::new(10, 0, 0, 5),
            port: 443,
        };

        let second = Endpoint {
            ip: Ipv4Addr::new(10, 0, 0, 5),
            port: 49152,
        };

        assert!(first < second);
        assert!(second > first);
    }

    #[test]
    fn equal_endpoints_have_equal_ordering() {
        let first = Endpoint {
            ip: Ipv4Addr::new(10, 0, 0, 5),
            port: 443,
        };

        let second = Endpoint {
            ip: Ipv4Addr::new(10, 0, 0, 5),
            port: 443,
        };

        assert_eq!(first, second);
        assert_eq!(first.cmp(&second), Ordering::Equal);
    }
}
