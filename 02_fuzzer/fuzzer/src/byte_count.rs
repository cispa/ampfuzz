use std::ops;
use std::cmp::{Ordering, max};

use std::slice::Iter;
use std::iter::Map;

pub static UDP_HEADER_SIZE: usize = 8;
pub static IPV4_HEADER_SIZE: usize = 20;
pub static ETH_HEADER_SIZE: usize = 6 + 6 + 2 + 4;
pub static MIN_ETH_FRAME_SIZE: usize = 64;

#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct UdpByteCount {
    pub l7: Vec<usize>,
}

impl UdpByteCount {
    pub fn from_l7(l7_size: usize) -> Self {
        Self {
            l7: vec![l7_size]
        }
    }

    fn as_l7_iter(&self) -> Iter<usize> {
        return self.l7.iter();
    }

    fn as_l4_iter(&self) -> Map<Iter<usize>, fn(&usize) -> usize> {
        return self.as_l7_iter().map(|l7| l7 + UDP_HEADER_SIZE);
    }

    fn as_l3_iter(&self) -> Map<Map<Iter<usize>, fn(&usize) -> usize>, fn(usize) -> usize> {
        return self.as_l4_iter().map(|l4| l4 + IPV4_HEADER_SIZE);
    }

    fn as_l2_iter(&self) -> Map<Map<Map<Iter<usize>, fn(&usize) -> usize>, fn(usize) -> usize>, fn(usize) -> usize> {
        return self.as_l3_iter().map(|l3| max(l3 + ETH_HEADER_SIZE, MIN_ETH_FRAME_SIZE));
    }

    pub fn l7_size(&self) -> usize {
        self.as_l7_iter().sum()
    }

    pub fn l4_size(&self) -> usize {
        self.as_l4_iter().sum()
    }

    pub fn l3_size(&self) -> usize {
        self.as_l3_iter().sum()
    }

    pub fn l2_size(&self) -> usize {
        self.as_l2_iter().sum()
    }
}

impl ops::Add<UdpByteCount> for UdpByteCount {
    type Output = UdpByteCount;

    fn add(self, rhs: UdpByteCount) -> Self::Output {
        let mut l7 = self.l7.clone();
        l7.extend(rhs.l7);
        UdpByteCount {
            l7
        }
    }
}

impl ops::AddAssign<UdpByteCount> for UdpByteCount {
    fn add_assign(&mut self, rhs: UdpByteCount) {
        self.l7.extend(rhs.l7)
    }
}

impl ops::Add<usize> for UdpByteCount {
    type Output = UdpByteCount;

    fn add(self, rhs: usize) -> Self::Output {
        let mut l7 = self.l7.clone();
        l7.push(rhs);
        UdpByteCount {
            l7
        }
    }
}

impl ops::AddAssign<usize> for UdpByteCount {
    fn add_assign(&mut self, rhs: usize) {
        self.l7.push(rhs);
    }
}

impl From<&UdpByteCount> for usize {
    fn from(x: &UdpByteCount) -> Self {
        x.l2_size()
    }
}


impl PartialEq<usize> for UdpByteCount {
    fn eq(&self, other: &usize) -> bool {
        usize::from(self) == *other
    }
}

impl PartialOrd<usize> for UdpByteCount {
    fn partial_cmp(&self, other: &usize) -> Option<Ordering> {
        Option::from(usize::from(self).cmp(other))
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmpByteCount {
    pub bytes_in: UdpByteCount,
    pub bytes_out: UdpByteCount,
}

impl AmpByteCount {
    pub fn as_factor(&self) -> f64 {
        if self.bytes_in > 0 {
            (usize::from(&self.bytes_out) as f64) / (usize::from(&self.bytes_in) as f64)
        } else {
            0.0
        }
    }

    fn cmp_amp(self_bytes_in: usize, self_bytes_out: usize, other_bytes_in: usize, other_bytes_out: usize) -> Ordering {
        if self_bytes_in > 0 && other_bytes_in > 0 {
            (self_bytes_out * other_bytes_in).cmp(&(other_bytes_out * self_bytes_in))
        } else {
            self_bytes_out.cmp(&other_bytes_out)
        }
    }
}

impl PartialOrd<Self> for AmpByteCount {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AmpByteCount {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut result = Self::cmp_amp(self.bytes_in.l2_size(), self.bytes_out.l2_size(), other.bytes_in.l2_size(), other.bytes_out.l2_size());
        if result == Ordering::Equal {
            result = Self::cmp_amp(self.bytes_in.l3_size(), self.bytes_out.l3_size(), other.bytes_in.l3_size(), other.bytes_out.l3_size());
        }
        if result == Ordering::Equal {
            result = Self::cmp_amp(self.bytes_in.l4_size(), self.bytes_out.l4_size(), other.bytes_in.l4_size(), other.bytes_out.l4_size());
        }
        if result == Ordering::Equal {
            result = Self::cmp_amp(self.bytes_in.l7_size(), self.bytes_out.l7_size(), other.bytes_in.l7_size(), other.bytes_out.l7_size());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use crate::byte_count::{AmpByteCount, UdpByteCount};

    #[test]
    fn check_compare() {
        let x = AmpByteCount{ bytes_in: UdpByteCount::from_l7(100), bytes_out: UdpByteCount::from_l7(1000) };
        let y = AmpByteCount{ bytes_in: UdpByteCount::from_l7(250), bytes_out: UdpByteCount::from_l7(1000) };

        let cmp = x.cmp(&y);
        match cmp {
            Ordering::Less => {assert!(x < y)}
            Ordering::Equal => { assert_eq!(x, y) }
            Ordering::Greater => {assert!(x > y)}
        };
    }
}