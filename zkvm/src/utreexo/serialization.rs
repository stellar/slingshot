use std::rc::Rc;
use byteorder::{ByteOrder, LittleEndian};

use serde::de::Visitor;
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

use super::forest::{WorkForest,Node};
use crate::merkle::{Hash};

impl WorkForest {
    /// Serializes the forest to a variable-length binary string.
    ///
    /// ```ascii
    ///    +-------------------------+--------+--------+-----
    ///    | number of roots: u64-LE | root 0 | root 1 | ... 
    ///    +-------------------------+--------+--------+-----
    /// ```
    ///
    /// The root is encoded in 33 bytes:
    ///
    /// ```ascii
    ///    +-----------------------------------------+-----------------+--------------+-----+---------------+-----+
    ///    | flags (1 byte)                          | 32-byte hash    | (left child) | ... | (right child) | ... |
    ///    +-------------------+----------+----------+-----------------+--------------+-----+---------------+-----+
    ///    | level (bits 0..5) | modified | children |
    ///    +-------------------+----------+----------+
    /// ```
    /// 
    /// Lower bits 0..5 indicate level 0..63. 6th bit is "modified" flag. 7th bit is "children present" flag.
    /// 
    /// If a node has children, then it immediately follows by the left child,
    /// which possibly is followed by its children; then the right child.
    /// 
    /// ```ascii
    ///      a
    ///   b     c     ->   {a,b,d,e,c,f,h,i,g}
    ///  d e   f g
    ///       h i
    /// ```
    ///
    /// It is a parsing error to have children with inconsistent level w.r.t. the parent.
    ///
    /// ### WARNING
    ///
    /// We currently do not check consistency of modification flags or values of hashes.
    /// **Do not** use this encoding for receiving work trees from untrusted sources.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(8 + 33*self.roots.len());

        // Write number of roots
        {
            let mut lenprefix = [0u8; 8];
            LittleEndian::write_u64(&mut lenprefix, self.roots.len() as u64);
            result.extend_from_slice(&lenprefix);
        }

        fn write_node(node: &Node, buf: &mut Vec<u8>) {
            let byte = 
                (node.level as u8) +
                (if node.modified { 64u8 } else { 0u8 }) + 
                (if node.children.is_some() { 128u8 } else { 0u8 });

            buf.push(byte);
            buf.extend_from_slice(&node.hash[..]);
        }
        
        let mut stack: Vec<&Node> = Vec::with_capacity(16);
        for root in self.roots.iter() {
            stack.push(&root);
            while let Some(node) = stack.pop() {
                write_node(&node, &mut result);
                if let Some((ref l, ref r)) = node.children {
                    stack.push(&r);
                    stack.push(&l); // we want to encode left-to-right, so push the left last.
                }
            }
        }

        result
    }

    /// Deserializes the forest from a binary string.
    /// See format description in the documentaton for [`to_bytes`](WorkForest::to_bytes).
    pub fn from_bytes(slice: &[u8]) -> Option<Self> {

        macro_rules! read {
            ($n:tt, $slice:ident) => {{
                let mut piece = [0u8; $n];
                if $slice.len() < $n {
                    return None;
                }
                piece[..].copy_from_slice(&$slice[..$n]);
                (piece, &$slice[$n..])
            }};
        }

        // recursively parses the nodes
        // max_level protects against stack exhaustion
        fn read_node(slice: &[u8], max_level: usize) -> Option<(Node, &[u8])> {
            let (flags, slice) = read!(1, slice);
            let flags = flags[0];
            let (hash, slice) = read!(32, slice);

            let level = (flags & 63) as usize;
            let modified = flags & 64 == 64;
            let has_children = (flags & 128) == 128;

            if level > max_level {
                // We are not supposed to have a child with a higher level than a parent.
                return None;
            }

            if level == 0 && has_children {
                // Format inconsistency!
                // Node with level 0 is marked as having children.
                return None;
            }

            let (children, slice) = if has_children {
                let (l, slice) = read_node(slice, level-1)?;
                let (r, slice) = read_node(slice, level-1)?;
                (
                    Some((Rc::new(l), Rc::new(r))),
                    slice
                )
            } else {
                (None, slice)
            };

            let node = Node {
                level,
                hash: Hash(hash),
                modified,
                children,
            };
            
            Some((node,slice))
        }

        let (prefix, slice) = read!(8, slice);
        let roots_count = LittleEndian::read_u64(&prefix);
        if roots_count > (slice.len() as u64)/33 {
            // DoS prevention: the slice consisting entirely of N roots
            // will be at least N*33 bytes long (we've already shifted
            // the slice by 8 bytes in read!(8)).
            return None;
        }

        let mut roots = Vec::with_capacity(roots_count as usize);
        
        let mut slice = slice;
        for _ in 0..roots_count {
            let (node, remainder) = read_node(slice, 63)?;
            slice = remainder;
            roots.push(Rc::new(node))
        }

        Some(WorkForest{roots})
    }
}

impl Serialize for WorkForest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}

impl<'de> Deserialize<'de> for WorkForest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct WorkForestVisitor;

        impl<'de> Visitor<'de> for WorkForestVisitor {
            type Value = WorkForest;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid WorkForest")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<WorkForest, E>
            where
                E: serde::de::Error,
            {
                WorkForest::from_bytes(v).ok_or(serde::de::Error::custom("WorkForest format error"))
            }
        }

        deserializer.deserialize_bytes(WorkForestVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        let wf = WorkForest{roots: Vec::new()};
        let bytes = wf.to_bytes();
        assert_eq!(hex::encode(&bytes), "0000000000000000");
        assert_eq!(WorkForest::from_bytes(&bytes).expect("should decode").roots, Vec::new());
    }
}