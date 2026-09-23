use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;

pub(crate) struct OrderedCompletionQueue<K, V> {
    order: VecDeque<K>,
    reserved: HashSet<K>,
    completed: HashMap<K, V>,
}

impl<K, V> Default for OrderedCompletionQueue<K, V> {
    fn default() -> Self {
        Self {
            order: VecDeque::new(),
            reserved: HashSet::new(),
            completed: HashMap::new(),
        }
    }
}

impl<K, V> OrderedCompletionQueue<K, V>
where
    K: Copy + Eq + Hash,
{
    pub(crate) fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub(crate) fn reserve(&mut self, key: K) {
        assert!(
            self.reserved.insert(key),
            "completion order keys must be reserved exactly once"
        );
        self.order.push_back(key);
    }

    pub(crate) fn complete(&mut self, key: K, value: V) -> Vec<V> {
        assert!(
            self.reserved.contains(&key),
            "only reserved completion order keys may complete"
        );
        assert!(
            self.completed.insert(key, value).is_none(),
            "completion order keys must complete exactly once"
        );

        let mut ready = Vec::new();
        while let Some(key) = self.order.front().copied() {
            let Some(value) = self.completed.remove(&key) else {
                break;
            };
            self.order.pop_front();
            self.reserved.remove(&key);
            ready.push(value);
        }
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_order_completions_are_released_in_reservation_order() {
        let mut queue = OrderedCompletionQueue::default();
        assert!(queue.is_empty());
        queue.reserve(10);
        assert!(!queue.is_empty());
        queue.reserve(20);
        queue.reserve(30);

        assert!(queue.complete(20, "second").is_empty());
        assert_eq!(queue.complete(10, "first"), ["first", "second"]);
        assert_eq!(queue.complete(30, "third"), ["third"]);
        assert!(queue.is_empty());
    }
}
