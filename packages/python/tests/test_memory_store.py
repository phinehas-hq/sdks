import unittest
from pathlib import Path
import sys

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from phinehas import MemoryStore


class TestMemoryStore(unittest.IsolatedAsyncioTestCase):
    async def test_memory_store_lru_and_capacity(self):
        store = MemoryStore(max_capacity=3, default_ttl_seconds=10)

        await store.ban("1.1.1.1")
        await store.ban("2.2.2.2")
        await store.ban("3.3.3.3")

        self.assertEqual(store.size, 3)
        self.assertTrue(await store.is_banned("1.1.1.1"))
        self.assertTrue(await store.is_banned("2.2.2.2"))
        self.assertTrue(await store.is_banned("3.3.3.3"))

        # Access 1.1.1.1 to move to MRU
        await store.is_banned("1.1.1.1")

        # Add 4th IP -> should evict 2.2.2.2
        await store.ban("4.4.4.4")
        self.assertEqual(store.size, 3)
        self.assertFalse(await store.is_banned("2.2.2.2"))
        self.assertTrue(await store.is_banned("1.1.1.1"))
        self.assertTrue(await store.is_banned("4.4.4.4"))

        # Unban
        await store.unban("4.4.4.4")
        self.assertFalse(await store.is_banned("4.4.4.4"))
        self.assertEqual(store.size, 2)

        await store.close()
        self.assertEqual(store.size, 0)

    async def test_memory_store_ttl_expiration(self):
        store = MemoryStore(max_capacity=10, default_ttl_seconds=1)
        await store.ban("10.0.0.1", ttl_seconds=1)
        self.assertTrue(await store.is_banned("10.0.0.1"))

        # Permanent ban (ttl: 0)
        await store.ban("10.0.0.2", ttl_seconds=0)
        self.assertTrue(await store.is_banned("10.0.0.2"))


if __name__ == "__main__":
    unittest.main()
