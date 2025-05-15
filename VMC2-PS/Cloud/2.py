import hashlib
import random
import string
from datetime import datetime


class MerkleTree:
    def __init__(self, data_blocks):
        self.data_blocks = data_blocks
        self.tree = self.build_merkle_tree(data_blocks)

    def hash_data(self, data):
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def build_merkle_tree(self, data_blocks):
        # Initial hash of data blocks
        current_level = [self.hash_data(data) for data in data_blocks]

        # Build the tree up to the root hash
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(self.hash_data(left + right))
            current_level = next_level

        return current_level[0] if current_level else None


def generate_random_data_block(size=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))


def measure_merkle_tree_build_time(num_blocks):
    data_blocks = [generate_random_data_block() for _ in range(num_blocks)]
    start_time = datetime.now()
    MerkleTree(data_blocks)
    end_time = datetime.now()
    elapsed_time = (end_time - start_time).total_seconds()
    return elapsed_time


if __name__ == "__main__":
    results = []
    for num_blocks in range(5, 101):
        elapsed_time = measure_merkle_tree_build_time(num_blocks)
        results.append((num_blocks, elapsed_time))

    for num_blocks, elapsed_time in results:
        print(f"Number of blocks: {num_blocks}, Time taken: {elapsed_time:.6f} seconds")
