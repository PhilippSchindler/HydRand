import os
import shutil
from hydrand.config import generate_sample_config, load_config, CONFIG_BASE_DIR


def test_save_load():
    x = generate_sample_config(17, write_to_disk=True)
    y = load_config(17)
    for a, b in zip(x, y):
        assert a.id == b.id
        assert a.address == b.address
        assert a.port == b.port
        assert a.keypair == b.keypair
        assert a.public_key == b.public_key
        assert a.initial_secret == b.initial_secret
        assert a.initial_shares == b.initial_shares
        assert a.initial_proof == b.initial_proof
        assert a.initial_merkle_root == b.initial_merkle_root

    shutil.rmtree(os.path.join(CONFIG_BASE_DIR, "017"))
