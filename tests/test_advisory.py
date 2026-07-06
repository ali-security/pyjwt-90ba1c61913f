import jwt
import pytest
from jwt.exceptions import InvalidKeyError

# NOTE: The upstream advisory test (GHSA-ffqj-6fqr-9h24) also exercises an
# ed25519 (EdDSA/OKP) vector. PyJWT 1.7.1 has no OKP/EdDSA algorithm, so only
# the ES256 / ssh-ecdsa vector applies here.

ssh_key_bytes = b"""ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJXMtkUkkoJ9kQP8QhpKO/TfuxcKC2a92dIo/xDY6MNl6VA8MChCpAJN0w1wvVPJ4qTJRnGO7A6V6dl8oRxDPkc="""


class TestAdvisory:
    def test_ghsa_ffqj_6fqr_9h24(self):
        # POC for the ecdsa-sha2-nistp256 format.
        # openssl ecparam -genkey -name prime256v1 -noout -out ec256-key-priv.pem
        # openssl ec -in ec256-key-priv.pem -pubout > ec256-key-pub.pem
        # ssh-keygen -y -f ec256-key-priv.pem > ec256-key-ssh.pub

        # Making a good jwt token that should work by signing it with the private key
        # encoded_good = jwt.encode({"test": 1234}, ssh_priv_key_bytes, algorithm="ES256")
        encoded_good = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoxMjM0fQ.NX42mS8cNqYoL3FOW9ZcKw8Nfq2mb6GqJVADeMA1-kyHAclilYo_edhdM_5eav9tBRQTlL0XMeu_WFE_mz3OXg"

        # Using HMAC with the ssh public key to trick the receiver to think that the public key is a HMAC secret
        # encoded_bad = jwt.encode({"test": 1234}, ssh_key_bytes, algorithm="HS256")
        encoded_bad = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoxMjM0fQ.5eYfbrbeGYmWfypQ6rMWXNZ8bdHcqKng5GPr9MJZITU"

        # The good token verifies with the ssh public key
        jwt.decode(
            encoded_good,
            ssh_key_bytes,
            algorithms=jwt.algorithms.get_default_algorithms(),
        )

        # The bad token must be rejected: an ssh public key cannot be used as an HMAC secret
        with pytest.raises(InvalidKeyError):
            jwt.decode(
                encoded_bad,
                ssh_key_bytes,
                algorithms=jwt.algorithms.get_default_algorithms(),
            )
