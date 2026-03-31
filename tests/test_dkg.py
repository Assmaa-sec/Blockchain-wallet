import pytest
from itertools import combinations

from crypto.dkg import DKGOrchestrator, CURVE_ORDER
from crypto.shamir import ShamirSecretSharing
from crypto.vss import VerifiableSecretSharing


class TestShareGeneration:
    def test_share_generation(self):
        dkg = DKGOrchestrator(threshold=3, total_parties=5)
        result = dkg.generate_shares()

        assert len(result.shares) == 5
        for i, share in enumerate(result.shares):
            assert share.party_index == i + 1
            assert 0 < share.secret_share < CURVE_ORDER
            assert len(share.public_share) == 65
            assert isinstance(share.commitments, list)

    def test_joint_public_key_is_bytes(self):
        dkg = DKGOrchestrator(threshold=3, total_parties=5)
        result = dkg.generate_shares()
        assert isinstance(result.joint_public_key, bytes)
        assert len(result.joint_public_key) > 0


class TestVSSVerification:
    def test_vss_verification_valid_share(self):
        sss = ShamirSecretSharing(threshold=3, total_parties=5)
        vss = VerifiableSecretSharing()

        import secrets as _secrets
        secret = _secrets.randbelow(CURVE_ORDER - 1) + 1
        coefficients, shares = sss.split_secret(secret)
        commitments = vss.generate_commitments(coefficients)

        for party_index, share_value in enumerate(shares, start=1):
            assert vss.verify_share(share_value, commitments, party_index)

    def test_vss_rejects_bad_share(self):
        sss = ShamirSecretSharing(threshold=3, total_parties=5)
        vss = VerifiableSecretSharing()

        import secrets as _secrets
        secret = _secrets.randbelow(CURVE_ORDER - 1) + 1
        coefficients, shares = sss.split_secret(secret)
        commitments = vss.generate_commitments(coefficients)

        bad_share = (shares[0] + 1) % CURVE_ORDER
        assert not vss.verify_share(bad_share, commitments, party_index=1)


class TestPublicKeyCombination:
    def test_public_key_combination(self):
        dkg = DKGOrchestrator(threshold=3, total_parties=5)
        result = dkg.generate_shares()

        pub_shares = [ps.public_share for ps in result.shares]
        joint_key = dkg.combine_public_keys(pub_shares)

        assert isinstance(joint_key, bytes)
        assert len(joint_key) == 65

    def test_combine_requires_at_least_one_share(self):
        dkg = DKGOrchestrator(threshold=3, total_parties=5)
        with pytest.raises(ValueError):
            dkg.combine_public_keys([])


class TestThresholdCombinations:
    def test_any_threshold_shares_reconstruct_correctly(self):
        sss = ShamirSecretSharing(threshold=3, total_parties=5)

        import secrets as _secrets
        secret = _secrets.randbelow(CURVE_ORDER - 1) + 1
        _, shares = sss.split_secret(secret)

        indexed_shares = [(i + 1, v) for i, v in enumerate(shares)]

        reconstructed_values = set()
        for subset in combinations(indexed_shares, 3):
            recovered = sss.reconstruct_secret(list(subset))
            reconstructed_values.add(recovered)

        assert len(reconstructed_values) == 1
        assert reconstructed_values.pop() == secret

    def test_insufficient_shares_raises(self):
        sss = ShamirSecretSharing(threshold=3, total_parties=5)
        with pytest.raises(ValueError):
            sss.reconstruct_secret([(1, 42), (2, 99)])
