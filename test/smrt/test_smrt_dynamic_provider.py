import pytest
from csirtg_smrt import Smrt
from csirtg_smrt.constants import REMOTE_ADDR

def test_smrt_dynamic_provider():
    with Smrt(REMOTE_ADDR, 1234, client='dummy') as s:
        for r, f in s.load_feeds('test/smrt/rules/smrt-honeypot-config.yml'):
            x = list(s.process(r, f))
            assert len(x) > 0
            for entry in x:
                # Access the 'provider' attribute directly from the Indicator object
                assert hasattr(entry, 'provider')  # Ensure 'provider' attribute exists
                assert getattr(entry, 'provider') != 'unknown'  # Ensure provider is dynamically set

def test_smrt_static_provider():
    with Smrt(REMOTE_ADDR, 1234, client='dummy') as s:
        for r, f in s.load_feeds('test/smrt/rules/csirtg.yml'):
            x = list(s.process(r, f))
            assert len(x) > 0
            for entry in x:
                assert hasattr(entry, 'provider')
                assert entry.provider == 'csirtg.io'  # Check for static provider

