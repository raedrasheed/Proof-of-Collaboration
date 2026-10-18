"""Explicit independent comparator adaptations; never installed into runtime.
CREATE-01: approved EIP-7610, complete fixture storage plus all actual overlay writes.
MODEXP: correct py-evm0.12.1b1's zero-base/zero-exponent shortcut using EIP-198
integer exponentiation (0**0 mod m); standard Cancun gas remains py-evm's own.
This is a patched independent comparator, not unmodified Cancun or signed-wire proof.
"""
from eth.vm.forks.cancun import CancunVM
from eth.vm.forks.cancun.state import CancunState
from eth.vm.forks.cancun.computation import CancunComputation

MODEXP=(5).to_bytes(20,'big')

class ComparisonComputation(CancunComputation):
    _precompiles=dict(CancunComputation._precompiles)

def modexp(computation):
    # First perform the unchanged engine's gas calculation/charge and bounded output.
    result=CancunComputation._precompiles[MODEXP](computation)
    data=computation.msg.data_as_bytes
    base_len=int.from_bytes(data[:32].ljust(32,b'\0'),'big')
    exp_len=int.from_bytes(data[32:64].ljust(32,b'\0'),'big')
    mod_len=int.from_bytes(data[64:96].ljust(32,b'\0'),'big')
    if base_len==0 and mod_len and not any(data[96:96+exp_len]):
        modulus=int.from_bytes(data[96+exp_len:96+exp_len+mod_len].ljust(mod_len,b'\0'),'big')
        value=pow(0,0,modulus) if modulus else 0
        computation.output=value.to_bytes(mod_len,'big')
    return result

ComparisonComputation._precompiles[MODEXP]=modexp

class ComparisonState(CancunState):
    computation_class=ComparisonComputation
    def __init__(self,*args,**kwargs):
        self._complete_keys={}
        super().__init__(*args,**kwargs)
    def set_storage(self,address,slot,value):
        self._complete_keys.setdefault(address,set()).add(slot)
        return super().set_storage(address,slot,value)
    def has_code_or_nonce(self,address):
        # Key union need not roll back: every value is read from the CURRENT journal.
        # Cleared/deleted/reverted writes therefore cannot manufacture a collision.
        return super().has_code_or_nonce(address) or any(self.get_storage(address,k) for k in self._complete_keys.get(address,()))

class ComparisonVM(CancunVM):
    _state_class=ComparisonState
