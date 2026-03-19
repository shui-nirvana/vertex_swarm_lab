import hashlib
import time
from typing import Dict


class SettlementEngine:
    def settle(self, payer: str, payee: str, amount: float, token: str = "USDT") -> Dict[str, str]:
        tx_seed = f"{payer}|{payee}|{amount}|{token}|{time.time()}"
        tx_hash = hashlib.sha256(tx_seed.encode("utf-8")).hexdigest()
        return {
            "status": "success",
            "tx_hash": f"0x{tx_hash}",
            "payer": payer,
            "payee": payee,
            "amount": str(amount),
            "token": token.upper(),
        }
