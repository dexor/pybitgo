
class BitGoError(Exception):
    pass


class UnauthorizedError(BitGoError):
    pass


class NotSpendableWallet(BitGoError):
    pass


class NotEnoughFunds(BitGoError):
    pass


class NotActiveWallet(BitGoError):
    pass
