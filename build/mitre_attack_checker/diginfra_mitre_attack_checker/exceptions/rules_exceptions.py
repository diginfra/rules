from pathlib import Path


class DiginfraException(Exception):
    pass


class DiginfraRulesFileContentError(Exception):
    def __init__(self, file: Path, message: str = "Wrong Diginfra Rules file content or format", *args):
        self.file = file
        self.message = message
        super().__init__(self.message, args)
