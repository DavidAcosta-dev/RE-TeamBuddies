# @category FieldTruth
from ghidra.app.script import GhidraScript


class EchoArgs(GhidraScript):
    def run(self):
        args = list(self.getScriptArgs())
        self.println("EchoArgs -> {}".format(args))


if __name__ == "__main__":
    EchoArgs().run()
