# @category FieldTruth
"""Print available loader names for headless imports."""

from ghidra.app.script import GhidraScript
from ghidra.app.util.opinion import LoaderService
import inspect


class ListLoaders(GhidraScript):
    def run(self):
        methods = [
            name
            for name, member in inspect.getmembers(LoaderService, predicate=inspect.isfunction)
        ]
        for method in methods:
            self.println("{} {}({})".format(method.getReturnType().getName(), method.getName(), ", ".join([param.getName() for param in method.getParameterTypes()])))


if __name__ == "__main__":
    ListLoaders().run()
