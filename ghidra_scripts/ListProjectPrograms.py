# @category FieldTruth
"""List all domain files in the current Ghidra project."""

from ghidra.app.script import GhidraScript


class ListProjectPrograms(GhidraScript):
    def run(self):
        project = self.getProject()
        if project is None:
            self.println("No open project")
            return
        data = project.getProjectData()
        root = data.getRootFolder()
        self.println("Project domain files:")
        self._print_folder(root, "")

    def _print_folder(self, folder, prefix):
        for file in folder.getFiles():
            self.println("{}FILE {} :: {}".format(prefix, file.getName(), file.getPathname()))
        for child in folder.getFolders():
            self.println("{}DIR  {}".format(prefix, child.getName()))
            self._print_folder(child, prefix + "  ")


if __name__ == "__main__":
    ListProjectPrograms().run()
