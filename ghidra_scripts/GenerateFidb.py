# GenerateFidb.py
# -----------------------------------------------------------------------------
# Headless helper for building a Function ID database from a manifest of PSYQ
# static libraries. Invoke via:
#
#   analyzeHeadless <proj_dir> fidb_build \
#       -scriptPath ghidra_scripts \
#       -preScript GenerateFidb.py manifest="scripts/data/fidb_libs.txt" \
#       output="exports/fidb/psyq_stdlib.fidb"
#
# The script will import each archive into the project (under a "fidb_sources"
# folder), open them, and call FunctionIDUtilities.createDatabase to emit the
# consolidated .fidb file.
# -----------------------------------------------------------------------------

from __future__ import print_function

import os

import importlib
from typing import Dict, Tuple


def _load_ghidra_bindings() -> Dict[str, object]:
    """Import Ghidra classes lazily so static analyzers don't complain."""

    try:
        script_mod = importlib.import_module("ghidra.app.script")
        importer_mod = importlib.import_module("ghidra.app.util.importer")
        fid_mod = importlib.import_module("ghidra.app.plugin.core.function")
        msg_mod = importlib.import_module("ghidra.util")
        java_io = importlib.import_module("java.io")
        java_util = importlib.import_module("java.util")
    except ImportError as exc:
        raise ImportError(
            "GenerateFidb must be executed within a Ghidra scripting context."
        ) from exc

    return {
        "GhidraScript": script_mod.GhidraScript,
        "AutoImporter": importer_mod.AutoImporter,
        "MessageLog": importer_mod.MessageLog,
        "FunctionIDUtilities": fid_mod.FunctionIDUtilities,
        "Msg": msg_mod.Msg,
        "File": java_io.File,
        "ArrayList": java_util.ArrayList,
    }


_BINDINGS = _load_ghidra_bindings()
GhidraScript = _BINDINGS["GhidraScript"]
AutoImporter = _BINDINGS["AutoImporter"]
MessageLog = _BINDINGS["MessageLog"]
FunctionIDUtilities = _BINDINGS["FunctionIDUtilities"]
Msg = _BINDINGS["Msg"]
File = _BINDINGS["File"]
ArrayList = _BINDINGS["ArrayList"]


class GenerateFidb(GhidraScript):
    def run(self):
        args = self._parse_args(self.getScriptArgs())
        manifest_path = self._resolve_path(args.get("manifest"))
        output_path = self._resolve_path(
            args.get("output", "exports/fidb/psyq_stdlib.fidb")
        )
        overwrite = args.get("overwrite", "false").lower() == "true"

        if not os.path.isfile(manifest_path):
            raise IOError("Manifest not found: {}".format(manifest_path))

        out_dir = os.path.dirname(output_path)
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir)

        project = self.getState().getProject()
        if project is None:
            raise RuntimeError("Active project required; run via analyzeHeadless.")

        project_data = project.getProjectData()
        root_folder = project_data.getRootFolder()
        sources_folder = self._ensure_folder(root_folder, "fidb_sources")

        libs = self._read_manifest(manifest_path)
        if not libs:
            Msg.warn(self, "Manifest is empty: {}".format(manifest_path))
            return

        imported_files = []
        opened_programs = []
        try:
            for lib_path in libs:
                file_obj = File(lib_path)
                if not file_obj.exists():
                    Msg.warn(self, "Skipping missing library: {}".format(lib_path))
                    continue

                domain_file = self._ensure_domain_file(sources_folder, file_obj)
                imported_files.append(domain_file)
                program = domain_file.getDomainObject(self, True, False, self.monitor)
                opened_programs.append(program)

            if not opened_programs:
                Msg.warn(self, "No programs imported; aborting FIDB build.")
                return

            program_list = ArrayList()
            for program in opened_programs:
                program_list.add(program)

            output_file = File(output_path)
            if output_file.exists() and not overwrite:
                raise IOError("Output already exists (use overwrite=true): {}".format(output_path))

            FunctionIDUtilities.createDatabase(output_file, program_list, self.monitor)
            Msg.info(self, "FIDB created at {} ({} programs)".format(output_path, program_list.size()))
        finally:
            for program in opened_programs:
                try:
                    program.release(self)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    def _parse_args(self, args):
        parsed = {}
        for token in args:
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            parsed[key.strip().lower()] = value.strip()
        return parsed

    def _resolve_path(self, path_value):
        if os.path.isabs(path_value):
            return path_value
        cwd = os.getcwd()
        return os.path.abspath(os.path.join(cwd, path_value))

    def _read_manifest(self, manifest_path):
        libs = []
        with open(manifest_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                libs.append(line)
        return libs

    def _ensure_folder(self, parent_folder, name):
        existing = parent_folder.getFolder(name)
        if existing is not None:
            return existing
        return parent_folder.createFolder(name)

    def _ensure_domain_file(self, parent_folder, source_file):
        existing = parent_folder.getFile(source_file.getName())
        if existing is not None:
            return existing
        log = MessageLog()
        return AutoImporter.importByUsingBestGuess(source_file, parent_folder, self.monitor, log)


def run():
    script = GenerateFidb()
    script.run()


if __name__ == "__main__":
    run()
