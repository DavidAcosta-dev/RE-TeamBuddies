# Team Buddies crate PSYQ domain logger
# Applies domain hints from exports/crate_crossref_summary.csv to functions.

import csv
import os

from ghidra.app.script import GhidraScript
from ghidra.util.task import ConsoleTaskMonitor


class CrossrefDomainLogger(GhidraScript):
    DEFAULT_CSV = os.path.join("exports", "crate_crossref_summary.csv")
    VALUE_PREFIXES = ("CRATE_VALUE_A_", "CRATE_VALUE_B_")

    def run(self):
        csv_path = self._resolve_csv_path()
        domains = self._load_domains(csv_path)
        monitor = ConsoleTaskMonitor()
        listing = self.currentProgram.getListing()
        functions = listing.getFunctions(True)
        while functions.hasNext() and not monitor.isCancelled():
            function = functions.next()
            self._annotate_function(function, domains, monitor)

    def _resolve_csv_path(self):
        if os.path.isabs(self.DEFAULT_CSV):
            return self.DEFAULT_CSV
        program_dir = os.path.dirname(self.currentProgram.getExecutablePath())
        return os.path.join(program_dir, self.DEFAULT_CSV)

    def _load_domains(self, csv_path):
        if not os.path.exists(csv_path):
            raise RuntimeError("Crossref summary CSV not found: %s" % csv_path)
        domains = {}
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                label = row.get("crate_label", "").strip()
                domain = row.get("dominant_domain", "")
                hint = row.get("dominant_domain_hint", "")
                if label:
                    domains[label] = (domain, hint)
        return domains

    def _annotate_function(self, function, domains, monitor):
        listing = self.currentProgram.getListing()
        instructions = listing.getInstructions(function.getBody(), True)
        while instructions.hasNext() and not monitor.isCancelled():
            instr = instructions.next()
            operands = instr.getOpObjects(0)
            for operand in operands:
                label = str(operand)
                crate_label = self._extract_label(label)
                if crate_label and crate_label in domains:
                    domain, hint = domains[crate_label]
                    comment = "[Crate %s] Domain: %s (%s)" % (crate_label, domain, hint)
                    self.setEOLComment(instr.getMinAddress(), comment)

    def _extract_label(self, operand_name):
        for prefix in self.VALUE_PREFIXES:
            if operand_name.startswith(prefix):
                parts = operand_name.split("_", 3)
                if len(parts) >= 4:
                    return parts[3]
        return None


if __name__ == "__main__":
    CrossrefDomainLogger().run()
#
# Team Buddies crate PSYQ domain logger
#
# Annotates memory addresses recorded during static analysis with the
# dominant PSYQ domain inferred from the crate cross-reference reports.
#

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor

import csv
import os
from collections import defaultdict

DEFAULT_CSV = os.path.join("exports", "crate_crossref_summary.csv")
VALUE_A_MARKER = "CRATE_VALUE_A_"
VALUE_B_MARKER = "CRATE_VALUE_B_"


class CrossrefDomainLogger(object):
    DOMAIN_COL = "dominant_domain"
    HINT_COL = "dominant_domain_hint"

    def __init__(self, csv_path=DEFAULT_CSV):
        self.csv_path = csv_path
        self.domain_by_label = {}
        self._load_csv()

    def _load_csv(self):
        data_path = os.path.join(currentProgram.getExecutablePath(), self.csv_path)
        if not os.path.exists(data_path):
            raise RuntimeError("Crossref summary CSV not found at %s" % data_path)
        with open(data_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                label = row.get("crate_label", "").strip()
                domain = row.get(self.DOMAIN_COL, "")
                hint = row.get(self.HINT_COL, "")
                if not label:
                    continue
                self.domain_by_label[label] = (domain, hint)

    def annotate(self):
        monitor = ConsoleTaskMonitor()
        listing = currentProgram.getListing()
        for function in listing.getFunctions(True):
            if monitor.isCancelled():
                break
            self._annotate_function(function)

    def _annotate_function(self, function):
        listing = currentProgram.getListing()
        instructions = listing.getInstructions(function.getBody(), True)
        while instructions.hasNext() and not monitor.isCancelled():
            instr = instructions.next()
            for operand in instr.getOpObjects(0):
                if operand is None:
                    continue
                label_name = str(operand)
                if label_name.startswith(VALUE_A_MARKER) or label_name.startswith(VALUE_B_MARKER):
                    crate_label = self._extract_label(label_name)
                    if crate_label and crate_label in self.domain_by_label:
                        self._label_address(instr.getMinAddress(), crate_label)

    def _extract_label(self, symbol_name):
        parts = symbol_name.split("_", 3)
        if len(parts) < 4:
            return None
        return parts[3]

    def _label_address(self, address, crate_label):
        domain, hint = self.domain_by_label[crate_label]
        listing = currentProgram.getListing()
        code_unit = listing.getCodeUnitAt(address)
        if code_unit is None:
            return
        note = "[Crate %s] Domain: %s (%s)" % (crate_label, domain, hint)
        code_unit.setComment(CodeUnit.EOL_COMMENT, note)


def main():
    logger = CrossrefDomainLogger()
    logger.annotate()


if __name__ == "__main__":
    main()
