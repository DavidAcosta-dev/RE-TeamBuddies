# @category FieldTruth
"""Ghidra script stub for PSYQ field truth tracing.

This script expects the following arguments (provided via analyzeHeadless or
Ghidra GUI):
  --crate <index>
  --slot <index>
  --priority <tier>
  --focusScore <scaled score>
  [--focus <hint string>]
  [--domains <comma-separated domains>]

It logs the crate/slot identifiers and leaves placeholder hooks for future
trace instrumentation (e.g., invoking custom analyzers or exporting data).
"""

import argparse
import os
import re
import codecs
from collections import OrderedDict

from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import SymbolType


class FieldTruthTracer(GhidraScript):
    def run(self):
        parser = argparse.ArgumentParser(description="Field truth tracer")
        parser.add_argument("--crate", type=int, required=True)
        parser.add_argument("--slot", type=int, required=True)
        parser.add_argument("--priority", default="")
        parser.add_argument("--focusScore", type=int, default=0)
        parser.add_argument("--focus", default="")
        parser.add_argument("--domains", default="")
        parser.add_argument("--enable-logging", action="store_true")
        parser.add_argument(
            "--log-dir",
            default=os.path.join("exports", "field_truth_logs"),
            help="Directory to write log files when logging is enabled.",
        )
        parser.add_argument(
            "--fallback-limit",
            type=int,
            default=20,
            help="Number of top referenced symbols to record when keywords miss.",
        )
        raw_args = list(self.getScriptArgs())
        self.println("Args: {}".format(raw_args))
        if raw_args:
            args = parser.parse_args(raw_args)
        else:
            env_args = self._env_fallback_args()
            self.println("Env fallback args: {}".format(env_args))
            args = parser.parse_args(env_args)

        self.print_headers()
        self.printf("Field truth target:\n")
        self.printf("  crate: %d\n", args.crate)
        self.printf("  slot: %d\n", args.slot)
        self.printf("  priority: %s\n", args.priority)
        self.printf("  focus score: %d\n", args.focusScore)
        if args.focus:
            self.printf("  focus hint: %s\n", args.focus)
        if args.domains:
            self.printf("  domains: %s\n", args.domains)

        if args.enable_logging:
            self._log_focus_hits(args)

    def _log_focus_hits(self, args):
        keywords = self._derive_keywords(args.focus, args.domains)
        if not keywords:
            keywords = ["libgte", "libgpu", "libspu", "libpad"]

        self.println("Scanning symbols for keywords: {}".format(", ".join(keywords)))
        matches = self._collect_symbol_matches(keywords)
        fallback, fallback_stats = self._collect_top_referenced_symbols(
            limit=max(0, args.fallback_limit)
        )
        log_dir = args.log_dir
        try:
            os.makedirs(log_dir)
        except OSError:
            pass
        log_path = os.path.join(
            log_dir,
            "crate{}_slot{}_focus{}.log".format(args.crate, args.slot, args.focusScore),
        )
        with codecs.open(log_path, "w", "utf-8") as fh:
            fh.write("Field Truth Trace Log\n")
            fh.write("crate={}, slot={}, priority={}, focus_score={}\n".format(
                args.crate, args.slot, args.priority, args.focusScore
            ))
            fh.write("focus_hint={}\n".format(args.focus))
            fh.write("domains={}\n".format(args.domains))
            fh.write("keywords={}\n".format(",".join(keywords)))
            fh.write("matches={}\n".format(len(matches)))
            fh.write("fallback_limit={}\n".format(args.fallback_limit))
            fh.write(
                "fallback_scanned_functions={}\n".format(
                    fallback_stats.get("functions", 0)
                )
            )
            fh.write(
                "fallback_scanned_symbols={}\n".format(
                    fallback_stats.get("symbols", 0)
                )
            )
            fh.write(
                "fallback_scanned_instructions={}\n".format(
                    fallback_stats.get("instructions", 0)
                )
            )
            fh.write(
                "fallback_reference_total={}\n".format(
                    fallback_stats.get("reference_total", 0)
                )
            )
            fh.write(
                "fallback_memory_blocks={}\n".format(
                    fallback_stats.get("memory_blocks", 0)
                )
            )
            fh.write("fallback_count={}\n".format(len(fallback)))
            fh.write("\n")
            if matches:
                for entry in matches:
                    fh.write("{name} @ {address} :: refs={refs} :: origin={origin}\n".format(**entry))
            else:
                fh.write("No keyword matches found.\n")
            if fallback:
                fh.write("\nTop referenced symbols (limit={}):\n".format(args.fallback_limit))
                for entry in fallback:
                    fh.write("{name} @ {address} :: refs={refs} :: origin={origin}\n".format(**entry))
        self.println("Wrote log to {} ({} matches)".format(log_path, len(matches)))
        if not matches and fallback:
            self.println("Used fallback candidates (no direct keyword matches).")
        if not fallback:
            self.println("No referenced symbols met fallback criteria (limit={}).".format(args.fallback_limit))

    def _collect_symbol_matches(self, keywords):
        program = self.getCurrentProgram()
        if program is None:
            return []
        symbol_table = program.getSymbolTable()
        reference_manager = program.getReferenceManager()
        keyword_hits = []
        seen_addresses = set()
        for symbol in symbol_table.getSymbolIterator(True):
            if symbol is None:
                continue
            name = symbol.getName()
            if not name:
                continue
            lower_name = name.lower()
            if not any(keyword in lower_name for keyword in keywords):
                continue
            address = symbol.getAddress()
            if address in seen_addresses:
                continue
            seen_addresses.add(address)
            ref_count = 0
            for _ in reference_manager.getReferencesTo(address):
                ref_count += 1
            reference_total += ref_count
            origin = symbol.getSymbolType().toString()
            keyword_hits.append(
                {
                    "name": name,
                    "address": str(address),
                    "refs": ref_count,
                    "origin": origin,
                }
            )
        keyword_hits.sort(key=lambda entry: (-entry["refs"], str(entry["name"])) )
        return keyword_hits

    def _collect_top_referenced_symbols(self, limit=20):
        program = self.getCurrentProgram()
        if program is None:
            return [], {"functions": 0}
        reference_manager = program.getReferenceManager()
        symbol_table = program.getSymbolTable()
        function_manager = program.getFunctionManager()
        memory = program.getMemory()

        hits = []
        address_index = {}
        function_count = 0
        symbol_count = 0
        instruction_count = 0
        reference_total = 0
        memory_blocks_examined = 0

        # Seed results with any defined functions.
        for function in function_manager.getFunctions(True):
            if function is None:
                continue
            function_count += 1
            address = function.getEntryPoint()
            ref_count = 0
            for _ in reference_manager.getReferencesTo(address):
                ref_count += 1
            reference_total += ref_count
            entry = {
                "name": function.getName(),
                "address": str(address),
                "refs": ref_count,
                "origin": "Function",
            }
            hits.append(entry)
            address_index[str(address)] = entry

        # Include label/data symbols that might not be tied to functions.
        for symbol in symbol_table.getSymbolIterator(True):
            if symbol is None:
                continue
            symbol_type = symbol.getSymbolType()
            if symbol_type not in (
                SymbolType.FUNCTION,
                SymbolType.LABEL,
                SymbolType.GLOBAL,
                SymbolType.DATA,
            ):
                continue
            address = symbol.getAddress()
            if address is None:
                continue
            symbol_count += 1
            address_str = str(address)
            if address_str in address_index:
                continue
            ref_count = 0
            for _ in reference_manager.getReferencesTo(address):
                ref_count += 1
            reference_total += ref_count
            entry = {
                "name": symbol.getName(),
                "address": address_str,
                "refs": ref_count,
                "origin": symbol_type.toString(),
            }
            hits.append(entry)
            address_index[address_str] = entry

        # Fall back to sampling memory blocks when nothing else surfaces.
        self.println(
            "Fallback stats pre-memory: limit={}, type={}, current_hits={}".format(
                limit, type(limit), len(hits)
            )
        )
        if limit and len(hits) < limit:
            self.println(
                "Fallback memory sampling active: limit={}, current_hits={}, block_count={}".format(
                    limit, len(hits), memory.getBlockCount()
                )
            )
            block_iter = memory.getBlockIterator(True)
            while block_iter.hasNext() and len(hits) < limit:
                block = block_iter.next()
                if block is None:
                    continue
                memory_blocks_examined += 1
                address = block.getStart()
                if address is None:
                    continue
                address_str = str(address)
                if address_str in address_index:
                    continue
                entry = {
                    "name": "{} ({})".format(block.getName(), address_str),
                    "address": address_str,
                    "refs": 0,
                    "origin": "MemoryBlock",
                }
                hits.append(entry)
                address_index[address_str] = entry

        hits.sort(key=lambda entry: (-entry["refs"], str(entry["name"])) )
        selected = hits[:limit] if limit else []
        self.println(
            "Fallback collection scanned {} functions, {} symbols, {} instructions, {} memory blocks; returning {} candidates (limit={}).".format(
                function_count, symbol_count, instruction_count, memory_blocks_examined, len(selected), limit
            )
        )
        return selected, {
            "functions": function_count,
            "symbols": symbol_count,
            "instructions": instruction_count,
            "reference_total": reference_total,
            "memory_blocks": memory_blocks_examined,
        }

    def _derive_keywords(self, focus, domains):
        tokens = []
        for value in (focus, domains):
            if not value:
                continue
            tokens.extend(re.findall(r"[A-Za-z0-9_]+", value))
        normalized = []
        seen = OrderedDict()
        for token in tokens:
            token_lower = token.lower()
            if token_lower and token_lower not in seen:
                seen[token_lower] = None
        normalized.extend(seen.keys())
        return normalized

    def print_headers(self):
        self.println("=== FieldTruthTracer ===")

    def _env_fallback_args(self):
        def get(name, default=""):
            return os.environ.get(name, default)

        fallback = [
            "--crate",
            get("FT_CRATE", "0"),
            "--slot",
            get("FT_SLOT", "0"),
            "--priority",
            get("FT_PRIORITY", ""),
            "--focusScore",
            get("FT_FOCUS_SCORE", "0"),
        ]
        focus = get("FT_FOCUS", "")
        if focus:
            fallback.extend(["--focus", focus])
        domains = get("FT_DOMAINS", "")
        if domains:
            fallback.extend(["--domains", domains])
        if get("FT_ENABLE_LOGGING"):
            fallback.append("--enable-logging")
        log_dir = get("FT_LOG_DIR")
        if log_dir:
            fallback.extend(["--log-dir", log_dir])
        fallback_limit = get("FT_FALLBACK_LIMIT")
        if fallback_limit:
            fallback.extend(["--fallback-limit", fallback_limit])
        return fallback


if __name__ == "__main__":
    FieldTruthTracer().run()
