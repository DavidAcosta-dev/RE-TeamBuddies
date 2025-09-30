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
import csv
import codecs
from collections import OrderedDict


DEFAULT_KEYWORDS = [
    "libgte",
    "libgpu",
    "libspu",
    "libpad",
    "gte",
    "gpu",
    "spu",
    "pad",
    "matrix",
    "mat",
    "vector",
    "vec",
    "transform",
    "trans",
    "geometry",
    "geo",
    "anim",
    "animation",
    "frame",
    "weapon",
    "projectile",
    "project",
    "combat",
    "fight",
    "battle",
    "ai",
    "enemy",
    "engine",
    "state",
    "update",
    "render",
    "draw",
    "physics",
    "phys",
    "collide",
    "collision",
    "input",
    "sound",
    "audio",
    "buddy",
    "team",
    "crate",
    "pickup",
]

FOCUS_ALIAS_MAP = {
    "geometry": ["geom", "geo"],
    "transforms": ["transform", "trans"],
    "transform": ["trans"],
    "gte": ["libgte"],
    "gpu": ["libgpu"],
    "spu": ["libspu"],
    "pad": ["libpad", "input"],
    "combat": ["fight", "battle"],
    "ai": ["enemy"],
    "engine": ["render", "update"],
    "animation": ["anim", "frame"],
    "anim": ["animation"],
    "vector": ["vec"],
    "matrix": ["mat"],
}

CALL_MAP_PATH = os.path.join("exports", "function_call_map.csv")

try:
    from ghidra.app.script import GhidraScript  # type: ignore
    from ghidra.program.model.symbol import SymbolType  # type: ignore
except ImportError:  # pragma: no cover - allows type checking outside Ghidra
    class GhidraScript:  # type: ignore
        def getCurrentProgram(self):
            return None

        def getState(self):
            class _State:
                def getCurrentProgram(self):
                    return None

            return _State()

        def println(self, *_args, **_kwargs):
            pass

        def printf(self, *_args, **_kwargs):
            pass

        def getScriptArgs(self):
            return []

    class SymbolType:  # type: ignore
        FUNCTION = None
        LABEL = None
        GLOBAL = None
        DATA = None

        @staticmethod
        def toString():
            return ""


class FieldTruthTracer(GhidraScript):
    def run(self):
        parser = argparse.ArgumentParser(description="Field truth tracer")
        parser.add_argument("--crate", type=int, required=True)
        parser.add_argument("--slot", type=int, required=True)
        parser.add_argument("--priority", default="")
        parser.add_argument("--focusScore", type=int, default=0)
        parser.add_argument("--focus", default="")
        parser.add_argument("--domains", default="")
        parser.add_argument("--crateLabel", default="", help="Human-readable crate label for context weighting")
        parser.add_argument("--enable-logging", action="store_true")
        parser.add_argument("--programPath", default="", help="Optional project-relative path to the program to open explicitly.")
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
        if args.crateLabel:
            self.printf("  crate label: %s\n", args.crateLabel)
        self.printf("  priority: %s\n", args.priority)
        self.printf("  focus score: %d\n", args.focusScore)
        if args.focus:
            self.printf("  focus hint: %s\n", args.focus)
        if args.domains:
            self.printf("  domains: %s\n", args.domains)

        if args.enable_logging:
            self._log_focus_hits(args)

    def _log_focus_hits(self, args):
        program = self._get_program()
        opened_program = False
        if program is None and args.programPath:
            program = self._open_program_from_project(args.programPath)
            opened_program = program is not None
        if program is None:
            self.println("Program detection failed (no current program).")
        else:
            try:
                self.println("Program detected: {}".format(program.getName()))
            except Exception:
                self.println("Program detected (name unavailable).")
        if program is None:
            self.println("No active program; skipping keyword scan and fallback collection.")
            return

        focus_tokens = self._extract_focus_tokens(args.focus, args.domains, args.crateLabel)
        keywords = self._derive_keywords(args.focus, args.domains, args.crateLabel)

        self.println("Scanning symbols for keywords: {}".format(", ".join(keywords)))
        matches = self._collect_symbol_matches(program, keywords)
        seen_addresses = set(entry["address"] for entry in matches)
        call_map_limit = max(args.fallback_limit if args.fallback_limit else 0, 10)
        call_map_hits = self._collect_call_map_hits(
            program,
            keywords,
            focus_tokens,
            seen_addresses,
            crate_label=args.crateLabel,
            limit=call_map_limit,
        )
        if call_map_hits:
            matches.extend(call_map_hits)
            seen_addresses.update(entry["address"] for entry in call_map_hits)
            self.println("Call-map augmentation added {} matches.".format(len(call_map_hits)))
        fallback, fallback_stats = self._collect_top_referenced_symbols(
            program, limit=max(0, args.fallback_limit)
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
            fh.write("crate_label={}\n".format(args.crateLabel))
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
        if opened_program and program is not None:
            try:
                self.closeProgram(program)
            except Exception:
                pass

    def _extract_focus_tokens(self, focus, domains, crate_label):
        tokens = []
        for value in (focus, domains, crate_label):
            if not value:
                continue
            tokens.extend(re.findall(r"[A-Za-z0-9_]+", value))
        normalized = []
        seen = OrderedDict()
        for token in tokens:
            lower = token.lower()
            if lower and lower not in seen:
                seen[lower] = None
        normalized.extend(seen.keys())
        return normalized

    def _collect_symbol_matches(self, program, keywords):
        symbol_table = program.getSymbolTable()
        reference_manager = program.getReferenceManager()
        keyword_hits = []
        seen_addresses = set()
        reference_total = 0
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
        if not keyword_hits:
            self.println("No keyword symbols matched current focus tokens.")
        return keyword_hits

    def _collect_call_map_hits(self, program, keywords, focus_tokens, seen_addresses, crate_label="", limit=10):
        if limit is None or limit <= 0:
            limit = 10
        path = CALL_MAP_PATH
        if not os.path.exists(path):
            return []
        keyword_set = {keyword.lower() for keyword in keywords if keyword}
        focus_set = {token.lower() for token in (focus_tokens or []) if token}
        if not focus_set:
            focus_set = set(keyword_set)
        crate_tokens = set(self._tokenize_text(crate_label)) if crate_label else set()
        address_factory = None
        default_space = None
        try:
            address_factory = program.getAddressFactory()
            if address_factory is not None:
                default_space = address_factory.getDefaultAddressSpace()
        except Exception:
            address_factory = None
            default_space = None
        if default_space is None:
            self.println("Unable to access program address space for call-map augmentation; skipping.")
            return []
        local_seen = set()
        try:
            reader_handle = codecs.open(path, "r", "utf-8")
        except Exception as exc:
            self.println("Unable to open call map {}: {}".format(path, exc))
            return []
        candidates = []
        reference_manager = program.getReferenceManager()
        function_manager = program.getFunctionManager()
        symbol_table = program.getSymbolTable()
        try:
            csv_reader = csv.DictReader(reader_handle)
            for row in csv_reader:
                if row is None:
                    continue
                tokens = self._tokenize_text(
                    row.get("function"),
                    row.get("category"),
                    row.get("context"),
                    row.get("tags"),
                    row.get("attributes"),
                )
                focus_overlap = tokens.intersection(focus_set)
                keyword_overlap = tokens.intersection(keyword_set)
                crate_overlap = tokens.intersection(crate_tokens)
                token_score = (len(focus_overlap) * 2) + len(keyword_overlap) + (len(crate_overlap) * 3)
                if token_score <= 0:
                    continue
                address_value = row.get("address")
                address_int = self._parse_address(address_value)
                if address_int is None:
                    continue
                try:
                    address = default_space.getAddress(address_int)
                except Exception:
                    continue
                if address is None:
                    continue
                address_key = str(address)
                if address_key in seen_addresses or address_key in local_seen:
                    continue
                function = function_manager.getFunctionAt(address)
                if function is None:
                    function = function_manager.getFunctionContaining(address)
                symbol_name = None
                if function is not None:
                    symbol_name = function.getName()
                if not symbol_name:
                    primary_symbol = symbol_table.getPrimarySymbol(address)
                    if primary_symbol is not None:
                        symbol_name = primary_symbol.getName()
                if not symbol_name:
                    symbol_name = row.get("function") or "FUN_{:08x}".format(address_int)
                ref_count = 0
                try:
                    for _ in reference_manager.getReferencesTo(address):
                        ref_count += 1
                except Exception:
                    ref_count = 0
                origin_parts = ["CallMap"]
                category = row.get("category") or ""
                source_file = row.get("source_file") or ""
                if category:
                    origin_parts.append(category)
                if source_file:
                    origin_parts.append(os.path.basename(source_file))
                if crate_overlap:
                    origin_parts.append("crateMatch")
                if focus_overlap and not crate_overlap:
                    origin_parts.append("focusMatch")
                origin_parts.append("score={}".format(token_score))
                origin = "/".join(filter(None, origin_parts))
                candidates.append(
                    {
                        "name": symbol_name,
                        "address": address_key,
                        "refs": ref_count,
                        "origin": origin,
                        "score": token_score,
                    }
                )
                local_seen.add(address_key)
        finally:
            try:
                reader_handle.close()
            except Exception:
                pass
        if not candidates:
            return []
        candidates.sort(key=lambda entry: (-entry["score"], -entry["refs"], entry["name"]))
        selected = candidates[:limit]
        for entry in selected:
            entry.pop("score", None)
            seen_addresses.add(entry["address"])
        return selected

    def _tokenize_text(self, *values):
        tokens = set()
        for value in values:
            if not value:
                continue
            for token in re.findall(r"[A-Za-z0-9_]+", str(value)):
                lower = token.lower()
                if lower:
                    tokens.add(lower)
        return tokens

    def _parse_address(self, value):
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except Exception:
            pass
        match = re.search(r"0x[0-9a-fA-F]+", text)
        if match:
            try:
                return int(match.group(0), 16)
            except Exception:
                return None
        hex_parts = re.findall(r"[0-9a-fA-F]+", text)
        if hex_parts:
            try:
                return int(hex_parts[0], 16)
            except Exception:
                return None
        try:
            return int(text)
        except Exception:
            return None

    def _collect_top_referenced_symbols(self, program, limit=20):
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
            try:
                blocks = list(memory.getBlocks())
            except Exception as exc:
                self.println("Unable to enumerate memory blocks: {}".format(exc))
                blocks = []
            self.println(
                "Fallback memory sampling active: limit={}, current_hits={}, blocks_available={}".format(
                    limit, len(hits), len(blocks)
                )
            )
            for block in blocks:
                if len(hits) >= limit:
                    break
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

        if not hits:
            self.println(
                "No functions or symbols yielded fallback candidates; limit={}, functions={}, symbols={}".format(
                    limit, function_count, symbol_count
                )
            )
        hits.sort(key=lambda entry: (-entry["refs"], str(entry["name"])) )
        if not limit:
            effective_limit = min(50, len(hits))
        else:
            effective_limit = min(limit, len(hits))
        selected = hits[:effective_limit]
        self.println(
            "Fallback collection scanned {} functions, {} symbols, {} instructions, {} memory blocks; returning {} candidates (limit={}).".format(
                function_count,
                symbol_count,
                instruction_count,
                memory_blocks_examined,
                len(selected),
                limit,
            )
        )
        return selected, {
            "functions": function_count,
            "symbols": symbol_count,
            "instructions": instruction_count,
            "reference_total": reference_total,
            "memory_blocks": memory_blocks_examined,
        }

    def _derive_keywords(self, focus, domains, crate_label):
        tokens = []
        for value in (focus, domains, crate_label):
            if not value:
                continue
            tokens.extend(re.findall(r"[A-Za-z0-9_]+", value))
        normalized = []
        seen = OrderedDict()
        for token in tokens:
            token_lower = token.lower()
            if token_lower and token_lower not in seen:
                seen[token_lower] = None
        # expand with alias heuristics derived from focus tokens
        expanded = list(seen.keys())
        for token_lower in list(seen.keys()):
            for alias in FOCUS_ALIAS_MAP.get(token_lower, []):
                alias_lower = alias.lower()
                if alias_lower and alias_lower not in seen:
                    seen[alias_lower] = None
                    expanded.append(alias_lower)
        # ensure baseline keywords are always available for broad coverage
        for base in DEFAULT_KEYWORDS:
            base_lower = base.lower()
            if base_lower not in seen:
                seen[base_lower] = None
                expanded.append(base_lower)
        return expanded

    def print_headers(self):
        self.println("=== FieldTruthTracer ===")

    def _get_program(self):
        try:
            program = self.getCurrentProgram()
            if program is not None:
                return program
        except Exception:
            pass
        try:
            program = getattr(self, "currentProgram")
            if program is not None:
                return program
        except Exception:
            pass
        try:
            program = globals().get("currentProgram")
            if program is not None:
                return program
        except Exception:
            pass
        return None

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
        crate_label = get("FT_CRATE_LABEL", "")
        if crate_label:
            fallback.extend(["--crateLabel", crate_label])
        program_path = get("FT_PROGRAM_PATH", "")
        if program_path:
            fallback.extend(["--programPath", program_path])
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

    def _open_program_from_project(self, program_path):
        try:
            project = self.getProject()
        except Exception:
            project = None
        if project is None:
            self.println("No project available to open program {}.".format(program_path))
            return None
        try:
            project_data = project.getProjectData()
        except Exception as exc:
            self.println("Failed to access project data: {}".format(exc))
            return None
        candidate_paths = []
        if program_path:
            candidate_paths.append(program_path)
            if not program_path.startswith("/"):
                candidate_paths.append("/" + program_path)
        for candidate in candidate_paths:
            try:
                domain_file = project_data.getFile(candidate)
            except Exception as exc:
                self.println("Error locating program {}: {}".format(candidate, exc))
                continue
            if domain_file is None:
                continue
            try:
                opened_program = self.openProgram(domain_file)
                if opened_program is not None:
                    self.println("Opened program from project path: {}".format(candidate))
                    return opened_program
            except Exception as exc:
                self.println("Failed to open domain file {}: {}".format(candidate, exc))
        self.println("Unable to locate program {} in project.".format(program_path))
        return None


if __name__ == "__main__":
    FieldTruthTracer().run()
