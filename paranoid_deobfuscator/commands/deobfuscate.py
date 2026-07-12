# Copyright 2024 Giacomo Ferretti
# Copyright 2026 Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging
import pathlib
import shutil
import sys
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List, Sequence, TypedDict

import click

from .. import __version__ as deobfuscator_version
from .. import paranoid, report_github_issue_message
from ..encoding import encode_smali_string
from ..smali import register

logger = logging.getLogger(__name__)

# Private sentinel returned by ParanoidSmaliDeobfuscator.process() when a
# getString invoke-static call is removed.  The update() method uses this to
# optionally drop the preceding dead const that loaded the obfuscated ID.
_REMOVED_GETSTRING = "<<REMOVED_GETSTRING>>"


class ParanoidSmaliDeobfuscator:
    class SmaliRegisterEncoder(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, register.SmaliRegister):
                return o.to_dict()
            return super().default(o)

    class ParanoidSmaliDeobfuscatorError(Exception):
        def __init__(self, message: str, extra: Dict[str, Any] = {}):
            super().__init__(message)
            self.extra = extra

        def __str__(self):
            if not self.extra:
                return super().__str__()
            return f"{super().__str__()}\n{json.dumps(self.extra, indent=4, cls=ParanoidSmaliDeobfuscator.SmaliRegisterEncoder)}"

    class State(TypedDict):
        class_name: str
        registers: Dict[str, paranoid.register.SmaliRegister]
        last_deobfuscated_string: str | None
        inside_try_block: bool

    def __init__(
        self,
        filepath: pathlib.Path | str,
        targets: Sequence[paranoid.GetStringTarget],
    ):
        self.filepath = filepath
        self.file = open(filepath, "r", encoding="utf-8", errors="replace")
        self.tmp_file = NamedTemporaryFile(
            mode="wt",
            dir=pathlib.Path(filepath).parent.absolute(),
            delete=False,
            encoding="utf-8",
        )

        self.targets_by_identity = paranoid.targets_by_identity(targets)

        # Deferred-output buffer for dead-const cleanup.
        # When we see a const(-wide) that might be a getString argument,
        # we buffer it instead of writing immediately.  If the very next
        # meaningful line is a removed getString targeting the same
        # register, the whole buffer is dropped.  Otherwise it is flushed.
        self._pending_lines: List[str] = []
        self._pending_const_reg: str | None = None

        self._removed_getstring_reg: str | None = None

        self._reset_state()

    def _reset_state(self, key_to_reset: str | None = None):
        default_state: ParanoidSmaliDeobfuscator.State = {
            "class_name": "",
            "registers": {},
            "last_deobfuscated_string": None,
            "inside_try_block": False,
        }
        if key_to_reset:
            self.state[key_to_reset] = default_state[key_to_reset]
        else:
            self.state = default_state

    # ------------------------------------------------------------------
    # Output buffering helpers
    # ------------------------------------------------------------------

    def _flush_pending(self) -> None:
        """Write every buffered line to the temporary file and clear state."""
        if self._pending_lines:
            self.tmp_file.writelines(self._pending_lines)
            self._pending_lines = []
        self._pending_const_reg = None

    # ------------------------------------------------------------------
    # Line-level processing
    # ------------------------------------------------------------------

    @staticmethod
    def get_fully_qualified_class_name(line: str) -> str:
        if not line.startswith(".class"):
            raise Exception("Line does not start with .class")
        return line.split()[-1]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.file.close()
        self.tmp_file.close()

    def process(self, line: str, line_num: int) -> str | None:
        # Reset the state if the result from the getString method is not used
        if self.state["last_deobfuscated_string"] and (line.startswith("invoke") or line.startswith("if-")):
            self.state["last_deobfuscated_string"] = None

        if line.startswith(":try_start"):
            self.state["inside_try_block"] = True
            return

        if line.startswith(":try_end"):
            self.state["inside_try_block"] = False
            return

        # Get fully qualified class name
        if line.startswith(".class"):
            self.state["class_name"] = self.get_fully_qualified_class_name(line)
            return

        # Update registers
        if line.startswith("const"):
            try:
                instr = paranoid.instructions.SmaliInstrConst.parse(line)
            except ValueError:
                return
            self.state["registers"][instr.register] = paranoid.register.SmaliRegisterConst(instr.value)
            return

        # Search for calls to any discovered getString method
        if line.startswith("invoke-static"):
            try:
                instr = paranoid.instructions.SmaliInstrInvokeStaticRange.parse(line)
                instr = paranoid.instructions.SmaliInstrInvokeStatic(
                    instr.registers, instr.class_name, instr.method, instr._raw
                )
            except ValueError:
                try:
                    instr = paranoid.instructions.SmaliInstrInvokeStatic.parse(line)
                except ValueError:
                    return

            method_name, method_arguments, method_return_type = paranoid.SmaliMethod.parse_method_signature(
                instr.method
            )

            identity = paranoid.method_identity_from_parts(
                instr.class_name, method_name, method_arguments, method_return_type
            )
            target = self.targets_by_identity.get(identity)
            if not target or len(instr.registers) != 2:
                return

            first_register = instr.registers[0]

            register_value = self.state["registers"].get(first_register)

            if first_register.startswith("p") and not register_value:
                raise ParanoidSmaliDeobfuscator.ParanoidSmaliDeobfuscatorError(
                    "Parameters are not supported",
                    extra={
                        "registers": self.state["registers"],
                        "register": first_register,
                        "line": line,
                    },
                )

            if not register_value:
                raise ParanoidSmaliDeobfuscator.ParanoidSmaliDeobfuscatorError(
                    "Register not found",
                    extra={
                        "registers": self.state["registers"],
                        "register": first_register,
                        "line": line,
                    },
                )

            if not isinstance(register_value, paranoid.register.SmaliRegisterConst):
                raise ParanoidSmaliDeobfuscator.ParanoidSmaliDeobfuscatorError(
                    "Register is not a constant",
                    extra={
                        "registers": self.state["registers"],
                        "register": first_register,
                        "line": line,
                    },
                )

            deobfuscated_string = paranoid.deobfuscate_string(register_value.value, target.chunks, True)
            self.state["last_deobfuscated_string"] = deobfuscated_string

            # Remember which register held the obfuscated ID so update()
            # can drop the preceding dead const from the output buffer.
            self._removed_getstring_reg = first_register

            if self.state["inside_try_block"]:
                return "    nop"

            return _REMOVED_GETSTRING

        # Move result object
        if line.startswith("move-result-object"):
            try:
                instr = paranoid.instructions.SmaliInstrMoveResult.parse(line)
            except ValueError:
                return

            if self.state["last_deobfuscated_string"] is not None:
                new_line = f'    const-string {instr.register}, "{encode_smali_string(self.state["last_deobfuscated_string"])}"'
                self.state["last_deobfuscated_string"] = None
                return new_line

            return

        return

    # ------------------------------------------------------------------
    # Line dispatch (called by the outer loop)
    # ------------------------------------------------------------------

    def update(self, _line: str, line_num: int = 0):
        """Process one smali line and write the result to the temporary file."""
        line_s = _line.strip()

        # --- run the deobfuscation logic first ---------------------------------
        try:
            result = self.process(line_s, line_num)
        except ParanoidSmaliDeobfuscator.ParanoidSmaliDeobfuscatorError as e:
            if e.args[0] == "Parameters are not supported":
                logger.warning(f"{self.filepath}:{line_num+1}: Detected unsupported method call")
                self._flush_pending()
                self.tmp_file.write(_line)
                return
            logger.error(report_github_issue_message(str(e)))
            raise e

        # --- handle a removed getString call -----------------------------------
        if result == _REMOVED_GETSTRING:
            removed_reg = self._removed_getstring_reg
            if removed_reg is not None and self._pending_const_reg == removed_reg:
                # The buffered const was dead — drop it and any blank lines
                # that followed it.
                self._pending_lines = []
                self._pending_const_reg = None
            else:
                # No matching buffered const — just flush whatever we have.
                self._flush_pending()
            return

        # --- blank lines -------------------------------------------------------
        if not line_s:
            if self._pending_lines:
                # Defer blank lines when a const is buffered — they might
                # sit between the const and a getString call.
                self._pending_lines.append(_line)
                return
            self.tmp_file.write(_line)
            return

        # --- const / const-wide lines (integer constants only) ------------------
        if line_s.startswith("const") and result is None:
            # result is None means process() kept the line as-is.
            # Check whether SmaliInstrConst can parse it (primitives only,
            # not const-string).
            try:
                instr = paranoid.instructions.SmaliInstrConst.parse(line_s)
                const_reg = instr.register
            except ValueError:
                const_reg = None

            if const_reg is not None:
                # Start a new deferred buffer in case this const feeds a
                # getString call on the very next meaningful line.
                self._flush_pending()
                self._pending_lines = [_line]
                self._pending_const_reg = const_reg
                return

        # --- everything else ---------------------------------------------------
        self._flush_pending()

        if result is not None:
            self.tmp_file.write(result + "\n")
        else:
            self.tmp_file.write(_line)


@click.command(name="deobfuscate", help="Deobfuscate a paranoid obfuscated APK smali files")
@click.argument("target", type=click.Path(exists=True, file_okay=False))
def cli(target: str):
    target_directory = pathlib.Path(target)

    # First pass: find all getString methods and their obfuscated string arrays
    try:
        targets = paranoid.discover_get_string_targets(target_directory)
    except paranoid.DiscoveryError as e:
        logger.error(str(e))
        sys.exit(1)

    logger.info("Found %d getString method(s)", len(targets))
    for get_string_target in targets:
        logger.debug("Method: %s", get_string_target.method)
        logger.debug("Field: %s", get_string_target.field)
        logger.debug("Chunks: %d", len(get_string_target.chunks))

    # Second pass: deobfuscate file, rewriting calls to any discovered target
    for smali_file in target_directory.rglob("*.smali"):
        with ParanoidSmaliDeobfuscator(smali_file, targets) as deobfuscator:
            for line_num, line in enumerate(deobfuscator.file):
                deobfuscator.update(line, line_num)

        # Replace the original file with the temporary one
        shutil.move(deobfuscator.tmp_file.name, smali_file)
