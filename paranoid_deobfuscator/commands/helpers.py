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

import click

from .. import paranoid, report_github_issue_message
from ..encoding import decode_unicode_chunks
from ..smali import register

logger = logging.getLogger(__name__)


@click.group(name="helpers", help="Helper commands")
def cli():
    pass


@cli.command(help="Extracts the strings from a paranoid obfuscated APK")
@click.argument("target", type=click.Path(exists=True, file_okay=False))
def extract_strings(target: str):
    target_directory = pathlib.Path(target)

    try:
        targets = paranoid.discover_get_string_targets(target_directory)
    except paranoid.DiscoveryError as e:
        logger.error(str(e))
        return

    logger.info("Found %d getString method(s)", len(targets))
    for get_string_target in targets:
        logger.debug("Method: %s", get_string_target.method)
        logger.debug("Field: %s", get_string_target.field)
        logger.debug("Chunks: %d", len(get_string_target.chunks))

    targets_lookup = paranoid.targets_by_identity(targets)
    methods = [t.method for t in targets]

    # Find all the deobfuscation values for every discovered getString method
    deobfuscation_calls = []
    for smali_file in target_directory.rglob("*.smali"):
        with open(smali_file, "r", encoding="utf-8", errors="replace") as f:
            smali_parser = paranoid.ParanoidSmaliParser(filename=str(smali_file), target_methods=methods)

            for line_num, line in enumerate(f):
                try:
                    smali_parser.update(line, line_num)
                except paranoid.ParanoidSmaliParserError as e:
                    # Ignore Parameters are not supported
                    if e.args[0] == "Parameters are not supported":
                        logger.warning(f"{smali_file}:{line_num+1}: Detected unsupported method call")
                        continue

                    # Log and raise the error
                    logger.error(report_github_issue_message(str(e)))
                    raise e

            deobfuscation_calls.extend(smali_parser.state["calls_to_target_method"])

    logger.debug("Deobfuscation calls: %d", len(deobfuscation_calls))

    multi = len(targets) > 1
    for call in deobfuscation_calls:
        # New multi-method format: (register_value, method_identity)
        if isinstance(call, tuple) and len(call) == 2:
            register_value, identity = call
        else:
            # Legacy single-value entries should not appear with current parser code,
            # but keep a safe fallback.
            register_value, identity = call, next(iter(targets_lookup))

        if not isinstance(register_value, register.SmaliRegisterConst):
            continue

        get_string_target = targets_lookup.get(identity)
        if get_string_target is None:
            continue

        text = paranoid.deobfuscate_string(register_value.value, get_string_target.chunks, True)
        if multi:
            print(f"[{get_string_target.method_signature}][{register_value.value:x}]:{text}")
        else:
            print(f"[{register_value.value:x}]:{text}")


@cli.command(help="Save the chunks from a paranoid obfuscated APK")
@click.argument("target", type=click.Path(exists=True, file_okay=False))
@click.argument("output", type=click.Path(exists=False, dir_okay=False))
def extract_chunks(target: str, output: str):
    target_directory = pathlib.Path(target)

    try:
        targets = paranoid.discover_get_string_targets(target_directory)
    except paranoid.DiscoveryError as e:
        logger.error(str(e))
        return

    logger.info("Found %d getString method(s)", len(targets))

    # Backward compatible: single target still writes a plain chunks list.
    # Multiple targets write a method-keyed object so callers can pick one.
    if len(targets) == 1:
        payload = targets[0].chunks
    else:
        payload = {t.method_signature: t.chunks for t in targets}

    with open(output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4)


@cli.command(help="Deobfuscate a string using extracted chunks")
@click.argument("chunk_file", type=click.Path(exists=True, dir_okay=False))
@click.argument("deobfuscation_long", type=int)
@click.option(
    "--method",
    "method_signature",
    default=None,
    help="Fully-qualified getString method signature when the chunk file contains multiple targets",
)
def deobfuscate_string(chunk_file: str, deobfuscation_long: int, method_signature: str | None):
    with open(chunk_file, "r", encoding="utf-8") as f:
        payload = json.load(f)

    if isinstance(payload, list):
        chunks = payload
    elif isinstance(payload, dict):
        if method_signature is None:
            if len(payload) == 1:
                chunks = next(iter(payload.values()))
            else:
                logger.error(
                    "Chunk file contains multiple methods; pass --method with one of: %s",
                    ", ".join(sorted(payload.keys())),
                )
                return
        elif method_signature not in payload:
            logger.error("Method %s not found in chunk file", method_signature)
            return
        else:
            chunks = payload[method_signature]
    else:
        logger.error("Unsupported chunk file format")
        return

    # Decode the chunks
    chunks = decode_unicode_chunks(chunks)

    print(f"[{deobfuscation_long:x}]:{paranoid.deobfuscate_string(deobfuscation_long, chunks, True)}")
