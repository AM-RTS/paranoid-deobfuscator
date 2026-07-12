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

"""Discovery helpers for Paranoid getString methods and their chunk arrays."""

from __future__ import annotations

import logging
import pathlib
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from .. import constants
from ..encoding import decode_unicode_chunks
from ..smali import SmaliField, SmaliMethod

logger = logging.getLogger(__name__)

# Identity used for invoke-static matching (modifiers are intentionally excluded).
MethodIdentity = Tuple[str | None, str, Tuple[str, ...], str]


@dataclass(frozen=True)
class GetStringTarget:
    """A resolved Paranoid getString method paired with its decoded chunk array."""

    method: SmaliMethod
    field: SmaliField
    chunks: List[str]

    @property
    def identity(self) -> MethodIdentity:
        return method_identity(self.method)

    @property
    def method_signature(self) -> str:
        """Fully-qualified method signature, e.g. ``LFoo;->a(J)Ljava/lang/String;``."""
        args = "".join(self.method.arguments)
        return f"{self.method.class_name}->{self.method.method}({args}){self.method.return_type}"


def method_identity(method: SmaliMethod) -> MethodIdentity:
    return (method.class_name, method.method, tuple(method.arguments), method.return_type)


def method_identity_from_parts(
    class_name: str,
    method_name: str,
    arguments: Sequence[str],
    return_type: str,
) -> MethodIdentity:
    return (class_name, method_name, tuple(arguments), return_type)


class DiscoveryError(Exception):
    """Raised when Paranoid targets cannot be resolved cleanly."""


def discover_get_string_targets(target_directory: pathlib.Path | str) -> List[GetStringTarget]:
    """
    Scan smali sources and return every valid Paranoid getString target.

    A method is considered a getString candidate when its const signature, argument
    list, and return type match the known Paranoid helper pattern. Each candidate
    must reference exactly one static ``String[]`` field whose initializer is present
    in a ``<clinit>`` of the same class.
    """
    # Local import avoids a circular dependency with paranoid.__init__.
    from . import ParanoidSmaliParser

    target_directory = pathlib.Path(target_directory)

    potential_get_string_methods: List[Tuple[SmaliMethod, List[SmaliField]]] = []
    potential_obfuscated_string_arrays: List[Tuple[SmaliField, List[str]]] = []

    for smali_file in target_directory.rglob("*.smali"):
        with open(smali_file, "r", encoding="utf-8", errors="replace") as f:
            smali_parser = ParanoidSmaliParser(filename=str(smali_file))

            for line_num, line in enumerate(f):
                smali_parser.update(line, line_num)

            for method, data in smali_parser.methods.items():
                if (
                    data["consts"] == constants.PARANOID_GET_STRING_CONST_SIGNATURE
                    and method.arguments == constants.PARANOID_GET_STRING_ARGUMENTS
                    and method.return_type == constants.PARANOID_GET_STRING_RETURN_TYPE
                ):
                    potential_get_string_methods.append((method, data["sget_objects"]))

            for field, data in smali_parser.fields.items():
                if field.type == "[Ljava/lang/String;":
                    potential_obfuscated_string_arrays.append((field, data["value"]))

    if not potential_get_string_methods:
        raise DiscoveryError("No potential get string method found")

    # Index chunk arrays by (class_name, field_name) for O(1) pairing.
    arrays_by_key: Dict[Tuple[str | None, str], List[str]] = {}
    for field, value in potential_obfuscated_string_arrays:
        key = (field.class_name, field.name)
        # Prefer the first non-empty initializer if duplicates exist.
        if key not in arrays_by_key or (not arrays_by_key[key] and value):
            arrays_by_key[key] = value

    targets: List[GetStringTarget] = []
    for method, sget_fields in potential_get_string_methods:
        if len(sget_fields) != 1:
            raise DiscoveryError(
                f"Found {len(sget_fields)} potential obfuscated string arrays for method "
                f"{method.class_name}->{method.method}; expected exactly one"
            )

        get_string_field = sget_fields[0]
        chunks = arrays_by_key.get((get_string_field.class_name, get_string_field.name))

        if not chunks:
            raise DiscoveryError(
                f"No chunks found for method {method.class_name}->{method.method} "
                f"(field {get_string_field.class_name}->{get_string_field.name})"
            )

        targets.append(
            GetStringTarget(
                method=method,
                field=get_string_field,
                chunks=decode_unicode_chunks(chunks),
            )
        )

    # Stable ordering for deterministic CLI output.
    targets.sort(key=lambda t: t.method_signature)

    logger.debug("Discovered %d getString target(s)", len(targets))
    for target in targets:
        logger.debug("  method=%s field=%s chunks=%d", target.method, target.field, len(target.chunks))

    return targets


def targets_by_identity(targets: Sequence[GetStringTarget]) -> Dict[MethodIdentity, GetStringTarget]:
    """Build a lookup table keyed by method identity for invoke matching."""
    result: Dict[MethodIdentity, GetStringTarget] = {}
    for target in targets:
        identity = target.identity
        if identity in result:
            raise DiscoveryError(f"Duplicate getString method identity: {target.method_signature}")
        result[identity] = target
    return result
