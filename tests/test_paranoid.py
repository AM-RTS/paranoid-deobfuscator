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

import tempfile

import numpy as np
import pytest

from paranoid_deobfuscator.paranoid import (
    DeobfuscatorHelper,
    GetStringTarget,
    RandomHelper,
    method_identity,
    method_identity_from_parts,
    targets_by_identity,
    utils,
)
from paranoid_deobfuscator.smali import SmaliField, SmaliMethod


@pytest.mark.parametrize(
    "input, expected_result",
    [
        ((-31289, 16, False), np.uint16(34247)),
    ],
)
def test_paranoid_utils_to_int(input, expected_result):
    assert utils.to_int(*input) == expected_result


@pytest.mark.parametrize(
    "input, expected_result",
    [
        (2669835571, 2366240958),
    ],
)
def test_paranoid_RandomHelper_seed(input, expected_result):
    assert RandomHelper.seed(input).view(np.int64) == expected_result


@pytest.mark.parametrize(
    "input, expected_result",
    [
        ((-31289, 9), -28673),
        ((-1858, 13), -8193),
        ((30135, 10), -9216),
        ((-1880, 9), 20991),
        ((7336, 13), 0),
        ((-16216, 10), -23553),
        ((-10841, 9), 20479),
        ((-10840, 13), 8191),
        ((10839, 10), 23552),
        ((-9400, 9), -28161),
        ((32584, 13), 0),
        ((9032, 10), 8192),
        ((27208, 9), -28672),
        ((19016, 13), 0),
        ((27208, 10), 8192),
        ((17224, 9), -28672),
        ((9032, 13), 0),
        ((840, 10), 8192),
    ],
)
def test_paranoid_RandomHelper_rotl(input, expected_result):
    assert RandomHelper.rotl(*input).view(np.int16) == expected_result


@pytest.mark.parametrize(
    "input, expected_result",
    [
        (2366240958, -603972440),
        (-603972440, -10840),
        (-10840, 41400733302600),
        (14428438344, 18997177240136),
        (361314142792, -41471667330232),
        (-281195266956472, -84352620795320),
    ],
)
def test_paranoid_RandomHelper_next(input, expected_result):
    assert RandomHelper.next(input).view(np.int64) == expected_result


@pytest.fixture
def paranoid_obfuscated_chunks():
    return ["\u0003foo\u0003bar"]


@pytest.mark.parametrize(
    "input, expected_result",
    [
        (0, b"foo"),
        (17179869184, b"bar"),
    ],
)
def test_paranoid_DeobfuscatorHelper_getString(paranoid_obfuscated_chunks, input, expected_result):
    assert DeobfuscatorHelper.getString(input, paranoid_obfuscated_chunks) == expected_result


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_targets():
    """Create synthetic GetStringTarget instances for testing."""
    method_a = SmaliMethod(
        "a",
        arguments=["J"],
        return_type="Ljava/lang/String;",
        modifiers=["static"],
        class_name="Lcom/example/A;",
    )
    field_a = SmaliField(
        "encryptedStrings",
        type="[Ljava/lang/String;",
        modifiers=["static"],
        class_name="Lcom/example/A;",
    )
    chunks_a = ["\u0003foo\u0003bar"]

    method_b = SmaliMethod(
        "getString",
        arguments=["J"],
        return_type="Ljava/lang/String;",
        modifiers=["static"],
        class_name="Lcom/example/B;",
    )
    field_b = SmaliField(
        "encryptedStrings",
        type="[Ljava/lang/String;",
        modifiers=["static"],
        class_name="Lcom/example/B;",
    )
    chunks_b = ["\u0003baz\u0003qux"]

    return [
        GetStringTarget(method=method_a, field=field_a, chunks=chunks_a),
        GetStringTarget(method=method_b, field=field_b, chunks=chunks_b),
    ]


def test_method_identity():
    method = SmaliMethod(
        "helper",
        arguments=["J"],
        return_type="Ljava/lang/String;",
        class_name="Lfoo/Bar;",
    )
    identity = method_identity(method)
    assert identity == ("Lfoo/Bar;", "helper", ("J",), "Ljava/lang/String;")


def test_method_identity_from_parts():
    identity = method_identity_from_parts("Lfoo/Bar;", "helper", ["J"], "Ljava/lang/String;")
    assert identity == ("Lfoo/Bar;", "helper", ("J",), "Ljava/lang/String;")


def test_method_identity_multiple_args():
    identity = method_identity_from_parts("Ltest/Cls;", "m", ["I", "Ljava/lang/String;", "Z"], "V")
    assert identity == ("Ltest/Cls;", "m", ("I", "Ljava/lang/String;", "Z"), "V")


def test_targets_by_identity(sample_targets):
    lookup = targets_by_identity(sample_targets)
    assert len(lookup) == 2

    identity_a = sample_targets[0].identity
    identity_b = sample_targets[1].identity

    assert lookup[identity_a] is sample_targets[0]
    assert lookup[identity_b] is sample_targets[1]


def test_targets_by_identity_duplicate_raises():
    """Duplicate method identities should raise DiscoveryError."""
    from paranoid_deobfuscator.paranoid.discovery import DiscoveryError

    method = SmaliMethod("dup", arguments=["J"], return_type="Ljava/lang/String;", class_name="Lfoo/A;")
    field = SmaliField("f", type="[Ljava/lang/String;", class_name="Lfoo/A;")
    target = GetStringTarget(method=method, field=field, chunks=[])
    with pytest.raises(DiscoveryError, match="Duplicate getString method"):
        targets_by_identity([target, target])


def test_get_string_target_identity(sample_targets):
    t = sample_targets[0]
    assert t.identity == method_identity(t.method)
    assert t.method_signature == "Lcom/example/A;->a(J)Ljava/lang/String;"


def test_get_string_target_repr():
    method = SmaliMethod("m", arguments=["J"], return_type="Ljava/lang/String;", class_name="LFoo;")
    field = SmaliField("f", type="[Ljava/lang/String;", class_name="LFoo;")
    target = GetStringTarget(method=method, field=field, chunks=["chunk"])
    assert repr(target).startswith("GetStringTarget(")
    assert target.method is method
    assert target.chunks == ["chunk"]


@pytest.mark.parametrize("method", ["a", "getString", "helper"])
def test_discover_targets_with_fixture(method, tmp_path):
    """Create synthetic smali and verify discover_get_string_targets finds it."""
    from paranoid_deobfuscator.constants import PARANOID_GET_STRING_CONST_SIGNATURE

    const_lines = "\n".join(f"    const-wide v0, {c:#x}" for c in PARANOID_GET_STRING_CONST_SIGNATURE)

    smali_content = f""".class public final Ltest/Target;
.super Ljava/lang/Object;


# static fields
.field static final encryptedStrings:[Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    const/4 v0, 0x1
    new-array v0, v0, [Ljava/lang/String;
    const/4 v1, 0x0
    const-string v2, "\\\\u0003foo\\\\u0003bar"
    aput-object v2, v0, v1
    sput-object v0, Ltest/Target;->encryptedStrings:[Ljava/lang/String;
    return-void
.end method

.method public static {method}(J)Ljava/lang/String;
    .locals 1

{const_lines}

    sget-object v0, Ltest/Target;->encryptedStrings:[Ljava/lang/String;

    invoke-static {{v0}}, Lparanoid/Helper;->doSomething(J)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
"""

    target_dir = tmp_path / "smali"
    target_dir.mkdir()
    smali_file = target_dir / "Target.smali"
    smali_file.write_text(smali_content, encoding="utf-8")

    from paranoid_deobfuscator.paranoid.discovery import discover_get_string_targets

    targets = discover_get_string_targets(target_dir)
    assert len(targets) == 1
    t = targets[0]
    assert t.method.method == method
    assert t.field.name == "encryptedStrings"
    assert t.method_signature == f"Ltest/Target;->{method}(J)Ljava/lang/String;"


# TODO: add tests for ParanoidSmaliParser
