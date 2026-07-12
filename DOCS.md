# paranoid-deobfuscator — Documentation

## Architecture

```
                    ┌──────────────────────┐
                    │  CLI (click)          │
                    │  deobfuscate / helpers│
                    └──────┬───────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
     discover_get_string  ParanoidSmali  ParanoidSmali
     _targets()           Deobfuscator   Parser
              │                │              │
              ▼                ▼              ▼
         GetStringTarget   replacement    smali → typed AST
         (method+field     of invoke-     (methods, fields,
          +chunks)         static calls    consts, sget)
```

## Detection Tiers

The tool discovers getString methods in two passes:

### Tier 1 — Exact const-signature match

Matches the classic Paranoid v0.3+ `DeobfuscatorHelper` pattern where the
method body begins with a specific sequence of `const-wide` values:

```python
PARANOID_GET_STRING_CONST_SIGNATURE = [
    4294967295, 33, 7109453100751455733, 28,
    -3808689974395783757, 32, 65535, 16, -65536, 0,
]
```

### Tier 2 — Structural fallback

When Tier 1 finds nothing, any `static (J) → String` method that references
exactly one `String[]` field **in its own class** via `sget-object` is
treated as a getString wrapper.  This catches:

- Thin wrappers that delegate to a separate deobfuscator class
- LSParanoid builds where the const preamble differs
- Any variant that follows the standard LSParanoid algorithm

### Why both tiers work

LSParanoid has a **single, public, deterministic** deobfuscation algorithm
(`DeobfuscatorHelper.getString` + `RandomHelper`).  The algorithm is:

1. Seed PRNG with lower 32 bits of the obfuscated `long` ID
2. Use PRNG output to derive chunk index and character position
3. XOR PRNG bytes with `chunk.charAt(i)` to reconstruct the original string

Only the chunk data and the call-site IDs change between APKs.  The tool
reimplements this algorithm once in Python (`paranoid.deobfuscate_string`).

## Output Cleanup

After deobfuscation:

- **`const-wide` loads** that fed a removed getString call are deleted
- **`invoke-static` calls** are removed without leaving a comment
- **`move-result-object`** instructions are replaced with `const-string`
  containing the deobfuscated text
- Inside try blocks, invoke-static is replaced with `nop` (smali requires
  at least one instruction per try block)

## Multi-Method Support

When an APK contains multiple getString methods (e.g., split across DEX
files or helper variants), the tool:

1. Discovers all candidates via `discover_get_string_targets()`
2. Pairs each method with its own chunk array
3. Builds a `Dict[MethodIdentity, GetStringTarget]` lookup table
4. Matches every `invoke-static` call site against all targets (O(1))
5. Uses the correct chunk list per call site

## Helper Commands

### `extract-strings`

Dumps all deobfuscated strings.  With multiple methods, each line is
prefixed with the method signature:

```
[Lfoo/Bar;->a(J)Ljava/lang/String;][3f2a]:Hello World
```

### `extract-chunks`

Saves chunk arrays.  Single-target → plain list (backward compatible).
Multi-target → `{signature: chunks}` dict.  Use `--method` with
`deobfuscate-string` to select one.

## API Reference

### `paranoid.discovery`

```python
@dataclass(frozen=True)
class GetStringTarget:
    method: SmaliMethod   # the getString wrapper
    field: SmaliField     # the String[] chunk field
    chunks: List[str]     # decoded chunk strings

    @property
    def identity(self) -> MethodIdentity: ...
    @property  
    def method_signature(self) -> str: ...

def discover_get_string_targets(path: Path) -> List[GetStringTarget]: ...
def targets_by_identity(targets: Sequence[GetStringTarget]) -> Dict[MethodIdentity, GetStringTarget]: ...
def method_identity(method: SmaliMethod) -> MethodIdentity: ...
def method_identity_from_parts(class_name, name, args, ret) -> MethodIdentity: ...

class DiscoveryError(Exception): ...
```

### `ParanoidSmaliParser` (updated)

```python
class ParanoidSmaliParser:
    # Now accepts both legacy single-target and multi-target:
    def __init__(self, *, filename: str,
                 target_method: SmaliMethod | None = None,
                 target_methods: List[SmaliMethod] | None = None): ...

    # Calls to any target method are recorded as (register_value, identity):
    @property
    def calls_to_target_method(self) -> List[Tuple[SmaliRegister, MethodIdentity]]: ...
```

### `ParanoidSmaliDeobfuscator` (updated)

```python
class ParanoidSmaliDeobfuscator:
    # Now accepts multiple targets:
    def __init__(self, filepath, targets: Sequence[GetStringTarget]): ...
```

## Adding Support for a New Variant

If you encounter an APK where the string deobfuscation algorithm differs:

1. Capture a sample smali file containing the deobfuscator method
2. Implement the algorithm in Python (usually porting a few bitwise ops)
3. Add structural detection in `discovery.py:_is_get_string_wrapper()`
4. The existing `deobfuscate_string()` handles standard LSParanoid;
   add a new path for your variant

For LSParanoid-based obfuscation, the algorithm is public — you rarely
need to reimplement it.  Usually only the detection pattern needs
adjustment.
