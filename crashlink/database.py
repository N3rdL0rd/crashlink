"""
.cldb — CrashLink analysis database.

A companion file that sits next to a .hl/.dat bytecode file and stores only the
*analysis layer* built on top of it: rename/comment patches (the "patch buffer"),
cached decompiled pseudocode, and optional GUI session state. It never embeds the
original bytecode — on load it's validated against the currently-open file by a
SHA-256 hash, and refuses to apply anything if that doesn't match.

Container format (RIFF/PNG-style chunks, so unknown future tags are skippable):

    magic:   4 bytes  b"CLDB"
    version: u16 LE            (format version)
    flags:   u8                 (bit0 = zlib-compressed body)
    body:    chunks, optionally zlib-compressed as a whole

    chunk := tag(4 ASCII bytes) + length(u32 LE) + payload(<length> bytes)

Chunks: SRCI (source identity), ANNO (rename/comment patches), DCAC (decompiled
pseudocode + opline-map cache), SESS (optional GUI session state).
"""

from __future__ import annotations

import hashlib
import os
import struct
import zlib
from dataclasses import dataclass, field
from io import BytesIO
from typing import BinaryIO, Dict, List, Optional, Tuple

from .core import Bytecode, Function, VarInt

MAGIC = b"CLDB"
FORMAT_VERSION = 1
FLAG_COMPRESSED = 0x01

TAG_SRCI = b"SRCI"
TAG_ANNO = b"ANNO"
TAG_DCAC = b"DCAC"
TAG_SESS = b"SESS"

_RenameEntry = Tuple[int, int, Optional[int], str]  # findex, reg_idx, defining_op_idx, name
_CommentEntry = Tuple[int, int, str]  # findex, src_op_idx, text
_CacheEntry = Tuple[int, bytes, str, Dict[int, int]]  # findex, content_hash, text, opline_map


class DatabaseError(Exception):
    """Raised for malformed/unreadable .cldb files."""


@dataclass
class SessionState:
    view_mode: int
    theme_name: str
    open_findices: List[int]
    current_tab_index: Optional[int]


@dataclass
class DatabaseInfo:
    """Raw contents of a .cldb, read without validating against any bytecode file
    — for standalone inspection (e.g. the `crashlink db` CLI)."""

    format_version: int
    source_basename: str
    source_size: int
    source_hash_hex: str
    hl_version: int
    nfunctions: int
    renames: List[_RenameEntry]
    comments: List[_CommentEntry]
    cache_findices: List[int]
    session: Optional[SessionState]


@dataclass
class DatabaseLoadResult:
    renames_applied: int = 0
    comments_applied: int = 0
    cache: Dict[int, Tuple[str, Dict[int, int]]] = field(default_factory=dict)
    session: Optional[SessionState] = None
    warnings: List[str] = field(default_factory=list)

    @property
    def matched(self) -> bool:
        """False if the database was rejected outright (e.g. hash mismatch) —
        every rejection path in `load_database` appends a warning and applies nothing."""
        return not self.warnings


# ── low-level primitives ────────────────────────────────────────────────────


def _write_varint(buf: BytesIO, value: int) -> None:
    buf.write(VarInt(value).serialise())


def _read_varint(buf: BinaryIO) -> int:
    return VarInt().deserialise(buf).value


def _write_str(buf: BytesIO, s: str) -> None:
    raw = s.encode("utf-8")
    _write_varint(buf, len(raw))
    buf.write(raw)


def _read_str(buf: BinaryIO) -> str:
    n = _read_varint(buf)
    return buf.read(n).decode("utf-8")


def hash_file(path: str) -> Tuple[bytes, int]:
    """SHA-256 digest + byte size of a file on disk, read in chunks."""
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
            size += len(block)
    return h.digest(), size


def _function_content_hash(code: Bytecode, findex: int) -> Optional[bytes]:
    """Hash of a function's own opcodes plus its own rename/comment entries —
    used to invalidate a single DCAC entry without needing a full SRCI mismatch."""
    func = code.get_findex_map().get(findex)
    if not isinstance(func, Function):
        return None
    h = hashlib.blake2b(digest_size=8)
    h.update(func.serialise())
    renames = sorted((k, v) for k, v in code.annotations.iter_renames() if k[0] == findex)
    for (fi, reg_idx, def_op), name in renames:
        h.update(f"R{reg_idx}:{def_op}:{name}\0".encode("utf-8"))
    comments = sorted((k, v) for k, v in code.annotations.iter_comments() if k[0] == findex)
    for (fi, src_op_idx), text in comments:
        h.update(f"C{src_op_idx}:{text}\0".encode("utf-8"))
    return h.digest()


# ── chunk container ──────────────────────────────────────────────────────────


def _pack_file(chunks: List[Tuple[bytes, bytes]], compress: bool = True) -> bytes:
    body = BytesIO()
    for tag, payload in chunks:
        assert len(tag) == 4
        body.write(tag)
        body.write(struct.pack("<I", len(payload)))
        body.write(payload)
    raw = body.getvalue()

    flags = FLAG_COMPRESSED if compress else 0
    if compress:
        raw = zlib.compress(raw, level=9)
    header = MAGIC + struct.pack("<HB", FORMAT_VERSION, flags)
    return header + raw


def _unpack_file(data: bytes) -> Dict[bytes, bytes]:
    if data[:4] != MAGIC:
        raise DatabaseError("Not a .cldb file (bad magic)")
    version, flags = struct.unpack("<HB", data[4:7])
    if version != FORMAT_VERSION:
        raise DatabaseError(f"Unsupported .cldb format version {version}")

    body = data[7:]
    if flags & FLAG_COMPRESSED:
        body = zlib.decompress(body)

    chunks: Dict[bytes, bytes] = {}
    buf = BytesIO(body)
    while True:
        tag = buf.read(4)
        if len(tag) < 4:
            break
        (length,) = struct.unpack("<I", buf.read(4))
        chunks[tag] = buf.read(length)
    return chunks


# ── SRCI: source identity ───────────────────────────────────────────────────


def _encode_srci(code: Bytecode, source_path: str, source_hash: bytes, source_size: int) -> bytes:
    buf = BytesIO()
    _write_str(buf, os.path.basename(source_path))
    buf.write(struct.pack("<Q", source_size))
    buf.write(source_hash)
    buf.write(bytes([code.version.value & 0xFF if code.version is not None else 0]))
    _write_varint(buf, len(code.functions))
    return buf.getvalue()


def _check_srci(payload: bytes, code: Bytecode, source_hash: bytes, source_size: int) -> Tuple[bool, str]:
    buf = BytesIO(payload)
    _read_str(buf)  # basename, informational only
    (stored_size,) = struct.unpack("<Q", buf.read(8))
    stored_hash = buf.read(32)
    stored_version = buf.read(1)[0]
    stored_nfunctions = _read_varint(buf)

    if stored_size != source_size or stored_hash != source_hash:
        return False, "file contents differ"
    if code.version is not None and stored_version != code.version.value:
        return False, "bytecode version differs"
    if stored_nfunctions != len(code.functions):
        return False, "function count differs"
    return True, ""


# ── ANNO: rename/comment patch buffer ───────────────────────────────────────


def _encode_anno(code: Bytecode) -> bytes:
    buf = BytesIO()
    renames = list(code.annotations.iter_renames())
    _write_varint(buf, len(renames))
    for (findex, reg_idx, def_op), name in renames:
        _write_varint(buf, findex)
        _write_varint(buf, reg_idx)
        buf.write(bytes([1 if def_op is not None else 0]))
        if def_op is not None:
            _write_varint(buf, def_op)
        _write_str(buf, name)

    comments = list(code.annotations.iter_comments())
    _write_varint(buf, len(comments))
    for (findex, src_op_idx), text in comments:
        _write_varint(buf, findex)
        _write_varint(buf, src_op_idx)
        _write_str(buf, text)
    return buf.getvalue()


def _decode_anno(payload: bytes) -> Tuple[List[_RenameEntry], List[_CommentEntry]]:
    buf = BytesIO(payload)
    renames: List[_RenameEntry] = []
    for _ in range(_read_varint(buf)):
        findex = _read_varint(buf)
        reg_idx = _read_varint(buf)
        has_def = buf.read(1)[0] != 0
        def_op = _read_varint(buf) if has_def else None
        name = _read_str(buf)
        renames.append((findex, reg_idx, def_op, name))

    comments: List[_CommentEntry] = []
    for _ in range(_read_varint(buf)):
        findex = _read_varint(buf)
        src_op_idx = _read_varint(buf)
        text = _read_str(buf)
        comments.append((findex, src_op_idx, text))
    return renames, comments


# ── DCAC: decompiled pseudocode + opline-map cache ──────────────────────────


def _encode_dcac(
    code: Bytecode,
    class_results: Dict[str, Dict[int, Optional[str]]],
    opline_cache: Dict[int, Dict[int, int]],
) -> bytes:
    texts: Dict[int, str] = {}
    for results in class_results.values():
        for findex, text in results.items():
            if text is not None:
                texts[findex] = text

    entries: List[_CacheEntry] = []
    for findex, text in texts.items():
        h = _function_content_hash(code, findex)
        if h is None:
            continue  # native or otherwise not a real Function — nothing to cache
        entries.append((findex, h, text, opline_cache.get(findex, {})))

    buf = BytesIO()
    _write_varint(buf, len(entries))
    for findex, h, text, opmap in entries:
        _write_varint(buf, findex)
        buf.write(h)
        _write_str(buf, text)
        _write_varint(buf, len(opmap))
        for op_idx, body_line in opmap.items():
            _write_varint(buf, op_idx)
            _write_varint(buf, body_line)
    return buf.getvalue()


def _decode_dcac(payload: bytes) -> List[_CacheEntry]:
    buf = BytesIO(payload)
    entries: List[_CacheEntry] = []
    for _ in range(_read_varint(buf)):
        findex = _read_varint(buf)
        h = buf.read(8)
        text = _read_str(buf)
        opmap: Dict[int, int] = {}
        for _ in range(_read_varint(buf)):
            op_idx = _read_varint(buf)
            body_line = _read_varint(buf)
            opmap[op_idx] = body_line
        entries.append((findex, h, text, opmap))
    return entries


# ── SESS: optional GUI session state ────────────────────────────────────────


def _encode_sess(session: SessionState) -> bytes:
    buf = BytesIO()
    buf.write(bytes([session.view_mode & 0xFF]))
    _write_str(buf, session.theme_name)
    _write_varint(buf, len(session.open_findices))
    for fi in session.open_findices:
        _write_varint(buf, fi)
    has_current = session.current_tab_index is not None
    buf.write(bytes([1 if has_current else 0]))
    if session.current_tab_index is not None:
        _write_varint(buf, session.current_tab_index)
    return buf.getvalue()


def _decode_sess(payload: bytes) -> SessionState:
    buf = BytesIO(payload)
    view_mode = buf.read(1)[0]
    theme_name = _read_str(buf)
    open_findices = [_read_varint(buf) for _ in range(_read_varint(buf))]
    has_current = buf.read(1)[0] != 0
    current_tab_index = _read_varint(buf) if has_current else None
    return SessionState(
        view_mode=view_mode,
        theme_name=theme_name,
        open_findices=open_findices,
        current_tab_index=current_tab_index,
    )


# ── Public API ───────────────────────────────────────────────────────────────


def save_database(
    path: str,
    *,
    code: Bytecode,
    source_path: str,
    class_results: Dict[str, Dict[int, Optional[str]]],
    opline_cache: Dict[int, Dict[int, int]],
    session: Optional[SessionState] = None,
) -> None:
    """Write a .cldb next to `source_path`, capturing `code`'s annotations and the
    given decompile caches. Never embeds the bytecode itself, only re-hashes it."""
    source_hash, source_size = hash_file(source_path)
    chunks = [
        (TAG_SRCI, _encode_srci(code, source_path, source_hash, source_size)),
        (TAG_ANNO, _encode_anno(code)),
        (TAG_DCAC, _encode_dcac(code, class_results, opline_cache)),
    ]
    if session is not None:
        chunks.append((TAG_SESS, _encode_sess(session)))

    data = _pack_file(chunks)
    tmp_path = path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(data)
    os.replace(tmp_path, path)


def load_database(path: str, *, code: Bytecode, source_path: str) -> DatabaseLoadResult:
    """Read a .cldb, validate it against the currently-open bytecode, and apply
    renames/comments directly onto `code.annotations`. Applies nothing (just a
    warning) if the database doesn't match the current file."""
    result = DatabaseLoadResult()

    with open(path, "rb") as f:
        data = f.read()
    try:
        chunks = _unpack_file(data)
    except DatabaseError as e:
        result.warnings.append(str(e))
        return result

    srci = chunks.get(TAG_SRCI)
    if srci is None:
        result.warnings.append("Database is missing its source-identity chunk; ignoring.")
        return result

    source_hash, source_size = hash_file(source_path)
    ok, reason = _check_srci(srci, code, source_hash, source_size)
    if not ok:
        result.warnings.append(f"Database doesn't match this bytecode ({reason}); ignoring.")
        return result

    anno = chunks.get(TAG_ANNO)
    if anno is not None:
        renames, comments = _decode_anno(anno)
        for findex, reg_idx, def_op, name in renames:
            code.annotations.rename(findex, reg_idx, def_op, name)
        for findex, src_op_idx, text in comments:
            code.annotations.set_comment(findex, src_op_idx, text)
        result.renames_applied = len(renames)
        result.comments_applied = len(comments)

    dcac = chunks.get(TAG_DCAC)
    if dcac is not None:
        for findex, stored_hash, text, opmap in _decode_dcac(dcac):
            if _function_content_hash(code, findex) == stored_hash:
                result.cache[findex] = (text, opmap)

    sess = chunks.get(TAG_SESS)
    if sess is not None:
        result.session = _decode_sess(sess)

    return result


def inspect_database(path: str) -> DatabaseInfo:
    """Read a .cldb's raw contents without needing (or validating against) the
    original bytecode file — used by the `crashlink db` CLI."""
    with open(path, "rb") as f:
        data = f.read()
    chunks = _unpack_file(data)  # raises DatabaseError on bad magic/version
    (format_version, _flags) = struct.unpack("<HB", data[4:7])

    srci = chunks.get(TAG_SRCI)
    if srci is None:
        raise DatabaseError("Database is missing its source-identity chunk")
    buf = BytesIO(srci)
    basename = _read_str(buf)
    (size,) = struct.unpack("<Q", buf.read(8))
    source_hash = buf.read(32)
    hl_version = buf.read(1)[0]
    nfunctions = _read_varint(buf)

    renames: List[_RenameEntry] = []
    comments: List[_CommentEntry] = []
    anno = chunks.get(TAG_ANNO)
    if anno is not None:
        renames, comments = _decode_anno(anno)

    cache_findices: List[int] = []
    dcac = chunks.get(TAG_DCAC)
    if dcac is not None:
        cache_findices = [entry[0] for entry in _decode_dcac(dcac)]

    session: Optional[SessionState] = None
    sess = chunks.get(TAG_SESS)
    if sess is not None:
        session = _decode_sess(sess)

    return DatabaseInfo(
        format_version=format_version,
        source_basename=basename,
        source_size=size,
        source_hash_hex=source_hash.hex(),
        hl_version=hl_version,
        nfunctions=nfunctions,
        renames=renames,
        comments=comments,
        cache_findices=cache_findices,
        session=session,
    )
