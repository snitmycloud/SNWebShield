"""A small, strict YAML-subset reader for Nuclei templates (no extra package).

It understands what real templates use: block mappings and sequences, plain / 'single' / "double" quoted scalars,
single- and multi-line flow lists, block scalars (| and >), comments and a leading `---`. It FAILS CLOSED: anything it does
not understand (anchors, aliases, tags, complex keys, tabs, merge keys, duplicate keys, odd indentation, excessive size
or depth) raises YamlError, and the validator then rejects the template as "unparseable". A template is never run on the
strength of a guess about what it meant.
"""
import re

MAX_BYTES = 128 * 1024
MAX_DEPTH = 24
MAX_NODES = 20000


class YamlError(Exception):
    pass


_KEY = re.compile(r"""^(?P<key>"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s#'"\[\]{},&*!|>%@`?-][^:#]*?|-[^\s:#][^:#]*?)\s*:(?:\s+(?P<value>.*))?$""")
_BLOCK = re.compile(r"^[|>][+-]?[0-9]?$")
_NUM = re.compile(r"^-?\d+$")


def _strip_comment(text: str) -> str:
    """Remove a trailing ' # comment' that is not inside quotes."""
    quote = None
    for i, ch in enumerate(text):
        if quote:
            if ch == "\\" and quote == '"':
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"" and (i == 0 or text[i - 1] in " \t[,{:("):
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
    return text.rstrip()


def _unquote(token: str):
    if len(token) >= 2 and token[0] == token[-1] == "'":
        return token[1:-1].replace("''", "'")
    if len(token) >= 2 and token[0] == token[-1] == '"':
        body = token[1:-1]
        out, i = [], 0
        while i < len(body):
            if body[i] == "\\" and i + 1 < len(body):
                nxt = body[i + 1]
                table = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "/": "/", "0": "\0"}
                if nxt in table:
                    out.append(table[nxt])
                    i += 2
                    continue
                if nxt == "x" and i + 3 < len(body) + 1 and re.fullmatch(r"[0-9a-fA-F]{2}", body[i + 2:i + 4]):
                    out.append(chr(int(body[i + 2:i + 4], 16)))
                    i += 4
                    continue
                raise YamlError("unsupported escape")
            out.append(body[i])
            i += 1
        return "".join(out)
    raise YamlError("bad quoted scalar")


def _scalar(token: str):
    token = token.strip()
    if token == "":
        return None
    if token[0] in "'\"":
        return _unquote(token)
    if token[0] in "&*!%@`":
        raise YamlError("anchors, aliases and tags are not supported")
    if token in ("true", "True"):
        return True
    if token in ("false", "False"):
        return False
    if token in ("null", "~", "Null"):
        return None
    if _NUM.match(token):
        return int(token)
    if token[0] in "{":
        raise YamlError("flow mappings are not supported")
    return token


def _split_flow(body: str) -> list[str]:
    parts, current, quote, depth = [], [], None, 0
    for ch in body:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            current.append(ch)
        elif ch == "[":
            depth += 1
            current.append(ch)
        elif ch == "]":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if quote or depth:
        raise YamlError("unbalanced flow list")
    tail = "".join(current).strip()
    if tail or parts:
        parts.append(tail)
    return parts


def _flow_list(text: str):
    text = text.strip()
    if not (text.startswith("[") and text.endswith("]")):
        raise YamlError("bad flow list")
    items = []
    for part in _split_flow(text[1:-1]):
        part = part.strip()
        if part == "":
            continue
        if part.startswith("["):
            items.append(_flow_list(part))
        else:
            items.append(_scalar(part))
    return items


class _Reader:
    def __init__(self, text: str):
        if len(text.encode("utf-8", "replace")) > MAX_BYTES:
            raise YamlError("file too large")
        if "\t" in text.replace("\t", "\t", 1) and re.search(r"^\t", text, re.M):
            raise YamlError("tab indentation")
        self.lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        self.i = 0
        self.nodes = 0

    # -- helpers
    def _skip(self):
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            body = raw.strip()
            if body == "" or body.startswith("#"):
                self.i += 1
            else:
                return
        return

    def _peek(self):
        self._skip()
        if self.i >= len(self.lines):
            return None
        raw = self.lines[self.i]
        return len(raw) - len(raw.lstrip(" ")), _strip_comment(raw.strip())

    def _count(self):
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise YamlError("too many nodes")

    # -- grammar
    def document(self):
        self._skip()
        if self.i < len(self.lines) and self.lines[self.i].strip() == "---":
            self.i += 1
        peek = self._peek()
        if peek is None:
            return None
        result = self.block(peek[0], 0)
        self._skip()
        if self.i < len(self.lines):
            if self.lines[self.i].strip() in ("...", "---"):
                raise YamlError("multiple documents")
            raise YamlError("unexpected content")
        return result

    def block(self, indent: int, depth: int):
        if depth > MAX_DEPTH:
            raise YamlError("too deep")
        peek = self._peek()
        if peek is None:
            return None
        _, content = peek
        if content.startswith("- ") or content == "-":
            return self.sequence(indent, depth)
        return self.mapping(indent, depth)

    def mapping(self, indent: int, depth: int):
        result = {}
        while True:
            peek = self._peek()
            if peek is None or peek[0] < indent:
                return result
            line_indent, content = peek
            if line_indent > indent:
                raise YamlError("unexpected indentation")
            if content.startswith("- ") or content == "-":
                return result  # a sequence at the same indent belongs to the parent key
            match = _KEY.match(content)
            if not match:
                raise YamlError(f"cannot read line {self.i + 1}")
            key = match.group("key")
            key = _unquote(key) if key[0] in "'\"" else key.strip()
            if key in result:
                raise YamlError("duplicate key")
            if key == "<<":
                raise YamlError("merge keys are not supported")
            value = (match.group("value") or "").strip()
            self._count()
            self.i += 1
            result[key] = self.value(value, indent, depth)

    def value(self, text: str, indent: int, depth: int):
        if text == "":
            nxt = self._peek()
            if nxt is None:
                return None
            n_indent, n_content = nxt
            if n_indent > indent:
                return self.block(n_indent, depth + 1)
            if n_indent == indent and (n_content.startswith("- ") or n_content == "-"):
                return self.sequence(indent, depth + 1)
            return None
        if _BLOCK.match(text):
            return self.block_scalar(text, indent)
        if text.startswith("["):
            joined = text
            guard = 0
            while True:
                try:
                    return _flow_list(joined)
                except YamlError:
                    guard += 1
                    if self.i >= len(self.lines) or guard > 200:
                        raise
                    joined += " " + _strip_comment(self.lines[self.i].strip())
                    self.i += 1
        if text[0] in "'\"":
            quote = text[0]
            joined = text
            guard = 0
            while not self._closed(joined, quote):
                guard += 1
                if self.i >= len(self.lines) or guard > 200:
                    raise YamlError("unterminated quoted scalar")
                joined += " " + self.lines[self.i].strip()
                self.i += 1
            return _unquote(joined)
        value = _scalar(text)
        if isinstance(value, str):  # a plain scalar may continue on deeper-indented lines
            parts = [value]
            while True:
                self._skip()
                if self.i >= len(self.lines):
                    break
                raw = self.lines[self.i]
                if len(raw) - len(raw.lstrip(" ")) <= indent:
                    break
                parts.append(_strip_comment(raw.strip()))
                self.i += 1
            value = " ".join(parts)
        return value

    @staticmethod
    def _closed(text: str, quote: str) -> bool:
        if len(text) < 2:
            return False
        i, closed = 1, False
        while i < len(text):
            ch = text[i]
            if quote == '"' and ch == "\\":
                i += 2
                continue
            if ch == quote:
                if quote == "'" and i + 1 < len(text) and text[i + 1] == "'":
                    i += 2
                    continue
                closed = i == len(text.rstrip()) - 1
                if not closed:
                    raise YamlError("text after a quoted scalar")
                return True
            i += 1
        return closed

    def block_scalar(self, header: str, indent: int):
        folded = header[0] == ">"
        keep = header[1:2] == "+"
        lines, block_indent = [], None
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            if raw.strip() == "":
                lines.append("")
                self.i += 1
                continue
            lead = len(raw) - len(raw.lstrip(" "))
            if lead <= indent:
                break
            if block_indent is None:
                block_indent = lead
            if lead < block_indent:
                raise YamlError("bad block scalar indentation")
            lines.append(raw[block_indent:])
            self.i += 1
        while lines and lines[-1] == "" and not keep:
            lines.pop()
        return (" ".join(lines) if folded else "\n".join(lines)) + ("" if header[1:2] == "-" or not lines else "")

    def sequence(self, indent: int, depth: int):
        if depth > MAX_DEPTH:
            raise YamlError("too deep")
        result = []
        while True:
            peek = self._peek()
            if peek is None or peek[0] != indent:
                if peek is not None and peek[0] > indent:
                    raise YamlError("unexpected indentation")
                return result
            content = peek[1]
            if not (content.startswith("- ") or content == "-"):
                return result
            self._count()
            rest = content[1:].strip()
            if rest == "":
                self.i += 1
                nxt = self._peek()
                result.append(self.block(nxt[0], depth + 1) if nxt and nxt[0] > indent else None)
                continue
            if rest.startswith("- "):
                raise YamlError("nested sequences are not supported")
            if _KEY.match(rest) and not rest.startswith(("'", '"', "[")) or (rest[0] in "'\"" and _KEY.match(rest)):
                # "- key: value" starts a mapping whose keys line up after the dash
                offset = len(self.lines[self.i]) - len(self.lines[self.i].lstrip(" ")) + (len(content) - len(content[1:].lstrip(" ")))
                self.lines[self.i] = " " * offset + rest
                result.append(self.mapping(offset, depth + 1))
                continue
            self.i += 1
            result.append(self.value(rest, indent, depth + 1))


def parse(text: str):
    """Parse a template. Raises YamlError for anything outside the supported subset."""
    if not isinstance(text, str):
        raise YamlError("not text")
    if "\x00" in text:
        raise YamlError("binary content")
    return _Reader(text).document()
