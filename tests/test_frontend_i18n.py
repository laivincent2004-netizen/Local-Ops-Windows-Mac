from html.parser import HTMLParser
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
HTML_PATH = ROOT / "static" / "index.html"
I18N_PATH = ROOT / "static" / "js" / "i18n.js"

LANGUAGE_TEXT_RE = re.compile(
    r"[\u3400-\u9fff\u3001\u3002\uff0c\uff1a\uff1b\uff01\uff1f"
    r"\u300c\u300d\u201c\u201d]"
)
VOID_ELEMENTS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
}
TRANSLATABLE_ATTRIBUTES = {
    "aria-label", "aria-roledescription", "placeholder", "title",
}


class MarkupNode:
    def __init__(self, tag, attrs, parent, line):
        self.tag = tag
        self.attrs = dict(attrs)
        self.parent = parent
        self.children = []
        self.text = []
        self.line = line

    def descendants(self):
        for child in self.children:
            yield child
            yield from child.descendants()

    def combined_text(self):
        parts = list(self.text)
        for child in self.children:
            parts.append(child.combined_text())
        return "".join(parts)


class LocalizedMarkupParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = MarkupNode("document", [], None, 1)
        self.stack = [self.root]
        self.nodes = []
        self.by_id = {}
        self.language_text = []

    def handle_starttag(self, tag, attrs):
        node = MarkupNode(tag, attrs, self.stack[-1], self.getpos()[0])
        self.stack[-1].children.append(node)
        self.nodes.append(node)
        node_id = node.attrs.get("id")
        if node_id:
            self.by_id[node_id] = node
        if tag not in VOID_ELEMENTS:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID_ELEMENTS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == tag:
                del self.stack[index:]
                return

    def handle_data(self, data):
        if self.stack[-1].tag in {"script", "style"}:
            return
        self.stack[-1].text.append(data)
        if LANGUAGE_TEXT_RE.search(data):
            self.language_text.append((self.stack[-1], data, self.getpos()[0]))


def parse_markup():
    parser = LocalizedMarkupParser()
    parser.feed(HTML_PATH.read_text(encoding="utf-8"))
    return parser


def has_text_translation(node):
    current = node
    while current is not None:
        if current.attrs.get("data-i18n"):
            return True
        # EN and 中 are the language selector's invariant, deliberately terse
        # visual labels.  Their accessible names are translated separately.
        if current.attrs.get("data-language") in {"en", "zh"}:
            return True
        current = current.parent
    return False


def is_filesystem_literal(value):
    compact = value.strip()
    return (
        "~/" in compact
        or "%LOCALAPPDATA%" in compact
        or re.search(r"[A-Za-z]:[\\/]", compact) is not None
        or "\\\\wsl" in compact.lower()
    )


def attribute_translation_key(node, attribute):
    direct = node.attrs.get(f"data-i18n-{attribute}")
    if direct:
        return direct
    generic = node.attrs.get("data-i18n-attrs", "")
    for entry in re.split(r"[,\s]+", generic):
        if not entry:
            continue
        name, _, key = entry.partition(":")
        if name == attribute and key:
            return key
    return None


def attribute_is_language_neutral(value):
    stripped = value.strip()
    if not stripped or is_filesystem_literal(stripped):
        return True
    # Acronyms, shortcuts and port/PID-like technical labels do not change
    # between Chinese and English.
    return re.fullmatch(r"[A-Z0-9\s:+./_()\-–—⌘↑↓↵]+", stripped) is not None


def javascript_string_literals(source):
    """Yield (decoded-ish literal content, line) while ignoring comments.

    This intentionally does not evaluate JavaScript.  It is a small lexical
    guard that catches user-facing Chinese left in quote/template literals;
    comments may remain Chinese for maintainers.
    """
    index = 0
    line = 1
    length = len(source)
    while index < length:
        char = source[index]
        next_char = source[index + 1] if index + 1 < length else ""
        if char == "/" and next_char == "/":
            index += 2
            while index < length and source[index] not in "\r\n":
                index += 1
            continue
        if char == "/" and next_char == "*":
            index += 2
            while index + 1 < length and source[index:index + 2] != "*/":
                if source[index] == "\n":
                    line += 1
                index += 1
            index = min(length, index + 2)
            continue
        if char == "/" and next_char not in {"/", "*"}:
            previous_index = index - 1
            while previous_index >= 0 and source[previous_index].isspace():
                previous_index -= 1
            previous = source[previous_index] if previous_index >= 0 else ""
            # JavaScript has no tokenizer in the Python standard library.
            # This conservative branch recognizes the regex positions used by
            # this codebase so quote characters inside /.../ cannot open a
            # fake string and swallow later Chinese comments.
            if not previous or previous in "([{=:;,!?&|":
                index += 1
                escaped = False
                in_class = False
                while index < length:
                    regex_char = source[index]
                    if regex_char == "\n":
                        line += 1
                    if escaped:
                        escaped = False
                    elif regex_char == "\\":
                        escaped = True
                    elif regex_char == "[":
                        in_class = True
                    elif regex_char == "]":
                        in_class = False
                    elif regex_char == "/" and not in_class:
                        index += 1
                        while index < length and source[index].isalpha():
                            index += 1
                        break
                    index += 1
                continue
        if char not in {"'", '"', "`"}:
            if char == "\n":
                line += 1
            index += 1
            continue

        quote = char
        literal_line = line
        index += 1
        value = []
        escaped = False
        while index < length:
            char = source[index]
            if char == "\n":
                line += 1
            if escaped:
                value.append(char)
                escaped = False
            elif char == "\\":
                value.append(char)
                escaped = True
            elif char == quote:
                index += 1
                break
            else:
                value.append(char)
            index += 1
        yield "".join(value), literal_line


def is_allowed_technical_js_literal(value):
    stripped = value.strip()
    if stripped in {"总控台.app", "总控台.exe"}:
        return True
    return is_filesystem_literal(stripped) and not re.search(r"[。！？；]", stripped)


class FrontendI18nMarkupTests(unittest.TestCase):
    def test_language_toggle_is_before_side_stats_and_defaults_to_chinese(self):
        parser = parse_markup()
        toggle = parser.by_id.get("languageToggle")
        stats = parser.by_id.get("sideStats")
        self.assertIsNotNone(toggle)
        self.assertIsNotNone(stats)
        self.assertIs(toggle.parent, stats.parent)
        self.assertIn("topbar-right", toggle.parent.attrs.get("class", "").split())
        self.assertLess(
            toggle.parent.children.index(toggle),
            toggle.parent.children.index(stats),
        )
        self.assertEqual(toggle.attrs.get("role"), "group")

        options = [
            node for node in toggle.descendants()
            if node.attrs.get("data-language") in {"en", "zh"}
        ]
        self.assertEqual(
            [node.attrs.get("data-language") for node in options],
            ["en", "zh"],
        )
        self.assertEqual([node.combined_text().strip() for node in options], ["EN", "中"])
        pressed = {
            node.attrs["data-language"]: node.attrs.get("aria-pressed")
            for node in options
        }
        self.assertEqual(pressed, {"en": "false", "zh": "true"})
        self.assertIn("active", options[1].attrs.get("class", "").split())

        html_node = next(node for node in parser.nodes if node.tag == "html")
        self.assertEqual(html_node.attrs.get("lang"), "zh-CN")

    def test_static_chinese_text_and_ui_attributes_are_i18n_annotated(self):
        parser = parse_markup()
        missing_text = []
        for node, text, line in parser.language_text:
            cleaned = " ".join(text.split())
            if not cleaned or is_filesystem_literal(cleaned):
                continue
            if not has_text_translation(node):
                missing_text.append(f"line {line}: {cleaned[:70]}")
        self.assertEqual(
            missing_text,
            [],
            "Chinese static UI text lacks data-i18n:\n" + "\n".join(missing_text),
        )

        missing_attributes = []
        for node in parser.nodes:
            for attribute in TRANSLATABLE_ATTRIBUTES:
                value = node.attrs.get(attribute)
                if value is None or attribute_is_language_neutral(value):
                    continue
                if not attribute_translation_key(node, attribute):
                    missing_attributes.append(
                        f"line {node.line}: <{node.tag}> {attribute}={value!r}"
                    )
        self.assertEqual(
            missing_attributes,
            [],
            "UI attributes lack data-i18n-* keys:\n" + "\n".join(missing_attributes),
        )

        keys = []
        for node in parser.nodes:
            keys.extend(
                value for name, value in node.attrs.items()
                if name == "data-i18n" or name.startswith("data-i18n-")
                if name != "data-i18n-attrs"
            )
        self.assertGreaterEqual(len(set(keys)), 50)
        for key in keys:
            self.assertRegex(key, r"^[a-z][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)+$")

    def test_text_translation_markers_only_target_structure_safe_leaves(self):
        parser = parse_markup()
        unsafe = []
        for node in parser.nodes:
            key = node.attrs.get("data-i18n")
            if not key:
                continue
            if node.tag in VOID_ELEMENTS or node.children:
                child_tags = ", ".join(child.tag for child in node.children)
                unsafe.append(
                    f"line {node.line}: <{node.tag}> {key!r} children=[{child_tags}]"
                )
        self.assertEqual(
            unsafe,
            [],
            "data-i18n writes textContent and must only annotate pure-text "
            "leaf elements; use data-i18n-* on containers and put text keys "
            "on a child span:\n" + "\n".join(unsafe),
        )

    def test_meta_description_translates_its_content_attribute(self):
        parser = parse_markup()
        descriptions = [
            node for node in parser.nodes
            if node.tag == "meta" and node.attrs.get("name") == "description"
        ]
        self.assertEqual(len(descriptions), 1)
        description = descriptions[0]
        self.assertEqual(
            description.attrs.get("data-i18n-content"),
            "app.description",
        )
        self.assertNotIn("data-i18n", description.attrs)
        self.assertTrue(description.attrs.get("content"))

    def test_language_toggle_has_slider_focus_and_motion_contracts(self):
        css = (ROOT / "static" / "base.css").read_text(encoding="utf-8")
        self.assertIn(".language-toggle", css)
        self.assertIn(".language-toggle::before", css)
        self.assertIn('.language-toggle[data-language="en"]::before', css)
        self.assertIn('.language-option[data-language="en"][aria-pressed="true"]', css)
        self.assertIn(".language-option:focus-visible", css)
        self.assertIn("prefers-reduced-motion", css)


class FrontendI18nJavaScriptContractTests(unittest.TestCase):
    def test_all_ui_modules_use_the_shared_dynamic_translation_api(self):
        modules = [
            ROOT / "static" / "app.js",
            ROOT / "static" / "js" / "core.js",
            ROOT / "static" / "js" / "launchpad.js",
            ROOT / "static" / "js" / "overlays.js",
            ROOT / "static" / "js" / "services.js",
            ROOT / "static" / "js" / "widgets.js",
        ]
        for path in modules:
            with self.subTest(module=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertRegex(source, r"import\s*\{[^}]*\bt\b[^}]*\}\s*from\s*['\"](?:\./)?(?:js/)?i18n\.js['\"]")
                self.assertRegex(source, r"\bt\s*\(")

    def test_ui_modules_have_no_untranslated_chinese_string_literals(self):
        modules = [
            ROOT / "static" / "app.js",
            *sorted((ROOT / "static" / "js").glob("*.js")),
        ]
        violations = []
        for path in modules:
            if path.name in {"i18n.js", "icons.js"} or path.name == "ports.js":
                continue
            source = path.read_text(encoding="utf-8")
            for value, line in javascript_string_literals(source):
                if not LANGUAGE_TEXT_RE.search(value):
                    continue
                if is_allowed_technical_js_literal(value):
                    continue
                compact = " ".join(value.split())
                violations.append(
                    f"{path.relative_to(ROOT)}:{line}: {compact[:90]}"
                )
        self.assertEqual(
            violations,
            [],
            "Move user-facing Chinese literals into i18n.js and call t(key):\n"
            + "\n".join(violations[:80]),
        )

    def test_language_change_is_local_only_and_rerenders_cached_state(self):
        i18n = I18N_PATH.read_text(encoding="utf-8")
        for exported in (
            "t", "getLanguage", "setLanguage", "toggleLanguage",
            "subscribeLanguage", "applyStaticTranslations",
        ):
            self.assertRegex(
                i18n,
                rf"(?:export\s+(?:function|const|let|class)\s+{exported}\b|"
                rf"export\s*\{{[^}}]*\b{exported}\b)",
            )
        self.assertIn("console-language", i18n)
        self.assertNotRegex(i18n, r"(?:fetch\s*\(|/api/|\bpost\s*\(|\breq\s*\()")
        self.assertNotRegex(i18n, r"from\s*['\"].*(?:core|server)")

        app = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        init_start = app.index("function initLanguageToggle")
        change_start = app.index("function handleLanguageChange")
        next_function = app.index("function browserPlatformFallback", change_start)
        init_block = app[init_start:change_start]
        change_block = app[change_start:next_function]

        self.assertIn("setLanguage(button.dataset.language)", init_block)
        self.assertNotRegex(init_block, r"(?:fetch\s*\(|\bpost\s*\(|\bpoll\s*\(|/api/)")
        self.assertIn("applyStaticTranslations(document)", change_block)
        self.assertIn("if (state.data) render()", change_block)
        self.assertNotRegex(change_block, r"(?:fetch\s*\(|\bpost\s*\(|\bpoll\s*\(|/api/)")
        self.assertNotRegex(change_block, r"state\.[A-Za-z_$][\w$]*\s*=")
        self.assertRegex(app, r"subscribeLanguage\s*\(\s*handleLanguageChange\s*\)")


if __name__ == "__main__":
    unittest.main()
