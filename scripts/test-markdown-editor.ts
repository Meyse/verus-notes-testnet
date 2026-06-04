import assert from "node:assert/strict";
import {
  markdownToEditorHtml,
  normalizeLinkHref,
  shouldEmitEditorChange
} from "../src/lib/notes/markdownEditor";

const httpsLink = markdownToEditorHtml("https://www.verus.io");
assert.match(httpsLink, /<a href="https:\/\/www\.verus\.io\/" rel="noopener noreferrer" data-autolink="true">https:\/\/www\.verus\.io<\/a>/);

const wwwLink = markdownToEditorHtml("www.verus.io");
assert.match(wwwLink, /<a href="https:\/\/www\.verus\.io\/" rel="noopener noreferrer" data-autolink="true">www\.verus\.io<\/a>/);

const markdownLink = markdownToEditorHtml("[Verus](https://www.verus.io)");
assert.match(markdownLink, /<a href="https:\/\/www\.verus\.io\/" rel="noopener noreferrer">Verus<\/a>/);

const inlineCode = markdownToEditorHtml("`https://www.verus.io`");
assert.equal(inlineCode, "<p><code>https://www.verus.io</code></p>");

const codeBlock = markdownToEditorHtml("```\nhttps://www.verus.io\n```");
assert.equal(codeBlock, '<pre><code>https://www.verus.io</code></pre><p data-code-exit-paragraph="true"><br></p>');

const followedCodeBlock = markdownToEditorHtml("```\npnpm check\n```\n\nAfter");
assert.equal(followedCodeBlock, "<pre><code>pnpm check</code></pre><p>After</p>");

const codeBlockBlankLine = markdownToEditorHtml("```\nline one\n\nline three\n```");
assert.equal(codeBlockBlankLine, '<pre><code>line one\n\nline three</code></pre><p data-code-exit-paragraph="true"><br></p>');

const unsafeScheme = markdownToEditorHtml("[bad](javascript:alert(1))");
assert.equal(unsafeScheme, "<p>[bad](javascript:alert(1))</p>");

const userinfoUrl = markdownToEditorHtml("[bad](https://user@example.com/private)");
assert.equal(userinfoUrl, "<p>[bad](https://user@example.com/private)</p>");

assert.equal(normalizeLinkHref("www.verus.io"), "https://www.verus.io/");
assert.equal(normalizeLinkHref("https://www.verus.io"), "https://www.verus.io/");
assert.equal(normalizeLinkHref("javascript:alert(1)"), null);
assert.equal(normalizeLinkHref("file:///tmp/private-note"), null);
assert.equal(normalizeLinkHref("https://user@example.com/private"), null);
assert.equal(normalizeLinkHref("https://user:pass@example.com/private"), null);

assert.equal(shouldEmitEditorChange("Body", "Body"), false);
assert.equal(shouldEmitEditorChange("See www.verus.io", "See [Verus](https://www.verus.io/)"), true);
