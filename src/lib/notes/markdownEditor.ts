const BLOCK_TAGS = new Set(["DIV", "H1", "H2", "P", "PRE"]);
const CODE_BLOCK_EXIT_PARAGRAPH_HTML = '<p data-code-exit-paragraph="true"><br></p>';
const SAFE_LINK_PROTOCOLS = new Set(["http:", "https:"]);
const BARE_LINK_CANDIDATE_PATTERN = /(?:https?:\/\/|www\.)[^\s<>"']+/gi;
const LINK_BOUNDARY_PATTERN = /[\s([{<"']/;
const TRAILING_LINK_PUNCTUATION_PATTERN = /[.,!?;:]$/;

export type MarkdownEditorBlockKind = "body" | "h1" | "h2" | "codeBlock";

export type MarkdownEditorToolbarState = {
  activeBlock: MarkdownEditorBlockKind;
  activeBold: boolean;
  activeItalic: boolean;
  activeCode: boolean;
  setBlock: (kind: Exclude<MarkdownEditorBlockKind, "codeBlock">) => void;
  toggleBold: () => void;
  toggleItalic: () => void;
  toggleInlineCode: () => void;
  toggleCodeBlock: () => void;
};

export function shouldEmitEditorChange(currentMarkdown: string, nextMarkdown: string) {
  return nextMarkdown !== currentMarkdown;
}

type DocumentWithCaretPoint = Document & {
  caretPositionFromPoint?: (x: number, y: number) => { offsetNode: Node; offset: number } | null;
  caretRangeFromPoint?: (x: number, y: number) => Range | null;
};

export function getCaretRangeFromPoint(x: number, y: number) {
  const pointDocument = document as DocumentWithCaretPoint;
  const position = pointDocument.caretPositionFromPoint?.(x, y);
  if (position) {
    const range = document.createRange();
    range.setStart(position.offsetNode, position.offset);
    range.collapse(true);
    return range;
  }

  return pointDocument.caretRangeFromPoint?.(x, y) ?? null;
}

export function selectRange(range: Range) {
  const selection = window.getSelection();
  if (!selection) return;
  selection.removeAllRanges();
  selection.addRange(range);
}

export function placeCursorAtNearestEditorBlockEdge(root: HTMLElement, clientY: number, preferStart: boolean) {
  const blocks = Array.from(root.querySelectorAll<HTMLElement>("p, h1, h2, pre"));
  const block = getNearestEditorBlock(blocks, clientY) ?? root;
  const target = block.tagName === "PRE" ? (block.querySelector<HTMLElement>("code") ?? block) : block;
  const range = document.createRange();
  range.selectNodeContents(target);
  range.collapse(preferStart);
  selectRange(range);
}

function getNearestEditorBlock(blocks: HTMLElement[], clientY: number) {
  let nearestBlock: HTMLElement | null = null;
  let nearestDistance = Number.POSITIVE_INFINITY;

  for (const block of blocks) {
    const rect = block.getBoundingClientRect();
    const distance =
      clientY >= rect.top && clientY <= rect.bottom
        ? 0
        : Math.min(Math.abs(clientY - rect.top), Math.abs(clientY - rect.bottom));
    if (distance < nearestDistance) {
      nearestBlock = block;
      nearestDistance = distance;
    }
  }

  return nearestBlock;
}

export function markdownToEditorHtml(markdown: string) {
  const normalized = markdown.replace(/\r\n?/g, "\n");
  const lines = normalized.split("\n");
  const blocks: string[] = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index] ?? "";

    if (line.trim() === "") {
      index += 1;
      continue;
    }

    const fenceMatch = line.match(/^```([A-Za-z0-9_-]+)?\s*$/);
    if (fenceMatch) {
      const codeLines: string[] = [];
      index += 1;

      while (index < lines.length && !/^```\s*$/.test(lines[index] ?? "")) {
        codeLines.push(lines[index] ?? "");
        index += 1;
      }

      if (index < lines.length) index += 1;
      const language = fenceMatch[1] ?? "";
      const languageAttrs = language
        ? ` data-language="${escapeAttribute(language)}" class="language-${escapeAttribute(language)}"`
        : "";
      blocks.push(`<pre><code${languageAttrs}>${escapeHtml(codeLines.join("\n"))}</code></pre>`);
      continue;
    }

    if (line.startsWith("# ")) {
      blocks.push(`<h1>${renderInlineMarkdown(line.slice(2))}</h1>`);
      index += 1;
      continue;
    }

    if (line.startsWith("## ")) {
      blocks.push(`<h2>${renderInlineMarkdown(line.slice(3))}</h2>`);
      index += 1;
      continue;
    }

    const paragraphLines: string[] = [];
    while (index < lines.length) {
      const paragraphLine = lines[index] ?? "";
      if (paragraphLine.trim() === "" || paragraphLine.startsWith("# ") || paragraphLine.startsWith("## ") || /^```/.test(paragraphLine)) {
        break;
      }
      paragraphLines.push(paragraphLine);
      index += 1;
    }

    blocks.push(`<p>${paragraphLines.map(renderInlineMarkdown).join("<br>")}</p>`);
  }

  if (blocks.length === 0) return "<p><br></p>";

  const html = blocks.join("");
  return blocks[blocks.length - 1]?.startsWith("<pre") ? `${html}${CODE_BLOCK_EXIT_PARAGRAPH_HTML}` : html;
}

export function editorElementToMarkdown(root: HTMLElement) {
  const blocks = Array.from(root.childNodes)
    .map((node) => blockNodeToMarkdown(node))
    .filter((block): block is string => block !== null);

  while (blocks[blocks.length - 1] === "") {
    blocks.pop();
  }

  return blocks.join("\n\n");
}

export function autolinkEditorLinks(root: HTMLElement) {
  const savedSelection = saveEditorSelection(root);
  const textNodes: Text[] = [];
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      if (!shouldAutolinkTextNode(node)) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    }
  });

  while (walker.nextNode()) {
    textNodes.push(walker.currentNode as Text);
  }

  const changed = textNodes.reduce((didChange, node) => linkifyTextNode(node) || didChange, false);
  if (changed && savedSelection) restoreEditorSelection(root, savedSelection);
  return changed;
}

export function normalizeLinkHref(value: string) {
  const trimmed = value.trim();
  if (!trimmed || /[\u0000-\u001F\u007F]/.test(trimmed)) return null;

  const candidate = trimmed.match(/^www\./i) ? `https://${trimmed}` : trimmed;
  try {
    const url = new URL(candidate);
    if (
      !SAFE_LINK_PROTOCOLS.has(url.protocol) ||
      !url.hostname ||
      url.username ||
      url.password
    ) return null;
    return url.href;
  } catch {
    return null;
  }
}

function blockNodeToMarkdown(node: ChildNode): string | null {
  if (node.nodeType === Node.TEXT_NODE) {
    const text = escapeMarkdownText(node.textContent ?? "");
    return text.trim() ? text : null;
  }

  if (!(node instanceof HTMLElement)) return null;

  const tagName = node.tagName;
  if (tagName === "BR") return "";
  if (tagName === "H1") return `# ${inlineNodeToMarkdown(node).trim()}`;
  if (tagName === "H2") return `## ${inlineNodeToMarkdown(node).trim()}`;

  if (tagName === "PRE") {
    const codeElement = node.querySelector("code");
    const code = codeElement?.textContent ?? node.textContent ?? "";
    const language = codeElement?.dataset.language?.trim() ?? "";
    const fence = codeFenceFor(code);
    return `${fence}${language}\n${code}\n${fence}`;
  }

  if (BLOCK_TAGS.has(tagName)) {
    const inline = inlineNodeToMarkdown(node).trimEnd();
    return inline.trim() ? inline : "";
  }

  const fallback = inlineNodeToMarkdown(node).trimEnd();
  return fallback.trim() ? fallback : null;
}

function inlineNodeToMarkdown(node: Node): string {
  if (node.nodeType === Node.TEXT_NODE) {
    return escapeMarkdownText(node.textContent ?? "");
  }

  if (!(node instanceof HTMLElement)) return "";

  if (node.tagName === "BR") return "\n";
  if (node.tagName === "CODE" && node.closest("pre")) return node.textContent ?? "";
  if (node.tagName === "CODE") return wrapInlineCode(node.textContent ?? "");
  if (node.tagName === "A") {
    const href = normalizeLinkHref(node.getAttribute("href") ?? "");
    const content = Array.from(node.childNodes).map(inlineNodeToMarkdown).join("");
    if (!href) return content;

    const text = node.textContent ?? "";
    if (node.dataset.autolink === "true" && normalizeLinkHref(text) === href) {
      return escapeMarkdownText(text);
    }

    return `[${escapeMarkdownLinkLabel(content)}](${escapeMarkdownLinkDestination(href)})`;
  }

  const content = Array.from(node.childNodes).map(inlineNodeToMarkdown).join("");
  const fontWeight = node.style.fontWeight;
  const isBold = node.tagName === "B" || node.tagName === "STRONG" || fontWeight === "bold" || Number(fontWeight) >= 600;
  const isItalic = node.tagName === "I" || node.tagName === "EM" || node.style.fontStyle === "italic";

  if (isBold && isItalic) return `***${content}***`;
  if (isBold) return `**${content}**`;
  if (isItalic) return `*${content}*`;
  return content;
}

function renderInlineMarkdown(value: string) {
  let output = "";
  let index = 0;

  while (index < value.length) {
    if (value[index] === "\\" && index + 1 < value.length) {
      output += escapeHtml(value[index + 1] ?? "");
      index += 2;
      continue;
    }

    if (value[index] === "`") {
      const end = value.indexOf("`", index + 1);
      if (end > index) {
        output += `<code>${escapeHtml(value.slice(index + 1, end))}</code>`;
        index = end + 1;
        continue;
      }
    }

    const markdownLink = parseMarkdownLinkAt(value, index);
    if (markdownLink) {
      output += markdownLink.html;
      index = markdownLink.endIndex;
      continue;
    }

    const bareLink = getBareLinkAt(value, index);
    if (bareLink) {
      output += renderAnchorHtml(bareLink.href, escapeHtml(bareLink.text), true);
      output += escapeHtml(bareLink.trailing);
      index = bareLink.endIndex;
      continue;
    }

    if (value.startsWith("***", index)) {
      const end = value.indexOf("***", index + 3);
      if (end > index) {
        output += `<strong><em>${escapeHtml(value.slice(index + 3, end))}</em></strong>`;
        index = end + 3;
        continue;
      }
    }

    if (value.startsWith("**", index)) {
      const end = value.indexOf("**", index + 2);
      if (end > index) {
        output += `<strong>${escapeHtml(value.slice(index + 2, end))}</strong>`;
        index = end + 2;
        continue;
      }
    }

    if (value[index] === "*") {
      const end = value.indexOf("*", index + 1);
      if (end > index) {
        output += `<em>${escapeHtml(value.slice(index + 1, end))}</em>`;
        index = end + 1;
        continue;
      }
    }

    output += escapeHtml(value[index] ?? "");
    index += 1;
  }

  return output;
}

type SavedEditorSelection = {
  end: number;
  start: number;
};

type BareLinkMatch = {
  endIndex: number;
  href: string;
  startIndex: number;
  text: string;
  trailing: string;
};

function parseMarkdownLinkAt(value: string, index: number) {
  if (value[index] !== "[") return null;

  const labelEnd = findUnescapedCharacter(value, "]", index + 1);
  if (labelEnd < 0 || value[labelEnd + 1] !== "(") return null;

  const destinationEnd = findUnescapedCharacter(value, ")", labelEnd + 2);
  if (destinationEnd < 0) return null;

  const href = normalizeLinkHref(value.slice(labelEnd + 2, destinationEnd));
  if (!href) return null;

  const label = value.slice(index + 1, labelEnd);
  return {
    endIndex: destinationEnd + 1,
    html: renderAnchorHtml(href, renderInlineMarkdown(label), false)
  };
}

function findUnescapedCharacter(value: string, character: string, startIndex: number) {
  for (let index = startIndex; index < value.length; index += 1) {
    if (value[index] === character && !isEscaped(value, index)) return index;
  }
  return -1;
}

function isEscaped(value: string, index: number) {
  let slashCount = 0;
  for (let cursor = index - 1; cursor >= 0 && value[cursor] === "\\"; cursor -= 1) {
    slashCount += 1;
  }
  return slashCount % 2 === 1;
}

function getBareLinkAt(value: string, index: number): BareLinkMatch | null {
  if (!hasLinkBoundaryBefore(value, index)) return null;

  const match = value.slice(index).match(/^(?:https?:\/\/|www\.)[^\s<>"']+/i);
  if (!match) return null;

  return buildBareLinkMatch(value, index, match[0]);
}

function findNextBareLink(value: string, startIndex: number): BareLinkMatch | null {
  const pattern = new RegExp(BARE_LINK_CANDIDATE_PATTERN);
  pattern.lastIndex = startIndex;

  let match: RegExpExecArray | null;
  while ((match = pattern.exec(value)) !== null) {
    if (!hasLinkBoundaryBefore(value, match.index)) continue;

    const link = buildBareLinkMatch(value, match.index, match[0]);
    if (link) return link;
  }

  return null;
}

function buildBareLinkMatch(value: string, startIndex: number, rawCandidate: string): BareLinkMatch | null {
  const { linkText, trailing } = splitTrailingLinkPunctuation(rawCandidate);
  const href = normalizeLinkHref(linkText);
  if (!href) return null;

  return {
    endIndex: startIndex + rawCandidate.length,
    href,
    startIndex,
    text: linkText,
    trailing
  };
}

function hasLinkBoundaryBefore(value: string, index: number) {
  return index === 0 || LINK_BOUNDARY_PATTERN.test(value[index - 1] ?? "");
}

function splitTrailingLinkPunctuation(value: string) {
  let linkText = value;
  let trailing = "";

  while (linkText && TRAILING_LINK_PUNCTUATION_PATTERN.test(linkText)) {
    trailing = `${linkText.slice(-1)}${trailing}`;
    linkText = linkText.slice(0, -1);
  }

  while (linkText && shouldTrimClosingLinkPunctuation(linkText)) {
    trailing = `${linkText.slice(-1)}${trailing}`;
    linkText = linkText.slice(0, -1);
  }

  return { linkText, trailing };
}

function shouldTrimClosingLinkPunctuation(value: string) {
  const close = value.slice(-1);
  const open = close === ")" ? "(" : close === "]" ? "[" : close === "}" ? "{" : null;
  if (!open) return false;
  return countCharacters(value, close) > countCharacters(value, open);
}

function countCharacters(value: string, character: string) {
  return Array.from(value).filter((candidate) => candidate === character).length;
}

function shouldAutolinkTextNode(node: Node) {
  const text = node.textContent ?? "";
  if (!/(?:https?:\/\/|www\.)/i.test(text)) return false;

  const parent = node.parentNode instanceof HTMLElement ? node.parentNode : null;
  if (!parent || parent.closest("a, code, pre")) return false;

  return true;
}

function linkifyTextNode(node: Text) {
  const text = node.textContent ?? "";
  const firstLink = findNextBareLink(text, 0);
  if (!firstLink) return false;

  const fragment = document.createDocumentFragment();
  let index = 0;
  let nextLink: BareLinkMatch | null = firstLink;

  while (nextLink) {
    if (nextLink.startIndex > index) {
      fragment.append(document.createTextNode(text.slice(index, nextLink.startIndex)));
    }

    const anchor = document.createElement("a");
    anchor.setAttribute("href", nextLink.href);
    anchor.setAttribute("rel", "noopener noreferrer");
    anchor.dataset.autolink = "true";
    anchor.textContent = nextLink.text;
    fragment.append(anchor);

    if (nextLink.trailing) {
      fragment.append(document.createTextNode(nextLink.trailing));
    }

    index = nextLink.endIndex;
    nextLink = findNextBareLink(text, index);
  }

  if (index < text.length) {
    fragment.append(document.createTextNode(text.slice(index)));
  }

  node.replaceWith(fragment);
  return true;
}

function saveEditorSelection(root: HTMLElement): SavedEditorSelection | null {
  const selection = window.getSelection();
  if (!selection || selection.rangeCount === 0) return null;

  const range = selection.getRangeAt(0);
  if (!root.contains(range.startContainer) || !root.contains(range.endContainer)) return null;

  return {
    end: getTextOffset(root, range.endContainer, range.endOffset),
    start: getTextOffset(root, range.startContainer, range.startOffset)
  };
}

function restoreEditorSelection(root: HTMLElement, selection: SavedEditorSelection) {
  const range = document.createRange();
  const start = getTextPosition(root, selection.start);
  const end = getTextPosition(root, selection.end);
  range.setStart(start.node, start.offset);
  range.setEnd(end.node, end.offset);
  selectRange(range);
}

function getTextOffset(root: Node, target: Node, targetOffset: number) {
  let offset = 0;
  let found = false;

  function visit(node: Node) {
    if (found) return;

    if (node === target) {
      offset += getOffsetInsideNode(node, targetOffset);
      found = true;
      return;
    }

    if (node.nodeType === Node.TEXT_NODE) {
      offset += (node.textContent ?? "").length;
      return;
    }

    node.childNodes.forEach(visit);
  }

  visit(root);
  return offset;
}

function getOffsetInsideNode(node: Node, targetOffset: number) {
  if (node.nodeType === Node.TEXT_NODE) {
    return Math.min(targetOffset, (node.textContent ?? "").length);
  }

  let offset = 0;
  const limit = Math.min(targetOffset, node.childNodes.length);
  for (let index = 0; index < limit; index += 1) {
    offset += node.childNodes[index]?.textContent?.length ?? 0;
  }
  return offset;
}

function getTextPosition(root: Node, targetOffset: number) {
  let remaining = Math.max(0, targetOffset);
  let lastTextNode: Text | null = null;
  let lastBoundary: { node: Node; offset: number } | null = null;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);

  while (walker.nextNode()) {
    const textNode = walker.currentNode as Text;
    const length = (textNode.textContent ?? "").length;
    lastTextNode = textNode;

    if (remaining < length) {
      return { node: textNode, offset: remaining };
    }

    if (remaining === length) {
      lastBoundary = getPositionAfterTextNode(textNode, root);
      remaining = 0;
      continue;
    }

    remaining -= length;
  }

  if (lastBoundary) return lastBoundary;

  if (lastTextNode) {
    return { node: lastTextNode, offset: (lastTextNode.textContent ?? "").length };
  }

  return { node: root, offset: root.childNodes.length };
}

function getPositionAfterTextNode(textNode: Text, root: Node) {
  let node: Node = textNode;

  while (node.parentNode && node.parentNode !== root && isInlineFormattingElement(node.parentNode)) {
    node = node.parentNode;
  }

  const parent = node.parentNode;
  if (!parent) return { node: root, offset: root.childNodes.length };

  return { node: parent, offset: Array.prototype.indexOf.call(parent.childNodes, node) + 1 };
}

function isInlineFormattingElement(node: Node): node is HTMLElement {
  return node instanceof HTMLElement && ["A", "B", "CODE", "EM", "I", "STRONG"].includes(node.tagName);
}

function renderAnchorHtml(href: string, content: string, autolink: boolean) {
  const autolinkAttribute = autolink ? ' data-autolink="true"' : "";
  return `<a href="${escapeHtmlAttribute(href)}" rel="noopener noreferrer"${autolinkAttribute}>${content}</a>`;
}

function escapeHtml(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function escapeAttribute(value: string) {
  return escapeHtml(value.replace(/[^A-Za-z0-9_-]/g, ""));
}

function escapeHtmlAttribute(value: string) {
  return escapeHtml(value);
}

function escapeMarkdownText(value: string) {
  return value.replace(/\u00a0/g, " ").replace(/([\\`*])/g, "\\$1");
}

function escapeMarkdownLinkLabel(value: string) {
  return value.replace(/([\[\]])/g, "\\$1");
}

function escapeMarkdownLinkDestination(value: string) {
  return value.replace(/\)/g, "%29");
}

function wrapInlineCode(value: string) {
  const longestRun = Math.max(0, ...Array.from(value.matchAll(/`+/g), (match) => match[0].length));
  const fence = "`".repeat(Math.max(1, longestRun + 1));
  return `${fence}${value}${fence}`;
}

function codeFenceFor(value: string) {
  const longestRun = Math.max(0, ...Array.from(value.matchAll(/`+/g), (match) => match[0].length));
  return "`".repeat(Math.max(3, longestRun + 1));
}
