<script lang="ts">
  import { invoke, isTauri } from "@tauri-apps/api/core";
  import { Check, Copy } from "@lucide/svelte";
  import { onDestroy, onMount } from "svelte";
  import {
    autolinkEditorLinks,
    editorElementToMarkdown,
    getCaretRangeFromPoint,
    markdownToEditorHtml,
    normalizeLinkHref,
    placeCursorAtNearestEditorBlockEdge,
    selectRange,
    shouldEmitEditorChange,
    type MarkdownEditorBlockKind,
    type MarkdownEditorToolbarState
  } from "$lib/notes/markdownEditor";

  type Props = {
    value: string;
    onChange: (value: string) => void;
    onEditorElementChange?: (element: HTMLElement | null) => void;
    onToolbarChange?: (state: MarkdownEditorToolbarState) => void;
  };

  let { value, onChange, onEditorElementChange, onToolbarChange }: Props = $props();

  let editorShell = $state<HTMLElement | null>(null);
  let editorElement = $state<HTMLElement | null>(null);
  let activeCodeBlock = $state<HTMLElement | null>(null);
  let hoveredCodeBlock = $state<HTMLElement | null>(null);
  let activeBlock = $state<MarkdownEditorBlockKind>("body");
  let activeBold = $state(false);
  let activeItalic = $state(false);
  let activeCode = $state(false);
  let codeCopyButtonStyle = $state("");
  let copied = $state(false);
  let renderedMarkdown = "";
  let copiedTimer: number | null = null;

  onMount(() => {
    document.addEventListener("selectionchange", refreshToolbarState);
    document.addEventListener("scroll", updateCodeCopyButton, true);
    window.addEventListener("resize", updateCodeCopyButton);
  });

  onDestroy(() => {
    document.removeEventListener("selectionchange", refreshToolbarState);
    document.removeEventListener("scroll", updateCodeCopyButton, true);
    window.removeEventListener("resize", updateCodeCopyButton);
    if (copiedTimer !== null) window.clearTimeout(copiedTimer);
    onEditorElementChange?.(null);
  });

  $effect(() => {
    if (!editorElement || value === renderedMarkdown) return;
    renderMarkdown(value);
  });

  $effect(() => {
    onEditorElementChange?.(editorElement);
  });

  $effect(() => {
    const shell = editorShell;
    if (!shell) return;

    shell.addEventListener("mouseleave", clearHoveredCodeBlock);
    shell.addEventListener("mousedown", handleEditorShellMousedown);
    return () => {
      shell.removeEventListener("mouseleave", clearHoveredCodeBlock);
      shell.removeEventListener("mousedown", handleEditorShellMousedown);
    };
  });

  function renderMarkdown(markdown: string) {
    if (!editorElement) return;
    editorElement.innerHTML = markdownToEditorHtml(markdown);
    hoveredCodeBlock = null;
    renderedMarkdown = markdown;
    refreshToolbarState();
  }

  function emitChange(options: { autolink?: boolean } = {}) {
    if (!editorElement) return;
    if (options.autolink) {
      autolinkEditorLinks(editorElement);
    }
    const nextMarkdown = editorElementToMarkdown(editorElement);
    renderedMarkdown = nextMarkdown;
    if (!shouldEmitEditorChange(value, nextMarkdown)) {
      refreshToolbarState();
      return;
    }
    onChange(nextMarkdown);
    refreshToolbarState();
  }

  function handleInput(event: Event) {
    emitChange({ autolink: shouldAutolinkAfterInput(event) });
  }

  function handlePaste(event: ClipboardEvent) {
    event.preventDefault();
    const text = event.clipboardData?.getData("text/plain") ?? "";
    insertPlainText(text);
    emitChange({ autolink: true });
  }

  function handleKeydown(event: KeyboardEvent) {
    if (event.key === "Enter") {
      if (getActiveCodeBlock()) {
        event.preventDefault();
        if (event.metaKey || event.ctrlKey) {
          exitCodeBlock();
        } else {
          insertCodeBlockText("\n");
        }
        return;
      }

      if (!event.shiftKey && exitHeadingBlock()) {
        event.preventDefault();
        return;
      }
    }

    if (event.key === "ArrowDown" && exitCodeBlockOnArrowDown(event)) {
      event.preventDefault();
      return;
    }

    const commandKey = event.metaKey || event.ctrlKey;
    if (!commandKey || event.altKey) return;

    const key = event.key.toLowerCase();
    if (key === "b") {
      event.preventDefault();
      toggleNativeInline("bold");
    } else if (key === "i") {
      event.preventDefault();
      toggleNativeInline("italic");
    } else if (key === "e") {
      event.preventDefault();
      toggleInlineCode();
    }
  }

  function handleBeforeInput(event: InputEvent) {
    if (event.inputType === "insertParagraph" || event.inputType === "insertLineBreak") {
      if (getActiveCodeBlock()) {
        event.preventDefault();
        insertCodeBlockText("\n");
        return;
      }
    }

    if (event.inputType !== "insertParagraph") return;

    if (exitHeadingBlock()) {
      event.preventDefault();
      return;
    }

    if (editorElement) autolinkEditorLinks(editorElement);
  }

  function shouldAutolinkAfterInput(event: Event) {
    if (!(event instanceof InputEvent)) return false;
    if (event.inputType === "insertFromPaste" || event.inputType === "insertFromDrop") return true;
    if (event.inputType !== "insertText") return false;

    const data = event.data ?? "";
    return /\s/.test(data);
  }

  async function handleEditorClick(event: MouseEvent) {
    const target = event.target instanceof Element ? event.target : null;
    const anchor = target?.closest<HTMLAnchorElement>("a[href]");
    if (!anchor || !editorElement?.contains(anchor)) return;

    const href = normalizeLinkHref(anchor.getAttribute("href") ?? "");
    if (!href) return;

    event.preventDefault();
    event.stopPropagation();
    if (!event.isTrusted || event.button !== 0) return;

    try {
      if (isTauri()) {
        await invoke("open_external_link", { input: { href } });
      } else {
        window.open(href, "_blank", "noopener,noreferrer");
      }
    } catch {
      // Link text can be private note content, so avoid logging the URL.
    }
  }

  function setBlock(kind: Exclude<MarkdownEditorBlockKind, "codeBlock">) {
    const tagName = kind === "h1" ? "h1" : kind === "h2" ? "h2" : "p";
    const block = getCurrentBlock();
    if (!block) return;

    const codeExitParagraph = block.tagName === "PRE" ? getGeneratedCodeExitParagraph(block.nextElementSibling) : null;
    const replacement = document.createElement(tagName);
    if (block.tagName === "PRE") {
      replacement.textContent = block.textContent ?? "";
    } else {
      replacement.innerHTML = block.innerHTML || "<br>";
    }

    block.replaceWith(replacement);
    codeExitParagraph?.remove();
    placeCursorEnd(replacement);
    emitChange();
  }

  function toggleNativeInline(command: "bold" | "italic") {
    editorElement?.focus();
    document.execCommand(command);
    emitChange();
  }

  function toggleInlineCode() {
    const range = getSelectionRange();
    if (!range) return;

    const codeAncestor = findAncestor(range.startContainer, ["CODE"]);
    if (codeAncestor && codeAncestor.parentElement?.tagName !== "PRE") {
      unwrapElement(codeAncestor);
      emitChange();
      return;
    }

    if (!range.collapsed && getBlockForNode(range.startContainer) !== getBlockForNode(range.endContainer)) {
      return;
    }

    const codeElement = document.createElement("code");
    if (range.collapsed) {
      codeElement.textContent = "code";
      range.insertNode(codeElement);
      selectElementContents(codeElement);
    } else {
      codeElement.appendChild(range.extractContents());
      range.insertNode(codeElement);
      selectElementContents(codeElement);
    }

    emitChange();
  }

  function toggleCodeBlock() {
    const block = getCurrentBlock();
    if (!block) return;

    if (block.tagName === "PRE") {
      const codeExitParagraph = getGeneratedCodeExitParagraph(block.nextElementSibling);
      const paragraph = document.createElement("p");
      paragraph.textContent = block.textContent ?? "";
      if (!paragraph.textContent) paragraph.append(document.createElement("br"));
      block.replaceWith(paragraph);
      codeExitParagraph?.remove();
      placeCursorEnd(paragraph);
      emitChange();
      return;
    }

    const pre = document.createElement("pre");
    const code = document.createElement("code");
    code.textContent = block.textContent ?? "";
    pre.append(code);
    block.replaceWith(pre);
    ensureCodeExitParagraphAfter(pre);
    placeCursorEnd(code);
    emitChange();
  }

  async function copyActiveCodeBlock() {
    const block = getCopyButtonCodeBlock() ?? activeCodeBlock ?? getCurrentBlock();
    if (block?.tagName !== "PRE") return;

    await writeClipboardText((block.textContent ?? "").replace(/\n$/, ""));
    copied = true;
    if (copiedTimer !== null) window.clearTimeout(copiedTimer);
    copiedTimer = window.setTimeout(() => {
      copied = false;
      copiedTimer = null;
    }, 1200);
  }

  function exitHeadingBlock() {
    const block = getActiveHeadingBlock();
    if (!block) return false;

    const paragraph = document.createElement("p");
    paragraph.append(document.createElement("br"));
    block.after(paragraph);
    placeCursorEnd(paragraph);
    emitChange();
    return true;
  }

  function getActiveHeadingBlock() {
    const block = getCurrentBlock();
    if (isHeadingBlock(block)) return block;

    if (activeBlock !== "h1" && activeBlock !== "h2") return null;

    const range = getSelectionRange();
    const ancestor = range ? findAncestor(range.startContainer, ["H1", "H2"]) : null;
    if (isHeadingBlock(ancestor)) return ancestor;

    if (range?.startContainer === editorElement) {
      const childBeforeCaret = editorElement.childNodes[Math.max(0, range.startOffset - 1)];
      const childAtCaret = editorElement.childNodes[range.startOffset];
      if (isHeadingBlock(childBeforeCaret)) return childBeforeCaret;
      if (isHeadingBlock(childAtCaret)) return childAtCaret;
    }

    return null;
  }

  function isHeadingBlock(node: Node | null | undefined): node is HTMLElement {
    return node instanceof HTMLElement && (node.tagName === "H1" || node.tagName === "H2");
  }

  function exitCodeBlock() {
    const block = getActiveCodeBlock() ?? getCurrentCodeBlock();
    if (!block) return false;

    const paragraph = ensureCodeExitParagraphAfter(block);
    placeCursorEnd(paragraph);
    emitChange();
    return true;
  }

  function exitCodeBlockOnArrowDown(event: KeyboardEvent) {
    if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey) return false;

    const block = getActiveCodeBlock();
    if (!block || !isCaretAtEndOfCodeBlock(block)) return false;

    const nextBlock = getFollowingEditorBlock(block) ?? ensureCodeExitParagraphAfter(block);
    placeCursorForCodeExit(nextBlock);
    emitChange();
    return true;
  }

  function insertCodeBlockText(text: string) {
    const range = getSelectionRange();
    if (!range || !getCodeBlockForRange(range)) return false;

    range.deleteContents();

    const textNode = document.createTextNode(text);
    range.insertNode(textNode);

    const selection = window.getSelection();
    if (selection) {
      const nextRange = document.createRange();
      nextRange.setStart(textNode, text.length);
      nextRange.collapse(true);
      selection.removeAllRanges();
      selection.addRange(nextRange);
    }

    emitChange();
    return true;
  }

  function getActiveCodeBlock() {
    const range = getSelectionRange();
    return range ? getCodeBlockForRange(range) : null;
  }

  function getCurrentCodeBlock() {
    const block = getCurrentBlock();
    return block?.tagName === "PRE" ? block : null;
  }

  function getCodeBlockForRange(range: Range) {
    const startBlock = getBlockForNode(range.startContainer);
    const endBlock = getBlockForNode(range.endContainer);
    return startBlock?.tagName === "PRE" && startBlock === endBlock ? startBlock : null;
  }

  function isCaretAtEndOfCodeBlock(block: HTMLElement) {
    const range = getSelectionRange();
    if (!range?.collapsed || getCodeBlockForRange(range) !== block) return false;

    const beforeCaret = document.createRange();
    beforeCaret.selectNodeContents(block);
    beforeCaret.setEnd(range.startContainer, range.startOffset);
    return beforeCaret.toString().length >= (block.textContent ?? "").length;
  }

  function getFollowingEditorBlock(block: HTMLElement) {
    const next = block.nextElementSibling;
    return isEditorBlock(next) ? next : null;
  }

  function getLastEditorBlock() {
    const blocks = Array.from(editorElement?.querySelectorAll<HTMLElement>("p, h1, h2, pre") ?? []);
    return blocks.at(-1) ?? null;
  }

  function isEditorBlock(node: Element | null): node is HTMLElement {
    return node instanceof HTMLElement && ["H1", "H2", "P", "PRE"].includes(node.tagName);
  }

  function ensureTerminalCodeBlockExitParagraph() {
    const block = getLastEditorBlock();
    if (block?.tagName !== "PRE") return null;
    return ensureCodeExitParagraphAfter(block);
  }

  function ensureCodeExitParagraphAfter(block: HTMLElement) {
    const existing = getGeneratedCodeExitParagraph(block.nextElementSibling);
    if (existing) return existing;

    const paragraph = createEmptyParagraph(true);
    block.after(paragraph);
    return paragraph;
  }

  function createEmptyParagraph(codeExitParagraph = false) {
    const paragraph = document.createElement("p");
    if (codeExitParagraph) paragraph.dataset.codeExitParagraph = "true";
    paragraph.append(document.createElement("br"));
    return paragraph;
  }

  function getGeneratedCodeExitParagraph(node: Element | null) {
    if (!(node instanceof HTMLElement) || node.tagName !== "P") return null;
    if (node.dataset.codeExitParagraph !== "true" || !isEmptyTextBlock(node)) return null;
    return node;
  }

  function isEmptyTextBlock(block: HTMLElement) {
    return (block.textContent ?? "").trim() === "";
  }

  function placeCursorForCodeExit(block: HTMLElement) {
    const target = getCursorTarget(block);
    if (isEmptyTextBlock(block)) {
      placeCursorEnd(target);
      return;
    }

    placeCursorStart(target);
  }

  function getCursorTarget(block: HTMLElement) {
    return block.tagName === "PRE" ? (block.querySelector<HTMLElement>("code") ?? block) : block;
  }

  function insertPlainText(text: string) {
    editorElement?.focus();
    if (document.queryCommandSupported?.("insertText")) {
      document.execCommand("insertText", false, text);
      return;
    }

    const range = getSelectionRange();
    if (!range) return;
    range.deleteContents();
    range.insertNode(document.createTextNode(text));
    range.collapse(false);
  }

  function getSelectionRange() {
    const selection = window.getSelection();
    if (!selection || selection.rangeCount === 0 || !editorElement) return null;

    const range = selection.getRangeAt(0);
    if (!editorElement.contains(range.commonAncestorContainer)) return null;
    return range;
  }

  function getCurrentBlock() {
    const range = getSelectionRange();
    const block = range ? getBlockForNode(range.startContainer) : null;
    if (block) return block;

    if (!editorElement) return null;
    const fallback = editorElement.querySelector<HTMLElement>("p, h1, h2, pre");
    if (fallback) return fallback;

    const paragraph = document.createElement("p");
    paragraph.append(document.createElement("br"));
    editorElement.append(paragraph);
    return paragraph;
  }

  function getBlockForNode(node: Node | null) {
    let current: Node | null = node?.nodeType === Node.ELEMENT_NODE ? node : node?.parentNode ?? null;
    while (current && current !== editorElement) {
      if (current instanceof HTMLElement && ["DIV", "H1", "H2", "P", "PRE"].includes(current.tagName)) {
        return current;
      }
      current = current.parentNode;
    }
    return null;
  }

  async function writeClipboardText(text: string) {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return;
    }

    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.append(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }

  function findAncestor(node: Node | null, tagNames: string[]) {
    let current: Node | null = node?.nodeType === Node.ELEMENT_NODE ? node : node?.parentNode ?? null;
    while (current && current !== editorElement) {
      if (current instanceof HTMLElement && tagNames.includes(current.tagName)) return current;
      current = current.parentNode;
    }
    return null;
  }

  function unwrapElement(element: HTMLElement) {
    const parent = element.parentNode;
    if (!parent) return;
    while (element.firstChild) {
      parent.insertBefore(element.firstChild, element);
    }
    parent.removeChild(element);
  }

  function selectElementContents(element: HTMLElement) {
    const selection = window.getSelection();
    if (!selection) return;
    const range = document.createRange();
    range.selectNodeContents(element);
    selection.removeAllRanges();
    selection.addRange(range);
  }

  function placeCursorEnd(element: HTMLElement) {
    const selection = window.getSelection();
    if (!selection) return;
    const range = document.createRange();
    range.selectNodeContents(element);
    range.collapse(false);
    selection.removeAllRanges();
    selection.addRange(range);
  }

  function placeCursorStart(element: HTMLElement) {
    const selection = window.getSelection();
    if (!selection) return;
    const range = document.createRange();
    range.selectNodeContents(element);
    range.collapse(true);
    selection.removeAllRanges();
    selection.addRange(range);
  }

  function handleEditorShellMousedown(event: MouseEvent) {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    if (event.target !== editorShell && event.target !== editorElement) return;

    ensureTerminalCodeBlockExitParagraph();
    event.preventDefault();
    placeCursorAtEditorPoint(event);
  }

  function placeCursorAtEditorPoint(event: MouseEvent) {
    if (!editorElement) return;

    const editorRect = editorElement.getBoundingClientRect();
    const adjustedX = Math.min(Math.max(event.clientX, editorRect.left + 1), editorRect.right - 1);
    const range = getCaretRangeFromPoint(adjustedX, event.clientY);

    editorElement.focus();
    if (range && editorElement.contains(range.commonAncestorContainer)) {
      selectRange(range);
      refreshToolbarState();
      return;
    }

    placeCursorAtNearestEditorBlockEdge(editorElement, event.clientY, event.clientX < editorRect.left);
    refreshToolbarState();
  }

  function handleEditorMousemove(event: MouseEvent) {
    const node = event.target instanceof Node ? event.target : null;
    const codeBlock = findAncestor(node, ["PRE"]);
    if (hoveredCodeBlock === codeBlock) return;

    hoveredCodeBlock = codeBlock;
    if (!codeBlock) copied = false;
    updateCodeCopyButton();
  }

  function clearHoveredCodeBlock() {
    if (!hoveredCodeBlock) return;
    hoveredCodeBlock = null;
    copied = false;
    updateCodeCopyButton();
  }

  function refreshToolbarState() {
    if (!editorElement) return;
    const range = getSelectionRange();
    if (!range) {
      activeCodeBlock = null;
      activeBlock = "body";
      activeBold = false;
      activeItalic = false;
      activeCode = false;
      updateCodeCopyButton();
      notifyToolbarChange();
      return;
    }

    const block = getBlockForNode(range.startContainer);
    activeBlock = block?.tagName === "H1" ? "h1" : block?.tagName === "H2" ? "h2" : block?.tagName === "PRE" ? "codeBlock" : "body";
    activeCodeBlock = block?.tagName === "PRE" ? block : null;
    activeBold = Boolean(findAncestor(range.startContainer, ["B", "STRONG"]) || document.queryCommandState("bold"));
    activeItalic = Boolean(findAncestor(range.startContainer, ["I", "EM"]) || document.queryCommandState("italic"));
    activeCode = activeBlock !== "codeBlock" && Boolean(findAncestor(range.startContainer, ["CODE"]));
    updateCodeCopyButton();
    notifyToolbarChange();
  }

  function getCopyButtonCodeBlock() {
    if (!editorElement || !hoveredCodeBlock || !hoveredCodeBlock.isConnected) return null;
    return editorElement.contains(hoveredCodeBlock) ? hoveredCodeBlock : null;
  }

  function updateCodeCopyButton() {
    const codeBlock = getCopyButtonCodeBlock();
    if (!editorShell || !codeBlock) {
      codeCopyButtonStyle = "";
      return;
    }

    const shellRect = editorShell.getBoundingClientRect();
    const blockRect = codeBlock.getBoundingClientRect();
    if (blockRect.bottom < shellRect.top || blockRect.top > window.innerHeight) {
      codeCopyButtonStyle = "";
      return;
    }

    const top = blockRect.top - shellRect.top + 8;
    const left = Math.min(
      Math.max(blockRect.left - shellRect.left + 8, blockRect.right - shellRect.left - 28),
      shellRect.width - 28
    );
    codeCopyButtonStyle = `top: ${top}px; left: ${left}px;`;
  }

  function notifyToolbarChange() {
    onToolbarChange?.({
      activeBlock,
      activeBold,
      activeCode,
      activeItalic,
      setBlock,
      toggleBold: () => toggleNativeInline("bold"),
      toggleCodeBlock,
      toggleInlineCode,
      toggleItalic: () => toggleNativeInline("italic")
    });
  }
</script>

<div class="markdown-editor" bind:this={editorShell}>
  <div
    bind:this={editorElement}
    class="rich-editor"
    role="textbox"
    aria-label="Note body"
    aria-multiline="true"
    tabindex="0"
    contenteditable="true"
    spellcheck="true"
    oninput={handleInput}
    onbeforeinput={handleBeforeInput}
    onclick={handleEditorClick}
    onkeydown={handleKeydown}
    onkeyup={refreshToolbarState}
    onmousemove={handleEditorMousemove}
    onmouseup={refreshToolbarState}
    onpaste={handlePaste}
    onblur={() => emitChange({ autolink: true })}
    ondrop={(event) => event.preventDefault()}
  ></div>
  {#if codeCopyButtonStyle}
    <button
      class="code-block-copy-button"
      type="button"
      style={codeCopyButtonStyle}
      title={copied ? "Copied" : "Copy code"}
      aria-label={copied ? "Copied code block" : "Copy code block"}
      onmousedown={(event) => event.preventDefault()}
      onclick={copyActiveCodeBlock}
    >
      {#if copied}
        <Check size={13} />
      {:else}
        <Copy size={13} />
      {/if}
    </button>
  {/if}
</div>
