---
version: alpha
name: Verus Notes Native App
description: Design contract for the Verus Notes encrypted notes app.
colors:
  primary: "#3165D4"
  primary-hover: "#2755B8"
  on-primary: "#FFFFFF"
  surface: "#FFFFFF"
  surface-raised: "#FBFBFB"
  surface-sidebar: "#F3F3F3"
  surface-selected: "#DEDEDE"
  surface-locked: "#F6F9FF"
  on-surface: "#222222"
  on-surface-muted: "#666666"
  on-surface-subtle: "#6F6F6F"
  keyline: "#E5E5E5"
  keyline-strong: "#D2D2D2"
  success: "#286A4E"
  success-surface: "#F0FAF4"
  danger: "#B84040"
typography:
  display:
    fontFamily: "Inter"
    fontSize: 3.05rem
    fontWeight: 800
    lineHeight: 1
    letterSpacing: 0em
  editor-title:
    fontFamily: "Inter"
    fontSize: 1.618rem
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: 0em
  editor-body:
    fontFamily: "Inter"
    fontSize: 1rem
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: 0em
  pane-title:
    fontFamily: "Inter"
    fontSize: 1rem
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: 0em
  body:
    fontFamily: "Inter"
    fontSize: 1rem
    fontWeight: 400
    lineHeight: 1.45
    letterSpacing: 0em
  body-small:
    fontFamily: "Inter"
    fontSize: 0.88rem
    fontWeight: 400
    lineHeight: 1.35
    letterSpacing: 0em
  navigator:
    fontFamily: "Inter"
    fontSize: 0.8125rem
    fontWeight: 400
    lineHeight: 1.3
    letterSpacing: 0em
  metadata:
    fontFamily: "Inter"
    fontSize: 0.78rem
    fontWeight: 500
    lineHeight: 1.25
    letterSpacing: 0em
  mono-small:
    fontFamily: "SF Mono"
    fontSize: 0.72rem
    fontWeight: 500
    lineHeight: 1.2
    letterSpacing: 0em
spacing:
  xxs: 2px
  xs: 4px
  sm: 8px
  md: 12px
  lg: 16px
  xl: 24px
  xxl: 34px
  panel-gutter: 7px
rounded:
  none: 0px
  xs: 5px
  sm: 7px
  md: 8px
  lg: 12px
  pill: 9999px
components:
  app-shell:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body}"
  locked-access:
    backgroundColor: "{colors.surface-locked}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body}"
  source-sidebar:
    backgroundColor: "{colors.surface-sidebar}"
    textColor: "{colors.on-surface-muted}"
    typography: "{typography.navigator}"
  note-browser:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-small}"
  topbar-tab:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface-muted}"
    typography: "{typography.navigator}"
    height: 40px
  editor-pane:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
    typography: "{typography.editor-body}"
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.body-small}"
    rounded: "{rounded.sm}"
    height: 36px
    padding: 13px
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
    textColor: "{colors.on-primary}"
    typography: "{typography.body-small}"
    rounded: "{rounded.sm}"
    height: 36px
    padding: 13px
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-small}"
    rounded: "{rounded.sm}"
    height: 36px
    padding: 13px
  selected-row:
    backgroundColor: "{colors.surface-selected}"
    textColor: "{colors.on-surface}"
    typography: "{typography.navigator}"
    rounded: "{rounded.sm}"
    height: 27px
    padding: 8px
  keyline:
    backgroundColor: "{colors.keyline}"
    textColor: "{colors.on-surface}"
    height: 1px
  strong-keyline:
    backgroundColor: "{colors.keyline-strong}"
    textColor: "{colors.on-surface}"
    height: 1px
  sync-success:
    backgroundColor: "{colors.success-surface}"
    textColor: "{colors.success}"
    typography: "{typography.metadata}"
    rounded: "{rounded.pill}"
    height: 26px
    padding: 9px
  danger-label:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.danger}"
    typography: "{typography.metadata}"
  subtle-label:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface-subtle}"
    typography: "{typography.metadata}"
---

## Overview

Verus Notes is a native encrypted notes app for people who care about privacy but still expect the quiet speed of a local desktop notes tool. The interface should feel calm, precise, and work-focused: closer to a mature macOS utility than a SaaS landing page.

The app's first priority is trust. Visual design must make it clear when the vault is locked, unlocking, syncing, or editing local plaintext. Avoid ornamental visuals that make the security model feel vague. Use small, concrete signals: lock icons, sync status, selected folders, ciphertext-safe language, and restrained color.

## Colors

The palette is intentionally narrow and neutral. Most of the product should be white, light gray, and high-contrast text so note content remains the primary object.

- `primary` is the only blue action color. Use it for the single most important action in a screen or for selected secure state.
- `surface`, `surface-raised`, `surface-sidebar`, and `surface-selected` define the three-pane notes workspace.
- `success` is reserved for verified sync or unlock state. Do not use it for general decoration.
- `danger` is for destructive actions and protocol/security errors.
- Use `on-surface-muted` or `on-surface-subtle` for metadata, but avoid lighter grays for small text.

## Dark Mode

Dark mode follows the user's system appearance through `prefers-color-scheme`; do not add an independent app theme toggle unless there is a product requirement for one. Use the Graphite palette: near-black app background, charcoal sidebars, slightly lighter selected rows, high-contrast off-white text, and the same blue primary action family adjusted brighter for dark surfaces.

Keep note content and editor affordances readable first. Avoid pure black panels, saturated blue backgrounds, decorative gradients, or dark-mode-only ornamentation.

## Typography

Use the bundled Inter variable font with the system font stack as fallback: `Inter`, `SF Pro Text`, `SF Pro Display`, `Segoe UI`, `ui-sans-serif`, and `system-ui`. Verus Notes should look consistent across desktop platforms while still falling back to native fonts if Inter cannot load.

Display-scale type is only for the locked welcome screen. In the unlocked app, pane headings should be compact, metadata should be scannable, and editor text should have enough line height for long-form writing.

Do not use negative letter spacing. Use `SF Mono` only for ciphertext previews, request IDs, hashes, or other technical identifiers.

## Layout

The unlocked app is a dense three-pane workspace: source sidebar, note browser, and editor. Preserve this structure unless a feature truly needs a different mode.

Panels should use stable dimensions and explicit resize gutters. Lists, toolbars, status strips, and editor chrome must not shift when labels, icons, or sync state changes. The editor should get the most visual space, with note title and body fields aligned to a comfortable reading column.

The locked state may use a larger hero composition, but it still needs to be a functional unlock screen rather than a marketing page. Keep the wallet QR panel immediately usable.

## Elevation & Depth

Use elevation sparingly. The main workspace is mostly flat, separated by keylines and background shifts. Shadows are appropriate for popovers, context menus, modal surfaces, QR unlock panels, and small illustrative locked-state panels.

Avoid layered card stacks and decorative floating sections. Verus Notes is an editor, not a dashboard.

## Shapes

Default controls use 7px radius. Repeated list rows, icon buttons, folder rows, note rows, and secondary controls should stay within the 5px-8px range. Use pill shapes only for compact status badges and search fields.

Do not mix highly rounded controls with square panes in the same local area.

## Components

Buttons should use icons when the action is common: create, lock, delete, search, folder, sync, and overflow/menu actions. Text buttons are appropriate for primary unlock flows and explicit destructive confirmations.

Sidebars and browsers should use rows, not cards. A selected row is shown with `surface-selected` and may use `primary` only for the icon or the strongest state accent.

Context menus should use a dark translucent surface with compact row heights and icon slots. Keep menu copy literal and short.

Inputs should look native and quiet. The editor title and body fields should have no heavy border while focused; surrounding pane structure already communicates the editing area.

Interactive controls should keep the default arrow cursor rather than switching to a hand cursor. Reserve specialized cursors for spatial interactions such as panel resizing.

## Do's and Don'ts

- Do keep the note content and folder hierarchy visually dominant once the vault is unlocked.
- Do reserve `primary` for the main action, selected secure state, and wallet unlock emphasis.
- Do maintain WCAG AA contrast for all normal text.
- Do show protocol and sync state with concise status badges, not decorative panels.
- Don't create marketing sections inside the app shell.
- Don't store design-only examples containing real wallet payloads, IVKs, keys, seeds, WIFs, or note content.
- Don't introduce generic purple/blue gradients, oversized cards, or decorative background orbs.
- Don't make Convex or cloud sync look like it can read plaintext note content.
