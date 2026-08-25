# LightDNS Control Plane Design

LightDNS is a dense dark infrastructure console organized as a routing ledger. Pico CSS owns standard controls, forms, tables, buttons, dialogs, and focus behavior; project CSS supplies the shell, responsive navigation, compact data treatment, status language, and tokens. The interface should make authority, ownership, revision, and policy state readable without translating decorative dashboard cards.

## Tokens

- Ink: `#f1f3f4`
- Muted ink: `#9ca2a8`
- Canvas: `#0a0b0c`
- Surface: `#101112`
- Raised surface: `#171819`
- Active surface: `#1b2d49`
- Line: `#303234`
- Action blue: `#2f7df4`
- Brand orange: `#d86d1c`
- Success: `#4fc78b`
- Warning: `#dba64b`
- Danger: `#e0646c`

## Structure

- Desktop uses a near-black masthead, persistent labeled rail, compact toolbars, and ruled data tables.
- The overview follows a DNS request from policy through cache and upstream instead of presenting interchangeable cards.
- Managed zones are a master-detail workspace. Name, owner, state, revision, records, and administrative decisions stay in one operational context.
- Legacy overrides remain distinct from reviewed managed zones and keep their staged save behavior.
- Resolver configuration spans blocking, upstream, and system sections but shares one persistent unsaved-change action bar.
- Mobile turns the rail into bottom navigation and stacks the zone list over its detail view. Wide operational tables remain horizontally scrollable rather than hiding fields.

## Interaction

- Blue means a primary control-plane action; orange belongs to product identity and current-location emphasis.
- Green, amber, and red are reserved for operational state, review state, and destructive outcomes.
- Managed-zone mutations apply immediately and use zone revisions to reject stale writes. Global resolver configuration remains staged until explicitly saved.
- Controls retain the original layered charcoal inputs and dimensional blue, gray, orange, and red button gradients. Short focused dialogs are preferred over multi-step overlays.
- Every icon-only action has an accessible name. Focus outlines remain visible, and reduced-motion preferences disable nonessential transitions.

Use the system sans stack and compact fixed type sizes. Keep controls familiar, corners restrained, state color purposeful, and data dense. Avoid decorative diagrams, metric-card grids, gradients, glass, invented controls, and explanatory filler.
