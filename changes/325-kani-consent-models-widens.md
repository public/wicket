---
area: Operations and audit
type: Added
---
- Kani now checks three more `wicket-core` decisions
  ([#325](https://github.com/public/wicket/issues/325)):
  - **`accept_from` (`manifest::accepts`):** a sender is let in exactly when an entry names it, a
    zone entry by its zone or a principal entry by its id, and the two kinds never cross (#250).
    An empty list refuses everyone, and adding an entry never refuses a sender let in before.
  - **Model allowlists (`manifest::model_covers`):** for the patterns `check_models` accepts, a
    name covers only itself, and a pattern that covers another covers every model that one
    covers. So a child zone's model list never lets in a model its parent's refuses.
  - **An approval's blast radius (`Effect::widens`):** an approval doesn't widen exactly when it
    grants one use, for at most an hour, to the asking run, for the asked path only.
