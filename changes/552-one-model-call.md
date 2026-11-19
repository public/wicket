---
area: Boxes and the egress path
type: Changed
---
- A model call now behaves the same whichever way it reaches the model host: through the model
  proxy, or through the egress proxy as a wrapped session's call does
  ([#552](https://github.com/public/wicket/issues/552)). Both go through one code path, and a
  test runs every model-call behaviour through both routes. What changes:
  - **A request that isn't one of the provider's model routes** (a batch, say) is refused with 404
    on both routes, and not counted. The egress route used to count it and answer 403.
  - **A request body too large to read** is a 400 on both. The model proxy used to answer 502.
  - **A login being rewritten by its owner** is waited for on both routes. A secret that can't be
    read, or isn't on a node yet, is a 503 that says so on both. The egress route used to fail with
    502.
  - **A credential reflected in the model host's answer** is masked on both routes. An answer
    encoded so it can't be checked for the credential is refused on both. Before, only the egress
    route did either.
  - **A run's placeholder in a URL or forwarded header** trips on both routes.
  - **A call the box gives up on** after it was sent is charged what the provider bills for it, on
    both routes. The egress route used to charge its whole reservation.
  - **A wrapped session's first model request** is recorded, so its node reports it, as the model
    proxy's always was.
