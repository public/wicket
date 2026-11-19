---
area: Build and CI
type: Fixed
---
- The install test's container falls back from the runner's Ubuntu mirror to Ubuntu's own hosts
  ([#219](https://github.com/public/wicket/issues/219)). Each apt source lists the runner's mirror
  first and its own host (`archive.ubuntu.com`, `security.ubuntu.com`) after it, so a package the
  mirror fails to serve (a runner's EC2 mirror answered 503) is fetched from the next. apt also
  retries each fetch up to 5 times.
