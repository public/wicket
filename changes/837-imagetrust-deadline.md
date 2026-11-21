---
area: Boxes and the egress path
type: Fixed
---
- An image whose signature check starts past its run's deadline is refused without anything being
  fetched ([#837](https://github.com/public/wicket/issues/837)). Before, a registry fast enough to
  answer within the first poll could still be asked, and the image admitted.
