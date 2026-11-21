### Thanks for contributing to sad-web-push!

`sad-web-push 0.11.x` keeps the `web-push 0.11.0` (`http 0.2`) public API stable. Please avoid
semver-incompatible changes on `0.11.x`, and call out any change in behavior (for example, a panic
becoming an error) in the description.

If the change is a backport of an upstream `pimeys/rust-web-push` PR, link it and keep the original
author on the commit (`git cherry-pick -x`).

Please consider adding a test to ensure your bug fix or feature will not break in the future.
