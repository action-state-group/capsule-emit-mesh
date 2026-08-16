> **About the entries in `ledger-live/`**
>
> These entries are demo-grade. They are signed with a self-attested node key — generated locally by this repository, not bound to a node identity, an owner policy, or a hardware root. The transparency service they are anchored to commits to digests: a receipt establishes that a statement was registered at a point in time and has not changed since. It does not establish who issued it.
>
> The signing key used for these historical runs was published in this repository between 2026-08-11 and 2026-08-13. The repository has since been rewritten so that keys are generated on first run into an ignored directory, and only the public half of the old key is retained so existing entries remain verifiable. A rewrite does not un-publish a key: anyone who cloned in that window still holds it and can mint further statements under `mesh-poc/mesh-node-demo-1`.
>
> Read these entries as a demonstration of the mechanism, not as authenticated evidence of what a node did. Binding a signing key to a trusted identity is tracked upstream as mesh-llm#1233.
