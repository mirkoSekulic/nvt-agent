# Work control

`work-control` exports the provider-neutral `nvt-work` tool. A cooperative
workflow posts its result through its existing mediated provider tooling and
then signals one fixed lifecycle event:

```text
nvt-work complete  # plugin.work.completed
nvt-work fail      # plugin.work.failed
```

Both events use source `plugin:work-control`. The tool accepts no event name or
payload, does not post results, and holds no credentials. AgentRuns that enable
these lifecycle events remain bounded by their active deadline if no signal is
published.
