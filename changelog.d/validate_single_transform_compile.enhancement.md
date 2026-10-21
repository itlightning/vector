`vector validate` no longer compiles every VRL program and condition twice. Building the components performs the same checks against the real enrichment tables and reports the same diagnostic text, so the standalone transform phase now runs only under `--no-environment`, where no components are built. The `Transforms configuration` success line is reported from the component phase instead.

Structural per-transform validation (reserved output names, duplicate routes, invalid sample rates) is unaffected: it runs unconditionally while the configuration is compiled, not in either phase. Only the environment-dependent checks moved. A failing program is reported under the `Component errors` heading rather than `Transform errors`, and route and reduce condition errors lose their `Transform "<id>"` prefix, with the message itself unchanged.

authors: klondikedragon
