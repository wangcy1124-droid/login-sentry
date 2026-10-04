# Login Sentry agent instructions

## Roles and stage gate
- ChatGPT main window: architecture, review, audit, next-stage instruction.
- WSL Codex: implementation, local testing, git commit, git push.
- Server: pull exact Git commit, independent test, runtime validation.

Only implement the currently authorized stage. After Stage 0 is pushed, STOP
and await ChatGPT review and explicit next-stage instructions.

## Change discipline
Keep changes within the current stage. No unrelated refactoring, large
unapproved dependencies, stack changes, SSH configuration edits, committed
secrets, runtime SQLite databases, or generated logs. Never remove valid test
assertions to make tests pass, skip failing tests, or hide exceptions.

Use Python, FastAPI, SQLite, regular expressions, ECharts, Linux, and pytest.
Do not introduce PostgreSQL, MySQL, Redis, Kafka, RabbitMQ, Elasticsearch,
mandatory Docker, Vue, or React. Prefer simple, reliable, explainable modules
and moderate type annotations over unnecessary classes and abstractions.

Keep parsers separate from detectors. Future detection logic must be testable;
time logic must accept deterministic injected time instead of requiring wall
clock time. A future LoginEvent may include timestamp, source_type, source_ip,
username, result, and raw_log; Stage 0 does not implement this model.

## Git discipline
Before each stage commit, run `git status`, `git diff --check`, and `pytest`
(with the project's virtual environment active). Commit only after checks pass.
Use a clear English commit message, for example
`chore: bootstrap login sentry project`, then push to `origin/main`.
Report branch, commit SHA, working tree status, and push result every stage.
Do not use `git push --force` or `git reset --hard` unless the main review
window explicitly requests it.

## Testing discipline
On failure, preserve the full traceback, identify the root cause, fix it, and
rerun the tests. Never weaken assertions to mask defects. Report failures
honestly. Server testing must use the exact commit SHA available on GitHub.
Stage 0 does not require connecting to the server.
