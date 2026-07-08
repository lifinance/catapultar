# Repository Guidelines

## Project Structure & Module Organization
This monorepo has two primary packages:
- `solidity/`: Foundry smart contracts, deployment scripts, and tests.
  - Source: `solidity/src`
  - Tests: `solidity/test`
  - Scripts: `solidity/script`
- `typescript/`: Bun + TypeScript client library for account and transaction flows.
  - Source: `typescript/src`
  - Tests: `typescript/test` and `*.spec.ts` near source modules
  - Build output: `typescript/dist`

Keep changes scoped to the relevant package; avoid editing generated artifacts (`out/`, `dist/`, coverage files).

## Build, Test, and Development Commands
- TypeScript package (`cd typescript`):
  - `bun install`: install dependencies.
  - `bun run build`: compile library to `dist/`.
  - `bun run test`: run Bun tests with preload setup.
  - `bun run coverage:lcov`: generate LCOV coverage for CI/codecov.
- Solidity package (`cd solidity`):
  - `forge fmt --check`: verify Solidity formatting.
  - `forge build --sizes`: compile contracts and report sizes.
  - `forge test -vvv`: run full Foundry test suite.
  - `forge coverage --no-match-coverage "(script|test)" --report lcov`: coverage output.

## Coding Style & Naming Conventions
- Solidity: use `forge fmt` defaults configured in `solidity/foundry.toml` (`tab_width = 4`, sorted imports).
- TypeScript: strict compiler settings are enabled (`strict`, `noUnusedLocals`, `noUnusedParameters`).
- Naming:
  - Types/classes: `PascalCase`
  - Functions/variables: `camelCase`
  - Test files: `*.spec.ts` (TS), `*.t.sol` (Solidity)
- Run formatting before commits (`typescript/.husky/pre-commit` runs `lint-staged`, build, and tests).

## Testing Guidelines
- Add tests for all behavior changes in the same package as the change.
- Prefer deterministic unit tests over network-dependent integration tests.
- Keep test names descriptive (example: `catapultar.spec.ts`, `CATValidator.t.sol`).
- Ensure both `bun run test` and `forge test -vvv` pass when touching shared behavior.
- AI agents may be unable to run `bun run test` or `bun run coverage:*` since they cannot spin up Anvil which is required for integration tests. If this is the case, they should ask the user to run test or coverage for them.


## Commit & Pull Request Guidelines
- Follow existing history style: short, imperative subject lines (e.g., `fix payable`, `feat: barrel export`).
- Recommended format: optional prefix (`feat:`, `fix:`) + concise summary.
- PRs should include:
  - What changed and why
  - Affected package(s): `solidity`, `typescript`, or both
  - Test evidence (commands run and result)
  - Linked issue/context when applicable
