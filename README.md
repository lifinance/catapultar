
<h1 align="center">Catapultar</h1>

Catapultar is an optimized smart account designed for reliable batch and scheduled execution. The main designs goals have been: broad chain compatibility, gas-efficient, and portable. It has been designed to extend from `ERC-7821` to facilitate easy switching.

This repository is a mono-repo consisting of 
- **Solidity contracts:** core account and factory implementation — see [solidity/README.md](solidity/README.md) for further details.
- **TypeScript library:** Smart account helper library for account creation, transaction structures, and versioning management — see [typescript/README.md](typescript/README.md) for further details.

Repository layout (top-level):
- `solidity/` — smart account, factory, tests, and deploy scripts
- `typescript/` — companion TypeScript library and utilities
- `LICENSE` — project license
- `README.md` — this overview

License: This project is distributed under the GNU Lesser General Public License v3.0 only (LGPL-3.0-only). See `LICENSE` for terms. Third-party components used by the project (for example, Solady and Permit2) are under their own licenses; see `solidity/README.md` for more.

