# Environment configuration

- Use only the repository root `.env` for file-based environment configuration across all apps, scripts, and tools.
- Add new environment variables to the existing root `.env`; never create `.env.local`, `.env.example`, mode-specific env files, or per-app env files.
- Keep `.env` ignored by Git and excluded from deployment artifacts. Never copy its secrets into tracked files.
- Configure tools to read the root `.env` instead of generating another env file.
