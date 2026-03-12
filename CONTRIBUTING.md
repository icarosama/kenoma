# Contributing

Original project by [@spaceraccoon](https://github.com/spaceraccoon).

Thanks for your interest in contributing!

## Development Setup

```bash
# Clone and install
git clone https://github.com/icarosama/kenoma.git
cd kenoma
npm install

# Type check
npm run typecheck

# Test
npm test

# Build
npm run build
```

## Making Changes

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `npm run typecheck`, `npm test`, and `npm run build`
5. Commit the `dist/` folder with your changes
6. Submit a Pull Request

## Building

The action uses `@vercel/ncc` to bundle everything into `dist/index.js`:

```bash
npm run build
```

**Important:** Always commit the `dist/` folder after making changes.

## Code Style

- TypeScript with strict mode
- ES Modules
- Clear, descriptive variable names

## Pull Request Guidelines

- Keep changes focused
- Update README if adding features
- Test your changes locally
- Include the built `dist/` folder

## Areas for Contribution

- Improving detection accuracy
- Adding new notification integrations
- Documentation improvements
- Bug fixes

## License

Contributions are licensed under MIT.
