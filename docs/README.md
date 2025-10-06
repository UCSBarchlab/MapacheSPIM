# MapacheSail Documentation

Welcome to the MapacheSail documentation! This directory contains all project documentation organized by audience and purpose.

> **Note:** MapacheSail will be renamed to MapacheSim in an upcoming release to reflect its ISA-agnostic nature.

## 📚 Quick Links

### For Students & Users
- **[Quick Start Guide](user/quick-start.md)** ⭐ - Get started in 5 minutes
- [Console Guide](user/console-guide.md) - Complete console command reference
- [Examples Guide](../examples/README.md) - Learn from example programs

### For Developers
- [Architecture Overview](developer/architecture.md) - System design and components
- [Multi-ISA Strategy](developer/multi-isa.md) - How we support multiple ISAs
- [Testing Guide](developer/testing.md) - Testing strategy and practices

### Design Documents
- [Implementation Plan](design/implementation-plan.md) - Overall project roadmap
- [SPIM Comparison](design/spim-comparison.md) - Feature comparison with SPIM
- [Enhancement History](design/enhancement-history.md) - Implementation details

### Historical Records
- [Progress Log](history/progress-log.md) - Development history
- [Library Status](history/libsailsim-status.md) - Historical status updates

---

## 📖 Documentation Structure

```
docs/
├── README.md (this file)       # Documentation index
│
├── user/                        # User documentation
│   ├── quick-start.md          # 5-minute getting started
│   └── console-guide.md        # Console usage reference
│
├── developer/                   # Developer documentation
│   ├── architecture.md         # System architecture
│   ├── multi-isa.md            # Multi-ISA design
│   └── testing.md              # Testing guide
│
├── design/                      # Design documents
│   ├── implementation-plan.md  # Overall roadmap
│   ├── spim-comparison.md      # Feature comparison
│   └── enhancement-history.md  # Implementation history
│
└── history/                     # Historical/archived docs
    ├── progress-log.md         # Development log
    └── libsailsim-status.md    # Historical status
```

---

## 🎯 Getting Started

**New to MapacheSail?** Start here:

1. **[Quick Start Guide](user/quick-start.md)** - Install and run your first program (5 minutes)
2. **[Console Guide](user/console-guide.md)** - Learn the debugging commands
3. **[Examples](../examples/README.md)** - Explore example programs

**Want to contribute?** Check out:

1. **[Architecture](developer/architecture.md)** - Understand the system
2. **[Testing](developer/testing.md)** - How we test
3. **[Multi-ISA Strategy](developer/multi-isa.md)** - Adding new ISAs

---

## 🔍 What is MapacheSail?

MapacheSail is an educational RISC-V simulator built on the Sail formal specification. It provides a SPIM-like debugging experience with:

- ✅ **Enhanced step display** - See instructions, register changes, and symbols
- ✅ **Symbol table support** - Use function names for breakpoints
- ✅ **Register tracking** - Automatic highlighting of changes
- ✅ **Formal specification** - Built on Sail's proven models
- ✅ **ISA-agnostic design** - Ready to support ARM, CHERI, and more

Perfect for:
- 🎓 Computer architecture courses
- 📚 Assembly programming labs
- 🔬 ISA research and education
- 🛠️ Formal methods teaching

---

## 📝 Contributing to Documentation

Found an issue or want to improve the docs?

1. **Small fixes**: Submit a pull request
2. **New sections**: Open an issue to discuss first
3. **Typos/clarifications**: Just fix and submit PR

Documentation guidelines:
- Use clear, simple language
- Include code examples where helpful
- Test all commands/examples before submitting
- Link to related docs

---

## ❓ Questions?

- **User questions**: Check [Quick Start](user/quick-start.md) or [Console Guide](user/console-guide.md)
- **Developer questions**: See [Architecture](developer/architecture.md)
- **Feature requests**: Open an issue on GitHub
- **Bugs**: Open an issue with reproduction steps

---

**Last Updated:** October 2025
**Version:** POC Phase (pre-1.0)
