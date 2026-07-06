# Database Setup & Configuration Guide

This guide describes how to configure, run, and maintain the PostgreSQL database foundation for the NetFusion project.

---

## 1. PostgreSQL Installation

Ensure PostgreSQL 16+ is installed on your local machine or container.

### Local Installation
- **macOS** (via Homebrew):
  ```bash
  brew install postgresql@16
  brew services start postgresql@16
  ```
- **Windows**:
  - Download and run the installer from the [PostgreSQL Official Website](https://www.postgresql.org/download/windows/).
  - Make sure the PostgreSQL service is running in `services.msc`.
- **Linux** (Debian/Ubuntu):
  ```bash
  sudo apt update
  sudo apt install postgresql-16 postgresql-contrib-16
  sudo systemctl start postgresql
  ```

---

## 2. Environment Variables

Create a local `.env` file in the project root directory. Use the structure in `.env.example` as a template:

```env
DATABASE_URL="postgresql://<username>:<password>@localhost:5432/<database_name>?schema=public"
NODE_ENV="development"
```

Replace `<username>`, `<password>`, and `<database_name>` with your PostgreSQL username, password, and database.

---

## 3. Prisma Commands

Execute the following commands in the project root to synchronize your schema with PostgreSQL:

### Generate Prisma Client
Generates the type-safe Prisma client based on the current models defined in `prisma/schema.prisma`:
```bash
npx prisma generate
```

### Apply Migrations
Creates and runs database migrations on the PostgreSQL instance:
```bash
npx prisma migrate dev --name init
```

### Seed Database
Seeds the database with foundation records using the entry point in `prisma/seed.ts`:
```bash
npx prisma db seed
```

### Open Prisma Studio
Starts the interactive browser tool to view and edit database data:
```bash
npx prisma studio
```

---

## 4. Development Workflow

1. **Schema Updates**: Modify `prisma/schema.prisma` to add, update, or remove models.
2. **Local Sync**: Run `npx prisma migrate dev` to generate type-safe client typings and update the PostgreSQL schema.
3. **Seeding**: Update the `prisma/seed.ts` logic as new system or lookup data models are introduced.
