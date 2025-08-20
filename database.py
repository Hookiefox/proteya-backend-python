
import aiosqlite
import json
import uuid
from pathlib import Path
import os
from contextlib import asynccontextmanager
import datetime

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DATABASE_NAME = DATA_DIR / "notes_v3.db"


DATA_DIR.mkdir(parents=True, exist_ok=True)

@asynccontextmanager
async def get_db_connection():
    conn = await aiosqlite.connect(DATABASE_NAME)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        await conn.close()

async def run_migrations(conn):
    
    cursor = await conn.execute("PRAGMA table_info(notes)")
    columns = [row[1] for row in await cursor.fetchall()]
    if 'type' not in columns:
        print("Running migration: Adding 'type' column to 'notes' table...")
        await conn.execute("ALTER TABLE notes ADD COLUMN type TEXT DEFAULT 'text'")
        await conn.commit()
        print("Migration complete.")

    
    cursor = await conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_workspace_order'")
    if await cursor.fetchone() is None:
        print("Running migration: Creating 'user_workspace_order' table...")
        await conn.execute("""
            CREATE TABLE user_workspace_order (
                user_id TEXT PRIMARY KEY,
                workspace_order TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        await conn.commit()
        print("Migration complete.")

async def create_tables():
    """
    Ensures the database is initialized with the correct schema.
    """
    async with get_db_connection() as conn:
        
        cursor = await conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if await cursor.fetchone() is None:
            print("No existing database found or schema is incomplete. Creating all tables...")
            
            await conn.execute("""
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                hashed_password TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            )
            """)

            await conn.execute("""
            CREATE TABLE workspaces (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                avatar_url TEXT,
                user_id TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """)

            await conn.execute("""            
            CREATE TABLE workspace_members (
                workspace_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                PRIMARY KEY (workspace_id, user_id),
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """)

            await conn.execute("""
            CREATE TABLE notes (
                id TEXT PRIMARY KEY, title TEXT NOT NULL, content TEXT, is_encrypted INTEGER,
                created_at TEXT, modified_at TEXT, workspace_id TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE)
            """)

            await conn.execute("""
            CREATE TABLE tags (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, parent_id TEXT, icon TEXT,
                workspace_id TEXT NOT NULL, FOREIGN KEY (parent_id) REFERENCES tags(id) ON DELETE CASCADE,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE)
            """)

            await conn.execute("""
            CREATE TABLE note_tags (note_id TEXT, tag_id TEXT, PRIMARY KEY (note_id, tag_id),
                FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE)
            """)
            await conn.commit()
            print("All tables created successfully.")

        
        await run_migrations(conn)



if __name__ == "__main__":
    import asyncio
    asyncio.run(create_tables())
