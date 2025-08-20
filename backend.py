

from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Form, Query, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path
import os
import json
from typing import Dict, List, Optional, Annotated
import uuid
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import database as db
from contextlib import asynccontextmanager
import aiosqlite
from PIL import Image
import io
import auth
import voice_backend  
from jose import jwt, JWTError
import threading
import asyncio


@asynccontextmanager
async def lifespan(app: FastAPI):
    
    db.DATA_DIR.mkdir(parents=True, exist_ok=True)
    await db.create_tables()

    
    def run_voice():
        try:
            print("[Voice] Запуск voice_backend.main()...")
            asyncio.run(voice_backend.main())
        except Exception as e:
            print(f"[Voice Backend] Ошибка при запуске: {e}")

    
    voice_thread = threading.Thread(target=run_voice, daemon=True)
    voice_thread.start()

    print("[Backend] Голосовой сервер запущен в фоне (порт 8765).")
    yield  

    print("[Backend] Приложение остановлено.")



app = FastAPI(body_limit=50 * 1024 * 1024, lifespan=lifespan)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



class Token(BaseModel):
    access_token: str
    token_type: str



@app.post("/register-admin")
async def register_admin(email: str = Form(...), password: str = Form(...)):
    async with db.get_db_connection() as conn:
        cursor = await conn.execute("SELECT id FROM users")
        if await cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="An admin account already exists.",
            )

        user_id = str(uuid.uuid4())
        hashed_password = auth.get_password_hash(password)

        await conn.execute(
            "INSERT INTO users (id, email, hashed_password, is_admin) VALUES (?, ?, ?, ?)",
            (user_id, email, hashed_password, 1)
        )
        await conn.commit()
        return {"message": f"Admin user {email} created successfully."}


@app.post("/login", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    async with db.get_db_connection() as conn:
        cursor = await conn.execute("SELECT * FROM users WHERE email = ?", (form_data.username,))
        user = await cursor.fetchone()

    if not user or not auth.verify_password(form_data.password, user['hashed_password']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user['email'], "user_id": user['id'], "is_admin": bool(user['is_admin'])},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}



async def get_current_db_user(token: str = Depends(auth.oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    async with db.get_db_connection() as conn:
        cursor = await conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = await cursor.fetchone()

    if user is None:
        raise credentials_exception
    return user


async def get_current_admin_user(current_user: Annotated[dict, Depends(get_current_db_user)]):
    if not current_user['is_admin']:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user does not have administrative privileges.",
        )
    return current_user


async def check_workspace_access(workspace_id: str, user_id: str, conn) -> bool:
    query = """
        SELECT w.id
        FROM workspaces w
        LEFT JOIN workspace_members wm ON w.id = wm.workspace_id
        WHERE w.id = ? AND (w.user_id = ? OR wm.user_id = ?)
    """
    cursor = await conn.execute(query, (workspace_id, user_id, user_id))
    return await cursor.fetchone() is not None


@app.post("/create-user")
async def create_new_user(
    admin_user: Annotated[dict, Depends(get_current_admin_user)],
    email: str = Form(...),
    password: str = Form(...)
):
    async with db.get_db_connection() as conn:
        cursor = await conn.execute("SELECT id FROM users WHERE email = ?", (email,))
        if await cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists.",
            )

        user_id = str(uuid.uuid4())
        hashed_password = auth.get_password_hash(password)

        await conn.execute(
            "INSERT INTO users (id, email, hashed_password, is_admin) VALUES (?, ?, ?, ?)",
            (user_id, email, hashed_password, 0)
        )
        await conn.commit()
        return {"message": f"User {email} created successfully."}


@app.get("/users", response_model=List[dict])
async def get_all_users(current_user: Annotated[dict, Depends(get_current_db_user)]):
    async with db.get_db_connection() as conn:
        cursor = await conn.execute("SELECT id, email, is_admin FROM users")
        users = await cursor.fetchall()
    return [dict(row) for row in users]


@app.delete("/users/{user_id}")
async def delete_user_by_id(
    user_id: str,
    admin_user: Annotated[dict, Depends(get_current_admin_user)]
):
    async with db.get_db_connection() as conn:
        cursor = await conn.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not await cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        await conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await conn.commit()
        return {"message": f"User {user_id} deleted successfully."}


@app.put("/users/{user_id}")
async def update_user_by_id(
    user_id: str,
    admin_user: Annotated[dict, Depends(get_current_admin_user)],
    email: Optional[str] = Form(None),
    password: Optional[str] = Form(None)
):
    async with db.get_db_connection() as conn:
        cursor = await conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = await cursor.fetchone()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        if email:
            await conn.execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))
        if password:
            hashed_password = auth.get_password_hash(password)
            await conn.execute("UPDATE users SET hashed_password = ? WHERE id = ?", (hashed_password, user_id))
        await conn.commit()
        return {"message": f"User {user_id} updated successfully."}



STATIC_DIR = "static"
FILES_SUBDIR = "files"
FILES_DIR = Path(STATIC_DIR) / FILES_SUBDIR
Path(FILES_DIR).mkdir(parents=True, exist_ok=True)

AVATAR_DIR = Path(STATIC_DIR) / "workspaces" / "avatars"
AVATAR_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.mount("/static/files", StaticFiles(directory=str(FILES_DIR)), name="files")


class Note(BaseModel):
    title: str
    content: Optional[str] = ""
    tags: Optional[List[str]] = []
    is_encrypted: Optional[bool] = False
    type: Optional[str] = "text"


class Workspace(BaseModel):
    id: str
    name: str
    created_at: str
    user_id: str
    avatar_url: Optional[str] = None



@app.get("/workspaces/", response_model=List[Workspace])
async def get_workspaces(current_user: dict = Depends(get_current_db_user)):
    user_id = current_user['id']
    async with db.get_db_connection() as conn:
        cursor = await conn.execute("SELECT workspace_order FROM user_workspace_order WHERE user_id = ?", (user_id,))
        order_row = await cursor.fetchone()
        workspace_order = json.loads(order_row['workspace_order']) if order_row else []

        if current_user['is_admin']:
            cursor = await conn.execute("SELECT id, name, created_at, avatar_url, user_id FROM workspaces")
        else:
            cursor = await conn.execute("""
                SELECT w.id, w.name, w.created_at, w.avatar_url, w.user_id
                FROM workspaces w
                LEFT JOIN workspace_members wm ON w.id = wm.workspace_id
                WHERE w.user_id = ? OR wm.user_id = ?
                GROUP BY w.id
            """, (user_id, user_id))

        workspaces = [dict(row) for row in await cursor.fetchall()]
        if workspace_order:
            order_map = {ws_id: i for i, ws_id in enumerate(workspace_order)}
            workspaces.sort(key=lambda ws: order_map.get(ws['id'], len(workspace_order)))

    return [Workspace(**row) for row in workspaces]


class WorkspaceOrder(BaseModel):
    workspace_ids: List[str]


@app.put("/workspaces/order")
async def update_workspace_order(
    order: WorkspaceOrder,
    current_user: dict = Depends(get_current_db_user)
):
    user_id = current_user['id']
    async with db.get_db_connection() as conn:
        await conn.execute(
            "INSERT OR REPLACE INTO user_workspace_order (user_id, workspace_order) VALUES (?, ?)",
            (user_id, json.dumps(order.workspace_ids))
        )
        await conn.commit()
    return {"message": "Workspace order updated successfully."}


@app.post("/workspaces/", response_model=Workspace)
async def create_workspace(name: str = Form(...), current_user: dict = Depends(get_current_db_user)):
    workspace_id = f"ws_{uuid.uuid4().hex}"
    created_at = datetime.utcnow().isoformat()
    user_id = current_user['id']
    async with db.get_db_connection() as conn:
        try:
            await conn.execute(
                "INSERT INTO workspaces (id, name, created_at, user_id) VALUES (?, ?, ?, ?)",
                (workspace_id, name, created_at, user_id)
            )
            await conn.commit()
        except aiosqlite.IntegrityError as e:
            raise HTTPException(status_code=400, detail=f"Failed to create workspace: {e}")
    return Workspace(id=workspace_id, name=name, created_at=created_at, user_id=user_id)


@app.put("/workspaces/{workspace_id}", response_model=Workspace)
async def update_workspace(
    workspace_id: str,
    name: str = Form(...),
    current_user: dict = Depends(get_current_db_user)
):
    user_id = current_user['id']
    async with db.get_db_connection() as conn:
        cursor = await conn.execute("SELECT user_id FROM workspaces WHERE id = ?", (workspace_id,))
        workspace = await cursor.fetchone()
        if not workspace:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")
        if not current_user['is_admin'] and workspace['user_id'] != user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No permission")
        await conn.execute("UPDATE workspaces SET name = ? WHERE id = ?", (name, workspace_id))
        await conn.commit()
        cursor = await conn.execute("SELECT * FROM workspaces WHERE id = ?", (workspace_id,))
        workspace = await cursor.fetchone()
    return Workspace(**dict(workspace))


@app.post("/workspaces/{workspace_id}/avatar")
async def upload_workspace_avatar(workspace_id: str, file: UploadFile = File(...), current_user: dict = Depends(get_current_db_user)):
    user_id = current_user['id']
    async with db.get_db_connection() as conn:
        cursor = await conn.execute("SELECT user_id FROM workspaces WHERE id = ?", (workspace_id,))
        workspace = await cursor.fetchone()
        if not workspace:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")
        if not current_user['is_admin'] and workspace['user_id'] != user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No permission")

    try:
        unique_filename = f"{workspace_id}.png"
        file_path = AVATAR_DIR / unique_filename
        content = await file.read()
        img = Image.open(io.BytesIO(content))
        img.thumbnail((128, 128))
        img.save(file_path, 'PNG')
        file_url = f"/static/workspaces/avatars/{unique_filename}"

        async with db.get_db_connection() as conn:
            await conn.execute("UPDATE workspaces SET avatar_url = ? WHERE id = ?", (file_url, workspace_id))
            await conn.commit()
        return {"avatar_url": file_url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload avatar: {e}")


@app.delete("/workspaces/{workspace_id}")
async def delete_workspace(workspace_id: str, current_user: dict = Depends(get_current_db_user)):
    user_id = current_user['id']
    async with db.get_db_connection() as conn:
        cursor = await conn.execute("SELECT user_id FROM workspaces WHERE id = ?", (workspace_id,))
        workspace = await cursor.fetchone()
        if not workspace:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")
        if not current_user['is_admin'] and workspace['user_id'] != user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No permission")
        await conn.execute("DELETE FROM workspaces WHERE id = ?", (workspace_id,))
        await conn.commit()
    return {"message": f"Workspace '{workspace_id}' deleted"}


class WorkspaceMember(BaseModel):
    user_id: str


@app.post("/workspaces/{workspace_id}/members")
async def add_workspace_member(
    workspace_id: str,
    member: WorkspaceMember,
    current_user: dict = Depends(get_current_db_user)
):
    user_id = current_user['id']
    async with db.get_db_connection() as conn:
        cursor = await conn.execute("SELECT user_id FROM workspaces WHERE id = ?", (workspace_id,))
        workspace = await cursor.fetchone()
        if not workspace:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")
        if not current_user['is_admin'] and workspace['user_id'] != user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No permission")
        cursor = await conn.execute("SELECT id FROM users WHERE id = ?", (member.user_id,))
        if not await cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        try:
            await conn.execute("INSERT INTO workspace_members (workspace_id, user_id) VALUES (?, ?)",
                               (workspace_id, member.user_id))
            await conn.commit()
        except aiosqlite.IntegrityError:
            raise HTTPException(status_code=400, detail="User already a member")
    return {"message": "User added to workspace"}



@app.post("/notes/{note_id}/attachments")
async def upload_attachment(note_id: str, file: UploadFile = File(...), current_user: dict = Depends(get_current_db_user)):
    async with db.get_db_connection() as conn:
        await get_note_for_user(note_id, current_user, conn)
    note_files_dir = FILES_DIR / f"note_{note_id}"
    note_files_dir.mkdir(exist_ok=True)
    file_path = note_files_dir / file.filename
    with open(file_path, "wb") as f:
        f.write(await file.read())
    return {"filename": file.filename, "file_path": str(file_path)}


async def get_note_for_user(note_id: str, current_user: dict, conn) -> dict:
    user_id = current_user['id']
    if current_user['is_admin']:
        query = "SELECT * FROM notes WHERE id = ?"
        cursor = await conn.execute(query, (note_id,))
    else:
        query = """
            SELECT n.*
            FROM notes n
            JOIN workspaces w ON n.workspace_id = w.id
            LEFT JOIN workspace_members wm ON n.workspace_id = wm.workspace_id
            WHERE n.id = ? AND (w.user_id = ? OR wm.user_id = ?)
        """
        cursor = await conn.execute(query, (note_id, user_id, user_id))
    note = await cursor.fetchone()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    return note


@app.get("/notes/")
async def get_notes(workspace_id: str, current_user: dict = Depends(get_current_db_user)):
    user_id = current_user['id']
    async with db.get_db_connection() as conn:
        if not current_user['is_admin']:
            cursor = await conn.execute("""
                SELECT w.id FROM workspaces w
                LEFT JOIN workspace_members wm ON w.id = wm.workspace_id
                WHERE w.id = ? AND (w.user_id = ? OR wm.user_id = ?)
            """, (workspace_id, user_id, user_id))
            if not await cursor.fetchone():
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No access")
        cursor = await conn.execute("SELECT * FROM notes WHERE workspace_id = ?", (workspace_id,))
        notes = [dict(row) for row in await cursor.fetchall()]
        for note in notes:
            tag_cursor = await conn.execute("SELECT tag_id FROM note_tags WHERE note_id = ?", (note['id'],))
            note['tags'] = [r['tag_id'] for r in await tag_cursor.fetchall()]
            note['filename'] = f"{note['id']}.json"
    return notes


@app.post("/notes/")
async def create_note(
    title: str = Form(...),
    content: str = Form(""),
    tags: str = Form("[]"),
    is_encrypted: bool = Form(False),
    workspace_id: str = Form(...),
    type: str = Form("text"),
    current_user: dict = Depends(get_current_db_user)
):
    user_id = current_user['id']
    async with db.get_db_connection() as conn:
        if not current_user['is_admin'] and not await check_workspace_access(workspace_id, user_id, conn):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No access")
        note_id = str(uuid.uuid4())
        FILES_DIR.joinpath(f"note_{note_id}").mkdir(exist_ok=True)
        try:
            note_tags = json.loads(tags)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid tags format")
        is_encrypted_int = int(is_encrypted)
        await conn.execute("""
            INSERT INTO notes (id, title, content, is_encrypted, created_at, modified_at, workspace_id, type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (note_id, title, content, is_encrypted_int, datetime.utcnow().isoformat(),
              datetime.utcnow().isoformat(), workspace_id, type))
        for tag_id in note_tags:
            try:
                await conn.execute("INSERT INTO note_tags (note_id, tag_id) VALUES (?, ?)", (note_id, tag_id))
            except aiosqlite.IntegrityError:
                print(f"Warning: Tag '{tag_id}' not found for note '{note_id}'")
        await conn.commit()
    return {
        "id": note_id,
        "title": title,
        "content": content,
        "tags": note_tags,
        "is_encrypted": bool(is_encrypted_int),
        "filename": f"{note_id}.json",
        "type": type
    }


@app.get("/notes/{note_id}")
async def get_note(note_id: str, current_user: dict = Depends(get_current_db_user)):
    async with db.get_db_connection() as conn:
        note = await get_note_for_user(note_id, current_user, conn)
        cursor = await conn.execute("SELECT tag_id FROM note_tags WHERE note_id = ?", (note_id,))
        tags = [r['tag_id'] for r in await cursor.fetchall()]
        note_dict = dict(note)
        note_dict['tags'] = tags
        note_dict['filename'] = f"{note_id}.json"
    return note_dict


@app.put("/notes/{note_id}")
async def update_note(
    note_id: str,
    title: str = Form(...),
    content: str = Form(...),
    tags: str = Form("[]"),
    is_encrypted: bool = Form(False),
    current_user: dict = Depends(get_current_db_user)
):
    async with db.get_db_connection() as conn:
        note = await get_note_for_user(note_id, current_user, conn)
        try:
            note_tags = json.loads(tags)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid tags format")
        is_encrypted_int = int(is_encrypted)
        await conn.execute("""
            UPDATE notes SET title = ?, content = ?, is_encrypted = ?, modified_at = ? WHERE id = ?
        """, (title, content, is_encrypted_int, datetime.utcnow().isoformat(), note_id))
        await conn.execute("DELETE FROM note_tags WHERE note_id = ?", (note_id,))
        for tag_id in note_tags:
            try:
                await conn.execute("INSERT INTO note_tags (note_id, tag_id) VALUES (?, ?)", (note_id, tag_id))
            except aiosqlite.IntegrityError:
                print(f"Warning: Tag '{tag_id}' not found for note '{note_id}'")
        await conn.commit()
    return {
        "id": note_id,
        "title": title,
        "content": content,
        "tags": note_tags,
        "is_encrypted": bool(is_encrypted_int),
        "filename": f"{note_id}.json"
    }


@app.delete("/notes/{note_id}")
async def delete_note(note_id: str, current_user: dict = Depends(get_current_db_user)):
    async with db.get_db_connection() as conn:
        await get_note_for_user(note_id, current_user, conn)
        await conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        await conn.commit()
    note_dir = FILES_DIR / f"note_{note_id}"
    if note_dir.exists():
        import shutil
        shutil.rmtree(note_dir)
    return {"message": f"Note '{note_id}' deleted"}


@app.get("/tags/")
async def get_all_tags(workspace_id: str, current_user: dict = Depends(get_current_db_user)):
    async with db.get_db_connection() as conn:
        await get_workspace_for_user(workspace_id, current_user, conn)
        cursor = await conn.execute("SELECT * FROM tags WHERE workspace_id = ?", (workspace_id,))
        tags = [dict(row) for row in await cursor.fetchall()]
        tags_data = {"tags": {}}
        for tag in tags:
            tag['children'] = []
            tags_data["tags"][tag['id']] = tag
        for tag_id, tag in tags_data["tags"].items():
            if tag['parent_id'] in tags_data["tags"]:
                tags_data["tags"][tag['parent_id']]['children'].append(tag_id)
    return tags_data


async def get_workspace_for_user(workspace_id: str, current_user: dict, conn) -> dict:
    user_id = current_user['id']
    if not current_user['is_admin']:
        if not await check_workspace_access(workspace_id, user_id, conn):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No access")
    cursor = await conn.execute("SELECT * FROM workspaces WHERE id = ?", (workspace_id,))
    workspace = await cursor.fetchone()
    if not workspace:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")
    return workspace


@app.post("/tags/")
async def add_tag_endpoint(
    name: str = Form(...),
    parent_id: Optional[str] = Form(None),
    icon: Optional[str] = Form(None),
    workspace_id: str = Form(...),
    current_user: dict = Depends(get_current_db_user)
):
    tag_id = f"tag_{uuid.uuid4().hex}"
    async with db.get_db_connection() as conn:
        await get_workspace_for_user(workspace_id, current_user, conn)
        if parent_id:
            cursor = await conn.execute("SELECT id FROM tags WHERE id = ? AND workspace_id = ?", (parent_id, workspace_id))
            if not await cursor.fetchone():
                raise HTTPException(status_code=400, detail="Parent tag not found")
        await conn.execute("INSERT INTO tags (id, name, parent_id, icon, workspace_id) VALUES (?, ?, ?, ?, ?)",
                           (tag_id, name, parent_id, icon, workspace_id))
        await conn.commit()
    return {"message": "Tag added", "tag": {"id": tag_id, "name": name, "parent_id": parent_id, "icon": icon, "children": []}}


@app.put("/tags/{tag_id}")
async def update_tag(
    tag_id: str,
    name: str = Form(...),
    icon: Optional[str] = Form(None),
    workspace_id: str = Form(...),
    current_user: dict = Depends(get_current_db_user)
):
    async with db.get_db_connection() as conn:
        await get_workspace_for_user(workspace_id, current_user, conn)
        cursor = await conn.execute("SELECT * FROM tags WHERE id = ? AND workspace_id = ?", (tag_id, workspace_id))
        if not await cursor.fetchone():
            raise HTTPException(status_code=404, detail="Tag not found")
        await conn.execute("UPDATE tags SET name = ?, icon = ? WHERE id = ?", (name, icon, tag_id))
        await conn.commit()
        cursor = await conn.execute("SELECT * FROM tags WHERE id = ?", (tag_id,))
        tag = dict(await cursor.fetchone())
    return {"message": "Tag updated", "tag": tag}


@app.delete("/tags/{tag_id}")
async def delete_tag(tag_id: str, workspace_id: str, current_user: dict = Depends(get_current_db_user)):
    async with db.get_db_connection() as conn:
        await get_workspace_for_user(workspace_id, current_user, conn)
        cursor = await conn.execute("SELECT id FROM tags WHERE id = ? AND workspace_id = ?", (tag_id, workspace_id))
        if not await cursor.fetchone():
            raise HTTPException(status_code=404, detail="Tag not found")
        tags_to_delete = [tag_id]
        async def collect_children(tid):
            cursor = await conn.execute("SELECT id FROM tags WHERE parent_id = ? AND workspace_id = ?", (tid, workspace_id))
            for row in await cursor.fetchall():
                cid = row['id']
                if cid not in tags_to_delete:
                    tags_to_delete.append(cid)
                    await collect_children(cid)
        await collect_children(tag_id)
        for tid in reversed(tags_to_delete):
            await conn.execute("DELETE FROM tags WHERE id = ?", (tid,))
        await conn.commit()
    return {"message": f"Tags {tags_to_delete} deleted"}


@app.get("/health")
async def health_check():
    return {"status": "ok"}



STATIC_DIR_FRONTEND = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'angular', 'dist', 'proteya_notes', 'browser')
)
app.mount("/", StaticFiles(directory=STATIC_DIR_FRONTEND, html=True), name="root_static")



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend:app",
        host="0.0.0.0",
        port=8000,
        reload=False
    )
