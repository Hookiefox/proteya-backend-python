import asyncio
import json
import websockets
import uuid
from collections import defaultdict


rooms = defaultdict(lambda: {
    'peers': {},  
})

async def handler(websocket):
    peer_id = None
    room_id = None
    
    try:
        
        path = websocket.request.path
        path_parts = path.strip('/').split('/')
        
        if len(path_parts) < 2:
            print("Invalid path format")
            await websocket.close()
            return
            
        room_id, peer_id = path_parts[0], path_parts[1]
        print(f"Peer {peer_id} attempting to join room {room_id}")

        
        
        if room_id in rooms:
            existing_peers = list(rooms[room_id]['peers'].keys())
            await websocket.send(json.dumps({
                "type": "existing-peers",
                "peerIds": existing_peers
            }))

        
        if room_id in rooms:
            for pid, ws in list(rooms[room_id]['peers'].items()):
                try:
                    await ws.send(json.dumps({"type": "peer-joined", "peerId": peer_id}))
                except Exception as e:
                    print(f"Error notifying peer {pid}: {e}")

        
        rooms[room_id]['peers'][peer_id] = websocket
        print(f"Peer {peer_id} joined room {room_id}")

        
        async for message in websocket:
            try:
                if isinstance(message, str):
                    
                    data = json.loads(message)
                    target_peer_id = data.get("targetPeerId")
                    
                    
                    data["fromPeerId"] = peer_id

                    
                    if target_peer_id and target_peer_id in rooms[room_id]['peers']:
                        target_ws = rooms[room_id]['peers'][target_peer_id]
                        try:
                            await target_ws.send(json.dumps(data))
                        except Exception as e:
                            print(f"Error sending message to {target_peer_id}: {e}")
                else:
                    
                    for pid, ws in list(rooms[room_id]['peers'].items()):
                        if pid != peer_id:
                            try:
                                await ws.send(message)
                            except Exception as e:
                                print(f"Error forwarding media to {pid}: {e}")
                                
            except json.JSONDecodeError:
                
                for pid, ws in list(rooms[room_id]['peers'].items()):
                    if pid != peer_id:
                        try:
                            await ws.send(message)
                        except Exception as e:
                            print(f"Error forwarding data to {pid}: {e}")
            except Exception as e:
                print(f"Error processing message from {peer_id}: {e}")

    except websockets.exceptions.ConnectionClosed as e:
        print(f"Connection for peer {peer_id} closed: {e}")
    except Exception as e:
        print(f"An error occurred with peer {peer_id}: {e}")
    finally:
        
        if room_id and peer_id:
            if room_id in rooms and peer_id in rooms[room_id]['peers']:
                del rooms[room_id]['peers'][peer_id]
                print(f"Peer {peer_id} left room {room_id}")
                
                
                for pid, ws in list(rooms[room_id]['peers'].items()):
                    try:
                        await ws.send(json.dumps({"type": "peer-left", "peerId": peer_id}))
                    except Exception as e:
                        print(f"Error notifying peer {pid} about {peer_id} leaving: {e}")
                
                
                if not rooms[room_id]['peers']:
                    del rooms[room_id]
                    print(f"Room {room_id} is now empty and has been removed.")

async def main():
    async with websockets.serve(handler, "0.0.0.0", 8765):
        print("SFU Voice server started on ws://0.0.0.0:8765")
        await asyncio.Future()



if __name__ == "__main__":
    asyncio.run(main())