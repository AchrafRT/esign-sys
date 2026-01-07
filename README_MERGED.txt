MERGED 5+6 (clean)

- Kept Folder 5 structure (app/, cfg/, www/, db/, assets/)
- Dropped PHP
- Replaced UI with improved contract.html (inline CSS)
- Added mapper.html for pixel-accurate mapping
- Server: stdlib only, deterministic overlay from cfg/field_map_px.json (pixels -> % at render time)

Run:
  python app/server.py

Open:
  http://127.0.0.1:8080/contract
Mapper:
  http://127.0.0.1:8080/mapper?page=1

Field map:
  cfg/field_map_px.json