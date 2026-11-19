from pathlib import Path
import base64
import hashlib
import json

ROOT = Path("loadtests/fixtures/generated")
ROOT.mkdir(parents=True, exist_ok=True)


def text_payload(seed: str, length: int) -> bytes:
    raw_length = (length * 3 + 3) // 4 + 3
    raw = hashlib.shake_256(seed.encode()).digest(raw_length)
    return base64.b64encode(raw)[:length]


manifest = []

for i in range(100):
    if i < 50:
        size = 4 * 1024
    elif i < 80:
        size = 64 * 1024
    elif i < 95:
        size = 256 * 1024
    else:
        size = 1024 * 1024

    kind = i % 3

    if kind == 0:
        ext = "txt"
        prefix = f"Benchmark fixture {i}\n".encode()
        content = prefix + text_payload(f"txt:{i}", size - len(prefix))

    elif kind == 1:
        ext = "json"
        prefix = f'{{"fixture_id":{i},"data":"'.encode()
        suffix = b'"}'
        content = (
            prefix
            + text_payload(
                f"json:{i}",
                size - len(prefix) - len(suffix),
            )
            + suffix
        )

    else:
        ext = "bin"
        content = hashlib.shake_256(f"binary:{i}".encode()).digest(size)

    filename = f"file-{i:03d}.{ext}"
    (ROOT / filename).write_bytes(content)

    manifest.append(
        {
            "filename": filename,
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    )

(ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2))

print(f"Generated {len(manifest)} fixtures in {ROOT}")
