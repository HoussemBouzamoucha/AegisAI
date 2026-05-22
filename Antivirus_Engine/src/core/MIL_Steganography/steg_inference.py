"""
MIL Steganography Inference Script
===================================
Detects LSB steganography using the exported TorchScript model (model_scripted.pt).
No timm / model source code required at inference time.

Architecture: SRMFilter -> EfficientNet-B0 -> AttentionMIL -> Classifier
Trained on: BOSSbase 1.01, LSB replacement @ 0.4 bpp, 256×256 lossless PNG

Modes
-----
Scan (default):
    python steg_inference.py --paths image1.png image2.png ...
    echo '{"paths":["img.png"]}' | python steg_inference.py

Embed LSB (generate a test stego image):
    python steg_inference.py --embed src.png dst_stego.png [--rate 0.4]

Scan output JSON schema (array, one entry per image):
    { path, stego_prob, is_stego, verdict, lsb_ones_ratio, warning, error }

    lsb_ones_ratio — fraction of pixels whose LSB == 1 (0.0–1.0).
      A natural image typically sits in [0.30, 0.65].
      True LSB steganography pushes this toward 0.50 ± 0.02.
      Use this to explain surprising clean/stego verdicts.
"""
import sys, os, json, random, warnings
from pathlib import Path

warnings.filterwarnings("ignore")

MODEL_DIR       = Path(__file__).parent
PATCH_SIZE      = 64
NUM_PATCHES     = 30          # matches inference_config.json
STEGO_THRESHOLD = 0.5

# ─── TorchScript model (loaded once) ─────────────────────────────────────────

_model  = None
_device = None


def get_model():
    global _model, _device
    if _model is not None:
        return _model, _device
    import torch
    script_path = MODEL_DIR / "model_scripted.pt"
    if not script_path.exists():
        raise FileNotFoundError(f"TorchScript model not found: {script_path}")
    _device = "cuda" if torch.cuda.is_available() else "cpu"
    _model  = torch.jit.load(str(script_path), map_location=_device)
    _model.eval()
    return _model, _device


# ─── LSB diagnostic ──────────────────────────────────────────────────────────

def lsb_ones_ratio(arr_uint8):
    """Fraction of pixels with LSB == 1.  Ideal LSB stego → ~0.50."""
    import numpy as np
    lsb = arr_uint8.flatten() & 1
    return float(lsb.mean())


# ─── Image → bag of patches ──────────────────────────────────────────────────

def image_to_bag(img_path: str, num_patches: int, patch_size: int):
    """
    Load image → grayscale → replicate to 3-ch → sample random patches.
    Returns (bag tensor [1, N, 3, ps, ps] in [0,1], lsb_ratio, warning).
    """
    import numpy as np, torch
    from PIL import Image

    warning = None
    pl = img_path.lower()
    if pl.endswith(".jpg") or pl.endswith(".jpeg"):
        warning = (
            "JPEG detected — JPEG recompression destroys LSB signal; "
            "convert to lossless PNG before embedding steganography"
        )

    img = Image.open(img_path).convert("L")
    arr = np.array(img, dtype=np.uint8)
    H, W = arr.shape

    if min(H, W) < patch_size:
        raise ValueError(
            f"Image too small ({W}×{H}); minimum {patch_size}×{patch_size} px required"
        )

    lsb_ratio = lsb_ones_ratio(arr)

    # Replicate L to 3 channels
    arr3 = arr.astype(np.float32)
    arr3 = arr3[:, :, None] * np.ones((1, 1, 3), dtype=np.float32)   # (H,W,3)

    patches = []
    for _ in range(num_patches):
        y = random.randint(0, max(H - patch_size - 1, 0))
        x = random.randint(0, max(W - patch_size - 1, 0))
        patch = arr3[y : y + patch_size, x : x + patch_size]
        t = torch.from_numpy(patch).permute(2, 0, 1).float() / 255.0
        patches.append(t)

    bag = torch.stack(patches).unsqueeze(0)   # (1, N, 3, ps, ps)
    return bag, lsb_ratio, warning


# ─── Single image inference ───────────────────────────────────────────────────

def predict_single(img_path: str) -> dict:
    try:
        import torch
        model, device = get_model()
        bag, lsb_ratio, warn = image_to_bag(img_path, NUM_PATCHES, PATCH_SIZE)
        bag = bag.to(device)

        with torch.no_grad():
            logits, _ = model(bag)
            probs      = torch.softmax(logits, dim=1)
            stego_prob = float(probs[0, 1].item())

        is_stego = stego_prob >= STEGO_THRESHOLD

        # Build an explanatory warning when the verdict seems wrong
        if warn is None:
            if not is_stego and (lsb_ratio < 0.30 or lsb_ratio > 0.70):
                warn = (
                    f"Low stego probability consistent with LSB bias "
                    f"({lsb_ratio:.2%} ones) — natural images have non-uniform LSBs"
                )
            elif is_stego and abs(lsb_ratio - 0.5) > 0.15:
                warn = (
                    f"High stego probability but unusual LSB distribution "
                    f"({lsb_ratio:.2%} ones) — verify embedding method"
                )

        return {
            "path":           img_path,
            "stego_prob":     round(stego_prob, 6),
            "is_stego":       is_stego,
            "verdict":        "stego" if is_stego else "clean",
            "lsb_ones_ratio": round(lsb_ratio, 4),
            "warning":        warn,
            "error":          None,
        }
    except Exception as exc:
        return {
            "path":           img_path,
            "stego_prob":     None,
            "is_stego":       None,
            "verdict":        "error",
            "lsb_ones_ratio": None,
            "warning":        None,
            "error":          str(exc),
        }


# ─── LSB embed (test-stego generator) ────────────────────────────────────────

def embed_lsb(src_path: str, dst_path: str, payload_rate: float = 0.4) -> dict:
    """
    Embed random payload bits at `payload_rate` bpp (bits per pixel) using
    LSB replacement — the exact method used to create the training data.
    Converts the source to grayscale and saves as lossless PNG.
    Returns { dst_path, pixels_modified, lsb_ones_before, lsb_ones_after }.
    """
    import numpy as np
    from PIL import Image

    img = Image.open(src_path).convert("L")
    arr = np.array(img, dtype=np.uint8)
    H, W = arr.shape
    n_embed = max(1, int(H * W * payload_rate))

    before = lsb_ones_ratio(arr)

    flat    = arr.flatten()
    indices = np.random.choice(H * W, n_embed, replace=False)
    payload = np.random.randint(0, 2, n_embed, dtype=np.uint8)
    flat[indices] = (flat[indices] & 0xFE) | payload
    stego_arr = flat.reshape(H, W)

    after = lsb_ones_ratio(stego_arr)

    Image.fromarray(stego_arr, "L").save(dst_path, "PNG", optimize=False)

    return {
        "dst_path":          dst_path,
        "pixels_modified":   int(n_embed),
        "lsb_ones_before":   round(before, 4),
        "lsb_ones_after":    round(after,  4),
    }


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]

    # ── Embed mode: --embed src.png dst.png [--rate 0.4] ─────────────────────
    if args and args[0] == "--embed":
        if len(args) < 3:
            print(json.dumps({"error": "--embed requires <src> <dst> arguments"}))
            return
        src  = args[1]
        dst  = args[2]
        rate = 0.4
        if "--rate" in args:
            idx  = args.index("--rate")
            rate = float(args[idx + 1])
        try:
            result = embed_lsb(src, dst, rate)
            print(json.dumps({"success": True, **result}))
        except Exception as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
        return

    # ── Scan mode ─────────────────────────────────────────────────────────────
    paths = []
    if args and args[0] == "--paths":
        paths = args[1:]
    elif not sys.stdin.isatty():
        try:
            data  = json.load(sys.stdin)
            paths = data.get("paths", [])
        except json.JSONDecodeError:
            pass

    if not paths:
        print(json.dumps([]))
        return

    results = [predict_single(p) for p in paths]
    print(json.dumps(results))


if __name__ == "__main__":
    main()
