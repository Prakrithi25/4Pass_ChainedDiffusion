import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from skimage import data, color, transform, io
import urllib.request
import os

# ==========================================
# 1. SETUP & HELPER FUNCTIONS
# ==========================================
def chacha20_keystream(key: bytes, nonce: bytes, nbytes: int) -> bytes:
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    enc = cipher.encryptor()
    return enc.update(b"\x00" * nbytes)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def fisher_yates(n: int, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    perm = np.arange(n)
    for i in range(n - 1, 0, -1):
        j = int(rng.integers(0, i + 1))
        perm[i], perm[j] = perm[j], perm[i]
    return perm

def keyed_sbox(seed: int) -> np.ndarray:
    return fisher_yates(256, seed).astype(np.uint8)

def apply_permutation(img: np.ndarray, perm: np.ndarray) -> np.ndarray:
    return img.flatten()[perm].reshape(img.shape)

def inverse_permutation(img: np.ndarray, perm: np.ndarray) -> np.ndarray:
    flat = img.flatten()
    out = np.empty_like(flat)
    out[perm] = flat
    return out.reshape(img.shape)

def apply_sbox(img: np.ndarray, sbox: np.ndarray) -> np.ndarray:
    return sbox[img]

def chacha20_encrypt(img: np.ndarray, key: bytes, nonce: bytes) -> np.ndarray:
    data = img.tobytes()
    ks = chacha20_keystream(key, nonce, len(data))
    return np.frombuffer(xor_bytes(data, ks), dtype=np.uint8).reshape(img.shape)

# ==========================================
# 2. CIPHERS (Base Paper A2 vs Proposed A3)
# ==========================================
def diffuse_cbc_forward(img: np.ndarray) -> np.ndarray:
    out = img.copy()
    H, W = img.shape
    for i in range(H):
        for j in range(1, W): out[i, j] = img[i, j] ^ out[i, j - 1]
    for j in range(W):
        for i in range(1, H): out[i, j] = out[i, j] ^ out[i - 1, j]
    return out

def diffuse_cbc_inverse(img: np.ndarray) -> np.ndarray:
    out = img.copy()
    H, W = img.shape
    for j in range(W):
        for i in range(H - 1, 0, -1): out[i, j] = img[i, j] ^ img[i - 1, j]
    for i in range(H):
        for j in range(W - 1, 0, -1): out[i, j] = out[i, j] ^ out[i, j - 1]
    return out

def diffuse_4pass(img: np.ndarray, keystream: np.ndarray, sbox: np.ndarray) -> np.ndarray:
    flat = img.flatten().astype(np.int64)
    ks = keystream.flatten().astype(np.int64)
    sbox_64 = sbox.astype(np.int64)
    n = len(flat)
    for i in range(1, n): flat[i] = sbox_64[(flat[i] + flat[i - 1] + ks[i]) % 256]
    for i in range(n - 2, -1, -1): flat[i] = sbox_64[(flat[i] + flat[i + 1] + ks[i]) % 256]
    for i in range(1, n): flat[i] = sbox_64[(flat[i] + flat[i - 1] + ks[i]) % 256]
    for i in range(n - 2, -1, -1): flat[i] = sbox_64[(flat[i] + flat[i + 1] + ks[i]) % 256]
    return flat.reshape(img.shape).astype(np.uint8)

def diffuse_4pass_inverse(img: np.ndarray, keystream: np.ndarray, sbox: np.ndarray) -> np.ndarray:
    inv_sbox = np.empty(256, dtype=np.int64)
    inv_sbox[sbox] = np.arange(256, dtype=np.int64)
    flat = img.flatten().astype(np.int64)
    ks = keystream.flatten().astype(np.int64)
    n = len(flat)
    for i in range(0, n - 1): flat[i] = (inv_sbox[flat[i]] - flat[i + 1] - ks[i]) % 256
    for i in range(n - 1, 0, -1): flat[i] = (inv_sbox[flat[i]] - flat[i - 1] - ks[i]) % 256
    for i in range(0, n - 1): flat[i] = (inv_sbox[flat[i]] - flat[i + 1] - ks[i]) % 256
    for i in range(n - 1, 0, -1): flat[i] = (inv_sbox[flat[i]] - flat[i - 1] - ks[i]) % 256
    return flat.reshape(img.shape).astype(np.uint8)

def encrypt_A2(img, key, nonce, sbox, ks, PERM):
    p = apply_permutation(img, PERM)
    s = apply_sbox(p, sbox)
    d = diffuse_cbc_forward(s)
    return chacha20_encrypt(d, key, nonce)

def decrypt_A2(img, key, nonce, sbox, ks, PERM):
    c = chacha20_encrypt(img, key, nonce) # ChaCha is symmetric
    d = diffuse_cbc_inverse(c)
    inv_sbox = np.empty(256, dtype=np.uint8); inv_sbox[sbox] = np.arange(256, dtype=np.uint8)
    s = inv_sbox[d]
    return inverse_permutation(s, PERM)

def encrypt_A3(img, key, nonce, sbox, ks, PERM):
    p = apply_permutation(img, PERM)
    s = apply_sbox(p, sbox)
    d = diffuse_4pass(s, ks, sbox)
    return chacha20_encrypt(d, key, nonce)

def decrypt_A3(img, key, nonce, sbox, ks, PERM):
    c = chacha20_encrypt(img, key, nonce)
    d = diffuse_4pass_inverse(c, ks, sbox)
    inv_sbox = np.empty(256, dtype=np.uint8); inv_sbox[sbox] = np.arange(256, dtype=np.uint8)
    s = inv_sbox[d]
    return inverse_permutation(s, PERM)

# ==========================================
# 3. METRICS
# ==========================================
def calc_npcr_uaci(c1, c2):
    d = (c1 != c2).astype(np.float64)
    npcr = d.mean() * 100.0
    uaci = np.abs(c1.astype(np.float64) - c2.astype(np.float64)).mean() / 255.0 * 100.0
    return npcr, uaci

def calc_entropy(img):
    hist, _ = np.histogram(img, bins=256, range=(0, 256))
    hist = hist / hist.sum()
    hist = hist[hist > 0]
    return -np.sum(hist * np.log2(hist))

def calc_correlation(img):
    # Horizontal, Vertical, Diagonal
    x = img[:, :-1].flatten(); y = img[:, 1:].flatten()
    h_corr = np.corrcoef(x, y)[0, 1] if len(x) > 1 else 0
    x = img[:-1, :].flatten(); y = img[1:, :].flatten()
    v_corr = np.corrcoef(x, y)[0, 1] if len(x) > 1 else 0
    x = img[:-1, :-1].flatten(); y = img[1:, 1:].flatten()
    d_corr = np.corrcoef(x, y)[0, 1] if len(x) > 1 else 0
    return h_corr, v_corr, d_corr

# ==========================================
# 4. DATASET PREPARATION
# ==========================================
def get_images():
    imgs = {}
    # 1. Cameraman (256x256)
    imgs["cameraman_256"] = data.camera()[:256, :256]
    # 2. Hurricane Katrina (Simulated via astronaut crop to match base paper size 601x601, resized to 256)
    imgs["katrina_256"] = color.rgb2gray(data.astronaut())[:256, :256] * 255
    # 3. Honeybadger (Simulated via coffee image)
    imgs["honeybadger_256"] = color.rgb2gray(data.coffee())[:256, :256] * 255
    # 4. Aeroblk (Simulated via chelsea)
    imgs["aeroblk_256"] = color.rgb2gray(data.chelsea())[:256, :256] * 255

    # 5. Varied Sizes (Cameraman)
    imgs["cameraman_128"] = transform.resize(data.camera(), (128, 128)) * 255
    imgs["cameraman_512"] = transform.resize(data.camera(), (512, 512)) * 255

    # 6. Edge Cases
    imgs["all_black_256"] = np.zeros((256, 256))
    imgs["all_white_256"] = np.ones((256, 256)) * 255

    # Convert to uint8
    return {k: v.astype(np.uint8) for k, v in imgs.items()}

# ==========================================
# 5. EXPERIMENT RUNNER
# ==========================================
def run_experiment():
    images = get_images()
    key = bytes(range(32))
    nonce = bytes(range(16))

    results = []

    print("Starting extensive metric evaluation... This will take ~1 minute.")

    for name, img in images.items():
        H, W = img.shape
        PERM = fisher_yates(img.size, seed=12345)
        sbox = keyed_sbox(seed=67890)
        ks = np.frombuffer(chacha20_keystream(key, nonce, img.size), dtype=np.uint8).reshape(img.shape)

        # -- A2 Pipeline --
        c2 = encrypt_A2(img, key, nonce, sbox, ks, PERM)
        dec2 = decrypt_A2(c2, key, nonce, sbox, ks, PERM)

        # -- A3 Pipeline --
        c3 = encrypt_A3(img, key, nonce, sbox, ks, PERM)
        dec3 = decrypt_A3(c3, key, nonce, sbox, ks, PERM)

        # Plaintext vs Ciphertext
        p2_npcr, p2_uaci = calc_npcr_uaci(img, c2)
        p3_npcr, p3_uaci = calc_npcr_uaci(img, c3)

        # Plaintext vs Decrypted (Should be 0 NPCR, 0 UACI)
        d2_npcr, d2_uaci = calc_npcr_uaci(img, dec2)
        d3_npcr, d3_uaci = calc_npcr_uaci(img, dec3)

        # Key Sensitivity
        key2 = bytearray(key); key2[0] ^= 1; key2 = bytes(key2)
        c2_k2 = encrypt_A2(img, key2, nonce, sbox, ks, PERM)
        c3_k2 = encrypt_A3(img, key2, nonce, sbox, ks, PERM)
        k2_npcr, k2_uaci = calc_npcr_uaci(c2, c2_k2)
        k3_npcr, k3_uaci = calc_npcr_uaci(c3, c3_k2)

        # Plaintext Sensitivity (20 trials)
        pt2_npcrs, pt3_npcrs = [], []
        pt2_uacis, pt3_uacis = [], []
        rng = np.random.default_rng(42)
        for _ in range(20):
            i0, j0 = rng.integers(0, H, 2)
            img_t = img.copy()
            img_t[i0, j0] = (int(img_t[i0, j0]) + 1) % 256

            t_c2 = encrypt_A2(img_t, key, nonce, sbox, ks, PERM)
            t_c3 = encrypt_A3(img_t, key, nonce, sbox, ks, PERM)

            n2, u2 = calc_npcr_uaci(c2, t_c2); pt2_npcrs.append(n2); pt2_uacis.append(u2)
            n3, u3 = calc_npcr_uaci(c3, t_c3); pt3_npcrs.append(n3); pt3_uacis.append(u3)

        # Structural Metrics
        ent2, ent3 = calc_entropy(c2), calc_entropy(c3)
        corr2, corr3 = calc_correlation(c2), calc_correlation(c3)

        results.append({
            "Image": name,
            "Size": f"{H}x{W}",
            "Method": "A2 (Base)",
            "PvsC_NPCR": p2_npcr, "PvsC_UACI": p2_uaci,
            "PtSens_NPCR": np.mean(pt2_npcrs), "PtSens_UACI": np.mean(pt2_uacis),
            "KeySens_NPCR": k2_npcr, "KeySens_UACI": k2_uaci,
            "Dec_NPCR": d2_npcr, "Entropy": ent2,
            "Corr_H": corr2[0], "Corr_V": corr2[1], "Corr_D": corr2[2]
        })

        results.append({
            "Image": name,
            "Size": f"{H}x{W}",
            "Method": "A3 (Prop)",
            "PvsC_NPCR": p3_npcr, "PvsC_UACI": p3_uaci,
            "PtSens_NPCR": np.mean(pt3_npcrs), "PtSens_UACI": np.mean(pt3_uacis),
            "KeySens_NPCR": k3_npcr, "KeySens_UACI": k3_uaci,
            "Dec_NPCR": d3_npcr, "Entropy": ent3,
            "Corr_H": corr3[0], "Corr_V": corr3[1], "Corr_D": corr3[2]
        })

    df = pd.DataFrame(results)
    df.to_csv("comprehensive_metrics.csv", index=False)
    print("Saved: comprehensive_metrics.csv")
    return df

df = run_experiment()

# ==========================================
# 6. OUTPUT DISPLAY
# ==========================================
# Re-arrange columns for readability
cols = ["Image", "Method", "Size", "PvsC_NPCR", "PtSens_NPCR", "KeySens_NPCR", "Dec_NPCR", "Entropy"]
print("\n--- TABLE 1: NPCR SUMMARY ACROSS ALL METRICS ---")
print(df[cols].to_string(index=False, formatters={
    "PvsC_NPCR": "{:.2f}%".format,
    "PtSens_NPCR": "{:.2f}%".format,
    "KeySens_NPCR": "{:.2f}%".format,
    "Dec_NPCR": "{:.2f}%".format,
    "Entropy": "{:.4f}".format
}))

print("\n--- TABLE 2: UACI SUMMARY ACROSS ALL METRICS ---")
cols_uaci = ["Image", "Method", "PvsC_UACI", "PtSens_UACI", "KeySens_UACI"]
print(df[cols_uaci].to_string(index=False, formatters={c: "{:.2f}%".format for c in cols_uaci[2:]}))

print("\n--- TABLE 3: CORRELATION & LIMITS ---")
cols_corr = ["Image", "Method", "Corr_H", "Corr_V", "Corr_D"]
print(df[cols_corr].to_string(index=False, formatters={c: "{:.4f}".format for c in cols_corr[2:]}))

print("\nLimits: NPCR Critical = 99.569% | UACI Critical = (33.283%, 33.644%)")
