"""
ZT-XGuard - src/ztx_model/transforms.py

Deterministic feature transformations for Step 37.

Only transformations selected from the Step 36 evidence are applied by the
Step 37 script. Any fitted transform parameter, such as a Yeo-Johnson lambda,
must be fitted from N1+N2 only by the caller.
"""
from __future__ import annotations

import numpy as np


SUPPORTED_TRANSFORMS = frozenset({"identity", "log1p", "signed_log1p", "yeo_johnson"})


def _finite_array(x: np.ndarray) -> np.ndarray:
    arr = np.asarray(x, dtype=float)
    return arr[np.isfinite(arr)]


def identity_transform(x: np.ndarray) -> np.ndarray:
    """Return a float copy without changing the feature scale."""
    return np.asarray(x, dtype=float)


def log1p_transform(x: np.ndarray) -> np.ndarray:
    """log1p transform for nonnegative features."""
    arr = np.asarray(x, dtype=float)
    finite = _finite_array(arr)
    if finite.size and np.min(finite) < 0:
        raise ValueError("log1p_transform requires nonnegative finite values.")
    return np.log1p(arr)


def signed_log1p_transform(x: np.ndarray) -> np.ndarray:
    """sign(x) * log1p(abs(x)) for signed features."""
    arr = np.asarray(x, dtype=float)
    return np.sign(arr) * np.log1p(np.abs(arr))


def inverse_log1p(x: np.ndarray) -> np.ndarray:
    return np.expm1(np.asarray(x, dtype=float))


def inverse_signed_log1p(x: np.ndarray) -> np.ndarray:
    arr = np.asarray(x, dtype=float)
    return np.sign(arr) * np.expm1(np.abs(arr))


def apply_transform(
    x: np.ndarray,
    transform_name: str,
    lambda_value: float | None = None,
) -> np.ndarray:
    """Apply a named deterministic transform."""
    if transform_name not in SUPPORTED_TRANSFORMS:
        raise ValueError(f"Unsupported transform: {transform_name!r}")
    if transform_name == "identity":
        return identity_transform(x)
    if transform_name == "log1p":
        return log1p_transform(x)
    if transform_name == "signed_log1p":
        return signed_log1p_transform(x)
    if lambda_value is None:
        raise ValueError("Yeo-Johnson transform requires a fitted lambda_value.")

    from scipy import stats

    arr = np.asarray(x, dtype=float)
    return stats.yeojohnson(arr, lmbda=float(lambda_value))


def fit_yeo_johnson_lambda(x: np.ndarray) -> float:
    """Fit the Yeo-Johnson lambda by maximum likelihood on finite values."""
    from scipy import stats

    finite = _finite_array(np.asarray(x, dtype=float))
    if finite.size == 0:
        raise ValueError("Cannot fit Yeo-Johnson lambda on an empty finite vector.")
    if np.all(finite == finite[0]):
        raise ValueError("Cannot fit Yeo-Johnson lambda on a constant vector.")
    return float(stats.yeojohnson_normmax(finite))
