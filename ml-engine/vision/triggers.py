"""Backdoor trigger detection in training imagery.

Two independent detectors run, because patch triggers and blended triggers leave
completely different traces.

**Per-image spectral and local-variance screening.** A BadNets-style patch is a small,
high-contrast, low-entropy region pasted over natural content. It shows up as excess
high-frequency energy in the 2-D FFT and as a local window whose variance and colour
statistics are wildly inconsistent with the rest of the image. This localises a
candidate bounding box, which is what an analyst needs to adjudicate the sample.

**Cross-sample consensus.** This is the stronger signal and the one that actually
separates a trigger from ordinary image content. A backdoor only works if the trigger is
*the same pattern in the same place* across every poisoned sample -- that consistency is
the attack's functional requirement, and it is not something natural imagery reproduces.
We build a per-class median image, take each sample's residual against it, and look for a
cluster of samples whose residual peaks at the same coordinates. When such a cluster
exists we average its residual patches to **recover the trigger itself**, which is
returned as evidence.

Covered by design: BadNets patches, blended/global overlays, corner and checkerboard
marks. Not covered: input-aware and warping attacks (WaNet, BppAttack) whose
perturbation is sample-specific and therefore leaves no cross-sample consensus; those
require the model-side Neural Cleanse and behavioural battery instead. That boundary is
published in the coverage matrix rather than left implicit.

References: Gu et al. (BadNets, 2017); Chen et al. (Blended, 2017); Nguyen & Tran
(WaNet, 2021); Tran et al. (Spectral Signatures, 2018).
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Sequence

import numpy as np

from core.config import SETTINGS


@dataclass
class TriggerCandidate:
    """One sample flagged as carrying a trigger artifact."""

    path: str
    score: float
    confidence: float
    bbox: tuple[int, int, int, int]  # x0, y0, x1, y1 in 64x64 analysis space
    bbox_original: tuple[int, int, int, int] | None
    method: str
    perturbation_magnitude: float
    high_freq_z: float
    patch_variance_ratio: float
    label: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "anomalyScore": round(self.score, 4),
            "confidence": round(self.confidence, 4),
            "bbox": list(self.bbox),
            "bboxOriginal": list(self.bbox_original) if self.bbox_original else None,
            "method": self.method,
            "perturbationMagnitude": round(self.perturbation_magnitude, 3),
            "highFrequencyZ": round(self.high_freq_z, 3),
            "patchVarianceRatio": round(self.patch_variance_ratio, 3),
            "label": self.label,
        }


@dataclass
class TriggerCluster:
    """A group of samples sharing one trigger, plus the recovered pattern."""

    label: str
    member_paths: list[str]
    bbox: tuple[int, int, int, int]
    consistency: float
    mean_magnitude: float
    recovered_patch_rgb: list[list[list[int]]]
    family: str
    reference: str = "class-median"
    significance: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "memberCount": len(self.member_paths),
            "members": self.member_paths[:24],
            "bbox": list(self.bbox),
            "spatialConsistency": round(self.consistency, 4),
            "meanPerturbationMagnitude": round(self.mean_magnitude, 3),
            "recoveredTriggerPatch": self.recovered_patch_rgb,
            "suspectedFamily": self.family,
            "referenceFrame": self.reference,
            "familyWisePValue": float(f"{self.significance:.3g}"),
        }


@dataclass
class TriggerReport:
    candidates: list[TriggerCandidate] = field(default_factory=list)
    clusters: list[TriggerCluster] = field(default_factory=list)
    analysed: int = 0
    consensus_available: bool = False
    limitation: str = ""

    @property
    def confirmed_samples(self) -> int:
        """Samples inside a consensus cluster -- the high-confidence population."""
        return sum(len(c.member_paths) for c in self.clusters)

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysedSamples": self.analysed,
            "candidateCount": len(self.candidates),
            "candidates": [c.to_dict() for c in self.candidates[:60]],
            "clusters": [c.to_dict() for c in self.clusters[:12]],
            "clusterCount": len(self.clusters),
            "confirmedSamples": self.confirmed_samples,
            "consensusAvailable": self.consensus_available,
            "limitation": self.limitation,
        }


# --- per-image screening ---------------------------------------------------------


def high_frequency_ratio(gray: np.ndarray) -> float:
    """Share of spectral energy above the half-Nyquist radius.

    Natural scenes concentrate energy at low spatial frequency. A pasted patch with hard
    edges injects broadband energy, which lifts this ratio.
    """
    spectrum = np.fft.fftshift(np.abs(np.fft.fft2(gray - gray.mean())))
    h, w = spectrum.shape
    cy, cx = h // 2, w // 2
    yy, xx = np.ogrid[:h, :w]
    radius = np.sqrt((yy - cy) ** 2 + (xx - cx) ** 2)
    cutoff = min(cy, cx) * 0.5
    total = spectrum.sum()
    if total <= 0:
        return 0.0
    return float(spectrum[radius > cutoff].sum() / total)


def _local_variance_peak(gray: np.ndarray, window: int = 16) -> tuple[float, tuple[int, int, int, int], float]:
    """Find the window whose local statistics deviate most from the image as a whole.

    Returns the variance ratio, the window box, and the mean absolute deviation of that
    window from the global mean.
    """
    h, w = gray.shape
    step = max(4, window // 2)
    global_var = float(gray.var()) + 1e-6
    global_mean = float(gray.mean())

    best_ratio = 0.0
    best_box = (0, 0, window, window)
    best_dev = 0.0

    for y in range(0, max(1, h - window + 1), step):
        for x in range(0, max(1, w - window + 1), step):
            patch = gray[y : y + window, x : x + window]
            if patch.size == 0:
                continue
            # A trigger patch is simultaneously high-contrast internally and far from the
            # image mean; scoring on both suppresses ordinary textured regions.
            dev = abs(float(patch.mean()) - global_mean)
            ratio = (float(patch.var()) / global_var) * (1.0 + dev / 64.0)
            if ratio > best_ratio:
                best_ratio = ratio
                best_box = (x, y, x + window, y + window)
                best_dev = dev

    return best_ratio, best_box, best_dev


def screen_image(path: str, gray: np.ndarray, high_freq_mean: float, high_freq_std: float) -> tuple[float, float, tuple[int, int, int, int], float]:
    """Score one image. Returns (high-freq z, variance ratio, bbox, deviation)."""
    hf = high_frequency_ratio(gray)
    z = (hf - high_freq_mean) / high_freq_std if high_freq_std > 1e-9 else 0.0
    ratio, box, dev = _local_variance_peak(gray)
    return z, ratio, box, dev


# --- cross-sample consensus ------------------------------------------------------


#: Minimum mean pairwise residual correlation for a localised trigger cluster.
#: A pasted stamp is the same pixels everywhere it appears, so its residuals correlate
#: near 1.0; loosely similar natural scenes sit well below this.
PATCH_AGREEMENT_MIN = 0.80

#: Minimum ratio of in-patch residual energy to whole-image residual energy.
PATCH_LOCALITY_MIN = 2.0

#: A blended overlay covers the whole frame, so it is confirmed on whole-image residual
#: agreement instead of spatial coincidence. The bar is high because whole-image
#: correlation is the easiest statistic to trip on genuinely similar scenes, and a false
#: "poisoned corpus" call is expensive.
BLENDED_AGREEMENT_MIN = 0.85

#: A trigger poisons a subset. A "cluster" containing most of a class is that class's
#: own appearance, not an injected pattern.
MAX_CLUSTER_SHARE = 0.6

#: Smallest cluster we will consider. Below three samples there is no meaningful notion
#: of consensus.
MIN_CLUSTER_MEMBERS = 3

#: Family-wise significance for the spatial-coincidence test, Bonferroni-corrected across
#: every grid cell. Tight because a false "poisoned corpus" verdict is expensive.
CLUSTER_ALPHA = 0.01

#: Above this mean pairwise image correlation the "cluster" is duplicate content rather
#: than a shared trigger. Duplicates are reported by the deduplication engine instead.
DUPLICATE_IMAGE_AGREEMENT = 0.95


def _mean_pairwise_agreement(rows: np.ndarray) -> float:
    """Mean pairwise Pearson correlation between flattened residual maps."""
    if rows.shape[0] < 2:
        return 0.0
    centred = rows - rows.mean(axis=1, keepdims=True)
    norms = np.linalg.norm(centred, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    normalised = centred / norms
    similarity = normalised @ normalised.T
    upper = similarity[np.triu_indices(rows.shape[0], 1)]
    return float(upper.mean()) if upper.size else 0.0


def _box_filter(array: np.ndarray, size: int) -> np.ndarray:
    """Mean filter via a summed-area table; avoids a hard scipy/cv2 dependency."""
    padded = np.pad(array, ((1, 0), (1, 0)), mode="constant")
    integral = padded.cumsum(axis=0).cumsum(axis=1)
    h, w = array.shape
    half = size // 2
    y0 = np.clip(np.arange(h) - half, 0, h)
    y1 = np.clip(np.arange(h) + half + 1, 0, h)
    x0 = np.clip(np.arange(w) - half, 0, w)
    x1 = np.clip(np.arange(w) + half + 1, 0, w)

    total = (
        integral[np.ix_(y1, x1)]
        - integral[np.ix_(y0, x1)]
        - integral[np.ix_(y1, x0)]
        + integral[np.ix_(y0, x0)]
    )
    area = np.outer(y1 - y0, x1 - x0).astype(np.float32)
    area[area == 0] = 1.0
    return total / area


def _poisson_tail(k: int, lam: float) -> float:
    """P(X >= k) for a Poisson(lam) variable.

    Used to ask how surprised we should be that `k` samples put their largest residual in
    the same grid cell. Poisson approximates the binomial well here because the per-cell
    probability is small and the sample count is modest.
    """
    if k <= 0:
        return 1.0
    if lam <= 0:
        return 0.0
    term = math.exp(-lam)
    cumulative = term
    for i in range(1, k):
        term *= lam / i
        cumulative += term
        if cumulative >= 1.0:
            return 0.0
    return max(0.0, 1.0 - cumulative)


def find_consensus_triggers(
    images: np.ndarray,
    labels: Sequence[str],
    paths: Sequence[str],
    patch_size: int = 12,
) -> list[TriggerCluster]:
    """Detect samples that share an identical perturbation at an identical location.

    `images` is a uint8 array shaped ``[N, 64, 64, 3]``.

    Two reference frames are used, and both are necessary:

    * **Per-class median.** The natural baseline -- "what does this class normally look
      like" -- and the more sensitive of the two.
    * **Whole-corpus median.** Needed because a heavily poisoned class corrupts its own
      median: when more than about half a class carries the trigger, the median contains
      the trigger and the residual against it vanishes. Measured on a corpus where 55% of
      one class was poisoned, the class-median pass found nothing while the corpus-median
      pass found the cluster cleanly.

    Clusters from both passes are merged and de-duplicated by overlapping membership.
    """
    clusters: list[TriggerCluster] = []
    if len(images) < 12:
        return clusters

    by_label: dict[str, list[int]] = defaultdict(list)
    for index, label in enumerate(labels):
        by_label[label].append(index)

    corpus_median = np.median(images.astype(np.float32), axis=0)

    for label, indices in by_label.items():
        if len(indices) < 12:
            continue

        stack = images[indices].astype(np.float32)
        references = [("class-median", np.median(stack, axis=0))]
        # Only worth a second pass when there is more than one class; otherwise the two
        # medians are identical.
        if len(by_label) > 1:
            references.append(("corpus-median", corpus_median))

        found_here: list[TriggerCluster] = []
        for reference_name, median in references:
            found_here.extend(
                _clusters_against_reference(
                    images, stack, median, indices, label, paths, patch_size, reference_name
                )
            )

        # De-duplicate: the same physical cluster often surfaces in both passes.
        for candidate in sorted(found_here, key=lambda c: (-len(c.member_paths), -c.consistency)):
            members = set(candidate.member_paths)
            if any(len(members & set(existing.member_paths)) > 0.5 * len(members) for existing in clusters):
                continue
            clusters.append(candidate)

    clusters.sort(key=lambda c: (-len(c.member_paths), -c.consistency))
    return clusters


def _clusters_against_reference(
    images: np.ndarray,
    stack: np.ndarray,
    median: np.ndarray,
    indices: list[int],
    label: str,
    paths: Sequence[str],
    patch_size: int,
    reference_name: str,
) -> list[TriggerCluster]:
    """One consensus pass against a given reference image."""
    clusters: list[TriggerCluster] = []
    if len(indices) < 12:
        return clusters

    residuals = np.abs(stack - median).mean(axis=3)  # [n, 64, 64]

    # Uncontaminated comparison population: a deterministic, capped sample of everything
    # outside this class. Computed once per pass because it does not depend on the bucket.
    inside_set = set(indices)
    outside_indices = [i for i in range(len(images)) if i not in inside_set]
    outside_residuals: np.ndarray | None = None
    if outside_indices:
        stride = max(1, len(outside_indices) // 200)
        sampled = outside_indices[::stride][:200]
        outside_residuals = np.abs(images[sampled].astype(np.float32) - median).mean(axis=3)

    smoothed = np.stack([_box_filter(r, patch_size) for r in residuals])
    flat = smoothed.reshape(len(indices), -1)
    peak_values = flat.max(axis=1)
    peak_flat = flat.argmax(axis=1)
    peak_y, peak_x = np.divmod(peak_flat, smoothed.shape[2])

    # The discriminator is *coincidence*, not magnitude. Diverse natural imagery
    # produces large residuals everywhere, so thresholding on peak height alone
    # either misses a real trigger or floods on a varied corpus. What natural
    # imagery does not do is put its largest residual at the same coordinates
    # across independent samples.
    cell = 6
    grid_h = (smoothed.shape[1] + cell - 1) // cell
    grid_w = (smoothed.shape[2] + cell - 1) // cell
    bucket_count = max(1, grid_h * grid_w)
    expected_per_bucket = len(indices) / bucket_count

    buckets: dict[tuple[int, int], list[int]] = defaultdict(list)
    for local_index in range(len(indices)):
        key = (int(peak_y[local_index]) // cell, int(peak_x[local_index]) // cell)
        buckets[key].append(local_index)


    for members in buckets.values():
        if len(members) < MIN_CLUSTER_MEMBERS:
            continue

        # Note: an earlier revision also required each member's peak to exceed the class
        # median peak. That filter is redundant with the contrast test further down --
        # which already demands the region be hotter than a typical non-member -- and it
        # actively breaks the corpus-median pass, where every sample has a large residual
        # because it is being compared against an average of all classes. It discarded 10
        # of the 11 members of a genuine trigger cluster.

        # Significance, with a multiple-comparisons correction, computed on the members
        # that actually survive into the cluster. Testing the raw bucket population
        # instead would overstate the result whenever the elevation filter removes most
        # of it -- which is how a three-sample coincidence on clean CIFAR-10 came out at
        # p=1.65e-04 instead of its true p=0.58. Under a null of peaks landing uniformly
        # at random, how often would *any* of the ~120 cells collect this many?
        family_wise_p = bucket_count * _poisson_tail(len(members), expected_per_bucket)
        if family_wise_p > CLUSTER_ALPHA:
            continue

        ys = peak_y[members]
        xs = peak_x[members]
        spread = float(np.std(ys) + np.std(xs))

        cy, cx = int(np.median(ys)), int(np.median(xs))
        half = patch_size // 2
        y0, y1 = max(0, cy - half), min(images.shape[1], cy + half)
        x0, x1 = max(0, cx - half), min(images.shape[2], cx + half)
        if y1 - y0 < 3 or x1 - x0 < 3:
            continue

        # Strongest confirmation: the residual patches must look like *each other*.
        # A pasted stamp is literally the same pixels in every poisoned sample, so
        # its residuals correlate near-perfectly. Structurally similar natural
        # imagery correlates too, but far more loosely -- measured separation on
        # synthetic corpora is ~0.99 against ~0.63, so the threshold sits between.
        patches = np.stack([residuals[m][y0:y1, x0:x1].ravel() for m in members])
        pattern_agreement = _mean_pairwise_agreement(patches)
        if pattern_agreement < PATCH_AGREEMENT_MIN:
            continue

        # Locality: a stamp concentrates its residual in a few percent of the frame.
        # Diffuse structural similarity spreads it, giving a ratio near 1.
        inside = float(np.mean([residuals[m][y0:y1, x0:x1].mean() for m in members]))
        whole = float(np.mean([residuals[m].mean() for m in members])) + 1e-6
        locality = inside / whole
        if locality < PATCH_LOCALITY_MIN:
            continue

        # Duplicate flooding also produces a perfectly shared residual, because the
        # samples are the same picture. That is a real defect but it is a *different*
        # one, already reported by the deduplication engine, and calling it a backdoor
        # would mischaracterise the attack an analyst is being asked to act on.
        member_images = np.stack(
            [images[indices[m]].astype(np.float32).reshape(-1) for m in members]
        )
        if _mean_pairwise_agreement(member_images) > DUPLICATE_IMAGE_AGREEMENT:
            continue

        # Contrast: is this region disproportionately hot for these samples compared with
        # samples the attack did not target?
        #
        # The comparison population is drawn from *outside* the class, not from the rest
        # of the class. A backdoor targets one class by construction, so the rest of that
        # class can be majority-poisoned -- at which point both its mean and its median
        # are contaminated and a genuine trigger fails its own contrast test. Measured on
        # a class that was 55% poisoned, the within-class median sat at 84 against a true
        # clean level of 57, and the real cluster was rejected.
        #
        # Locality ratios are compared rather than raw energies, because a raw residual
        # against a corpus-wide median is dominated by class identity and is not
        # comparable across classes; the ratio is normalised per sample and is.
        non_members = [i for i in range(len(indices)) if i not in set(members)]
        member_energy = inside
        if outside_residuals is not None and len(outside_residuals) > 0:
            outside_locality = float(
                np.median(
                    [
                        r[y0:y1, x0:x1].mean() / (r.mean() + 1e-6)
                        for r in outside_residuals
                    ]
                )
            )
        else:
            outside_locality = 1.0
        if locality < 1.5 * outside_locality:
            continue

        # Secondary energy reference for the grow step, taken from the same uncontaminated
        # population rather than from the possibly-poisoned remainder of the class.
        other_energy = (
            float(np.median([r[y0:y1, x0:x1].mean() for r in outside_residuals]))
            if outside_residuals is not None and len(outside_residuals) > 0
            else float(np.median([residuals[m][y0:y1, x0:x1].mean() for m in non_members]))
            if non_members
            else 0.0
        )

        # Seed and grow. The bucketing step only catches samples whose *largest* residual
        # happens to fall on the trigger; in a heavily poisoned class, many poisoned
        # samples have some natural region that residuals higher still. Now that the
        # location is known, sweep the whole class for samples that agree with the
        # recovered pattern there. This is what turns "11 of 36" into an attribution an
        # analyst can act on.
        seed_pattern = np.stack([residuals[m][y0:y1, x0:x1].ravel() for m in members]).mean(axis=0)
        grown = set(members)
        for candidate_index in non_members:
            patch = residuals[candidate_index][y0:y1, x0:x1].ravel()
            if patch.mean() < 1.5 * other_energy:
                continue
            pair = _mean_pairwise_agreement(np.stack([seed_pattern, patch]))
            if pair >= PATCH_AGREEMENT_MIN:
                grown.add(candidate_index)
        members = sorted(grown)

        spatial = float(np.exp(-spread / 6.0))
        consistency = float(min(0.99, 0.4 * spatial + 0.6 * pattern_agreement))

        member_global = [indices[m] for m in members]
        patch_stack = images[member_global][:, y0:y1, x0:x1, :].astype(np.float32)
        recovered = np.median(patch_stack, axis=0).clip(0, 255).astype(np.uint8)

        area_fraction = ((y1 - y0) * (x1 - x0)) / float(images.shape[1] * images.shape[2])
        family = _classify_family(area_fraction, member_energy, recovered)

        clusters.append(
            TriggerCluster(
                label=label,
                member_paths=[paths[i] for i in member_global],
                bbox=(x0, y0, x1, y1),
                consistency=consistency,
                mean_magnitude=member_energy,
                recovered_patch_rgb=recovered.tolist(),
                family=family,
                reference=reference_name,
                significance=family_wise_p,
            )
        )

    # A blended overlay has no peak to bucket on: it covers the whole frame at low
    # amplitude. It is still a *shared* pattern, so it is found by whole-image residual
    # agreement instead of by spatial coincidence.
    already = {m for cluster in clusters for m in cluster.member_paths}
    blended = _find_blended_cluster(residuals, images, indices, paths, label, already)
    if blended is not None:
        blended.reference = reference_name
        clusters.append(blended)

    return clusters


def _find_blended_cluster(
    residuals: np.ndarray,
    images: np.ndarray,
    indices: list[int],
    paths: Sequence[str],
    label: str,
    already_clustered: set[str],
) -> TriggerCluster | None:
    """Detect a low-amplitude overlay shared across a subset of one class."""
    if len(indices) < 12:
        return None

    # Downsample: a blended pattern is low-frequency, and 16x16 removes the per-image
    # content that would otherwise dominate the correlation.
    coarse = np.stack([_box_filter(r, 4)[::4, ::4].ravel() for r in residuals])
    centred = coarse - coarse.mean(axis=1, keepdims=True)
    norms = np.linalg.norm(centred, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    normalised = centred / norms
    similarity = normalised @ normalised.T
    np.fill_diagonal(similarity, 0.0)

    # Seed on whichever sample agrees with the most others, then take its neighbourhood.
    degrees = (similarity >= BLENDED_AGREEMENT_MIN).sum(axis=1)
    seed = int(degrees.argmax())
    if degrees[seed] < 2:
        return None

    members = [seed, *np.flatnonzero(similarity[seed] >= BLENDED_AGREEMENT_MIN).tolist()]
    members = sorted(set(members))
    if len(members) < 3 or len(members) > MAX_CLUSTER_SHARE * len(indices):
        return None

    agreement = _mean_pairwise_agreement(coarse[members])
    if agreement < BLENDED_AGREEMENT_MIN:
        return None

    # Duplicate samples trivially share a residual, because they are the same picture.
    # That is duplicate flooding, which the dedup engine already reports; calling it a
    # blended trigger would be a false characterisation of the attack. Require the member
    # *images* to be genuinely different from one another.
    member_images = np.stack(
        [images[indices[m]].astype(np.float32).reshape(-1) for m in members]
    )
    if _mean_pairwise_agreement(member_images) > DUPLICATE_IMAGE_AGREEMENT:
        return None

    member_global = [indices[m] for m in members]
    member_paths = [paths[i] for i in member_global]
    if all(path in already_clustered for path in member_paths):
        return None

    height, width = residuals.shape[1], residuals.shape[2]
    magnitude = float(np.mean([residuals[m].mean() for m in members]))
    recovered = (
        np.median(images[member_global].astype(np.float32), axis=0)[:: max(1, height // 16), :: max(1, width // 16), :]
        .clip(0, 255)
        .astype(np.uint8)
    )

    return TriggerCluster(
        label=label,
        member_paths=member_paths,
        bbox=(0, 0, width, height),
        consistency=float(min(0.9, agreement)),
        mean_magnitude=magnitude,
        recovered_patch_rgb=recovered.tolist(),
        family="Blended / low-amplitude global overlay (Chen et al. family)",
    )


def _classify_family(area_fraction: float, magnitude: float, patch: np.ndarray) -> str:
    """Name the likely attack family from the recovered pattern's geometry."""
    unique_colours = len(np.unique(patch.reshape(-1, patch.shape[-1]), axis=0))
    if area_fraction < 0.08 and magnitude > 30 and unique_colours <= 8:
        return "BadNets / localised patch trigger (low-entropy, high-contrast stamp)"
    if area_fraction < 0.10 and magnitude > 15:
        return "Localised patch trigger (BadNets family)"
    if magnitude < 15:
        return "Blended / low-amplitude overlay (Chen et al. family)"
    return "Unclassified localised perturbation"


def analyse_triggers(
    images: np.ndarray,
    grays: Sequence[np.ndarray],
    labels: Sequence[str],
    paths: Sequence[str],
    original_sizes: Sequence[tuple[int, int]] | None = None,
) -> TriggerReport:
    """Run both detectors and fuse them into one report."""
    thresholds = SETTINGS.thresholds
    report = TriggerReport(analysed=len(paths))

    if len(paths) == 0:
        report.limitation = "No decodable samples were available for trigger screening."
        return report

    high_freqs = np.array([high_frequency_ratio(g) for g in grays], dtype=np.float32)
    hf_mean = float(high_freqs.mean())
    hf_std = float(high_freqs.std())

    clusters = find_consensus_triggers(images, labels, paths) if len(paths) >= 12 else []
    report.clusters = clusters
    report.consensus_available = len(paths) >= 12

    clustered_paths: dict[str, TriggerCluster] = {}
    for cluster in clusters:
        for path in cluster.member_paths:
            clustered_paths[path] = cluster

    for index, path in enumerate(paths):
        gray = grays[index]
        z, ratio, box, dev = screen_image(path, gray, hf_mean, hf_std)

        in_cluster = clustered_paths.get(path)
        spectral_hit = z >= thresholds.trigger_highfreq_z
        variance_hit = ratio >= thresholds.trigger_patch_variance_ratio
        signals = int(spectral_hit) + int(variance_hit)

        if not (spectral_hit or variance_hit or in_cluster):
            continue

        # Consensus membership dominates: agreeing with other samples on an identical
        # artifact is far stronger evidence than any single-image statistic.
        if in_cluster is not None:
            confidence = min(0.97, 0.60 + 0.30 * in_cluster.consistency + 0.05 * len(in_cluster.member_paths) / 10)
            method = f"Cross-sample consensus ({in_cluster.family})"
            bbox = in_cluster.bbox
            score = min(1.0, 0.6 + 0.4 * in_cluster.consistency)
        else:
            confidence = 0.35 + 0.15 * signals
            method = "Single-image spectral / local-variance screening"
            bbox = box
            score = min(1.0, (max(0.0, z) / 10.0) + (ratio / 20.0))

        if confidence < thresholds.trigger_min_confidence and in_cluster is None:
            # Keep single-image hits only when both statistics agree; otherwise the
            # false-positive rate on textured imagery is unacceptable for an analyst.
            if signals < 2:
                continue
            confidence = thresholds.trigger_min_confidence

        scale_box = None
        if original_sizes is not None and index < len(original_sizes):
            width, height = original_sizes[index]
            sx, sy = width / 64.0, height / 64.0
            # grays are 256x256; the consensus bbox is in 64x64 space, the single-image
            # bbox in 256x256 space.
            if in_cluster is not None:
                scale_box = (int(bbox[0] * sx), int(bbox[1] * sy), int(bbox[2] * sx), int(bbox[3] * sy))
            else:
                sx, sy = width / 256.0, height / 256.0
                scale_box = (int(bbox[0] * sx), int(bbox[1] * sy), int(bbox[2] * sx), int(bbox[3] * sy))

        report.candidates.append(
            TriggerCandidate(
                path=path,
                score=score,
                confidence=confidence,
                bbox=bbox,
                bbox_original=scale_box,
                method=method,
                perturbation_magnitude=dev if in_cluster is None else in_cluster.mean_magnitude,
                high_freq_z=z,
                patch_variance_ratio=ratio,
                label=labels[index] if index < len(labels) else None,
            )
        )

    report.candidates.sort(key=lambda c: -c.confidence)

    report.limitation = (
        "Screening covers static, spatially consistent triggers (BadNets patches, blended "
        "overlays, corner stamps). Sample-specific warping attacks such as WaNet and "
        "BppAttack produce no cross-sample consensus and are not detectable from imagery "
        "alone; they are addressed by the model-side trigger inversion and behavioural "
        "battery."
    )
    if not report.consensus_available:
        report.limitation += (
            " Fewer than 12 samples were available, so only single-image screening ran and "
            "confidence is correspondingly lower."
        )
    return report


__all__ = [
    "TriggerCandidate",
    "TriggerCluster",
    "TriggerReport",
    "analyse_triggers",
    "find_consensus_triggers",
    "high_frequency_ratio",
]
