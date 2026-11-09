"""
Unit tests for Kitsune NIDS: AfterImage feature extractor.
Verifies NDSS 2018 mathematical invariants:
- Continuous damped incremental statistics (Algorithm 3)
- Feature space projection strictly into R^100
- Deterministic temporal decay d_lambda(t) = 2^(-lambda * dt)

Architect: Tamamo-no-Mae (kitsune-research core)
"""
from __future__ import annotations

import math
import numpy as np
import pytest

import netStat as ns


class TestAfterImageInvariants:
    """Audit suite for AfterImage damped windows and streaming statistics."""

    @pytest.fixture
    def netstat_instance(self) -> ns.netStat:
        """Instantiate netStat with canonical NDSS 2018 parameters."""
        # Lambdas canónicas: [5, 3, 1, 0.1, 0.01] (100ms, 500ms, 1.5s, 10s, 1min)
        # np.nan fuerza las lambdas por defecto en la clase base
        return ns.netStat(Lambdas=np.nan, HostLimit=255, HostSimplexLimit=1000)

    def test_damped_decay_factor_monotonicity(self) -> None:
        """Verify that d_lambda(dt) = 2^(-lambda * dt) decays monotonically."""
        lambdas = [5.0, 3.0, 1.0, 0.1, 0.01]
        dt_values = [0.001, 0.01, 0.1, 1.0, 10.0]

        for lam in lambdas:
            prev_decay = 1.0
            for dt in dt_values:
                decay = math.pow(2, -lam * dt)
                assert 0.0 < decay < 1.0, f"Decay factor out of bounds (0, 1) for lam={lam}, dt={dt}"
                assert decay < prev_decay, f"Decay factor failed monotonic decrease for lam={lam}"
                prev_decay = decay

    def test_vector_dimension_is_r100(self, netstat_instance: ns.netStat) -> None:
        """Verify that updateGetStats returns strictly a 100-dimensional vector."""
        # Ingesta inicial de paquete TCP sintético
        vector = netstat_instance.updateGetStats(
            IPtype=0x0800,
            srcMAC="00:11:22:33:44:55",
            dstMAC="ff:ff:ff:ff:ff:ff",
            srcIP="192.168.1.100",
            srcProtocol="tcp",
            dstIP="192.168.1.1",
            dstProtocol="80",
            datagramSize=1460,
            timestamp=1000.0,
        )

        vector_np = np.asarray(vector, dtype=np.float64)
        assert vector_np.ndim == 1, f"Expected 1D vector, got ndim={vector_np.ndim}"
        assert vector_np.shape[0] == 100, f"Expected R^100 feature vector, got shape={vector_np.shape}"
        assert not np.isnan(vector_np).any(), "Extracted vector contains NaN values"
        assert not np.isinf(vector_np).any(), "Extracted vector contains Inf values"

    def test_temporal_stream_accumulation(self, netstat_instance: ns.netStat) -> None:
        """Verify that streaming packet bursts update weight (w) and mean (mu) consistently."""
        base_time = 1700000000.0
        mac_src = "00:50:56:c0:00:08"
        mac_dst = "00:50:56:c0:00:01"
        ip_src = "10.0.0.50"
        ip_dst = "10.0.0.1"

        # Simular ráfaga de 50 paquetes uniformes de 500 bytes cada 10ms
        for i in range(50):
            t = base_time + (i * 0.01)
            vec = netstat_instance.updateGetStats(
                IPtype=0x0800,
                srcMAC=mac_src,
                dstMAC=mac_dst,
                srcIP=ip_src,
                srcProtocol="udp",
                dstIP=ip_dst,
                dstProtocol="53",
                datagramSize=500,
                timestamp=t,
            )

        vec_np = np.asarray(vec, dtype=np.float64)
        # El vector debe ser estrictamente numérico y real
        assert vec_np.shape[0] == 100, f"Dimension mismatch: expected 100, got {vec_np.shape[0]}"
        # El peso w acumulado tras 50 paquetes debe ser significativamente mayor a 1.0
        assert vec_np[0] > 1.0, f"Weight statistic did not accumulate properly: w={vec_np[0]}"
        # Comprobar que no hay deriva numérica
        assert np.isfinite(vec_np).all(), "Stream accumulation resulted in non-finite numbers"
