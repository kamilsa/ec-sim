import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "shadow-sim.py"
SPEC = importlib.util.spec_from_file_location("shadow_sim", SCRIPT)
assert SPEC and SPEC.loader
shadow_sim = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shadow_sim)


def nodes(count: int) -> list:
    return [shadow_sim.Node(i, f"node{i:03d}", i == 0) for i in range(count)]


class HybridSubscriberSelectionTests(unittest.TestCase):
    def test_fraction_selection_is_deterministic_and_includes_builder(self) -> None:
        first = nodes(8)
        second = nodes(8)

        first_selected = shadow_sim.assign_hybrid_subscribers(
            first, "hybrid", "fraction", 0.5, 42)
        second_selected = shadow_sim.assign_hybrid_subscribers(
            second, "hybrid", "fraction", 0.5, 42)

        self.assertEqual([node.name for node in first_selected], [node.name for node in second_selected])
        self.assertEqual(len(first_selected), 4)
        self.assertTrue(first[0].is_rs_subnet_subscriber)

    def test_fraction_must_select_at_least_two_nodes(self) -> None:
        with self.assertRaises(SystemExit):
            shadow_sim.assign_hybrid_subscribers(nodes(8), "hybrid", "fraction", 0.1, 42)

    def test_supernode_selection_includes_builder(self) -> None:
        selected_nodes = nodes(5)
        selected_nodes[3].is_supernode = True

        selected = shadow_sim.assign_hybrid_subscribers(
            selected_nodes, "hybrid", "supernodes", 0.0, 42)

        self.assertEqual([node.name for node in selected], ["node000", "node003"])
        self.assertTrue(selected_nodes[0].is_rs_subnet_subscriber)
        self.assertTrue(selected_nodes[3].is_rs_subnet_subscriber)

    def test_hybrid_node_argument_includes_the_subscriber_flag(self) -> None:
        node = nodes(1)[0]
        node.is_rs_subnet_subscriber = True
        args = shadow_sim.build_args(node, {"sim": {"mode": "hybrid", "seed": 42}}, [])
        self.assertIn("--rs-subnet-subscriber", args)

    def test_mesh_profiles_are_emitted_independently(self) -> None:
        args = shadow_sim.build_args(nodes(1)[0], {"sim": {
            "mode": "hybrid",
            "seed": 42,
            "execution_mesh_n": 40,
            "execution_mesh_n_low": 30,
            "execution_mesh_n_high": 50,
            "execution_mesh_outbound_min": 10,
            "chunked_mesh_n": 16,
            "chunked_mesh_n_low": 12,
            "chunked_mesh_n_high": 20,
            "chunked_mesh_outbound_min": 4,
            "subnet_mesh_n": 8,
            "subnet_mesh_n_low": 4,
            "subnet_mesh_n_high": 12,
            "subnet_mesh_outbound_min": 2,
            "partial_mesh_n": 20,
            "partial_mesh_n_low": 10,
            "partial_mesh_n_high": 30,
            "partial_mesh_outbound_min": 4,
            "chunk_subnet_mesh_n": 6,
            "chunk_subnet_mesh_n_low": 5,
            "chunk_subnet_mesh_n_high": 9,
            "chunk_subnet_mesh_outbound_min": 3,
        }}, [])

        self.assertIn("--execution-mesh-n 40", args)
        self.assertIn("--chunked-mesh-n 16", args)
        self.assertIn("--subnet-mesh-n 8", args)
        self.assertIn("--partial-mesh-n 20", args)
        self.assertNotIn("--mesh-n", args)

    def test_chunk_subnet_mesh_flags_use_dashes_not_underscores(self) -> None:
        args = shadow_sim.build_args(nodes(1)[0], {"sim": {
            "mode": "chunk-subnets",
            "seed": 42,
            "chunk_subnet_mesh_n": 6,
            "chunk_subnet_mesh_n_low": 5,
            "chunk_subnet_mesh_n_high": 9,
            "chunk_subnet_mesh_outbound_min": 3,
        }}, [])

        self.assertIn("--chunk-subnet-mesh-n 6", args)
        self.assertIn("--chunk-subnet-mesh-n-low 5", args)
        self.assertIn("--chunk-subnet-mesh-n-high 9", args)
        self.assertIn("--chunk-subnet-mesh-outbound-min 3", args)
        self.assertNotIn("chunk_subnet", args)

    def test_chunk_subnets_mode_reuses_the_chunked_chunk_settings(self) -> None:
        args = shadow_sim.build_args(nodes(1)[0], {"sim": {
            "mode": "chunk-subnets",
            "seed": 42,
            "gossipsub_chunk_count": 128,
            "chunked_send_idontwant": True,
        }}, [])

        self.assertIn("--mode chunk-subnets", args)
        self.assertIn("--gossipsub-chunk-count 128", args)
        self.assertIn("--chunked-send-idontwant", args)

    def test_chunk_subnets_rejects_a_chunk_count_above_the_topic_cap(self) -> None:
        sim = {"mode": "chunk-subnets", "seed": 42,
               "gossipsub_chunk_count": shadow_sim.MAX_CHUNK_SUBNETS + 1}
        with self.assertRaises(SystemExit):
            shadow_sim.gossipsub_chunk_count_setting(sim)

    def test_gossipsub_rs_emits_its_rate_and_mesh_flags(self) -> None:
        args = shadow_sim.build_args(nodes(1)[0], {"sim": {
            "mode": "gossipsub-rs",
            "seed": 42,
            "gossipsub_rs_data_shards": 64,
            "gossipsub_rs_total_shards": 80,
            "gossipsub_rs_mesh_n": 10,
            "gossipsub_rs_mesh_n_low": 6,
            "gossipsub_rs_mesh_n_high": 14,
            "gossipsub_rs_mesh_outbound_min": 4,
        }}, [])

        self.assertIn("--mode gossipsub-rs", args)
        self.assertIn("--gossipsub-rs-data-shards 64", args)
        self.assertIn("--gossipsub-rs-total-shards 80", args)
        self.assertIn("--gossipsub-rs-mesh-n 10", args)
        self.assertIn("--gossipsub-rs-mesh-outbound-min 4", args)
        self.assertNotIn("gossipsub_rs", args)

    def test_gossipsub_rs_defaults_to_64_of_128(self) -> None:
        self.assertEqual(
            shadow_sim.gossipsub_rs_shard_settings({"mode": "gossipsub-rs"}), (64, 128))

    def test_gossipsub_rs_rejects_rates_reed_solomon_cannot_represent(self) -> None:
        for data, total in [
            (64, 64),                              # no parity shards
            (64, 32),                              # total below data
            (64, shadow_sim.MAX_TOTAL_SHARDS + 1),  # beyond GF(2^8)
            (0, 128),                              # no data shards
        ]:
            with self.subTest(data=data, total=total), self.assertRaises(SystemExit):
                shadow_sim.gossipsub_rs_shard_settings({
                    "mode": "gossipsub-rs",
                    "gossipsub_rs_data_shards": data,
                    "gossipsub_rs_total_shards": total,
                })

    def test_chunked_mode_allows_chunk_counts_above_the_subnet_cap(self) -> None:
        # Only chunk-subnets spends a gossipsub topic per chunk.
        count = shadow_sim.MAX_CHUNK_SUBNETS + 1
        sim = {"mode": "gossipsub-chunked", "seed": 42, "gossipsub_chunk_count": count}
        self.assertEqual(shadow_sim.gossipsub_chunk_count_setting(sim), count)

    def test_generic_mesh_settings_are_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            shadow_sim.mesh_settings({"mesh_n": 8}, "execution")

    def test_chunked_mode_emits_its_chunk_and_lazy_gossip_settings(self) -> None:
        args = shadow_sim.build_args(nodes(1)[0], {"sim": {
            "mode": "gossipsub-chunked",
            "seed": 42,
            "gossipsub_chunk_count": 96,
            "chunked_send_idontwant": True,
            "chunked_gossip_lazy": 7,
        }}, [])

        self.assertIn("--mode gossipsub-chunked", args)
        self.assertIn("--gossipsub-chunk-count 96", args)
        self.assertIn("--chunked-send-idontwant", args)
        self.assertIn("--chunked-gossip-lazy 7", args)

    def test_chunked_mode_rejects_non_boolean_idontwant_setting(self) -> None:
        with self.assertRaises(SystemExit):
            shadow_sim.build_args(nodes(1)[0], {"sim": {
                "mode": "gossipsub-chunked", "seed": 42, "chunked_send_idontwant": 1,
            }}, [])

    def test_chunked_mode_rejects_non_positive_chunk_count(self) -> None:
        with self.assertRaises(SystemExit):
            shadow_sim.build_args(nodes(1)[0], {"sim": {
                "mode": "gossipsub-chunked", "seed": 42, "gossipsub_chunk_count": 0,
            }}, [])


if __name__ == "__main__":
    unittest.main()
