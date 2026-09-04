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
        }}, [])

        self.assertIn("--execution-mesh-n 40", args)
        self.assertIn("--chunked-mesh-n 16", args)
        self.assertIn("--subnet-mesh-n 8", args)
        self.assertIn("--partial-mesh-n 20", args)
        self.assertNotIn("--mesh-n", args)

    def test_generic_mesh_settings_are_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            shadow_sim.mesh_settings({"mesh_n": 8}, "execution")

    def test_chunked_mode_emits_its_chunk_and_lazy_gossip_settings(self) -> None:
        args = shadow_sim.build_args(nodes(1)[0], {"sim": {
            "mode": "gossipsub-chunked",
            "seed": 42,
            "gossipsub_chunk_count": 96,
            "chunked_gossip_lazy": 7,
        }}, [])

        self.assertIn("--mode gossipsub-chunked", args)
        self.assertIn("--gossipsub-chunk-count 96", args)
        self.assertIn("--chunked-gossip-lazy 7", args)

    def test_chunked_mode_rejects_non_positive_chunk_count(self) -> None:
        with self.assertRaises(SystemExit):
            shadow_sim.build_args(nodes(1)[0], {"sim": {
                "mode": "gossipsub-chunked", "seed": 42, "gossipsub_chunk_count": 0,
            }}, [])


if __name__ == "__main__":
    unittest.main()
