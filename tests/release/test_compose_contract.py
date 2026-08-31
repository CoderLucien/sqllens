import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class ComposeContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compose = json.loads((ROOT / "deploy" / "compose.json").read_text())

    def test_only_web_api_publishes_a_loopback_port(self) -> None:
        services = self.compose["services"]

        self.assertEqual(
            services["web-api"]["ports"],
            ["127.0.0.1:${SQLLENS_PORT:-8080}:8080"],
        )
        self.assertNotIn("ports", services["worker"])
        self.assertNotIn("ports", services["model-controller"])

    def test_services_have_no_host_control_or_privileged_escape_hatches(self) -> None:
        for service_name, service in self.compose["services"].items():
            self.assertFalse(service.get("privileged", False), service_name)
            self.assertEqual(service["cap_drop"], ["ALL"], service_name)
            self.assertIn("no-new-privileges:true", service["security_opt"], service_name)
            self.assertTrue(service["read_only"], service_name)

            for mount in service.get("volumes", []):
                self.assertNotIn("docker.sock", mount, service_name)
                self.assertNotIn("/var/run", mount, service_name)

    def test_external_mode_fits_inside_the_2c4g_service_budget(self) -> None:
        services = self.compose["services"].values()
        cpu_total = sum(float(service["cpus"]) for service in services)
        memory_mib = {"256m": 256, "768m": 768, "1024m": 1024, "1536m": 1536}
        memory_total = sum(memory_mib[service["mem_limit"]] for service in services)

        self.assertLessEqual(cpu_total, 2.0)
        self.assertLessEqual(memory_total, 4096)
        self.assertNotIn("model-weights", self.compose.get("volumes", {}))

    def test_bootstrap_code_uses_a_file_secret(self) -> None:
        self.assertEqual(
            self.compose["secrets"]["bootstrap_code"]["file"],
            "${SQLLENS_BOOTSTRAP_FILE:?launcher must set SQLLENS_BOOTSTRAP_FILE}",
        )
        web = self.compose["services"]["web-api"]
        self.assertEqual(web["secrets"], ["bootstrap_code"])
        self.assertIn("SQLLENS_BOOTSTRAP_CODE_FILE=/run/secrets/bootstrap_code", web["environment"])

    def test_default_compose_only_starts_the_web_api(self) -> None:
        services = self.compose["services"]

        self.assertNotIn("profiles", services["web-api"])
        self.assertNotIn("depends_on", services["web-api"])
        self.assertEqual(services["worker"]["profiles"], ["async-runtime"])
        self.assertEqual(services["model-controller"]["profiles"], ["local-runtime"])

    def test_web_healthcheck_uses_the_frozen_endpoint(self) -> None:
        command = self.compose["services"]["web-api"]["healthcheck"]["test"]

        self.assertIn("http://127.0.0.1:8080/healthz", command[-1])
        self.assertNotIn("/api/v1/health", command[-1])

    def test_model_controller_is_internal_only_and_always_idle_in_external_mode(self) -> None:
        controller = self.compose["services"]["model-controller"]

        self.assertEqual(controller["networks"], ["model-control"])
        self.assertTrue(self.compose["networks"]["model-control"]["internal"])
        self.assertEqual(controller["environment"], ["SQLLENS_MODEL_MODE=external-idle"])
        self.assertEqual(controller["command"], ["model-controller"])


if __name__ == "__main__":
    unittest.main()
