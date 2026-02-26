"""Tests for agent_identity.plugins.registry — PluginRegistry."""
from __future__ import annotations

from abc import ABC, abstractmethod
from unittest.mock import MagicMock, patch

import pytest

from agent_identity.plugins.registry import (
    PluginAlreadyRegisteredError,
    PluginNotFoundError,
    PluginRegistry,
)


# ---------------------------------------------------------------------------
# Helpers — a concrete ABC and two implementations for testing
# ---------------------------------------------------------------------------


class BaseProcessor(ABC):
    @abstractmethod
    def process(self, data: bytes) -> bytes: ...


class UpperProcessor(BaseProcessor):
    def process(self, data: bytes) -> bytes:
        return data.upper()


class LowerProcessor(BaseProcessor):
    def process(self, data: bytes) -> bytes:
        return data.lower()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def registry() -> PluginRegistry[BaseProcessor]:
    return PluginRegistry(BaseProcessor, "test-processors")


# ---------------------------------------------------------------------------
# PluginNotFoundError / PluginAlreadyRegisteredError
# ---------------------------------------------------------------------------


class TestErrors:
    def test_not_found_is_key_error(self) -> None:
        with pytest.raises(KeyError):
            raise PluginNotFoundError("x", "reg")

    def test_not_found_stores_names(self) -> None:
        err = PluginNotFoundError("my-plugin", "my-registry")
        assert err.plugin_name == "my-plugin"
        assert err.registry_name == "my-registry"

    def test_already_registered_is_value_error(self) -> None:
        with pytest.raises(ValueError):
            raise PluginAlreadyRegisteredError("x", "reg")

    def test_already_registered_stores_names(self) -> None:
        err = PluginAlreadyRegisteredError("my-plugin", "my-registry")
        assert err.plugin_name == "my-plugin"
        assert err.registry_name == "my-registry"


# ---------------------------------------------------------------------------
# PluginRegistry — register decorator
# ---------------------------------------------------------------------------


class TestRegisterDecorator:
    def test_register_decorator_returns_class_unchanged(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        result = registry.register("upper")(UpperProcessor)
        assert result is UpperProcessor

    def test_registered_class_retrievable(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        registry.register("upper")(UpperProcessor)
        cls = registry.get("upper")
        assert cls is UpperProcessor

    def test_register_duplicate_raises(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        registry.register("upper")(UpperProcessor)
        with pytest.raises(PluginAlreadyRegisteredError):
            registry.register("upper")(LowerProcessor)

    def test_register_non_subclass_raises_type_error(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        class NotAProcessor:
            pass

        with pytest.raises(TypeError, match="subclass"):
            registry.register("invalid")(NotAProcessor)  # type: ignore[arg-type]

    def test_register_abstract_class_raises_type_error(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        # BaseProcessor itself is abstract and doesn't fully satisfy isinstance check
        # Actually a subclass of the base class, so let's check a non-subclass
        class Unrelated(ABC):
            pass

        with pytest.raises(TypeError):
            registry.register("unrelated")(Unrelated)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# PluginRegistry — register_class
# ---------------------------------------------------------------------------


class TestRegisterClass:
    def test_register_class_directly(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        registry.register_class("upper", UpperProcessor)
        assert registry.get("upper") is UpperProcessor

    def test_register_class_duplicate_raises(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        registry.register_class("upper", UpperProcessor)
        with pytest.raises(PluginAlreadyRegisteredError):
            registry.register_class("upper", LowerProcessor)

    def test_register_class_non_subclass_raises(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        class NotProcessor:
            pass

        with pytest.raises(TypeError):
            registry.register_class("bad", NotProcessor)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# PluginRegistry — deregister
# ---------------------------------------------------------------------------


class TestDeregister:
    def test_deregister_removes_plugin(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        registry.register_class("upper", UpperProcessor)
        registry.deregister("upper")
        assert "upper" not in registry

    def test_deregister_unknown_raises_not_found(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        with pytest.raises(PluginNotFoundError):
            registry.deregister("ghost")

    def test_get_after_deregister_raises(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        registry.register_class("upper", UpperProcessor)
        registry.deregister("upper")
        with pytest.raises(PluginNotFoundError):
            registry.get("upper")


# ---------------------------------------------------------------------------
# PluginRegistry — get
# ---------------------------------------------------------------------------


class TestGet:
    def test_get_unknown_raises_not_found(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        with pytest.raises(PluginNotFoundError):
            registry.get("missing")

    def test_get_returns_class_not_instance(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        registry.register_class("upper", UpperProcessor)
        cls = registry.get("upper")
        assert isinstance(cls, type)


# ---------------------------------------------------------------------------
# PluginRegistry — list_plugins / __contains__ / __len__ / __repr__
# ---------------------------------------------------------------------------


class TestQueryMethods:
    def test_list_plugins_empty_initially(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        assert registry.list_plugins() == []

    def test_list_plugins_sorted(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        registry.register_class("zzz", UpperProcessor)
        registry.register_class("aaa", LowerProcessor)
        plugins = registry.list_plugins()
        assert plugins == sorted(plugins)

    def test_contains_false_for_unknown(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        assert "missing" not in registry

    def test_contains_true_after_registration(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        registry.register_class("upper", UpperProcessor)
        assert "upper" in registry

    def test_len_zero_initially(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        assert len(registry) == 0

    def test_len_increments_after_registration(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        registry.register_class("upper", UpperProcessor)
        registry.register_class("lower", LowerProcessor)
        assert len(registry) == 2

    def test_repr_contains_registry_name(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        assert "test-processors" in repr(registry)

    def test_repr_contains_base_class_name(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        assert "BaseProcessor" in repr(registry)


# ---------------------------------------------------------------------------
# PluginRegistry — load_entrypoints
# ---------------------------------------------------------------------------


class TestLoadEntrypoints:
    def test_load_entrypoints_empty_group_is_noop(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        # Patching entry_points to return empty iterable
        with patch("importlib.metadata.entry_points", return_value=[]):
            registry.load_entrypoints("agent_identity.plugins")
        assert len(registry) == 0

    def test_load_entrypoints_registers_valid_plugin(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        mock_ep = MagicMock()
        mock_ep.name = "upper"
        mock_ep.load.return_value = UpperProcessor

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            registry.load_entrypoints("agent_identity.plugins")

        assert "upper" in registry
        assert registry.get("upper") is UpperProcessor

    def test_load_entrypoints_skips_already_registered(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        registry.register_class("upper", UpperProcessor)

        mock_ep = MagicMock()
        mock_ep.name = "upper"
        mock_ep.load.return_value = LowerProcessor

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            registry.load_entrypoints("agent_identity.plugins")

        # Should still be the original UpperProcessor
        assert registry.get("upper") is UpperProcessor

    def test_load_entrypoints_skips_on_load_failure(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        mock_ep = MagicMock()
        mock_ep.name = "broken"
        mock_ep.load.side_effect = ImportError("module not found")

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            registry.load_entrypoints("agent_identity.plugins")

        assert "broken" not in registry

    def test_load_entrypoints_skips_invalid_class(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        class NotAProcessor:
            pass

        mock_ep = MagicMock()
        mock_ep.name = "invalid"
        mock_ep.load.return_value = NotAProcessor

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            registry.load_entrypoints("agent_identity.plugins")

        assert "invalid" not in registry

    def test_load_entrypoints_idempotent_on_second_call(
        self, registry: PluginRegistry[BaseProcessor]
    ) -> None:
        mock_ep = MagicMock()
        mock_ep.name = "upper"
        mock_ep.load.return_value = UpperProcessor

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            registry.load_entrypoints("agent_identity.plugins")
            registry.load_entrypoints("agent_identity.plugins")  # second call

        assert len(registry) == 1
