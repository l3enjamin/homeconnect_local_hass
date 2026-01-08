"""Tests for config flow."""

from __future__ import annotations

from binascii import Error as BinasciiError
from typing import TYPE_CHECKING
from unittest.mock import ANY, AsyncMock, MagicMock, Mock, call, patch
from uuid import uuid4

from aiohttp import ClientConnectionError, ClientConnectorSSLError
from custom_components.homeconnect_ws import config_flow
from custom_components.homeconnect_ws.const import (
    CONF_AES_IV,
    CONF_FILE,
    CONF_MANUAL_HOST,
    CONF_PSK,
    DOMAIN,
)
from homeassistant.config_entries import SOURCE_IGNORE, SOURCE_USER
from homeassistant.const import CONF_DESCRIPTION, CONF_DEVICE, CONF_HOST, CONF_NAME
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers.selector import SelectOptionDict
from pytest_homeassistant_custom_component.common import MockConfigEntry
import pytest
from homeassistant.core import HomeAssistant
from .const import (
    DEVICE_DESCRIPTION,
    MOCK_AES_DEVICE_DESCRIPTION,
    MOCK_AES_DEVICE_ID,
    MOCK_AES_DEVICE_INFO,
    MOCK_CONFIG_DATA,
    MOCK_TLS_DEVICE_DESCRIPTION,
    MOCK_TLS_DEVICE_ID,
    MOCK_TLS_DEVICE_ID_2,
    MOCK_TLS_DEVICE_INFO,
)

if TYPE_CHECKING:
    import pytest
    from homeassistant.core import HomeAssistant

UPLOADED_FILE = str(uuid4())


async def test_user_init(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,  # noqa: ARG001
    monkeypatch: pytest.MonkeyPatch,
    mock_setup_entry: AsyncMock,
) -> None:
    """Test config flow init."""
    hc_socket = Mock()
    tls_socket = Mock(return_value=AsyncMock())
    hc_socket.TlsSocket = tls_socket
    monkeypatch.setattr(config_flow, "hc_socket", hc_socket)

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    assert result["type"] is FlowResultType.MENU
    assert result["step_id"] == "user"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "upload"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "device_select"
    assert not result["errors"]
    assert result["data_schema"].schema.get("device").config["options"] == [
        SelectOptionDict(
            value=MOCK_TLS_DEVICE_ID,
            label="Test_Brand Test_TLS (Test_vib)",
        ),
        SelectOptionDict(
            value=MOCK_AES_DEVICE_ID,
            label="Test_Brand Test_AES (Test_vib)",
        ),
        SelectOptionDict(
            value=MOCK_TLS_DEVICE_ID_2,
            label="Test_Brand Test_TLS (Test_vib)",
        ),
    ]

    hass.config_entries.flow.async_abort(result["flow_id"])
    mock_setup_entry.assert_not_awaited()


async def test_user_tls(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    mock_setup_entry: AsyncMock,
) -> None:
    """Test config flow compleate for TLS Appliance."""
    hc_socket = Mock()
    tls_socket = Mock(return_value=AsyncMock())
    hc_socket.TlsSocket = tls_socket
    monkeypatch.setattr(config_flow, "hc_socket", hc_socket)

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    assert result["type"] is FlowResultType.MENU

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "upload"
    assert not result["errors"]

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_DEVICE: MOCK_TLS_DEVICE_ID,
        },
    )

    tls_socket.assert_called_once_with(
        "Test_Brand-Test_TLS-010203040506070809",
        MOCK_TLS_DEVICE_INFO["key"],
    )
    tls_socket.return_value.connect.assert_awaited_once()
    tls_socket.return_value.close.assert_awaited_once()

    mock_process_profile_file.assert_called_once_with(UPLOADED_FILE)

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Test_Brand Test_TLS"
    assert result["data"][CONF_DESCRIPTION] == MOCK_TLS_DEVICE_DESCRIPTION
    assert result["data"][CONF_HOST] == "Test_Brand-Test_TLS-010203040506070809"
    assert result["data"][CONF_PSK] == MOCK_TLS_DEVICE_INFO["key"]
    assert CONF_AES_IV not in result["data"]
    assert result["data"][CONF_NAME] == "Test_Brand Test_TLS"

    mock_setup_entry.assert_awaited_once()


async def test_user_aes(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    mock_setup_entry: AsyncMock,
) -> None:
    """Test config flow compleate for AES Appliance."""
    hc_socket = Mock()
    aes_socket = Mock(return_value=AsyncMock())
    hc_socket.AesSocket = aes_socket
    monkeypatch.setattr(config_flow, "hc_socket", hc_socket)

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "upload"
    assert not result["errors"]

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_DEVICE: MOCK_AES_DEVICE_ID,
        },
    )

    aes_socket.assert_called_once_with(
        MOCK_AES_DEVICE_ID,
        MOCK_AES_DEVICE_INFO["key"],
        MOCK_AES_DEVICE_INFO["iv"],
    )
    aes_socket.return_value.connect.assert_awaited_once()
    aes_socket.return_value.close.assert_awaited_once()

    mock_process_profile_file.assert_called_once_with(UPLOADED_FILE)

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Test_Brand Test_AES"
    assert result["data"][CONF_DESCRIPTION] == MOCK_AES_DEVICE_DESCRIPTION
    assert result["data"][CONF_HOST] == "101112131415161718"
    assert result["data"][CONF_PSK] == MOCK_AES_DEVICE_INFO["key"]
    assert result["data"][CONF_AES_IV] == MOCK_AES_DEVICE_INFO["iv"]
    assert result["data"][CONF_NAME] == "Test_Brand Test_AES"

    mock_setup_entry.assert_awaited_once()


async def test_user_select_device(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,  # noqa: ARG001
) -> None:
    """Test select device."""
    mock_config = MockConfigEntry(
        domain=DOMAIN,
        data=MOCK_CONFIG_DATA,
        unique_id=MOCK_TLS_DEVICE_ID,
    )
    mock_config.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "upload"
    assert not result["errors"]

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "device_select"
    assert not result["errors"]
    assert result["data_schema"].schema.get("device").config["options"] == [
        SelectOptionDict(
            value=MOCK_AES_DEVICE_ID,
            label="Test_Brand Test_AES (Test_vib)",
        ),
        SelectOptionDict(
            value=MOCK_TLS_DEVICE_ID_2,
            label="Test_Brand Test_TLS (Test_vib)",
        ),
    ]
    hass.config_entries.flow.async_abort(result["flow_id"])


async def test_user_select_device_one(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,  # noqa: ARG001
    mock_setup_entry: AsyncMock,  # noqa: ARG001
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test select device when only one device left to setup."""
    hc_socket = Mock()
    aes_socket = Mock(return_value=AsyncMock())
    hc_socket.AesSocket = aes_socket
    monkeypatch.setattr(config_flow, "hc_socket", hc_socket)

    mock_config = MockConfigEntry(
        domain=DOMAIN,
        data=MOCK_CONFIG_DATA,
        unique_id=MOCK_TLS_DEVICE_ID,
    )
    mock_config.add_to_hass(hass)
    mock_config = MockConfigEntry(
        domain=DOMAIN,
        data=MOCK_CONFIG_DATA,
        unique_id=MOCK_TLS_DEVICE_ID_2,
    )
    mock_config.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "upload"
    assert not result["errors"]

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Test_Brand Test_AES"
    assert result["data"][CONF_DESCRIPTION] == MOCK_AES_DEVICE_DESCRIPTION
    assert result["data"][CONF_HOST] == "101112131415161718"
    assert result["data"][CONF_PSK] == MOCK_AES_DEVICE_INFO["key"]
    assert result["data"][CONF_AES_IV] == MOCK_AES_DEVICE_INFO["iv"]
    assert result["data"][CONF_NAME] == "Test_Brand Test_AES"


async def test_user_select_device_ignore(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,  # noqa: ARG001
) -> None:
    """Test select device when one discovered device was ignored."""
    mock_config = MockConfigEntry(
        domain=DOMAIN,
        data=MOCK_CONFIG_DATA,
        unique_id=MOCK_TLS_DEVICE_ID,
        source=SOURCE_IGNORE,
    )
    mock_config.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "upload"
    assert not result["errors"]

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "device_select"
    assert not result["errors"]
    assert result["data_schema"].schema.get("device").config["options"] == [
        SelectOptionDict(
            value=MOCK_TLS_DEVICE_ID,
            label="Test_Brand Test_TLS (Test_vib)",
        ),
        SelectOptionDict(
            value=MOCK_AES_DEVICE_ID,
            label="Test_Brand Test_AES (Test_vib)",
        ),
        SelectOptionDict(
            value=MOCK_TLS_DEVICE_ID_2,
            label="Test_Brand Test_TLS (Test_vib)",
        ),
    ]
    hass.config_entries.flow.async_abort(result["flow_id"])


async def test_user_set_host(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,  # noqa: ARG001
    mock_setup_entry: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test set host."""
    hc_socket = Mock()
    mock_hc_socket = Mock(return_value=AsyncMock())
    hc_socket.TlsSocket = mock_hc_socket
    monkeypatch.setattr(config_flow, "hc_socket", hc_socket)

    mock_hc_socket.return_value.connect.side_effect = ClientConnectionError()

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_DEVICE: MOCK_TLS_DEVICE_ID,
        },
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "host"
    assert result["errors"]["base"] == "cannot_connect"

    mock_hc_socket.assert_called_once_with(
        "Test_Brand-Test_TLS-010203040506070809",
        MOCK_TLS_DEVICE_INFO["key"],
    )
    mock_hc_socket.return_value.connect.assert_awaited_once()
    mock_hc_socket.return_value.close.assert_awaited_once()

    mock_hc_socket.reset_mock()
    mock_hc_socket.return_value.connect.reset_mock()

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_HOST: "1.2.3.4",
        },
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "host"
    assert result["errors"]["base"] == "cannot_connect"

    mock_hc_socket.assert_called_once_with(
        "1.2.3.4",
        MOCK_TLS_DEVICE_INFO["key"],
    )
    mock_hc_socket.return_value.connect.assert_awaited_once()
    mock_hc_socket.return_value.close.assert_awaited_once()

    mock_hc_socket.reset_mock(side_effect=True)
    mock_hc_socket.return_value.connect.reset_mock(side_effect=True)

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_HOST: "5.6.7.8",
        },
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_HOST] == "5.6.7.8"
    assert result["data"][CONF_MANUAL_HOST] is True

    mock_hc_socket.assert_called_once_with(
        "5.6.7.8",
        MOCK_TLS_DEVICE_INFO["key"],
    )
    mock_hc_socket.return_value.connect.assert_awaited_once()
    mock_hc_socket.return_value.close.assert_awaited_once()
    mock_setup_entry.assert_awaited_once()


async def test_user_auth_failed_ssl_error(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,  # noqa: ARG001
    mock_setup_entry: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test a config flow with ClientConnectorSSLError."""
    hc_socket = Mock()
    mock_hc_socket = Mock(return_value=AsyncMock())
    hc_socket.TlsSocket = mock_hc_socket
    monkeypatch.setattr(config_flow, "hc_socket", hc_socket)

    mock_hc_socket.return_value.connect.side_effect = ClientConnectorSSLError(
        MagicMock(), MagicMock()
    )

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_DEVICE: MOCK_TLS_DEVICE_ID,
        },
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "auth_failed"

    mock_hc_socket.return_value.close.assert_awaited_once()
    mock_setup_entry.assert_not_awaited()


async def test_user_auth_failed_binascii_error(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,  # noqa: ARG001
    mock_setup_entry: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test a config flow with BinasciiError."""
    hc_socket = Mock()
    mock_hc_socket = Mock(return_value=AsyncMock())
    hc_socket.TlsSocket = mock_hc_socket
    monkeypatch.setattr(config_flow, "hc_socket", hc_socket)

    mock_hc_socket.return_value.connect.side_effect = BinasciiError()

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_DEVICE: MOCK_TLS_DEVICE_ID,
        },
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "auth_failed"

    mock_hc_socket.return_value.close.assert_awaited_once()
    mock_setup_entry.assert_not_awaited()


async def test_user_connection_failed_timeout(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,  # noqa: ARG001
    mock_setup_entry: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test a config flow with TimeoutError."""
    hc_socket = Mock()
    mock_hc_socket = Mock(return_value=AsyncMock())
    hc_socket.TlsSocket = mock_hc_socket
    monkeypatch.setattr(config_flow, "hc_socket", hc_socket)

    mock_hc_socket.return_value.connect.side_effect = TimeoutError()

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_DEVICE: MOCK_TLS_DEVICE_ID,
        },
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "host"
    assert result["errors"]["base"] == "cannot_connect"

    mock_hc_socket.return_value.close.assert_awaited_once()
    hass.config_entries.flow.async_abort(result["flow_id"])
    mock_setup_entry.assert_not_awaited()


async def test_user_connection_failed_connection_error(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,  # noqa: ARG001
    mock_setup_entry: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test a config flow with ClientConnectionError."""
    hc_socket = Mock()
    mock_hc_socket = Mock(return_value=AsyncMock())
    hc_socket.TlsSocket = mock_hc_socket
    monkeypatch.setattr(config_flow, "hc_socket", hc_socket)

    mock_hc_socket.return_value.connect.side_effect = ClientConnectionError()

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_DEVICE: MOCK_TLS_DEVICE_ID,
        },
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "host"
    assert result["errors"]["base"] == "cannot_connect"

    mock_hc_socket.return_value.close.assert_awaited_once()
    hass.config_entries.flow.async_abort(result["flow_id"])
    mock_setup_entry.assert_not_awaited()


async def test_user_invalid_config_parser(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,
    mock_setup_entry: AsyncMock,
) -> None:
    """Test a config flow with error in config parser."""
    mock_process_profile_file.side_effect = Exception("Test Error")

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "profile_file_parser_error"
    assert result["description_placeholders"] == {"error": "Test Error"}
    mock_setup_entry.assert_not_awaited()


async def test_user_invalid_profile_no_info(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,
    mock_setup_entry: AsyncMock,
) -> None:
    """Test a reauthentication flow with no profile info."""
    mock_process_profile_file.return_value[MOCK_AES_DEVICE_ID] = {}

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "invalid_profile_file"
    mock_setup_entry.assert_not_awaited()


async def test_user_invalid_profile_no_description(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,
    mock_setup_entry: AsyncMock,
) -> None:
    """Test a config flow with no description."""
    mock_process_profile_file.return_value[MOCK_AES_DEVICE_ID].pop("description")

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_DEVICE: MOCK_AES_DEVICE_ID,
        },
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "invalid_profile_file"
    mock_setup_entry.assert_not_awaited()


async def test_user_invalid_profile_info(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,
    mock_setup_entry: AsyncMock,
) -> None:
    """Test a reauthentication flow with invalid info."""
    mock_process_profile_file.return_value[MOCK_AES_DEVICE_ID]["info"].pop("key")

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_DEVICE: MOCK_AES_DEVICE_ID,
        },
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "invalid_profile_file"
    mock_setup_entry.assert_not_awaited()


async def test_user_select_all_setup(
    hass: HomeAssistant,
    mock_process_profile_file: MagicMock,  # noqa: ARG001
    mock_setup_entry: AsyncMock,
) -> None:
    """Test a config flow with all devices setup."""
    mock_config = MockConfigEntry(
        domain=DOMAIN,
        data=MOCK_CONFIG_DATA,
        unique_id=MOCK_TLS_DEVICE_ID,
    )
    mock_config.add_to_hass(hass)
    mock_config = MockConfigEntry(
        domain=DOMAIN,
        data=MOCK_CONFIG_DATA,
        unique_id=MOCK_TLS_DEVICE_ID_2,
    )
    mock_config.add_to_hass(hass)
    mock_config = MockConfigEntry(
        domain=DOMAIN,
        data=MOCK_CONFIG_DATA,
        unique_id=MOCK_AES_DEVICE_ID,
    )
    mock_config.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            "next_step_id": "upload",
        },
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={
            CONF_FILE: UPLOADED_FILE,
        },
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "all_setup"
    mock_setup_entry.assert_not_awaited()


async def test_process_profile(
    monkeypatch: pytest.MonkeyPatch,
    hass: HomeAssistant,
    mock_process_uploaded_file: MagicMock,
) -> None:
    """Test processing profile file."""
    mock_parser = MagicMock()
    monkeypatch.setattr(config_flow, "parse_device_description", mock_parser)

    mock_config_flow = AsyncMock()
    mock_config_flow.hass = hass
    result = config_flow.HomeConnectConfigFlow._process_profile_file(
        mock_config_flow, UPLOADED_FILE
    )

    assert result == {
        MOCK_TLS_DEVICE_ID: {
            "info": MOCK_TLS_DEVICE_INFO,
            "description": mock_parser.return_value,
        },
        MOCK_AES_DEVICE_ID: {
            "info": MOCK_AES_DEVICE_INFO,
            "description": mock_parser.return_value,
        },
    }

    mock_parser.assert_has_calls(
        [
            call(b"TLS_DeviceDescription", b"TLS_FeatureMapping"),
            call(b"AES_DeviceDescription", b"AES_FeatureMapping"),
        ],
        any_order=True,
    )
    mock_process_uploaded_file.assert_called_with(ANY, UPLOADED_FILE)

async def test_user_login(
    hass: HomeAssistant,
    mock_setup_entry: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
    aioclient_mock: ANY,
) -> None:
    """Test config flow with login."""
    hc_socket = Mock()
    tls_socket = Mock(return_value=AsyncMock())
    hc_socket.TlsSocket = tls_socket
    monkeypatch.setattr(config_flow, "hc_socket", hc_socket)

    with patch("custom_components.homeconnect_ws.config_flow.parse_device_description", return_value=DEVICE_DESCRIPTION):
        result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

        # Select Login
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={
                "next_step_id": "login",
            },
        )

        assert result["type"] is FlowResultType.FORM
        assert result["step_id"] == "login"

        # Select Region
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={
                "region": "EU",
            },
        )

        assert result["type"] is FlowResultType.FORM
        assert result["step_id"] == "auth"

        # Mock Token and Data Fetch
        aioclient_mock.post(
            "https://api.home-connect.com/security/oauth/token",
            json={"access_token": "TEST_TOKEN"},
        )

        aioclient_mock.get(
            "https://prod.reu.rest.homeconnectegw.com/account/details",
            json={
                "homeAppliances": [
                    {
                        "identifier": MOCK_TLS_DEVICE_ID,
                        "brand": "Test_Brand",
                        "type": "Test_TLS",
                        "vib": "Test_vib",
                        "tls": {"key": MOCK_TLS_DEVICE_INFO["key"]},
                    }
                ]
            },
        )

        # Use zipfile to create a zip response
        from zipfile import ZipFile
        from io import BytesIO

        zip_buffer = BytesIO()
        with ZipFile(zip_buffer, "w") as zip_file:
            zip_file.writestr(f"{MOCK_TLS_DEVICE_ID}_FeatureMapping.xml", "dummy")
            zip_file.writestr(f"{MOCK_TLS_DEVICE_ID}_DeviceDescription.xml", "dummy")

        aioclient_mock.get(
            f"https://prod.reu.rest.homeconnectegw.com/api/iddf/v1/iddf/{MOCK_TLS_DEVICE_ID}",
            content=zip_buffer.getvalue(),
        )

        # Provide Code
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={
                "code": "TEST_CODE",
            },
        )

        assert result["type"] is FlowResultType.CREATE_ENTRY
        assert result["title"] == "Test_Brand Test_TLS"

        mock_setup_entry.assert_awaited_once()
