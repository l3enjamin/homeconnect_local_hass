"""Config flow."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import random
import re
import secrets
from binascii import Error as BinasciiError
from io import BytesIO
from typing import TYPE_CHECKING, Any
from zipfile import ZipFile

import aiohttp
import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from aiohttp import ClientConnectionError, ClientConnectorSSLError
from homeassistant.components.file_upload import process_uploaded_file
from homeassistant.config_entries import SOURCE_IGNORE, ConfigFlow
from homeassistant.const import (
    CONF_DESCRIPTION,
    CONF_DEVICE,
    CONF_DEVICE_ID,
    CONF_HOST,
    CONF_MODE,
    CONF_NAME,
)
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    FileSelector,
    FileSelectorConfig,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
)
from homeconnect_websocket import (
    DeviceDescription,
    socket as hc_socket,
    parse_device_description,
)

from . import HC_KEY, HCConfig
from .const import CONF_AES_IV, CONF_FILE, CONF_MANUAL_HOST, CONF_PSK, DOMAIN

if TYPE_CHECKING:
    from pathlib import Path

    from homeassistant.config_entries import ConfigFlowResult
    from homeassistant.data_entry_flow import FlowResult
    from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo

    from . import HCConfigEntry

_LOGGER = logging.getLogger(__name__)

CLIENT_ID = "9B75AC9EC512F36C84256AC47D813E2C1DD0D6520DF774B020E1E6E2EB29B1F3"
REDIRECT_URI = "hcauth://auth/prod"
SCOPES = "Control DeleteAppliance IdentifyAppliance Images Monitor ReadAccount ReadOrigApi Settings WriteAppliance WriteOrigApi"

CONFIG_FILE_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_FILE): FileSelector(config=FileSelectorConfig(accept=".zip")),
    }
)
CONFIG_FILE_SCHEMA_JSON = vol.Schema(
    {
        vol.Required(CONF_FILE): FileSelector(config=FileSelectorConfig(accept=".zip,.json")),
    }
)
CONFIG_HOST_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): cv.string,
    }
)


def process_zip_file(config_path: Path) -> dict[str, dict[str, dict | DeviceDescription]]:
    """Process uploaded zip file."""
    profile_file = ZipFile(config_path)
    return process_zip_data(profile_file)

def process_zip_data(profile_file: ZipFile) -> dict[str, dict[str, dict | DeviceDescription]]:
    """Process zip file data."""
    appliances = {}
    re_info = re.compile(".*.json$")
    infolist = profile_file.infolist()
    for file in infolist:
        if re_info.match(file.filename):
            appliance_info = json.load(profile_file.open(file))

            description_file_name = appliance_info["deviceDescriptionFileName"]
            feature_file_name = appliance_info["featureMappingFileName"]
            description_file = profile_file.open(description_file_name).read()
            feature_file = profile_file.open(feature_file_name).read()

            appliance_description = parse_device_description(description_file, feature_file)
            appliances[appliance_info["haId"]] = {
                "info": appliance_info,
                "description": appliance_description,
            }
            _LOGGER.debug("Found Appliance %s", appliance_info["vib"])
    return appliances


def process_json_file(config_path: Path) -> dict[str, dict[str, dict | DeviceDescription]]:
    """Process uploaded json file."""
    with config_path.open() as file:
        entry_data = json.load(file)
    return {"config_entry": entry_data["data"]["entry_data"]}


def generate_code_verifier() -> str:
    """Generate PKCE code verifier."""
    return secrets.token_urlsafe(32)


def generate_code_challenge(verifier: str) -> str:
    """Generate PKCE code challenge."""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class HomeConnectConfigFlow(ConfigFlow, domain=DOMAIN):
    """HomeConnect Config flow."""

    def __init__(self) -> None:
        super().__init__()
        self.errors = {}
        self.data = {}
        self.appliances: dict[str, dict[str, dict | DeviceDescription]] = {}
        self.reauth_entry: HCConfigEntry = None
        self.global_config: HCConfig | None = None
        self.pkce_verifier = None
        self.region = None
        self.api_base_url = None
        self.asset_base_url = None
        self.token_url = None
        self.account_details_url = None
        self.device_info_url = None

    def _process_profile_file(
        self, uploaded_file_id: str
    ) -> dict[str, dict[str, dict | DeviceDescription]]:
        with process_uploaded_file(self.hass, uploaded_file_id) as config_path:
            if config_path.suffix == ".zip":
                return process_zip_file(config_path)
            if config_path.suffix == ".json":
                return process_json_file(config_path)
            msg = "Unexpected profile file suffix: %s"
            raise ValueError(msg, config_path.name)

    def _set_encryption_keys(self, appliance_info: dict) -> None:
        self.data[CONF_MODE] = appliance_info["connectionType"]
        if self.data[CONF_MODE] == "TLS":
            if CONF_HOST not in self.data:
                self.data[CONF_HOST] = (
                    f"{appliance_info['brand']}-{appliance_info['type']}-{appliance_info['haId']}"
                )
                _LOGGER.debug("Set Host to: %s", self.data[CONF_HOST])
            self.data[CONF_PSK] = appliance_info["key"]
        else:
            if CONF_HOST not in self.data:
                self.data[CONF_HOST] = appliance_info["haId"]
                _LOGGER.debug("Set Host to: %s", self.data[CONF_HOST])
            self.data[CONF_PSK] = appliance_info["key"]
            self.data[CONF_AES_IV] = appliance_info["iv"]
        _LOGGER.debug("Set Keys for %s Appliance", self.data[CONF_MODE])

        if self.global_config:
            if self.global_config.override_host is not None:
                # Dev mode host override
                self.data[CONF_HOST] = self.global_config.override_host
                self.data[CONF_MANUAL_HOST] = True
                _LOGGER.info("Host override: %s", self.data[CONF_HOST])
            if self.global_config.override_psk is not None:
                # Dev mode psk override
                self.data[CONF_PSK] = self.global_config.override_psk
                self.data[CONF_MODE] = "TLS"
                self.data[CONF_AES_IV] = None
                _LOGGER.info("PSK override")

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle a flow initialized by the user."""
        _LOGGER.debug("Config flow initialized by user")
        self.global_config = self.hass.data.get(HC_KEY)

        return self.async_show_menu(
            step_id="user",
            menu_options=["login", "upload"]
        )

    async def async_step_login(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle login region selection."""
        if user_input is not None:
            self.region = user_input["region"]
            if self.region == 'EU':
                self.api_base_url = "https://api.home-connect.com"
                self.asset_base_url = 'https://prod.reu.rest.homeconnectegw.com'
            elif self.region == 'NA':
                self.api_base_url = "https://api-rna.home-connect.com"
                self.asset_base_url = 'https://prod.rna.rest.homeconnectegw.com'
            elif self.region == 'CN':
                self.api_base_url = "https://api.home-connect.cn"
                self.asset_base_url = 'https://prod.rgc.rest.homeconnectegw.cn'
            elif self.region == 'RU':
                self.api_base_url = "https://api-rus.home-connect.com"
                self.asset_base_url = 'https://prod.rus.rest.homeconnectegw.com'

            self.token_url = self.api_base_url + '/security/oauth/token'
            self.account_details_url = self.asset_base_url + '/account/details'
            self.device_info_url = self.asset_base_url + '/api/iddf/v1/iddf/'

            return await self.async_step_auth()

        return self.async_show_form(
            step_id="login",
            data_schema=vol.Schema({
                vol.Required("region", default="EU"): vol.In(["EU", "NA", "CN", "RU"])
            })
        )

    async def async_step_auth(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle authentication."""
        if user_input is not None:
            code_input = user_input["code"]
            # Extract code if full URL is pasted
            if "code=" in code_input:
                try:
                    match = re.search(r"code=([^&]+)", code_input)
                    if match:
                        code = match.group(1)
                    else:
                        raise ValueError("No code found in URL")
                except ValueError:
                     self.errors["base"] = "invalid_auth"
                     return await self.async_step_auth()
            else:
                code = code_input

            return await self.async_step_fetch(code)

        self.pkce_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(self.pkce_verifier)

        params = {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPES,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "login"
        }

        # Build URL manually to ensure order or correct encoding if needed,
        # though aiohttp or urllib works too.
        from urllib.parse import urlencode
        auth_url = f"{self.api_base_url}/security/oauth/authorize?{urlencode(params)}"

        return self.async_show_form(
            step_id="auth",
            description_placeholders={"auth_url": auth_url},
            data_schema=vol.Schema({
                vol.Required("code"): str
            }),
            errors=self.errors
        )

    async def async_step_fetch(self, code: str) -> FlowResult:
        """Fetch tokens and profiles."""
        session = async_get_clientsession(self.hass)

        # 1. Get Token
        try:
            token_response = await session.post(
                self.token_url,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": CLIENT_ID,
                    "redirect_uri": REDIRECT_URI,
                    "code_verifier": self.pkce_verifier
                }
            )
            token_data = await token_response.json()
            if "access_token" not in token_data:
                _LOGGER.error("Token response error: %s", token_data)
                self.errors["base"] = "token_error"
                return await self.async_step_auth()

            access_token = token_data["access_token"]

        except Exception as e:
            _LOGGER.exception("Error fetching token")
            self.errors["base"] = "token_error"
            return await self.async_step_auth()

        # 2. Get Account Details
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            account_response = await session.get(self.account_details_url, headers=headers)
            if account_response.status != 200:
                 _LOGGER.error("Account details error: %s", await account_response.text())
                 self.errors["base"] = "fetch_error"
                 return await self.async_step_auth()

            account_data = await account_response.json()
            home_appliances = account_data.get("homeAppliances", [])

            self.appliances = {}

            for appliance in home_appliances:
                 haId = appliance["identifier"]

                 # Construct appliance info similar to what the downloader does
                 appliance_info = {
                    "haId": haId,
                    "type": appliance["type"],
                    "serialNumber": appliance.get("serialnumber"),
                    "brand": appliance["brand"],
                    "vib": appliance["vib"],
                    "mac": appliance.get("mac"),
                    "featureMappingFileName": f"{haId}_FeatureMapping.xml",
                    "deviceDescriptionFileName": f"{haId}_DeviceDescription.xml",
                 }

                 if "tls" in appliance and "key" in appliance["tls"]:
                      appliance_info["connectionType"] = "TLS"
                      appliance_info["key"] = appliance["tls"]["key"]
                 elif "aes" in appliance and "key" in appliance["aes"]:
                      appliance_info["connectionType"] = "AES"
                      appliance_info["key"] = appliance["aes"]["key"]
                      appliance_info["iv"] = appliance["aes"]["iv"]
                 else:
                      _LOGGER.warning("No keys found for appliance %s", haId)
                      continue

                 # 3. Download Device ZIP
                 zip_url = f"{self.device_info_url}{haId}"
                 zip_response = await session.get(zip_url, headers=headers)

                 if zip_response.status == 200:
                      zip_content = await zip_response.read()
                      with ZipFile(BytesIO(zip_content)) as z:
                           # Extract XMLs
                           try:
                                description_file = z.open(appliance_info["deviceDescriptionFileName"]).read()
                                feature_file = z.open(appliance_info["featureMappingFileName"]).read()
                                appliance_description = parse_device_description(description_file, feature_file)

                                self.appliances[haId] = {
                                    "info": appliance_info,
                                    "description": appliance_description,
                                }
                           except Exception as e:
                                _LOGGER.error("Error parsing zip for %s: %s", haId, e)
                 else:
                      _LOGGER.error("Failed to download zip for %s: %s", haId, zip_response.status)

        except Exception as e:
            _LOGGER.exception("Error fetching appliances")
            self.errors["base"] = "fetch_error"
            return await self.async_step_auth()

        if not self.appliances:
            self.errors["base"] = "fetch_error" # Or no appliances found
            return await self.async_step_auth()

        return await self.async_step_device_select()


    async def async_step_upload(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle profile file upload."""
        if user_input is not None:
            _LOGGER.debug("Got Profile file")
            try:
                self.appliances = await self.hass.async_add_executor_job(
                    self._process_profile_file, user_input[CONF_FILE]
                )
                _LOGGER.debug("Found %s Appliances in Profile file", len(self.appliances))
                if "config_entry" in self.appliances:
                    _LOGGER.debug("Setting up form config entry")
                    self.data = self.appliances["config_entry"]
                    if self.global_config:
                        if self.global_config.override_host is not None:
                            # Dev mode host override
                            self.data[CONF_HOST] = self.global_config.override_host
                            self.data[CONF_MANUAL_HOST] = True
                            _LOGGER.info("Host override: %s", self.data[CONF_HOST])
                        if self.global_config.override_psk is not None:
                            # Dev mode psk override
                            self.data[CONF_PSK] = self.global_config.override_psk
                            self.data[CONF_MODE] = "TLS"
                            self.data[CONF_AES_IV] = None
                            _LOGGER.info("PSK override")

            except Exception as exc:
                _LOGGER.error("Error parsing profile file: %s", exc)
                return self.async_abort(
                     reason="profile_file_parser_error",
                     description_placeholders={"error": str(exc)},
                )
            except (KeyError, ValueError):
                return self.async_abort(reason="invalid_profile_file")

            if not self.errors:
                if "config_entry" in self.appliances:
                    return await self.async_step_test_connection()

                if self.unique_id:
                    return await self.async_step_set_data()
                return await self.async_step_device_select()

        if (global_config := self.hass.data.get(HC_KEY)) and global_config.setup_from_dump:
            scheam = CONFIG_FILE_SCHEMA_JSON
        else:
            scheam = CONFIG_FILE_SCHEMA
        return self.async_show_form(step_id="upload", data_schema=scheam, errors=self.errors)

    async def async_step_device_select(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle device selection."""
        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_DEVICE])
            return await self.async_step_set_data()

        appliance_options: list[SelectOptionDict] = []
        try:
            for appliance_id, appliance_info in self.appliances.items():
                existing_entry = self.hass.config_entries.async_entry_for_domain_unique_id(
                    self.handler, appliance_id
                )

                if not existing_entry or existing_entry.source == SOURCE_IGNORE:
                    brand = appliance_info["info"]["brand"]
                    appliance_type = appliance_info["info"]["type"]
                    vib = appliance_info["info"]["vib"]
                    appliance_name = f"{brand} {appliance_type} ({vib})"
                    appliance_options.append(
                        SelectOptionDict(
                            value=appliance_id,
                            label=appliance_name,
                        )
                    )
                else:
                    _LOGGER.debug("Found Setup Appliance %s", appliance_info["info"]["vib"])
        except KeyError:
            return self.async_abort(reason="invalid_profile_file")
        if len(appliance_options) == 0:
            _LOGGER.debug("No Appliances left to setup")
            return self.async_abort(reason="all_setup")
        if len(appliance_options) == 1:
            _LOGGER.debug("Only one Appliances left to setup")
            await self.async_set_unique_id(appliance_options[0]["value"])
            return await self.async_step_set_data()
        _LOGGER.debug("Found %s Appliances not setup", len(appliance_options))
        schema = vol.Schema(
            {
                vol.Required(CONF_DEVICE): SelectSelector(
                    SelectSelectorConfig(options=appliance_options, sort=True)
                )
            }
        )
        return self.async_show_form(step_id="device_select", data_schema=schema, errors=self.errors)

    async def async_step_test_connection(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Test connection with Appliance."""
        host = self.data[CONF_HOST]
        _LOGGER.debug("Testing connection to %s Appliance", self.data[CONF_MODE])
        self.errors = {}
        if self.data[CONF_MODE] == "AES":
            socket = hc_socket.AesSocket(host, self.data[CONF_PSK], self.data[CONF_AES_IV])
        else:
            socket = hc_socket.TlsSocket(host, self.data[CONF_PSK])
        try:
            await socket.connect()
        except (ClientConnectorSSLError, BinasciiError) as ex:
            _LOGGER.debug("validate_config failed: %s", ex)
            return self.async_abort(reason="auth_failed")
        except (TimeoutError, ClientConnectionError) as ex:
            _LOGGER.debug("validate_config failed: %s", ex)
            self.errors["base"] = "cannot_connect"
        finally:
            await socket.close()
        if self.errors:
            _LOGGER.debug("Connection error, showing host step")
            return await self.async_step_host()
        _LOGGER.debug("config vaild, adding config entry")
        return await self.async_step_create_entry(self.data)

    async def async_step_host(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle Host setting."""
        if user_input is not None:
            self.data[CONF_MANUAL_HOST] = True
            self.data[CONF_HOST] = user_input[CONF_HOST]
            _LOGGER.debug("User set Host to: %s", self.data[CONF_HOST])
            return await self.async_step_test_connection()

        schema = self.add_suggested_values_to_schema(
            CONFIG_HOST_SCHEMA, {CONF_HOST: self.data[CONF_HOST]}
        )
        return self.async_show_form(
            step_id="host",
            data_schema=schema,
            errors=self.errors,
            description_placeholders={CONF_HOST: self.data[CONF_HOST]},
        )

    async def async_step_create_entry(self, data: dict) -> ConfigFlowResult:
        """Create an config entry or update existing entry for reauth."""
        if self.reauth_entry:
            return self.async_update_reload_and_abort(
                self.reauth_entry,
                data_updates=data,
            )
        return self.async_create_entry(title=data[CONF_NAME], data=data)

    async def async_step_reauth(self, user_input: dict[str, Any]) -> ConfigFlowResult:
        """Reauth flow initialized."""
        _LOGGER.debug("Reauth flow initialized")
        self.reauth_entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        self.data[CONF_HOST] = self.reauth_entry.data[CONF_HOST]
        return await self.async_step_upload()

    async def async_step_set_data(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm reauth dialog."""
        if self.unique_id not in self.appliances:
            return self.async_abort(reason="appliance_not_in_profile_file")

        appliance = self.appliances[self.unique_id]
        try:
            appliance_info = appliance["info"]

            self.data[CONF_DESCRIPTION] = appliance["description"]

            self.data[CONF_DEVICE_ID] = random.randbytes(4).hex()  # noqa: S311
            self.data[CONF_NAME] = f"{appliance_info['brand']} {appliance_info['type']}"

            self._set_encryption_keys(appliance_info)
        except (KeyError, ValueError):
            return self.async_abort(reason="invalid_profile_file")

        return await self.async_step_test_connection()

    async def async_step_zeroconf(self, discovery_info: ZeroconfServiceInfo) -> FlowResult:
        try:
            _LOGGER.debug(
                "Discovered Appliance %s @ %s",
                discovery_info.properties["vib"],
                discovery_info.host,
            )
            await self.async_set_unique_id(discovery_info.properties["id"])
            updates = None
            config_entry = self.hass.config_entries.async_entry_for_domain_unique_id(
                self.handler, self.unique_id
            )
            if config_entry and not config_entry.data.get(CONF_MANUAL_HOST, False):
                updates = {CONF_HOST: str(discovery_info.ip_address)}
            self._abort_if_unique_id_configured(updates=updates)
            self.data[CONF_HOST] = str(discovery_info.ip_address)
            self.data[CONF_NAME] = (
                f"{discovery_info.properties['brand']} {discovery_info.properties['type']}"
            )

            self.context.update(
                {
                    "title_placeholders": {"name": discovery_info.name.split(".")[0]},
                }
            )

            return await self.async_step_user()
        except KeyError:
            return self.async_abort(reason="invalid_discovery_info")
