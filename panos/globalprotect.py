#!/usr/bin/env python

# Copyright (c) 2014, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


# import other parts of this panos package
import panos.errors as err
# import modules
from panos import getlogger
from panos.base import ENTRY, MEMBER, PanObject, Root
from panos.base import VarPath as Var
from panos.base import VersionedPanObject, VersionedParamPath

logger = getlogger(__name__)


class GlobalProtectGateway(VersionedPanObject):
    """GlobalProtectGateway for a Firewall object.

    Note: This is valid for PAN-OS x.x+.

    Args:
        name (string): The name
        certficate_profile (string): Selected certificate profile
        ssl_tls_service_profile (string):
        tunnel_mode (bool): Tunnel mode
        remote_user_tunnel (string): Remote user tunnel
        roles (list): Roles
        remote_user_tunnel_configs (list): Remote User tunnel configurations
    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY
    CHILDTYPES = (
        "globalprotect.Roles",
        "globalprotect.ClientAuth",
        "globalprotect.RemoteUserTunnelConfig",
        "globalprotect.HIPNotification",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/global-protect/global-protect-gateway")

        # params
        params = []
        params.append(
            VersionedParamPath(
                "certificate_profile", path="certificate_profile", vartype="string"
            )
        )
        params.append(
            VersionedParamPath(
                "hip_notification", path="hip-notification", vartype="entry"
            )
        )
        params.append(
            VersionedParamPath(
                "ssl_tls_service_profile", path="ssl-tls-service-profile"
            )
        )
        # TODO: Implement this
        # disallow-automatic-restoration
        # source-ip-enforcement
        # params.append(
        #    VersionedParamPath(
        #        "security_restrictions",
        #        path="security-restrictions/disallow-automatic-restoration",
        #    )
        # )
        # params.append(
        #    VersionedParamPath(
        #        "security_restrictions",
        #        path="security-restrictions/source-ip-enforcement",
        #    )
        # )
        params.append(
            VersionedParamPath("tunnel_mode", vartype="yesno", path="tunnel-mode")
        )
        params.append(
            VersionedParamPath("remote_user_tunnel", path="remote-user-tunnel")
        )
        params.append(VersionedParamPath("roles", vartype="entry", path="roles"))
        params.append(
            VersionedParamPath(
                "remote_user_tunnel_configs",
                path="remote-user-tunnel-configs",
                vartype="entry",
            )
        )
        not_implemented_items = [
            ("local_address", "local-address"),
            ("satellite_tunnel", "satellite-tunnel"),
        ]
        for name, path in not_implemented_items:
            params.append(VersionedParamPath(name, path=path))

        self._params = tuple(params)


class Roles(VersionedPanObject):
    """Roles object
    Note:

    Args:
    """

    ROOT = Root.VSYS
    NAME = "Roles"
    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/roles")

        params = []
        params.append(
            VersionedParamPath(
                "login_lifetime_unit",
                path="login-lifetime/{login_lifetime_unit}",
                values=("days", "hours", "minutes"),
            )
        )
        params.append(
            VersionedParamPath(
                "login_lifetime",
                vartype="int",
                path="login-lifetime/{login_lifetime_unit}",
            )
        )
        params.append(
            VersionedParamPath(
                "inactivity_logout_unit",
                path="inactivity-logout/{inactivity_logout_unit}",
                values=("days", "hours", "minutes"),
            )
        )
        params.append(
            VersionedParamPath(
                "inactivity_logout",
                vartype="int",
                path="inactivity-logout/{inactivity_logout_unit}",
            )
        )
        params.append(
            VersionedParamPath(
                "disconnect-on-idle",
                vartype="int",
                path="disconnect-on-idle/minutes",
            )
        )

        self._params = tuple(params)


class ClientAuth(VersionedPanObject):
    """Roles object
    Note:

    Args:
    """

    ROOT = Root.VSYS
    NAME = "ClientAuth"
    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/client-auth")

        params = []
        params.append(
            VersionedParamPath("authentication_profile", path="authentication-profile")
        )
        params.append(VersionedParamPath("os", default="Any", path="os"))
        params.append(
            VersionedParamPath("authentication-message", path="authentication-message")
        )
        params.append(
            VersionedParamPath(
                "user_credential_or_client_cert_required",
                path="user-credential-or-client-cert-required",
                vartype="yesno",
                default="no",
            )
        )
        params.append(
            VersionedParamPath(
                "username_label", path="username-label", vartype="string"
            )
        )
        params.append(
            VersionedParamPath(
                "password_label", path="password-label", vartype="string"
            )
        )

        self._params = tuple(params)


class RemoteUserTunnelConfig(VersionedPanObject):
    """Roles object
    Note:

    Args:
    """

    ROOT = Root.VSYS
    NAME = "RemoteUserTunnelConfig"
    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/remote-user-tunnel-configs")
        # params
        params = []
        params.append(
            VersionedParamPath(
                "accept_cookie_in_days",
                vartype="int",
                path="authentication-override/accept-cookie/cookie-lifetime/lifetime-in-days",
            )
        )
        params.append(
            VersionedParamPath(
                "accept_cookie_in_hours",
                vartype="int",
                path="authentication-override/accept-cookie/cookie-lifetime/lifetime-in-hours",
            )
        )
        params.append(
            VersionedParamPath(
                "accept_cookie_in_minutes",
                vartype="int",
                path="authentication-override/accept-cookie/cookie-lifetime/lifetime-in-minutes",
            )
        )
        params.append(
            VersionedParamPath(
                "cookie_encrypt_decrypt_cert",
                path="authentication-override/cookie-encrypt-decrypt-cert",
            )
        )
        params.append(
            VersionedParamPath(
                "generate_cookie",
                vartype="yesno",
                path="authentication-override/generate-cookie",
            )
        )
        params.append(
            VersionedParamPath(
                "split_tunneling_access_route",
                vartype="member",
                path="split-tunneling/access-route",
            )
        )
        params.append(
            VersionedParamPath(
                "split_tunneling_exclude_access_route",
                vartype="member",
                path="split-tunneling/exclude-access-route",
            )
        )
        params.append(
            VersionedParamPath(
                "split_tunneling_exclude_applications",
                vartype="member",
                path="split-tunneling/exclude-applications",
            )
        )
        params.append(
            VersionedParamPath(
                "split_tunneling_include_applications",
                vartype="member",
                path="split-tunneling/include-applications",
            )
        )
        params.append(
            VersionedParamPath(
                "split_tunneling_exclude_domains",
                vartype="entry",
                path="split-tunneling/exclude-domains/list",
            )
        )
        params.append(
            VersionedParamPath(
                "split_tunneling_include_domains",
                vartype="entry",
                path="split-tunneling/include-domains/list",
            )
        )
        params.append(
            VersionedParamPath("source_user", vartype="member", path="source-user")
        )
        params.append(
            VersionedParamPath(
                "authentication_servier_ip_pool",
                vartype="member",
                path="authentication-server-ip-pool",
            )
        )
        params.append(VersionedParamPath("ip_pool", vartype="member", path="ip-pool"))
        params.append(VersionedParamPath("os", vartype="member", path="os"))
        params.append(
            VersionedParamPath(
                "retrieve_framed_ip_address",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "no_direct_access_to_local_network",
                vartype="yseno",
            )
        )

        self._params = tuple(params)


class HIPNotification(VersionedPanObject):
    """HIP Notification for a Globalprotect Gateway
    Note:
    Args:
    """

    ROOT = Root.VSYS
    NAME = "HIPNotification"
    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/hip-notification")

        params = []
        params.append(VersionedParamPath("match_message", path="match-message/message"))
        params.append(
            VersionedParamPath(
                "match_show_notification_as",
                path="match-message/show-notification-as",
                vartype="string",
                values=("system-tray-balloon", "pop-up-message"),
            )
        )
        params.append(
            VersionedParamPath(
                "match_include_app_list",
                path="match-message/include-app-list",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath("not_match_message", path="not-match-message/message")
        )
        params.append(
            VersionedParamPath(
                "not_match_show_notification_as",
                path="not-match-message/show-notification-as",
                vartype="string",
                values=("system-tray-balloon", "pop-up-message"),
            )
        )

        self._params = tuple(params)


class GlobalProtectPortal(VersionedPanObject):
    """GlobalProtectPortal for a Firewall
    Note:

    Args:
    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY
    CHILDTYPES = ()

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/global-protject/global-protect-portal")

        # params
        params = []

        params.append(
            VersionedParamPath(
                "ssl_tls_service_profile", path="portal-config/ssl-tsl-service-profile"
            )
        )
        params.append(
            VersionedParamPath(
                "local_interface", path="portal-config/local-address/interface"
            )
        )
        params.append(
            VersionedParamPath(
                "local_ip_address_family",
                path="portal-config/local-address/ip-address-family",
            )
        )
        params.append(
            VersionedParamPath(
                "local_ip",
                path="portal-config/local-address/ip/{local_ip_addrses_family}",
            )
        )
        params.append(
            VersionedParamPath(
                "client_config_agent_user_override_key",
                path="client-config/agent-user-override-key",
            )
        )
        params.append(
            VersionedParamPath(
                "satellite_config_client_certificate_local",
                path="satellite-config/client-certificate/local",
            )
        )

        self._params = tuple(params)
