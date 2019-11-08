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



# import modules
from pandevice import getlogger
from pandevice.base import PanObject, Root, MEMBER, ENTRY
from pandevice.base import VarPath as Var
from pandevice.base import VersionedPanObject
from pandevice.base import VersionedParamPath

# import other parts of this pandevice package
import pandevice.errors as err

logger = getlogger(__name__)

class GlobalProtectGateway(VersionedPanObject):
    """GlobalProtectGateway for a Firewall
    """
    ROOT = Root.VSYS
    SUFFIX = ENTRY
    CHILDTYPES = (
        "globalprotect.Roles",
        "globalprotect.ClientAuth",
        "globalprotect.RemoteUserTunnelConfig",
    )
    
    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/global-protect/global-protect-gateway')

        # params
        params = []
        params.append(VersionedParamPath(
            'ssl_tls_service_profile', path='ssl-tls-service-profile')
        )
        params.append(VersionedParamPath(
            'tunnel_mode', vartype='yesno', path='tunnel-mode')
        )
        params.append(VersionedParamPath(
            'remote_user_tunnel', path='remote-user-tunnel')
        )
        #params.append(VersionedParamPath(
        #    'remote_user_tunnel_configs', path='remote-user-tunnel-configs', vartype='entry')
        #)
        not_implemented_items = [
            ('certificate_profile', 'certificate-profile'),
            ('hip_notification', 'hip-notification'),
            ('local_address', 'local-address'),
            ('satellite_tunnel', 'satellite-tunnel'),
        ]
        for name, path in not_implemented_items:
            params.append(VersionedParamPath(
                name, path=path))

        self._params = tuple(params)


class Roles(VersionedPanObject):
    ROOT = Root.VSYS
    NAME = 'Roles'
    SUFFIX = ENTRY
    
    def _setup(self):
        self._xpaths.add_profile(value='/roles')
    
        params = []
        params.append(VersionedParamPath(
            'login_lifetime_unit', path ='login-lifetime/{login_lifetime_unit}',
            values=('days', 'hours', 'minutes'))
        )
        params.append(VersionedParamPath(
            'login_lifetime', vartype='int', path='login-lifetime/{login_lifetime_unit}')
        )
        params.append(VersionedParamPath(
            'inactivity_logout_unit', path='inactivity-logout/{inactivity_logout_unit}',
            values=('days', 'hours', 'minutes'))
        )
        params.append(VersionedParamPath(
            'inactivity_logout', vartype='int', path='inactivity-logout/{inactivity_logout_unit}')
        )
        params.append(VersionedParamPath(
            'disconnection_on_idle_unit', path='disconnection-on-idle/{disconnection_on_idle_unit}',
            values=('days', 'hours', 'minutes'))
        )
        params.append(VersionedParamPath(
            'disconnection_on_idle', vartype='int', path='disconnection-on-idle/{disconnection_on_idle_unit}')
        )

        self._params = tuple(params)


class ClientAuth(VersionedPanObject):
    ROOT = Root.VSYS
    NAME = 'ClientAuth'
    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value='/client-auth')
    
        params = []
        params.append(VersionedParamPath(
            'authentication_profile', path='authentication-profile')
        )
        params.append(VersionedParamPath(
            'os', default='Any', path='os')
        )
        params.append(VersionedParamPath(
            'authentication-message', path='authentication-message')
        )

        self._params = tuple(params)


class RemoteUserTunnelConfig(VersionedPanObject):
    ROOT = Root.VSYS
    NAME = 'RemoteUserTunnelConfig'
    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value='/remote-user-tunnel-configs')
        # params
        params = []
        params.append(VersionedParamPath(
            'authentication_override', path='authentication-override')
        )
        params.append(VersionedParamPath(
            'split_tunneling_access-route', vartype='member', path='split-tunneling/access-route')
        )
        params.append(VersionedParamPath(
            'source_user', vartype='member', path='source-user')
        )
        params.append(VersionedParamPath(
            'authentication_servier_ip_pool', vartype='member', path='authentication-server-ip-pool')
        )
        params.append(VersionedParamPath(
            'ip_pool', vartype='member', path='ip-pool')
        )
        params.append(VersionedParamPath(
            'os', vartype='member', path='os')
        )
        params.append(VersionedParamPath(
            'retrieve_framed_ip_address', vartype='yesno', path='retrieve_framed_ip_address')
        )
        params.append(VersionedParamPath(
            'no_direct_access_to_local_networks', vartype='yseno', path='no_direct_access_to_local_networks')
        )

        self._params = tuple(params)



class GlobalProtectPortal(VersionedPanObject):
    """ GlobalProtectPortal for a Firewall
    """
    ROOT = Root.VSYS
    SUFFIX = ENTRY
    CHILDTYPES = (

    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/global-protject/global-protect-portal')

        # params
        params = []

        params.append(VersionedParamPath(
            'ssl_tls_service_profile', path='portal-config/ssl-tsl-service-profile')
        )
        params.append(VersionedParamPath(
            'local_interface', path='portal-config/local-address/interface')
        )
        params.append(VersionedParamPath(
            'local_ip_address_family', path='portal-config/local-address/ip-address-family')
        )
        params.append(VersionedParamPath(
            'local_ip', path='portal-config/local-address/ip/{local_ip_addrses_family}')
        )
        params.append(VersionedParamPath(
           'client_config_agent_user_override_key', path='client-config/agent-user-override-key')
        )
        params.append(VersionedParamPath(
            'satellite_config_client_certificate_local', path='satellite-config/client-certificate/local')
        )

        self._params = tuple(params)