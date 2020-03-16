from pyovpn.plugin import *

#
# Following has been updated as tempoary workaround to issues with OpenVPN Radius Responses...
#

def post_auth(authcred, attributes, authret, info):

    # Create user prop list, if one does not already exist
    proplist = authret.setdefault('proplist', {})

    # user properties to save
    proplist_save = {}

    # Proceed with post_auth script if the server is using RADIUS, otherwise skip this script
    if info.get('auth_method') == 'radius':

        # Every valid user should be able to connect to the VPN
        authret['proplist']['prop_autogenerate'] = 'true'

        # Evaluating RADIUS server reply for user access flags, 19 is the new code for Callback-Number
        if 19 in info['radius_reply']:

            print("***** RADIUS-Reply: Callback-Number received, evaluating reply for OpenVPN Access Server access flags...")

            # Does it look like we are dealing with some access flags?
            if ''.join(info['radius_reply'].get(19)).__len__() == 5:

                # Is the superuser bit set?
                if ''.join(info['radius_reply'].get(19))[0] == '0':
                    print("*** RADIUS-Reply: Overrride found for prop_superuser, setting to false...")
                    authret['proplist']['prop_superuser'] = 'false'
                elif ''.join(info['radius_reply'].get(19))[0] == '1':
                    print("*** RADIUS-Reply: Overrride found for prop_superuser, setting to true...")
                    authret['proplist']['prop_superuser'] = 'true'

                # Is the autologin bit set?
                if ''.join(info['radius_reply'].get(19))[1] == '0':
                    print("*** RADIUS-Reply: Overrride found for prop_autologin, setting to false...")
                    proplist_save['prop_autologin'] = 'false'
                elif ''.join(info['radius_reply'].get(19))[1] == '1':
                    print("*** RADIUS-Reply: Overrride found for prop_autologin, setting to true...")
                    proplist_save['prop_autologin'] = 'true'

                # Is the lzo bit set?
                if ''.join(info['radius_reply'].get(19))[2] == '0':
                    print("*** RADIUS-Reply: Overrride found for prop_lzo, setting to false...")
                    authret['proplist']['prop_lzo'] = 'false'
                elif ''.join(info['radius_reply'].get(19))[2] == '1':
                    print("*** RADIUS-Reply: Overrride found for prop_lzo, setting to true...")
                    authret['proplist']['prop_lzo'] = 'true'

                # Is the reroute_gw bit set?
                if ''.join(info['radius_reply'].get(19))[3] == '0':
                    print("*** RADIUS-Reply: Overrride found for prop_reroute_gw_override, setting to 'disable'...")
                    authret['proplist']['prop_reroute_gw_override'] = 'disable'
                elif ''.join(info['radius_reply'].get(19))[3] == '1':
                    print("*** RADIUS-Reply: Overrride found for prop_reroute_gw_override, setting to 'dns_only'...")
                    authret['proplist']['prop_reroute_gw_override'] = 'dns_only'

                # Is the deny_web bit set?
                if ''.join(info['radius_reply'].get(19))[4] == '0':
                    print("*** RADIUS-Reply: Overrride found for prop_deny_web, setting to false...")
                    authret['proplist']['prop_deny_web'] = 'false'
                elif ''.join(info['radius_reply'].get(19))[4] == '1':
                    print("*** RADIUS-Reply: Overrride found for prop_deny_web, setting to true...")
                    authret['proplist']['prop_deny_web'] = 'true'

        # If Framed-Pool is set, set that as the group for the AS server, 88 is the Framed-Pool response
        if 88 in info['radius_reply']:
            print("***** RADIUS-Reply: Framed-Pool received, setting OpenVPN Access Server group to:", ''.join(info['radius_reply'].get(88)))
            authret['proplist']['conn_group'] = ''.join(info['radius_reply'].get(88))

        # If a static IP address is defined, use it, unless the group is not explicitly defined, 8 is the Framed-IP-Address respone
        if 8 in info['radius_reply']:
            if authret['proplist'].get('conn_group') is not None:
                print("***** RADIUS-Reply: Framed-IP-Address received, trying to set client IP address to: %s with group name: %s" % (''.join(info['radius_reply'].get(8)), authret['proplist'].get('conn_group')))
                authret['proplist']['conn_ip'] = ''.join(info['radius_reply'].get(8))
            else:
                print("*** RADIUS-Reply: Framed-IP-Address received, but no group name is specified. Ignoring reply attribute...")

    return authret, proplist_save
