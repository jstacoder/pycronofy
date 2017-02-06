import datetime
from pycronofy import settings
from pycronofy.auth import Auth
from pycronofy.datetime_utils import get_iso8601_string
from pycronofy.pagination import Pages
from pycronofy.request_handler import RequestHandler
from pycronofy.validation import validate

class Client(object):
    """Client for cronofy web service.
    Performs authentication, and wraps API: https://www.cronofy.com/developers/api/
    """

    def _return_correct_response(
        self,
        response,
        response_key,
        only_return_ok=None,
        only_return_status_code=None
    ):        
        return \
        (
            response.json()[response_key]\
            if response.ok\
            else response.status_code
        )\
        if not (only_return_ok or only_return_status_code) else\
            (response.ok if only_return_ok else response.status_code)

    def _good_request(
        self,
        endpoint,
        method='get',
        url=None,
        only_return_ok=None,
        only_return_status_code=None,        
        *args,
        **kwargs
        ):
        return self._return_correct_response(
            getattr(
                self.request_handler,method
            )(
                endpoint=url or endpoint,
                *args,
                **kwargs
            ),
            endpoint, 
            only_return_ok=only_return_ok,
            only_return_status_code=only_return_status_code
        )

    def __init__(
        self, 
        client_id=None, 
        client_secret=None, 
        access_token=None, 
        refresh_token=None, 
        token_expiration=None
    ):
        """
        Example Usage:

        pycronofy.Client(access_token='')
        pycronofy.Client(client_id='', client_secret='')

        :param string client_id: OAuth Client ID. (Optional, default None)
        :param string client_secret: OAuth Client Secret. (Optional, default None)
        :param string access_token: Access Token for User's Account. (Optional, default None)
        :param string refresh_token: Existing Refresh Token for User's Account. (Optional, default None)
        :param string token_expiration: Datetime token expires. (Optional, default None)
        """
        self.auth = Auth(client_id, client_secret, access_token, refresh_token, token_expiration)
        self.request_handler = RequestHandler(self.auth)

    def account(self):
        """Get identifying information for the active account.

        :return: Account data.
        :rtype: ``dict``
        """
        endpoint = 'account'        
        return self._good_request(endpoint,only_return_ok=True)
        
    def close_notification_channel(self, channel_id):
        """Close a notification channel to stop push notifications from being sent.

        :param string channel_id: The id of the notification channel.
        :rtype: ``int`` STATUS CODE
        """                
        return self.request_handler.delete(endpoint = 'channels/{}'.format(channel_id)).status_code
        
    def create_notification_channel(self, callback_url, calendar_ids=()):
        """Create a new channel for receiving push notifications.

        :param string callback_url: The url that will receive push notifications.
        Must not be longer than 128 characters and should be HTTPS.
        :param tuple calendar_ids: List of calendar ids to create notification channels for. (Optional. Default empty tuple)
        :return: Channel id and channel callback
        :rtype: ``dict``
        """
        endpoint = 'channels'
        data = {'callback_url': callback_url}
        if calendar_ids:
            data['filters'] = {'calendar_ids':calendar_ids}
        return self._good_request(endpoint,method='post',data=data)        

    def delete_all_events(self, calendar_ids=()):
        """Deletes all events managed through Cronofy from the all of the user's calendars.

        :param tuple calendar_ids: List of calendar ids to delete events for. (Optional. Default empty tuple)
        """
        endpoint = 'events'
        params = dict( delete_all = True ) if not len(calendar_ids) else {'calendar_ids[]': calendar_ids }            
        return self._good_request(endpoint,method='delete',params=params,only_return_status_code=True)

    def delete_event(self, calendar_id, event_id):
        """Delete an event from the specified calendar.

        :param string calendar_id: ID of calendar to insert/update event into.
        :param string event_id: ID of event to delete.
        """
        endpoint = 'calendars/{}/events'.format(calendar_id)
        params = {'event_id': event_id}
        return self._good_request(endpoint,method='delete',data=params, only_return_status_code=True)

    def get_authorization_from_code(self, code, redirect_uri=''):
        """Updates the authorization tokens from the user provided code.

        :param string code: Authorization code to pass to Cronofy.
        :param string redirect_uri: Optionally override redirect uri obtained from user_auth_link. (They must match however).
        :return: Dictionary containing auth tokens, expiration info, and response status.
        :rtype: ``dict``
        """
        response = self.request_handler.post(
            url='%s/oauth/token' % settings.API_BASE_URL,
            data={
                'grant_type': 'authorization_code',
                'client_id': self.auth.client_id,
                'client_secret': self.auth.client_secret,
                'code': code,
                'redirect_uri': redirect_uri if redirect_uri else self.auth.redirect_uri,
        })
        data = response.json()
        token_expiration = (datetime.datetime.utcnow() + datetime.timedelta(seconds=data['expires_in']))
        self.auth.update(
            token_expiration=token_expiration,
            access_token=data['access_token'],
            refresh_token=data['refresh_token'],
        )
        return {
            'access_token': self.auth.access_token,
            'refresh_token': self.auth.refresh_token,
            'token_expiration': get_iso8601_string(self.auth.token_expiration),
        }

    def is_authorization_expired(self):
        """Checks if the authorization token (access_token) has expired.

        :return: If expired.
        :rtype: ``bool``
        """
        if not self.auth.token_expiration:
            return True
        return (datetime.datetime.utcnow() > self.auth.token_expiration)

    def list_calendars(self):
        """Return a list of calendars available for the active account.

        :return: List of calendars (dictionaries).
        :rtype: ``list``
        """
        endpoint = 'calendars'
        return self._good_request(endpoint=endpoint)        

    def list_profiles(self):
        """Get list of active user's calendar profiles.

        :return: Calendar profiles.
        :rtype: ``list``
        """
        endpoint = 'profiles'
        return self._good_request(endpoint=endpoint)        

    def list_notification_channels(self):
        """Return a list of notification channels available for the active account.

        :return: List of notification channels (dictionaries).
        :rtype: ``list``
        """
        endpoint = 'channels'
        return self._good_request(endpoint=endpoint)

    def read_events(self,
        calendar_ids=(),
        from_date=None,
        to_date=None,
        last_modified=None,
        tzid=settings.DEFAULT_TIMEZONE_ID,
        only_managed=False,
        include_managed=True,
        include_deleted=False,
        include_moved=False,
        localized_times=False,
        automatic_pagination=True):
        """Read events for linked account (optionally for the specified calendars).

        :param tuple calendar_ids: Tuple or list of calendar ids to pass to cronofy. (Optional).
        :param datetime.date from_date: Start datetime (or ISO8601 string) for query. (Optional).
        :param datetime.date to_date: End datetime (or ISO8601 string) for query. (Optional).
        :param datetime.datetime last_modified: Return items modified on or after last_modified. Datetime or ISO8601 string. (Optional).
        :param string tzid: Timezone ID for query. (Optional, default settings.DEFAULT_TIMEZONE_ID). Should match tzinfo on datetime objects.
        :param bool only_managed: Only include events created through the API. (Optional, default False)
        :param bool include_managed: Include events created through the API. (Optional, default True)
        :param bool include_deleted: Include deleted events. (Optional, default False)
        :param bool include_moved: Include events that ever existed within the from_date/to_date time window. (Optional, default False)
        :param bool localized_times: Return time values for event start/end with localization information. This varies across providers. (Optional, default False).
        :param bool automatic_pagination: Autonatically fetch next page when iterating through results (Optional, default True)
        :return: Wrapped results (Containing first page of events).
        :rtype: ``Pages``
        """
        endpoint = 'events'
        params = {
            'tzid': tzid,
            'calendar_ids[]':calendar_ids,
            'from': get_iso8601_string(from_date),
            'to': get_iso8601_string(to_date),
            'last_modified': get_iso8601_string(last_modified),
            'only_managed': only_managed,
            'include_managed': include_managed,
            'include_deleted': include_deleted,
            'include_moved': include_moved,
            'localized_times': localized_times,
        }
        return self._good_request(endpoint=endpoint,params=params)
        #return Pages(self.request_handler, results, 'events', automatic_pagination)

    def read_free_busy(self,
        calendar_ids=(),
        from_date=None,
        to_date=None,
        last_modified=None,
        tzid=settings.DEFAULT_TIMEZONE_ID,
        include_managed=True,
        localized_times=False,
        automatic_pagination=True):
        """Read free/busy blocks for linked account (optionally for the specified calendars).

        :param tuple calendar_ids: Tuple or list of calendar ids to pass to cronofy. (Optional).
        :param datetime.date from_date: Start datetime (or ISO8601 string) for query. (Optional).
        :param datetime.date to_date: End datetime (or ISO8601 string) for query. (Optional).
        :param string tzid: Timezone ID for query. (Optional, default settings.DEFAULT_TIMEZONE_ID). Should match tzinfo on datetime objects.
        :param bool include_managed: Include pages created through the API. (Optional, default True)
        :param bool localized_times: Return time values for event start/end with localization information. This varies across providers. (Optional, default False).
        :param bool automatic_pagination: Autonatically fetch next page when iterating through results (Optional, default True)
        :return: Wrapped results (Containing first page of free/busy blocks).
        :rtype: ``Pages``
        """
        endpoint = 'free_busy'
        params = {
            'tzid': tzid,
            'calendar_ids[]':calendar_ids,
            'from': get_iso8601_string(from_date),
            'to': get_iso8601_string(to_date),
            'include_managed': include_managed,
            'localized_times': localized_times,
        }
        return self._good_request(endpoint=endpoint,params=params)
        #return Pages(self.request_handler, results, 'free_busy', automatic_pagination)

    def refresh_authorization(self):
        """Refreshes the authorization tokens.

        :return: Dictionary containing auth tokens, expiration info, and response status.
        :rtype: ``dict``
        """
        response = self.request_handler.post(
            url='%s/oauth/token' % settings.API_BASE_URL,
            data={
                'grant_type': 'refresh_token',
                'client_id': self.auth.client_id,
                'client_secret': self.auth.client_secret,
                'refresh_token': self.auth.refresh_token,
            }
        )
        data = response.json()
        token_expiration = (datetime.datetime.utcnow() + datetime.timedelta(seconds=data['expires_in']))
        self.auth.update(
            token_expiration=token_expiration,
            access_token=data['access_token'],
            refresh_token=data['refresh_token'],
        )
        return {
            'access_token': self.auth.access_token,
            'refresh_token': self.auth.refresh_token,
            'token_expiration': get_iso8601_string(self.auth.token_expiration),
        }

    def revoke_authorization(self):
        """Revokes Oauth authorization."""
        response = self.request_handler.post(
            url='%s/oauth/token/revoke' % settings.API_BASE_URL,
            data={
                'client_id': self.auth.client_id,
                'client_secret': self.auth.client_secret,
                'token': self.auth.access_token,
            }
        )
        self.auth.update(
            token_expiration=None,
            access_token=None,
            refresh_token=None,
        )

    def upsert_event(self, calendar_id, event):
        """Inserts or updates an event for the specified calendar.

        :param string calendar_id: ID of calendar to insert/update event into.
        :param dict event: Dictionary of event data to send to cronofy.
        """
        event['start'] = get_iso8601_string(event['start'])
        event['end'] = get_iso8601_string(event['end'])
        endpoint = 'events'
        url = 'calendars/{}/events'.format(calendar_id)
        return self._good_request(endpoint=endpoint, url=url, data=event, method="post", only_return_ok=True)        

    def user_auth_link(self, redirect_uri, scope='', state='', avoid_linking=False):
        """Generates a URL to send the user for OAuth 2.0

        :param string redirect_uri: URL to redirect the user to after auth.
        :param string scope: The scope of the privileges you want the eventual access_token to grant.
        :param string state: A value that will be returned to you unaltered along with the user's authorization request decision.
        (The OAuth 2.0 RFC recommends using this to prevent cross-site request forgery.)
        :param bool avoid_linking: Avoid linking calendar accounts together under one set of credentials. (Optional, default: false).
        :return: authorization link
        :rtype: ``string``
        """
        if not scope:
            scope = ' '.join(settings.DEFAULT_OAUTH_SCOPE)
        self.auth.update(redirect_uri=redirect_uri)
        response = self.request_handler.get(
            url='%s/oauth/authorize' % settings.APP_BASE_URL,
            params={
                'response_type': 'code',
                'client_id': self.auth.client_id,
                'redirect_uri': redirect_uri,
                'scope': scope,
                'state': state,
                'avoid_linking': avoid_linking,
            }
        )
        return response.url

    def validate(self, method, *args, **kwargs):
        """Validate authentication and values passed to the specified method.
        Raises a PyCronofyValidationError on error.

        :param string method: Method name to check.
        :param *args: Arguments for "Method".
        :param **kwargs: Keyword arguments for "Method".
        """
        validate(method, self.auth, *args, **kwargs)


