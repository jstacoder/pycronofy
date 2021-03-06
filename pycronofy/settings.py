# Settings for Cronofy Client

# API URL and Version 
API_BASE_URL = 'https://api.cronofy.com'
APP_BASE_URL = 'https://app.cronofy.com'
API_VERSION = 'v1'

# Turned into a space separated string
DEFAULT_OAUTH_SCOPE = (
    'read_account',
    'list_calendars',
    'read_events', 
    'create_event',
    #'event_reminders',
    'delete_event',
    'create_calendar',
    #'change_participation_status',
    # 'read_free_busy', # implicitly included by 'read_events'
)

# Default Timezone ID (used in read_events)
DEFAULT_TIMEZONE_ID = 'Etc/UTC'

# Dictionary for request event hooks. Either empty or {'response': function}
REQUEST_HOOK = {}
