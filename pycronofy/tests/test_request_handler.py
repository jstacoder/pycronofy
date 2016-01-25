import pytest
import requests
import responses
from pycronofy.client import CronofyClient
from pycronofy import settings
import common_data

TEST_EVENTS_ARGS = { 
    'url': '%s/%s/events' % (settings.API_BASE_URL, settings.API_VERSION),
    'body': '{"example": 1}',
    'status': 200,
    'content_type':'application/json'
}

@pytest.fixture(scope="module")
def request_handler():
    """Setup RequestHandler instance with test values."""
    return CronofyClient(**common_data.AUTH_ARGS).request_handler

@responses.activate
def test_get(request_handler):
    """Test RequestHandler.get().

    :param RequestHandler request_handler: RequestHandler instance with test data.
    """
    responses.add(method=responses.GET, **TEST_EVENTS_ARGS)
    response = request_handler.get(endpoint='events')
    assert response['example'] == 1

@responses.activate
def test_delete(request_handler):
    """Test RequestHandler.delete().

    :param RequestHandler request_handler: RequestHandler instance with test data.
    """
    calendar_id = '123'
    event_id = 'evt_12345'
    responses.add(
        method=responses.DELETE, 
        url='%s/%s/calendars/%s/events' % (settings.API_BASE_URL, settings.API_VERSION, calendar_id),
        status=200,
        content_type='application/json',
    )
    response = request_handler.delete(endpoint='calendars/%s/events' % calendar_id, params={'event_id': event_id})
    assert response.status_code == requests.codes.ok

@responses.activate
def test_post(request_handler):
    """Test RequestHandler.post().

    :param RequestHandler request_handler: RequestHandler instance with test data.
    """
    responses.add(method=responses.POST, **TEST_EVENTS_ARGS)
    response = request_handler.post(endpoint='events')
    assert response.status_code == requests.codes.ok