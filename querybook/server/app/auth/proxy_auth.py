import flask_login

# from requests_oauthlib import OAuth2Session

from app.db import with_session, DBSession

# from env import QuerybookSettings
from lib.logger import get_logger
from logic.user import (
    get_user_by_name,
    create_user,
)
from .utils import (
    AuthenticationError,
    AuthUser,
    abort_unauthorized,
    QuerybookLoginManager,
)

LOG = get_logger(__file__)


class OAuthLoginManager(object):
    def __init__(self):
        self.login_manager = QuerybookLoginManager()

    def init_app(self, flask_app):
        self.flask_app = flask_app

        self.login_manager.init_app(self.flask_app)

    def login(self, request):
        LOG.debug("Handling proxy login...")

        username = request.headers.get("X-Auth-Username")
        email = request.headers.get("X-Auth-Username")
        LOG.debug("got email: ", email)

        try:
            with DBSession() as session:
                flask_login.login_user(
                    AuthUser(self.login_user(username, email, session=session))
                )
        except AuthenticationError as e:
            LOG.error("Failed authenticate oauth user", e)
            abort_unauthorized()

    @with_session
    def login_user(self, username, email, session=None):
        if not username:
            raise AuthenticationError("Username must not be empty!")

        user = get_user_by_name(username, session=session)
        if not user:
            user = create_user(
                username=username, fullname=username, email=email, session=session
            )
        return user


login_manager = OAuthLoginManager()


def init_app(app):
    login_manager.init_app(app)


def login(request):
    return login_manager.login(request)
