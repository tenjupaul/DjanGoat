from app.models import User
from django.http import SimpleCookie

def current_user(request):
    return User.authenticate_by_token(request.COOKIES['auth_token'])


def simulate_simple_authentication(factory, client, email, password, path, add_messages_middleware, views):
    auth_request = factory.post('/sessions/')
    add_messages_middleware(auth_request)
    auth_response = views.sessions_index(auth_request,
                                                  email=email,
                                                  password=password,
                                                  path=path)
    # Add auth token cookie to request
    auth_token = auth_response.cookies['auth_token'].value

    client.cookies = SimpleCookie({'auth_token': auth_token})

def simulate_dead_code():
    always_none = None 
    if not always_none:
        # do nothing
        pass 
    else:
        # this 'else' condition will never get executed. 
        # Intentional - to demo dead code
        pass

