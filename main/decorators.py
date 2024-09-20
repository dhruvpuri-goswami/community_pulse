from django.shortcuts import redirect
from functools import wraps
from django.contrib import messages

def check_session(func):
    @wraps(func)
    def wrap(request, *args, **kwargs):
        if 'user_info' not in request.session:  
            messages.error(request, 'You must be logged in to access this page.')
            return redirect('/signin/')  
        return func(request, *args, **kwargs)
    return wrap
