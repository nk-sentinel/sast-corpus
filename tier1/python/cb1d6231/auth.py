def login_required(view):
    def wrapped(*args, **kwargs):
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped
