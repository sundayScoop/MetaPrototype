import inspect

def test(*args):
    d = {}
    for arg in args:
        d[retrieve_name(arg)[0]] = arg
    print(d)

def retrieve_name(var):
    callers_local_vars = inspect.currentframe().f_back.f_back.f_locals.items()
    return [var_name for var_name, var_val in callers_local_vars if var_val is var]

hello = 1
byte = 2

test(hello, byte)