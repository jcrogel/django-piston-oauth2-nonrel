typemapper = { }

class HandlerType(type):
    """
    Metaclass that keeps a registry of class -> handler
    mappings. It uses a global variable, so it is *not*
    thread-safe, although that's probably not a concern.
    """
    def __init__(cls, name, bases, dct):
        model = dct.get('model', None)
        
        if model:
            typemapper[model] = cls
        
        return super(HandlerType, cls).__init__(name, bases, dct)

class BaseHandler(object):
    """
    Basehandler that gives you CRUD for free.
    You are supposed to subclass this for specific
    functionality.
    
    All CRUD methods (`read`/`update`/`create`/`delete`)
    receive a request as the first argument from the
    resource. Use this for checking `request.user`, etc.
    """
    __metaclass__ = HandlerType

    allowed_methods = ('GET', 'POST', 'PUT', 'DELETE')
    exclude = ( 'id' )
    fields =  ( )

    def flatten_dict(self, dct):
        return dict([ (str(k), dct.get(k)) for k in dct.keys() ])

    def has_model(self):
        return hasattr(self, 'model')

    def exists(self, **kwa):
        if not self.has_model():
            raise NotImplementedError
            
        try:
            self.model.objects.get(**kwa)
            return True
        except self.model.DoesNotExist:
            return False

    def read(self, request, *a, **kwa):
        if not self.has_model():
            raise NotImplementedError

        return self.model.objects.filter(*a, **kwa)
        
    def create(self, request, *a, **kwa):
        if not self.has_model():
            raise NotImplementedError
    
        attrs = self.flatten_dict(request.POST)

        try:
            inst = self.model.objects.get(**attrs)
            raise ValueError("Already exists.")
        except self.model.DoesNotExist:
            inst = self.model(attrs)
            inst.save()
            return inst
            
    def update(self, request, *a, **kwa):
        if not self.has_model():
            raise NotImplementedError
            
        inst = self.model.objects.get(*a, **kwa)
        print "must update instance", inst, "with", request.PUT

        return "I can't do this yet."

    def delete(self, request, *a, **kwa):
        if not self.has_model():
            raise NotImplementedError

        return "I can't do this yet."
