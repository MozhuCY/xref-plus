import idaapi,idc 

class Taint:
    def __init__(self,level):
        self.level = level
        self.div = (0xff0000//level) & 0xff0000
    
    def TaintFunc(self,name,xref,level):
        if level == 0:
            return
        else:
            if GetMnem(xref).lower() == "call" or "BL":
                SetColor(xref, CIC_FUNC, 0xffffff - (self.div*level))
                callby = LocByName(GetFunctionName(xref))
                xrefs = CodeRefsTo(callby, False)
                for _xref in xrefs:
                    self.TaintFunc(name,_xref,level - 1)
                # _xrefs = CodeRefsTo(,False)
    
    def OneFunc(self,address):
        self.TaintFunc("",address,self.level)

def xrefplus():
    ea = get_screen_ea()
    print(hex(ea))
    T = Taint(5)
    T.OneFunc(ea)

def Taint_t():
    print("xref plus has been loaded")
    idaapi.add_hotkey('ctrl+shift+x', xrefplus)
    return idaapi.PLUGIN_KEEP

def PLUGIN_ENTRY():
    return Taint_t()