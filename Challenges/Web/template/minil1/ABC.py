def abc(key,value):
    klen=len(key)
    vlen=len(value)
    l=[]
    for i in range(vlen):
        l.append(chr(ord(key[i%klen])^ord(value[i])))
    result = ''.join(l)
    return result