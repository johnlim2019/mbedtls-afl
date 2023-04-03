import random

#delete random character
def delete_character(s: str) -> str:
    if s == "":
        return s
    
    pos = random.randint(0, len(s) - 1)
    return s[:pos] + s[pos + 1:]

#insert random character
def insert_character(s: str) -> str:
    pos = random.randint(0, len(s))
    random_character = chr(random.randrange(0, 255))
    # print("Inserting", repr(random_character), "at", pos)
    return s[:pos] + random_character + s[pos:]

#flip random bit
def flip_random_character(s: str) -> str:
    if s == "":
        return s

    pos = random.randint(0, len(s) - 1)
    c = s[pos]
    bit = 1 << random.randint(0, 6)
    new_c = chr(ord(c) ^ bit)
    return s[:pos] + new_c + s[pos + 1:]

#increment random character
def increment_character(s: str) -> str:
    if s == "":
        return s
    pos = random.randint(0, len(s) - 1)
    c = s[pos]
    new_c = chr((ord(c) + 1) % 256)
    return s[:pos] + new_c + s[pos + 1:]

#decrement random character
def decrement_character(s: str) -> str:
    if s == "":
        return s
    pos = random.randint(0, len(s) - 1)
    c = s[pos]
    new_c = chr((ord(c) - 1) % 256)
    return s[:pos] + new_c + s[pos + 1:]

#adds string with integer
def arithmethic_add(s: str, max= 256) -> str:
    if s == "":
        return s

    try:
        int_value = int(str)
        addend = random.randint(1, max)
        return str(int_value + addend)
    except:
        return s

#subtracts integer from strintg
def arithmethic_subtract(s: str, max = 256) -> str:
    if s == "":
        return s

    try:
        int_value = int(str)
        addend = random.randint(1, max)
        return str(int_value - addend)
    except:
        return s

#chooses a random character and changes adjacent characters to the same one.
def pollute(s: str) ->str:
    
    if s == "":
        return s

    pos = random.randint(0, len(s) - 1)
    #print("polluting " + str(pos))
    if (pos == 0):
        if len(s) > 1:
            return s[pos] + s[pos]+ s[pos + 1:]
    elif(pos == len(s) - 1):
        
        return s[:pos -1] + s[pos] + s[pos]

    return s[:pos-1 ] +s[pos] + s[pos]+ s[pos] + s[pos + 2:]
