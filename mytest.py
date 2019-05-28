
cidr = 23
mask = 0
for i in range(32):
    if i < cidr:
        mask = mask | (1 << (32-i-1))
    else:
        break
print(mask)

first = (mask & int('0xFF000000', 16)) >> (31 - 7)
second = (mask & int('0x00FF0000', 16)) >> (31 - 15)
third = (mask & int('0x0000FF00', 16)) >> (31 - 23)
fourth = (mask & int('0x000000FF', 16))
print("%d.%d.%d.%d" % (first, second, third, fourth))

seq = []
for x in range(4):
        seq.append((mask & int('0xFF000000', 16)) >> (31 - (8*(x+1)) + 1))
print(seq)


def chunkInt(m, n):
    chunk = []
    while True:
        if m - n > 0:
            chunk.append(n)
            m = m - n
        else:
            chunk.append(m)
            return chunk

print(chunkInt(4000, 1480))