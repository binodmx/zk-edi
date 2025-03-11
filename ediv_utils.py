import hashlib
import random
import math
from queue import Queue


class Node:
    def __init__(self, level, index, ln, num_children, hash_val):
        self.level = level
        self.index = index
        self.ln = ln  # leaf nodes
        self.num_children = num_children
        self.hash_val = hash_val
        self.firstChild = None
        self.secondChild = None
        self.thirdChild = None
        self.height = None


def Pr(x, y):
    random.seed(x)
    elements = list(range(y))
    random.shuffle(elements)
    return elements


def Hash(val):
    return hashlib.sha256(val).digest()


def VMHTGen(D, g, sh, block_size, sample_indices):
    m = len(D)
    H = math.floor(math.log2(m)) + 1
    Q = Queue()
    # D_shuffled = [D[i] for i in Pr(sh, m)]

    for i, idx in enumerate(sample_indices):
        n_i = Node(H, i + 1, 1, 0, Hash(bytes(x | y for x, y in zip(g, D[idx*block_size:idx*block_size+block_size]))))
        Q.put(n_i)

    l = H
    r = 1

    while Q.qsize() > 1:
        x = Q.get()  # the first node in current Q
        y = Q.get()  # the second node in current Q
        z = Q.queue[0] if Q.qsize() > 0 else None  # the third node in current Q
        w = Q.queue[1] if Q.qsize() > 1 else None  # the fourth node in current Q

        if z is not None and (w is None and z.level == y.level) or (w is not None and z.level > w.level):
            # New node t has three children
            t = Node(l - 1, r, x.ln + y.ln + z.ln, 3,
                     Hash(bytes(x | y | z for x, y, z in zip(x.hash_val, y.hash_val, z.hash_val))))
            t.firstChild = x
            t.secondChild = y
            t.thirdChild = Q.get()  # node z
        else:
            # New node t has two children
            t = Node(l - 1, r, x.ln + y.ln, 2, Hash(bytes(x | y for x, y in zip(x.hash_val, y.hash_val))))
            t.firstChild = x
            t.secondChild = y

        r += 1
        Q.put(t)

        if Q.queue[0].level < l:
            l -= 1
            r = 1

    t = Q.get()
    t.height = H
    return t  # Returns the root of the VMHT

def ProGen(R_i, D_i, block_size):
    m = int(len(D_i) / block_size)
    H = math.floor(math.log2(m)) + 1
    SI_i = R_i["SI_i"]
    DI_i = R_i["DI_i"]
    sh = R_i["sh"]
    g = bytes.fromhex(R_i["g"])
    l = R_i["l"]
    r = R_i["r"]
    ln = R_i["ln"]
    # D_shuffled = [D_i[i] for i in Pr(sh, m)]
    # Sample = D_shuffled[2**(H-l)*(r-1):2**(H-l)*(r-1)+ln]
    sample_indices = Pr(sh, m)[2**(H-l)*(r-1):2**(H-l)*(r-1)+ln] # Using indices for memory optimization
    t = VMHTGen(D_i, g, sh, block_size, sample_indices)
    tag = t.hash_val
    P_i = (SI_i, DI_i, tag.hex())
    return P_i
