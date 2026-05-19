"""
scripts/mke_mgkm.py
Exact match to working reference implementation.
"""
import random
import sys
from math import gcd
sys.set_int_max_str_digits(0)

def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def inverse(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Inverse doesn't exist")
    return x % m

def find_e(x, y):
    while True:
        k = random.getrandbits(512)
        e = 4 * k + 1
        if gcd(e, x * y) == 1:
            return e

def compute_d(e, x, y):
    exp = 2 * (x - 1) * (y - 1) - 1
    mod = 4 * x * y
    return pow(e, exp, mod)

def compute_eM_n(e_list, xy_list):
    n_total = 1
    for val in xy_list:
        n_total *= val
    eM = 0
    for i in range(len(e_list)):
        Mi  = n_total // xy_list[i]
        Ni  = inverse(Mi, xy_list[i])
        eM += e_list[i] * Mi * Ni
    eM = eM % n_total
    while eM % 4 != 1:
        eM += n_total
    return eM, n_total

def MKeyGen(primes):
    """
    Algorithm 1: MKeyGen
    Returns eM, N_global, n_total, and slave list.
    """
    e_list  = []
    d_list  = []
    xy_list = []
    n_list  = []
    x_list  = []
    y_list  = []

    for p, q in primes:
        x = (p - 1) // 2
        y = (q - 1) // 2
        e = find_e(x, y)
        d = compute_d(e, x, y)
        e_list.append(e)
        d_list.append(d)
        xy_list.append(x * y)
        n_list.append(p * q)
        x_list.append(x)
        y_list.append(y)

    eM, n_total = compute_eM_n(e_list, xy_list)

    # N_global = product of all p_i * q_i (used for encryption)
    N_global = 1
    for ni in n_list:
        N_global *= ni

    # CRT coefficients
    M_list = []
    N_coeff_list = []
    for i in range(len(e_list)):
        Mi = n_total // xy_list[i]
        Ni = inverse(Mi, xy_list[i])
        M_list.append(Mi)
        N_coeff_list.append(Ni)

    slaves = []
    for i in range(len(e_list)):
        slaves.append({
            "index": i,
            "e_i":   e_list[i],
            "d_i":   d_list[i],
            "n_i":   n_list[i],
            "x_i":   x_list[i],
            "y_i":   y_list[i],
            "Mi":    M_list[i],
            "Ni":    N_coeff_list[i],
            "xy_i":  xy_list[i],
            "p_i":   primes[i][0],
            "q_i":   primes[i][1],
        })

    return {
        "eM":       eM,
        "n_total":  n_total,
        "N_global": N_global,
        "slaves":   slaves,
    }

def MTokenGen(mkg, user_indices, message):
    """
    Algorithm 2: MTokenGen
    message = TEK as integer (small enough to encrypt)

    Selective encryption:
      e_MK = eM restricted to user group
      C    = pow(message, e_MK, N_group)  ← this IS MT_K

    Each slave in group decrypts:
      m_i = pow(MT_K, d_i, n_i) == message % n_i
    """
    eM      = mkg["eM"]
    slaves  = mkg["slaves"]
    n_total = mkg["n_total"]

    # e_MK = eM with non-group contributions removed
    e_MK = eM
    for slave in slaves:
        if slave["index"] not in user_indices:
            e_MK -= slave["e_i"] * slave["Mi"] * slave["Ni"]

    e_MK = e_MK % n_total
    while e_MK % 4 != 1:
        e_MK += n_total

    # N_group = product of n_i for group members only
    N_group = 1
    for slave in slaves:
        if slave["index"] in user_indices:
            N_group *= slave["n_i"]

    # MT_K = pow(message, e_MK, N_group)
    # This is the ciphertext — slaves decrypt with d_i
    MT_K = pow(message, e_MK, N_group)

    return {
        "MT_K":         MT_K,
        "e_MK":         e_MK,
        "N_group":      N_group,
        "message":      message,    # TEK integer
        "user_indices": user_indices,
    }

def JoKeyUpdate(mkg, mtoken, join_index):
    """
    Algorithm 3: JoKeyUpdate
    Add joining slave to group, regenerate MT_K.
    """
    slaves  = mkg["slaves"]
    n_total = mkg["n_total"]
    message = mtoken["message"]

    join_slave = slaves[join_index]
    old_e_MK   = mtoken["e_MK"]

    # Add joining slave contribution
    e_MK = old_e_MK + (join_slave["e_i"] *
                        join_slave["Mi"] *
                        join_slave["Ni"])
    e_MK = e_MK % n_total
    while e_MK % 4 != 1:
        e_MK += n_total

    # New group
    new_indices = list(mtoken["user_indices"]) + [join_index]

    N_group = 1
    for slave in slaves:
        if slave["index"] in new_indices:
            N_group *= slave["n_i"]

    MT_K = pow(message, e_MK, N_group)

    return {
        "MT_K":         MT_K,
        "e_MK":         e_MK,
        "N_group":      N_group,
        "message":      message,
        "user_indices": new_indices,
    }

def LeKeyUpdate(mkg, mtoken, leave_index):
    """
    Algorithm 5: LeKeyUpdate
    Remove leaving slave from group, regenerate MT_K.
    """
    slaves  = mkg["slaves"]
    n_total = mkg["n_total"]
    message = mtoken["message"]

    leave_slave = slaves[leave_index]
    old_e_MK    = mtoken["e_MK"]

    # Remove leaving slave contribution
    e_MK = old_e_MK - (leave_slave["e_i"] *
                        leave_slave["Mi"] *
                        leave_slave["Ni"])
    e_MK = e_MK % n_total
    while e_MK % 4 != 1:
        e_MK += n_total

    # New group
    new_indices = [u for u in mtoken["user_indices"]
                   if u != leave_index]

    N_group = 1
    for slave in slaves:
        if slave["index"] in new_indices:
            N_group *= slave["n_i"]

    MT_K = pow(message, e_MK, N_group)

    return {
        "MT_K":         MT_K,
        "e_MK":         e_MK,
        "N_group":      N_group,
        "message":      message,
        "user_indices": new_indices,
    }

def slave_decrypt(slave, MT_K):
    """
    Slave decrypts: pow(MT_K, d_i, n_i)
    Should equal message % n_i
    """
    return pow(MT_K, slave["d_i"], slave["n_i"])

def verify_mtoken(mkg, mtoken):
    """Verify all slaves in group can decrypt MT_K to recover message."""
    message = mtoken["message"]
    errors  = []
    for slave in mkg["slaves"]:
        if slave["index"] not in mtoken["user_indices"]:
            continue
        recovered = slave_decrypt(slave, mtoken["MT_K"])
        expected  = message % slave["n_i"]
        if recovered != expected:
            errors.append(
                f"Slave {slave['index']}: got {recovered}, "
                f"expected {expected}")
    return len(errors) == 0, errors
