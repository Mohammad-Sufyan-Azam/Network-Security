# # def order_matrix(key):
# #     ''' Returns the list of columns of the matrix in the order specified by the key'''
# #     order_indices = []
    
# #     for i in key:
# #         order_indices.append((int(i), key.index(i)))

# #     order_indices.sort()

# #     return order_indices

# # print(order_matrix("4037"))
# # matrix = []
# # for i in range(4):
# #     matrix.append([])
# # print(matrix)

# # import numpy as np

# # n = '4037'
# # s = np.argsort(n)
# # print(s)

# # # create a numpy array of size n_rows x n_cols
# # matrix = np.empty((3, 4), dtype=str)
# # print(matrix)

# # c2 = 'abc'
# # # add c2 to column 2
# # matrix[:, 2] = list(c2)
# # print(matrix)


import time
import sys
from termcolor import colored

strings = ["Hello", "Pythonista", "World"] * 10000
i = 0
# note the time for the start of the loop
start = time.time()
for s in strings:
    sys.stdout.write('\r' + colored(s, 'green'))
    sys.stdout.flush()
    # time.sleep(0.001)  # sleep for 1ms
    sys.stdout.write('\r' + ' '*len(s))
    i+=1
end = time.time()
print(f"\nTime taken: {end-start}")

# f2 = open("keys.txt", "r")
# # encrypted_text = f.read().split("\n")
# keys = f2.read().split("\n")
# keys = [i for i in keys if i != '']
# print(keys)